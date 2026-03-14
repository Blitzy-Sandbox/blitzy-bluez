// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — SDP (Service Discovery Protocol) Subsystem
//
// Copyright 2024 BlueZ Project
//
// Module root for the SDP subsystem in the `bluetoothd` crate. Unifies the
// public API previously spread across `src/sdpd.h`, `src/sdp-client.h`, and
// `src/sdp-xml.h` in the C codebase.
//
// Declares the four submodules (`client`, `server`, `database`, `xml`),
// defines shared types (`SdpRecord` helper methods, `SdpData`, `SdpError`),
// SDP protocol constants, and re-exports the primary public API surface.

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

pub mod client;
pub mod database;
pub mod server;
pub mod xml;

// ---------------------------------------------------------------------------
// Re-exports — client submodule
// ---------------------------------------------------------------------------

pub use client::{bt_cancel_discovery, bt_clear_cached_session, bt_search, bt_search_service};

// ---------------------------------------------------------------------------
// Re-exports — server submodule
// ---------------------------------------------------------------------------

pub use server::{start_sdp_server, stop_sdp_server};

// ---------------------------------------------------------------------------
// Re-exports — database submodule
// ---------------------------------------------------------------------------

pub use database::{SdpDatabase, add_record_to_server, remove_record_from_server};

// ---------------------------------------------------------------------------
// Re-exports — xml submodule (shared types defined there)
// ---------------------------------------------------------------------------

pub use xml::{SdpData, SdpRecord, parse_record, record_to_xml};

// ---------------------------------------------------------------------------
// SDP attribute ID constants (Bluetooth SDP Spec — §5.1)
// ---------------------------------------------------------------------------

/// ServiceRecordHandle — unique 32-bit identifier for each record.
pub const SDP_ATTR_RECORD_HANDLE: u16 = 0x0000;

/// ServiceClassIDList — list of UUIDs identifying the service classes.
pub const SDP_ATTR_SVCLASS_ID_LIST: u16 = 0x0001;

/// ServiceRecordState — incremented when the record is modified.
pub const SDP_ATTR_RECORD_STATE: u16 = 0x0002;

/// ServiceID — UUID uniquely identifying a specific service instance.
pub const SDP_ATTR_SERVICE_ID: u16 = 0x0003;

/// ProtocolDescriptorList — protocol stack(s) to reach the service.
pub const SDP_ATTR_PROTO_DESC_LIST: u16 = 0x0004;

/// BrowseGroupList — browse group(s) this service belongs to.
pub const SDP_ATTR_BROWSE_GRP_LIST: u16 = 0x0005;

/// LanguageBaseAttributeIDList — language/encoding/base offset triples.
pub const SDP_ATTR_LANG_BASE_ATTR_ID_LIST: u16 = 0x0006;

/// ServiceInfoTimeToLive — seconds before the record is considered stale.
pub const SDP_ATTR_SVCINFO_TTL: u16 = 0x0007;

/// ServiceAvailability — 0x00 (not available) to 0xFF (fully available).
pub const SDP_ATTR_SERVICE_AVAILABILITY: u16 = 0x0008;

/// BluetoothProfileDescriptorList — profile UUIDs with version numbers.
pub const SDP_ATTR_PFILE_DESC_LIST: u16 = 0x0009;

/// DocumentationURL — URL pointing to documentation for the service.
pub const SDP_ATTR_DOC_URL: u16 = 0x000A;

/// ClientExecutableURL — URL for a downloadable client application.
pub const SDP_ATTR_CLNT_EXEC_URL: u16 = 0x000B;

/// IconURL — URL for an icon representing the service.
pub const SDP_ATTR_ICON_URL: u16 = 0x000C;

/// AdditionalProtocolDescriptorLists — extra protocol stacks.
pub const SDP_ATTR_ADD_PROTO_DESC_LIST: u16 = 0x000D;

// ---------------------------------------------------------------------------
// SDP attribute ID constants — PnP / Device Information (offset 0x0200+)
// ---------------------------------------------------------------------------

/// GroupID — browse group identifier (context-dependent at 0x0200).
pub const SDP_ATTR_GROUP_ID: u16 = 0x0200;

/// SpecificationID — PnP device information specification version.
pub const SDP_ATTR_SPECIFICATION_ID: u16 = 0x0200;

/// VendorID — vendor identifier from the PnP record.
pub const SDP_ATTR_VENDOR_ID: u16 = 0x0201;

/// ProductID — product identifier from the PnP record.
pub const SDP_ATTR_PRODUCT_ID: u16 = 0x0202;

/// Version — product version from the PnP record.
pub const SDP_ATTR_VERSION: u16 = 0x0203;

/// PrimaryRecord — boolean indicating the primary PnP device record.
pub const SDP_ATTR_PRIMARY_RECORD: u16 = 0x0204;

/// VendorIDSource — identifies the source of the VendorID field.
pub const SDP_ATTR_VENDOR_ID_SOURCE: u16 = 0x0205;

// ---------------------------------------------------------------------------
// SDP attribute ID constants — HID profile (offset 0x0200+ in HID context)
// ---------------------------------------------------------------------------

/// HIDDeviceReleaseNumber — BCD device release number.
pub const SDP_ATTR_HID_DEVICE_RELEASE_NUMBER: u16 = 0x0200;

/// HIDParserVersion — HID parser version supported.
pub const SDP_ATTR_HID_PARSER_VERSION: u16 = 0x0201;

/// HIDDeviceSubclass — HID device subclass (keyboard, mouse, etc.).
pub const SDP_ATTR_HID_DEVICE_SUBCLASS: u16 = 0x0202;

/// HIDCountryCode — country code for localized hardware.
pub const SDP_ATTR_HID_COUNTRY_CODE: u16 = 0x0203;

/// HIDVirtualCable — whether virtual cable is supported.
pub const SDP_ATTR_HID_VIRTUAL_CABLE: u16 = 0x0204;

/// HIDReconnectInitiate — whether the device initiates reconnection.
pub const SDP_ATTR_HID_RECONNECT_INITIATE: u16 = 0x0205;

/// HIDDescriptorList — sequence of HID report descriptors.
pub const SDP_ATTR_HID_DESCRIPTOR_LIST: u16 = 0x0206;

/// HIDLANGIDBaseList — language ID base list for HID strings.
pub const SDP_ATTR_HID_LANG_ID_BASE_LIST: u16 = 0x0207;

/// HIDSDPDisable — whether SDP is disabled during HID connection.
pub const SDP_ATTR_HID_SDP_DISABLE: u16 = 0x0208;

/// HIDBatteryPower — whether the device is battery-powered.
pub const SDP_ATTR_HID_BATTERY_POWER: u16 = 0x0209;

/// HIDRemoteWake — whether the device supports remote wake.
pub const SDP_ATTR_HID_REMOTE_WAKEUP: u16 = 0x020A;

/// HIDProfileVersion — version of the HID profile implemented.
pub const SDP_ATTR_HID_PROFILE_VERSION: u16 = 0x020B;

/// HIDSupervisionTimeout — link supervision timeout for HID.
pub const SDP_ATTR_HID_SUPERVISION_TIMEOUT: u16 = 0x020C;

/// HIDNormallyConnectable — whether the device is normally connectable.
pub const SDP_ATTR_HID_NORMALLY_CONNECTABLE: u16 = 0x020D;

/// HIDBootDevice — whether the device supports boot protocol.
pub const SDP_ATTR_HID_BOOT_DEVICE: u16 = 0x020E;

// ---------------------------------------------------------------------------
// SDP attribute ID constants — miscellaneous
// ---------------------------------------------------------------------------

/// SupportedFormatsList — formats supported by the service (e.g., OBEX).
pub const SDP_ATTR_SUPPORTED_FORMATS_LIST: u16 = 0x0303;

// ---------------------------------------------------------------------------
// Service class UUID constants (Bluetooth Assigned Numbers)
// ---------------------------------------------------------------------------

/// SDP Server service class identifier.
pub const SDP_SERVER_SVCLASS_ID: u16 = 0x1000;

/// Public Browse Group — root of the browse group hierarchy.
pub const PUBLIC_BROWSE_GROUP: u16 = 0x1002;

/// Serial Port Profile service class identifier.
pub const SERIAL_PORT_SVCLASS_ID: u16 = 0x1101;

/// OBEX Object Push service class identifier.
pub const OBEX_OBJPUSH_SVCLASS_ID: u16 = 0x1105;

/// OBEX File Transfer service class identifier.
pub const OBEX_FILETRANS_SVCLASS_ID: u16 = 0x1106;

/// Human Interface Device service class identifier.
pub const HID_SVCLASS_ID: u16 = 0x1124;

/// Multi Profile Specification service class identifier.
pub const MPS_SVCLASS_ID: u16 = 0x113A;

/// PnP Information service class identifier.
pub const PNP_INFO_SVCLASS_ID: u16 = 0x1200;

// ---------------------------------------------------------------------------
// Protocol UUID constants (Bluetooth Assigned Numbers)
// ---------------------------------------------------------------------------

/// L2CAP protocol UUID.
pub const L2CAP_UUID: u16 = 0x0100;

/// RFCOMM protocol UUID.
pub const RFCOMM_UUID: u16 = 0x0003;

/// OBEX protocol UUID.
pub const OBEX_UUID: u16 = 0x0008;

/// HIDP (HID Protocol) UUID.
pub const HIDP_UUID: u16 = 0x0011;

// ---------------------------------------------------------------------------
// Primary language base
// ---------------------------------------------------------------------------

/// Base attribute offset for the primary (universal) language.
/// Service name is at this offset, description at +1, provider at +2.
const SDP_PRIMARY_LANG_BASE: u16 = 0x0100;

/// Default ISO 639 language code for English ("en" = 0x656e).
/// Use with [`SdpRecord::add_lang_attr`] for the standard English entry.
pub const SDP_DEFAULT_LANG_CODE: u16 = 0x656E;

/// Default IANA character encoding MIBEnum for UTF-8.
/// Use with [`SdpRecord::add_lang_attr`] for the standard UTF-8 encoding.
pub const SDP_DEFAULT_ENCODING: u16 = 106;

// ---------------------------------------------------------------------------
// SDP subsystem error type
// ---------------------------------------------------------------------------

/// Shared error type for the SDP subsystem.
///
/// Provides a unified error surface for SDP operations spanning client
/// searches, server lifecycle, database manipulation, and XML conversion.
/// Maps to D-Bus error responses where appropriate.
#[derive(Debug, thiserror::Error)]
pub enum SdpError {
    /// L2CAP or Unix socket connection to the SDP service failed.
    #[error("SDP connection failed: {0}")]
    ConnectionFailed(std::io::Error),

    /// The SDP search returned a protocol-level error or no results.
    #[error("SDP search failed")]
    SearchFailed,

    /// The SDP request exceeded the configured timeout.
    #[error("SDP request timed out")]
    Timeout,

    /// The SDP operation was explicitly cancelled.
    #[error("SDP operation cancelled")]
    Cancelled,

    /// The specified SDP record handle is invalid or does not exist.
    #[error("Invalid SDP record handle: {0}")]
    InvalidHandle(u32),

    /// Access to the specified SDP record is denied for this source address.
    #[error("Access denied for handle: {0}")]
    AccessDenied(u32),

    /// The received SDP PDU is malformed or has an unrecognised opcode.
    #[error("Invalid SDP PDU")]
    InvalidPdu,

    /// An error occurred during SDP record XML conversion.
    #[error("XML parsing error: {0}")]
    XmlError(String),

    /// Underlying I/O error from socket or file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// SdpRecord helper methods — extends the type defined in `xml.rs`
// ---------------------------------------------------------------------------

/// Builder and accessor methods for [`SdpRecord`], providing convenient
/// APIs for constructing SDP service records with standard attributes.
///
/// These methods mirror the C `sdp_set_*` / `sdp_get_*` family of
/// functions from `lib/bluetooth/sdp_lib.h`.
impl SdpRecord {
    // -------------------------------------------------------------------
    // Attribute accessors
    // -------------------------------------------------------------------

    /// Retrieve an attribute value by its 16-bit attribute identifier.
    ///
    /// Returns `None` if the attribute is not present in the record.
    pub fn get_attribute(&self, attr_id: u16) -> Option<&SdpData> {
        self.attrs.get(&attr_id)
    }

    /// Set (insert or overwrite) an attribute in the record.
    pub fn set_attribute(&mut self, attr_id: u16, value: SdpData) {
        self.attrs.insert(attr_id, value);
    }

    // -------------------------------------------------------------------
    // Browse groups
    // -------------------------------------------------------------------

    /// Set the `BrowseGroupList` attribute to the given list of browse group
    /// UUIDs.
    ///
    /// Each UUID is stored as a `Uuid16` inside a `Sequence`.
    /// Pass `&[PUBLIC_BROWSE_GROUP]` for the standard public browse root.
    ///
    /// Corresponds to C `sdp_set_browse_groups()`.
    pub fn set_browse_groups(&mut self, groups: &[u16]) {
        let items: Vec<SdpData> = groups.iter().map(|&g| SdpData::Uuid16(g)).collect();
        self.attrs.insert(SDP_ATTR_BROWSE_GRP_LIST, SdpData::Sequence(items));
    }

    // -------------------------------------------------------------------
    // Service class list
    // -------------------------------------------------------------------

    /// Set the `ServiceClassIDList` attribute to the given list of service
    /// class UUIDs.
    ///
    /// Corresponds to C `sdp_set_service_classes()`.
    pub fn set_service_classes(&mut self, classes: &[u16]) {
        let items: Vec<SdpData> = classes.iter().map(|&c| SdpData::Uuid16(c)).collect();
        self.attrs.insert(SDP_ATTR_SVCLASS_ID_LIST, SdpData::Sequence(items));
    }

    // -------------------------------------------------------------------
    // Profile descriptor list
    // -------------------------------------------------------------------

    /// Set the `BluetoothProfileDescriptorList` attribute.
    ///
    /// Each entry in `profiles` is a `(uuid16, version)` pair.  The version
    /// is a 16-bit BCD value (e.g., 0x0100 for v1.0).
    ///
    /// Wire format:
    /// ```text
    /// Sequence([
    ///     Sequence([Uuid16(uuid), UInt16(version)]),
    ///     ...
    /// ])
    /// ```
    ///
    /// Corresponds to C `sdp_set_profile_descs()`.
    pub fn set_profile_descs(&mut self, profiles: &[(u16, u16)]) {
        let items: Vec<SdpData> = profiles
            .iter()
            .map(|&(uuid, version)| {
                SdpData::Sequence(vec![SdpData::Uuid16(uuid), SdpData::UInt16(version)])
            })
            .collect();
        self.attrs.insert(SDP_ATTR_PFILE_DESC_LIST, SdpData::Sequence(items));
    }

    // -------------------------------------------------------------------
    // Protocol descriptor list
    // -------------------------------------------------------------------

    /// Set the `ProtocolDescriptorList` attribute.
    ///
    /// `protos` is a slice of protocol stacks.  Each stack is a `Vec` of
    /// protocol descriptors.  Each protocol descriptor is already an
    /// `SdpData::Sequence` containing a protocol UUID and optional
    /// parameters (e.g., PSM, channel number).
    ///
    /// Wire format:
    /// ```text
    /// Sequence([
    ///     Sequence([proto_desc_1, proto_desc_2, ...]),   // stack 1
    ///     ...
    /// ])
    /// ```
    ///
    /// Corresponds to C `sdp_set_access_protos()`.
    pub fn set_access_protos(&mut self, protos: &[Vec<SdpData>]) {
        let stacks: Vec<SdpData> =
            protos.iter().map(|stack| SdpData::Sequence(stack.clone())).collect();
        self.attrs.insert(SDP_ATTR_PROTO_DESC_LIST, SdpData::Sequence(stacks));
    }

    // -------------------------------------------------------------------
    // Additional protocol descriptor list
    // -------------------------------------------------------------------

    /// Set the `AdditionalProtocolDescriptorLists` attribute.
    ///
    /// Same structure as [`set_access_protos`] but stored under
    /// `SDP_ATTR_ADD_PROTO_DESC_LIST` (0x000D).
    ///
    /// Corresponds to C `sdp_set_add_access_protos()`.
    pub fn set_add_access_protos(&mut self, protos: &[Vec<SdpData>]) {
        let stacks: Vec<SdpData> =
            protos.iter().map(|stack| SdpData::Sequence(stack.clone())).collect();
        self.attrs.insert(SDP_ATTR_ADD_PROTO_DESC_LIST, SdpData::Sequence(stacks));
    }

    // -------------------------------------------------------------------
    // Language base attribute ID list
    // -------------------------------------------------------------------

    /// Add a language entry to the `LanguageBaseAttributeIDList`.
    ///
    /// Each entry is a triple: ISO 639 language code, IANA character
    /// encoding MIBEnum, and attribute base offset.  If the attribute does
    /// not yet exist, a new `Sequence` is created.  Otherwise the new
    /// triple is appended to the existing sequence.
    ///
    /// Standard defaults:
    /// - `code_iso639 = 0x656E` (English, "en")
    /// - `encoding = 106` (UTF-8)
    /// - `base_offset = 0x0100` (SDP_PRIMARY_LANG_BASE)
    ///
    /// Corresponds to C `sdp_add_lang_attr()` (which always adds the
    /// English/UTF-8 default).
    pub fn add_lang_attr(&mut self, code_iso639: u16, encoding: u16, base_offset: u16) {
        let triple = vec![
            SdpData::UInt16(code_iso639),
            SdpData::UInt16(encoding),
            SdpData::UInt16(base_offset),
        ];

        match self.attrs.get_mut(&SDP_ATTR_LANG_BASE_ATTR_ID_LIST) {
            Some(SdpData::Sequence(items)) => {
                items.extend(triple);
            }
            _ => {
                self.attrs.insert(SDP_ATTR_LANG_BASE_ATTR_ID_LIST, SdpData::Sequence(triple));
            }
        }
    }

    // -------------------------------------------------------------------
    // Service information attributes (name, description, provider)
    // -------------------------------------------------------------------

    /// Set the primary service name, description, and provider name.
    ///
    /// Each non-empty string is stored as a `Text` attribute at the
    /// primary language base offset:
    /// - Service name at `0x0100`
    /// - Service description at `0x0101`
    /// - Provider name at `0x0102`
    ///
    /// Empty strings are skipped (the corresponding attribute is not set).
    ///
    /// Corresponds to C `sdp_set_info_attr()`.
    pub fn set_info_attr(&mut self, name: &str, provider: &str, desc: &str) {
        if !name.is_empty() {
            self.attrs.insert(SDP_PRIMARY_LANG_BASE, SdpData::Text(name.as_bytes().to_vec()));
        }
        if !desc.is_empty() {
            self.attrs.insert(SDP_PRIMARY_LANG_BASE + 1, SdpData::Text(desc.as_bytes().to_vec()));
        }
        if !provider.is_empty() {
            self.attrs
                .insert(SDP_PRIMARY_LANG_BASE + 2, SdpData::Text(provider.as_bytes().to_vec()));
        }
    }

    // -------------------------------------------------------------------
    // URL attributes
    // -------------------------------------------------------------------

    /// Set a URL attribute (e.g., `SDP_ATTR_DOC_URL`, `SDP_ATTR_ICON_URL`,
    /// `SDP_ATTR_CLNT_EXEC_URL`).
    ///
    /// Corresponds to C `sdp_set_url_attr()`.
    pub fn set_url_attr(&mut self, attr_id: u16, url: &str) {
        self.attrs.insert(attr_id, SdpData::Url(url.to_owned()));
    }

    // -------------------------------------------------------------------
    // ServiceID
    // -------------------------------------------------------------------

    /// Set the `ServiceID` attribute to a UUID-16 value.
    ///
    /// Corresponds to C `sdp_set_service_id()`.
    pub fn set_service_id(&mut self, uuid: u16) {
        self.attrs.insert(SDP_ATTR_SERVICE_ID, SdpData::Uuid16(uuid));
    }

    // -------------------------------------------------------------------
    // ServiceInfoTimeToLive
    // -------------------------------------------------------------------

    /// Set the `ServiceInfoTimeToLive` attribute (seconds).
    ///
    /// Corresponds to the `ttl` field used in C `sdp_set_service_ttl()`.
    pub fn set_service_ttl(&mut self, ttl: u32) {
        self.attrs.insert(SDP_ATTR_SVCINFO_TTL, SdpData::UInt32(ttl));
    }

    // -------------------------------------------------------------------
    // ServiceAvailability
    // -------------------------------------------------------------------

    /// Set the `ServiceAvailability` attribute.
    ///
    /// `avail` ranges from `0x00` (not available) to `0xFF` (fully
    /// available).
    ///
    /// Corresponds to C `sdp_set_service_avail()`.
    pub fn set_service_avail(&mut self, avail: u8) {
        self.attrs.insert(SDP_ATTR_SERVICE_AVAILABILITY, SdpData::UInt8(avail));
    }

    // -------------------------------------------------------------------
    // ServiceRecordState
    // -------------------------------------------------------------------

    /// Set the `ServiceRecordState` attribute.
    ///
    /// The state value is incremented whenever the record is modified;
    /// clients can compare it to detect changes.
    ///
    /// Corresponds to C `sdp_set_record_state()`.
    pub fn set_record_state(&mut self, state: u32) {
        self.attrs.insert(SDP_ATTR_RECORD_STATE, SdpData::UInt32(state));
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdp_record_new_and_accessors() {
        let mut rec = SdpRecord::new(0x0001_0000);
        assert_eq!(rec.handle, 0x0001_0000);
        assert!(rec.attrs.is_empty());

        rec.set_attribute(SDP_ATTR_RECORD_HANDLE, SdpData::UInt32(0x0001_0000));
        assert_eq!(rec.get_attribute(SDP_ATTR_RECORD_HANDLE), Some(&SdpData::UInt32(0x0001_0000)));
        assert_eq!(rec.get_attribute(SDP_ATTR_SERVICE_ID), None);
    }

    #[test]
    fn test_set_browse_groups() {
        let mut rec = SdpRecord::new(1);
        rec.set_browse_groups(&[PUBLIC_BROWSE_GROUP]);
        match rec.get_attribute(SDP_ATTR_BROWSE_GRP_LIST) {
            Some(SdpData::Sequence(items)) => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0], SdpData::Uuid16(PUBLIC_BROWSE_GROUP));
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn test_set_service_classes() {
        let mut rec = SdpRecord::new(2);
        rec.set_service_classes(&[SERIAL_PORT_SVCLASS_ID, HID_SVCLASS_ID]);
        match rec.get_attribute(SDP_ATTR_SVCLASS_ID_LIST) {
            Some(SdpData::Sequence(items)) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], SdpData::Uuid16(SERIAL_PORT_SVCLASS_ID));
                assert_eq!(items[1], SdpData::Uuid16(HID_SVCLASS_ID));
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn test_set_profile_descs() {
        let mut rec = SdpRecord::new(3);
        rec.set_profile_descs(&[(PNP_INFO_SVCLASS_ID, 0x0103)]);
        match rec.get_attribute(SDP_ATTR_PFILE_DESC_LIST) {
            Some(SdpData::Sequence(items)) => {
                assert_eq!(items.len(), 1);
                match &items[0] {
                    SdpData::Sequence(inner) => {
                        assert_eq!(inner.len(), 2);
                        assert_eq!(inner[0], SdpData::Uuid16(PNP_INFO_SVCLASS_ID));
                        assert_eq!(inner[1], SdpData::UInt16(0x0103));
                    }
                    other => panic!("expected inner Sequence, got {:?}", other),
                }
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn test_set_access_protos() {
        let mut rec = SdpRecord::new(4);
        let l2cap_desc = SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID), SdpData::UInt16(1)]);
        let rfcomm_desc = SdpData::Sequence(vec![SdpData::Uuid16(RFCOMM_UUID), SdpData::UInt8(3)]);
        rec.set_access_protos(&[vec![l2cap_desc.clone(), rfcomm_desc.clone()]]);
        match rec.get_attribute(SDP_ATTR_PROTO_DESC_LIST) {
            Some(SdpData::Sequence(stacks)) => {
                assert_eq!(stacks.len(), 1);
                match &stacks[0] {
                    SdpData::Sequence(descs) => {
                        assert_eq!(descs.len(), 2);
                    }
                    other => panic!("expected Sequence, got {:?}", other),
                }
            }
            other => panic!("expected Sequence, got {:?}", other),
        }
    }

    #[test]
    fn test_set_add_access_protos() {
        let mut rec = SdpRecord::new(5);
        let obex_desc = SdpData::Sequence(vec![SdpData::Uuid16(OBEX_UUID)]);
        rec.set_add_access_protos(&[vec![obex_desc]]);
        assert!(rec.get_attribute(SDP_ATTR_ADD_PROTO_DESC_LIST).is_some());
    }

    #[test]
    fn test_add_lang_attr() {
        let mut rec = SdpRecord::new(6);
        rec.add_lang_attr(SDP_DEFAULT_LANG_CODE, SDP_DEFAULT_ENCODING, SDP_PRIMARY_LANG_BASE);
        match rec.get_attribute(SDP_ATTR_LANG_BASE_ATTR_ID_LIST) {
            Some(SdpData::Sequence(items)) => {
                assert_eq!(items.len(), 3);
                assert_eq!(items[0], SdpData::UInt16(SDP_DEFAULT_LANG_CODE));
                assert_eq!(items[1], SdpData::UInt16(SDP_DEFAULT_ENCODING));
                assert_eq!(items[2], SdpData::UInt16(SDP_PRIMARY_LANG_BASE));
            }
            other => panic!("expected Sequence, got {:?}", other),
        }

        // Add a second language — items should be appended.
        rec.add_lang_attr(0x6672, 106, 0x0200); // "fr"
        match rec.get_attribute(SDP_ATTR_LANG_BASE_ATTR_ID_LIST) {
            Some(SdpData::Sequence(items)) => {
                assert_eq!(items.len(), 6);
            }
            other => panic!("expected Sequence with 6 elements, got {:?}", other),
        }
    }

    #[test]
    fn test_set_info_attr() {
        let mut rec = SdpRecord::new(7);
        rec.set_info_attr("Test Service", "BlueZ", "A test service record");
        match rec.get_attribute(SDP_PRIMARY_LANG_BASE) {
            Some(SdpData::Text(name)) => {
                assert_eq!(name, b"Test Service");
            }
            other => panic!("expected Text for name, got {:?}", other),
        }
        match rec.get_attribute(SDP_PRIMARY_LANG_BASE + 1) {
            Some(SdpData::Text(desc)) => {
                assert_eq!(desc, b"A test service record");
            }
            other => panic!("expected Text for desc, got {:?}", other),
        }
        match rec.get_attribute(SDP_PRIMARY_LANG_BASE + 2) {
            Some(SdpData::Text(prov)) => {
                assert_eq!(prov, b"BlueZ");
            }
            other => panic!("expected Text for provider, got {:?}", other),
        }
    }

    #[test]
    fn test_set_info_attr_skips_empty() {
        let mut rec = SdpRecord::new(8);
        rec.set_info_attr("Only Name", "", "");
        assert!(rec.get_attribute(SDP_PRIMARY_LANG_BASE).is_some());
        assert!(rec.get_attribute(SDP_PRIMARY_LANG_BASE + 1).is_none());
        assert!(rec.get_attribute(SDP_PRIMARY_LANG_BASE + 2).is_none());
    }

    #[test]
    fn test_set_url_attr() {
        let mut rec = SdpRecord::new(9);
        rec.set_url_attr(SDP_ATTR_DOC_URL, "https://www.bluez.org/");
        match rec.get_attribute(SDP_ATTR_DOC_URL) {
            Some(SdpData::Url(url)) => {
                assert_eq!(url, "https://www.bluez.org/");
            }
            other => panic!("expected Url, got {:?}", other),
        }
    }

    #[test]
    fn test_set_service_id() {
        let mut rec = SdpRecord::new(10);
        rec.set_service_id(SDP_SERVER_SVCLASS_ID);
        assert_eq!(
            rec.get_attribute(SDP_ATTR_SERVICE_ID),
            Some(&SdpData::Uuid16(SDP_SERVER_SVCLASS_ID))
        );
    }

    #[test]
    fn test_set_service_ttl() {
        let mut rec = SdpRecord::new(11);
        rec.set_service_ttl(3600);
        assert_eq!(rec.get_attribute(SDP_ATTR_SVCINFO_TTL), Some(&SdpData::UInt32(3600)));
    }

    #[test]
    fn test_set_service_avail() {
        let mut rec = SdpRecord::new(12);
        rec.set_service_avail(0xFF);
        assert_eq!(rec.get_attribute(SDP_ATTR_SERVICE_AVAILABILITY), Some(&SdpData::UInt8(0xFF)));
    }

    #[test]
    fn test_set_record_state() {
        let mut rec = SdpRecord::new(13);
        rec.set_record_state(42);
        assert_eq!(rec.get_attribute(SDP_ATTR_RECORD_STATE), Some(&SdpData::UInt32(42)));
    }

    #[test]
    fn test_sdp_error_display() {
        let err = SdpError::SearchFailed;
        assert_eq!(format!("{err}"), "SDP search failed");

        let err = SdpError::InvalidHandle(0x0001_0000);
        assert_eq!(format!("{err}"), "Invalid SDP record handle: 65536");

        let err = SdpError::XmlError("bad input".into());
        assert_eq!(format!("{err}"), "XML parsing error: bad input");
    }

    #[test]
    fn test_sdp_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let sdp_err: SdpError = io_err.into();
        match sdp_err {
            SdpError::Io(_) => {}
            other => panic!("expected SdpError::Io, got {:?}", other),
        }
    }

    #[test]
    fn test_constants_values() {
        // Verify key constant values match the Bluetooth SDP specification.
        assert_eq!(SDP_ATTR_RECORD_HANDLE, 0x0000);
        assert_eq!(SDP_ATTR_SVCLASS_ID_LIST, 0x0001);
        assert_eq!(SDP_ATTR_RECORD_STATE, 0x0002);
        assert_eq!(SDP_ATTR_SERVICE_ID, 0x0003);
        assert_eq!(SDP_ATTR_PROTO_DESC_LIST, 0x0004);
        assert_eq!(SDP_ATTR_BROWSE_GRP_LIST, 0x0005);
        assert_eq!(SDP_ATTR_LANG_BASE_ATTR_ID_LIST, 0x0006);
        assert_eq!(SDP_ATTR_SVCINFO_TTL, 0x0007);
        assert_eq!(SDP_ATTR_SERVICE_AVAILABILITY, 0x0008);
        assert_eq!(SDP_ATTR_PFILE_DESC_LIST, 0x0009);
        assert_eq!(SDP_ATTR_DOC_URL, 0x000A);
        assert_eq!(SDP_ATTR_CLNT_EXEC_URL, 0x000B);
        assert_eq!(SDP_ATTR_ICON_URL, 0x000C);
        assert_eq!(SDP_ATTR_ADD_PROTO_DESC_LIST, 0x000D);
        assert_eq!(SDP_ATTR_GROUP_ID, 0x0200);
        assert_eq!(SDP_ATTR_SPECIFICATION_ID, 0x0200);
        assert_eq!(SDP_ATTR_VENDOR_ID, 0x0201);
        assert_eq!(SDP_ATTR_PRODUCT_ID, 0x0202);
        assert_eq!(SDP_ATTR_VERSION, 0x0203);
        assert_eq!(SDP_ATTR_PRIMARY_RECORD, 0x0204);
        assert_eq!(SDP_ATTR_VENDOR_ID_SOURCE, 0x0205);
        assert_eq!(SDP_SERVER_SVCLASS_ID, 0x1000);
        assert_eq!(PUBLIC_BROWSE_GROUP, 0x1002);
        assert_eq!(PNP_INFO_SVCLASS_ID, 0x1200);
        assert_eq!(MPS_SVCLASS_ID, 0x113A);
        assert_eq!(L2CAP_UUID, 0x0100);
        assert_eq!(RFCOMM_UUID, 0x0003);
        assert_eq!(OBEX_UUID, 0x0008);
        assert_eq!(HIDP_UUID, 0x0011);
        assert_eq!(SERIAL_PORT_SVCLASS_ID, 0x1101);
        assert_eq!(OBEX_OBJPUSH_SVCLASS_ID, 0x1105);
        assert_eq!(OBEX_FILETRANS_SVCLASS_ID, 0x1106);
        assert_eq!(HID_SVCLASS_ID, 0x1124);
        assert_eq!(SDP_ATTR_SUPPORTED_FORMATS_LIST, 0x0303);
        assert_eq!(SDP_ATTR_HID_DEVICE_RELEASE_NUMBER, 0x0200);
        assert_eq!(SDP_ATTR_HID_BOOT_DEVICE, 0x020E);
    }
}
