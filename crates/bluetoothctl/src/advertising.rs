// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2016  Intel Corporation. All rights reserved.
//
//! LE advertising control module — Rust rewrite of `client/advertising.c`.
//!
//! This module manages the `LEAdvertisement1` D-Bus object exposed at
//! `/org/bluez/advertising` and the `RegisterAdvertisement` /
//! `UnregisterAdvertisement` flows with the `LEAdvertisingManager1` interface.
//!
//! All public `ad_*` functions are designed to be called from shell command
//! handlers in `bluetoothctl`.  They modify module-level advertising state and
//! emit D-Bus property-change signals when an advertisement is registered.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use bluez_shared::shell::{bt_shell_hexdump, bt_shell_noninteractive_quit, bt_shell_printf};
use bluez_shared::util::uuid::{bt_appear_to_str, bt_uuidstr_to_str};
use zbus::Connection;
use zbus::zvariant::OwnedValue;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Advertising data type index for primary advertising data.
pub const AD_TYPE_AD: usize = 0;

/// Advertising data type index for scan response data.
pub const AD_TYPE_SRD: usize = 1;

/// Total number of advertising data types (advertising + scan response).
pub const AD_TYPE_COUNT: usize = 2;

/// D-Bus object path for the advertising object.
const AD_PATH: &str = "/org/bluez/advertising";

/// D-Bus interface name for LEAdvertisement1.
const AD_IFACE: &str = "org.bluez.LEAdvertisement1";

/// Maximum length of raw advertising data (BT Core Spec).
const AD_DATA_MAX_LEN: usize = 245;

/// Exit status: success.
const EXIT_SUCCESS: i32 = 0;

/// Exit status: failure.
const EXIT_FAILURE: i32 = 1;

/// Negative EINPROGRESS — signals async operation in progress.
const NEG_EINPROGRESS: i32 = -115;

// ─────────────────────────────────────────────────────────────────────────────
// Internal Data Types
// ─────────────────────────────────────────────────────────────────────────────

/// Raw advertising data buffer (max 245 bytes per BT spec).
///
/// Replaces C `struct ad_data` (lines 31-34).
#[derive(Clone, Default)]
struct AdData {
    /// Data bytes.
    data: Vec<u8>,
}

/// Service data entry: UUID string + associated data.
///
/// Replaces C `struct service_data` (lines 36-39).
#[derive(Clone, Default)]
struct ServiceDataEntry {
    /// Service UUID string.
    uuid: Option<String>,
    /// Associated service data bytes.
    data: AdData,
}

/// Manufacturer-specific data entry: company ID + data.
///
/// Replaces C `struct manufacturer_data` (lines 41-44).
#[derive(Clone, Default)]
struct ManufacturerDataEntry {
    /// Company identifier (Bluetooth SIG assigned).
    id: u16,
    /// Associated manufacturer data bytes.
    data: AdData,
}

/// Generic AD type data entry with validity flag.
///
/// Replaces C `struct data` (lines 46-50).
#[derive(Clone, Default)]
struct DataEntry {
    /// Whether this entry contains valid data.
    valid: bool,
    /// The AD type code.
    ad_type: u8,
    /// The raw data bytes.
    data: AdData,
}

/// Main advertising state — replaces C `static struct ad` (lines 52-79).
///
/// Fields are initialised with the same defaults as the C original:
/// `local_appearance = UINT16_MAX`, `discoverable = true`, `rsi = true`.
struct AdState {
    /// Whether the advertisement is currently registered with BlueZ.
    registered: bool,
    /// Advertising type string ("peripheral", "broadcast", etc.).
    ad_type: Option<String>,
    /// Custom local name override.
    local_name: Option<String>,
    /// Secondary advertising channel ("1M", "2M", "Coded").
    secondary: Option<String>,
    /// Minimum advertising interval in milliseconds.
    min_interval: u32,
    /// Maximum advertising interval in milliseconds.
    max_interval: u32,
    /// Local appearance value (u16::MAX means unset).
    local_appearance: u16,
    /// Advertising duration in seconds.
    duration: u16,
    /// Advertising timeout in seconds.
    timeout: u16,
    /// Discoverable timeout in seconds.
    discoverable_to: u16,
    /// Service UUIDs per ad type (AD / scan response).
    uuids: [Vec<String>; AD_TYPE_COUNT],
    /// Solicit UUIDs per ad type (AD / scan response).
    solicit: [Vec<String>; AD_TYPE_COUNT],
    /// Service data per ad type.
    service: [ServiceDataEntry; AD_TYPE_COUNT],
    /// Manufacturer data per ad type.
    manufacturer: [ManufacturerDataEntry; AD_TYPE_COUNT],
    /// Raw AD type data per ad type.
    data_entries: [DataEntry; AD_TYPE_COUNT],
    /// Whether the advertisement is discoverable.
    discoverable: bool,
    /// Whether to include TX power in the advertisement.
    tx_power: bool,
    /// Whether to include local name in the Includes list.
    name: bool,
    /// Whether to include appearance in the Includes list.
    appearance: bool,
    /// Whether to include RSI (Resolvable Set Identifier).
    rsi: bool,
}

impl Default for AdState {
    fn default() -> Self {
        Self {
            registered: false,
            ad_type: None,
            local_name: None,
            secondary: None,
            min_interval: 0,
            max_interval: 0,
            local_appearance: u16::MAX,
            duration: 0,
            timeout: 0,
            discoverable_to: 0,
            uuids: [Vec::new(), Vec::new()],
            solicit: [Vec::new(), Vec::new()],
            service: [ServiceDataEntry::default(), ServiceDataEntry::default()],
            manufacturer: [ManufacturerDataEntry::default(), ManufacturerDataEntry::default()],
            data_entries: [DataEntry::default(), DataEntry::default()],
            discoverable: true,
            tx_power: false,
            name: false,
            appearance: false,
            rsi: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global State
// ─────────────────────────────────────────────────────────────────────────────

/// Process-wide advertising state, protected by a mutex.
static AD_STATE: LazyLock<Mutex<AdState>> = LazyLock::new(|| Mutex::new(AdState::default()));

// ─────────────────────────────────────────────────────────────────────────────
// Name Lookup Tables
// ─────────────────────────────────────────────────────────────────────────────

/// Human-readable names for printing advertising data entries.
///
/// Replaces C `static const struct { ... } ad_names` (lines 141-153).
struct AdNames {
    uuid: [&'static str; AD_TYPE_COUNT],
    solicit: [&'static str; AD_TYPE_COUNT],
    service: [&'static str; AD_TYPE_COUNT],
    manufacturer: [&'static str; AD_TYPE_COUNT],
    data: [&'static str; AD_TYPE_COUNT],
}

static AD_NAMES: AdNames = AdNames {
    uuid: ["UUID", "Scan Response UUID"],
    solicit: ["Solicit UUID", "Scan Response Solicit UUID"],
    service: ["UUID", "Scan Response UUID"],
    manufacturer: ["Manufacturer", "Scan Response Manufacturer"],
    data: ["Data", "Scan Response Data"],
};

/// D-Bus property names indexed by ad type (AD vs Scan Response).
///
/// Replaces C `static const struct { ... } prop_names` (lines 775-787).
struct PropNames {
    uuid: [&'static str; AD_TYPE_COUNT],
    solicit: [&'static str; AD_TYPE_COUNT],
    service: [&'static str; AD_TYPE_COUNT],
    manufacturer: [&'static str; AD_TYPE_COUNT],
    data: [&'static str; AD_TYPE_COUNT],
}

static PROP_NAMES: PropNames = PropNames {
    uuid: ["ServiceUUIDs", "ScanResponseServiceUUIDs"],
    solicit: ["SolicitUUIDs", "ScanResponseSolicitUUIDs"],
    service: ["ServiceData", "ScanResponseServiceData"],
    manufacturer: ["ManufacturerData", "ScanResponseManufacturerData"],
    data: ["Data", "ScanResponseData"],
};

// ─────────────────────────────────────────────────────────────────────────────
// D-Bus LEAdvertisement1 Interface
// ─────────────────────────────────────────────────────────────────────────────

/// LEAdvertisement1 D-Bus interface implementation.
///
/// Registered at [`AD_PATH`] when the user requests advertisement
/// registration.  BlueZ reads properties from this object to configure the
/// advertising parameters.
///
/// All property getters read from the module-level [`AD_STATE`] mutex.
struct AdInterface;

#[zbus::interface(name = "org.bluez.LEAdvertisement1")]
impl AdInterface {
    // ── Methods ──────────────────────────────────────────────────────────

    /// Called by BlueZ when the advertisement is released.
    ///
    /// Replaces C `release_advertising` (lines 88-96).
    fn release(&self) {
        bt_shell_printf(format_args!("Advertising released\n"));
        let mut state = AD_STATE.lock().unwrap();
        state.registered = false;
    }

    // ── Properties ───────────────────────────────────────────────────────
    //
    // Properties match the C `ad_props[]` table (lines 666-697) exactly.
    // Conditional properties return fdo::Error when their "exists" predicate
    // would have returned FALSE in the C code, causing GetAll to omit them.

    /// Advertising type — always present (C: get_type, lines 254-265).
    #[zbus(property, name = "Type")]
    fn ad_type(&self) -> String {
        let state = AD_STATE.lock().unwrap();
        match &state.ad_type {
            Some(t) if !t.is_empty() => t.clone(),
            _ => "peripheral".to_string(),
        }
    }

    /// Service UUIDs for primary advertising data.
    #[zbus(property, name = "ServiceUUIDs")]
    fn service_uuids(&self) -> zbus::fdo::Result<Vec<String>> {
        let state = AD_STATE.lock().unwrap();
        if state.uuids[AD_TYPE_AD].is_empty() {
            Err(zbus::fdo::Error::UnknownProperty("ServiceUUIDs not set".into()))
        } else {
            Ok(state.uuids[AD_TYPE_AD].clone())
        }
    }

    /// Solicit UUIDs for primary advertising data.
    #[zbus(property, name = "SolicitUUIDs")]
    fn solicit_uuids(&self) -> zbus::fdo::Result<Vec<String>> {
        let state = AD_STATE.lock().unwrap();
        if state.solicit[AD_TYPE_AD].is_empty() {
            Err(zbus::fdo::Error::UnknownProperty("SolicitUUIDs not set".into()))
        } else {
            Ok(state.solicit[AD_TYPE_AD].clone())
        }
    }

    /// Service data dictionary for primary advertising data.
    ///
    /// D-Bus type: `a{sv}` where each value variant is a byte array `ay`.
    #[zbus(property, name = "ServiceData")]
    fn service_data(&self) -> zbus::fdo::Result<HashMap<String, OwnedValue>> {
        let state = AD_STATE.lock().unwrap();
        let svc = &state.service[AD_TYPE_AD];
        match &svc.uuid {
            Some(uuid) => {
                let mut map = HashMap::new();
                let bytes = svc.data.data.clone();
                if let Ok(val) = OwnedValue::try_from(zbus::zvariant::Value::from(bytes)) {
                    map.insert(uuid.clone(), val);
                }
                Ok(map)
            }
            None => Err(zbus::fdo::Error::UnknownProperty("ServiceData not set".into())),
        }
    }

    /// Manufacturer data dictionary for primary advertising data.
    ///
    /// D-Bus type: `a{qv}` where each value variant is a byte array `ay`.
    #[zbus(property, name = "ManufacturerData")]
    fn manufacturer_data(&self) -> zbus::fdo::Result<HashMap<u16, OwnedValue>> {
        let state = AD_STATE.lock().unwrap();
        let mfr = &state.manufacturer[AD_TYPE_AD];
        if mfr.id == 0 {
            Err(zbus::fdo::Error::UnknownProperty("ManufacturerData not set".into()))
        } else {
            let mut map = HashMap::new();
            let bytes = mfr.data.data.clone();
            if let Ok(val) = OwnedValue::try_from(zbus::zvariant::Value::from(bytes)) {
                map.insert(mfr.id, val);
            }
            Ok(map)
        }
    }

    /// Raw AD type data dictionary for primary advertising data.
    ///
    /// D-Bus type: `a{yv}` where each value variant is a byte array `ay`.
    #[zbus(property, name = "Data")]
    fn data(&self) -> zbus::fdo::Result<HashMap<u8, OwnedValue>> {
        let state = AD_STATE.lock().unwrap();
        let entry = &state.data_entries[AD_TYPE_AD];
        if !entry.valid {
            Err(zbus::fdo::Error::UnknownProperty("Data not set".into()))
        } else {
            let mut map = HashMap::new();
            let bytes = entry.data.data.clone();
            if let Ok(val) = OwnedValue::try_from(zbus::zvariant::Value::from(bytes)) {
                map.insert(entry.ad_type, val);
            }
            Ok(map)
        }
    }

    /// Scan response service UUIDs.
    #[zbus(property, name = "ScanResponseServiceUUIDs")]
    fn scan_response_service_uuids(&self) -> zbus::fdo::Result<Vec<String>> {
        let state = AD_STATE.lock().unwrap();
        if state.uuids[AD_TYPE_SRD].is_empty() {
            Err(zbus::fdo::Error::UnknownProperty("ScanResponseServiceUUIDs not set".into()))
        } else {
            Ok(state.uuids[AD_TYPE_SRD].clone())
        }
    }

    /// Scan response solicit UUIDs.
    #[zbus(property, name = "ScanResponseSolicitUUIDs")]
    fn scan_response_solicit_uuids(&self) -> zbus::fdo::Result<Vec<String>> {
        let state = AD_STATE.lock().unwrap();
        if state.solicit[AD_TYPE_SRD].is_empty() {
            Err(zbus::fdo::Error::UnknownProperty("ScanResponseSolicitUUIDs not set".into()))
        } else {
            Ok(state.solicit[AD_TYPE_SRD].clone())
        }
    }

    /// Scan response service data.
    #[zbus(property, name = "ScanResponseServiceData")]
    fn scan_response_service_data(&self) -> zbus::fdo::Result<HashMap<String, OwnedValue>> {
        let state = AD_STATE.lock().unwrap();
        let svc = &state.service[AD_TYPE_SRD];
        match &svc.uuid {
            Some(uuid) => {
                let mut map = HashMap::new();
                let bytes = svc.data.data.clone();
                if let Ok(val) = OwnedValue::try_from(zbus::zvariant::Value::from(bytes)) {
                    map.insert(uuid.clone(), val);
                }
                Ok(map)
            }
            None => {
                Err(zbus::fdo::Error::UnknownProperty("ScanResponseServiceData not set".into()))
            }
        }
    }

    /// Scan response manufacturer data.
    #[zbus(property, name = "ScanResponseManufacturerData")]
    fn scan_response_manufacturer_data(&self) -> zbus::fdo::Result<HashMap<u16, OwnedValue>> {
        let state = AD_STATE.lock().unwrap();
        let mfr = &state.manufacturer[AD_TYPE_SRD];
        if mfr.id == 0 {
            Err(zbus::fdo::Error::UnknownProperty("ScanResponseManufacturerData not set".into()))
        } else {
            let mut map = HashMap::new();
            let bytes = mfr.data.data.clone();
            if let Ok(val) = OwnedValue::try_from(zbus::zvariant::Value::from(bytes)) {
                map.insert(mfr.id, val);
            }
            Ok(map)
        }
    }

    /// Scan response raw AD type data.
    #[zbus(property, name = "ScanResponseData")]
    fn scan_response_data(&self) -> zbus::fdo::Result<HashMap<u8, OwnedValue>> {
        let state = AD_STATE.lock().unwrap();
        let entry = &state.data_entries[AD_TYPE_SRD];
        if !entry.valid {
            Err(zbus::fdo::Error::UnknownProperty("ScanResponseData not set".into()))
        } else {
            let mut map = HashMap::new();
            let bytes = entry.data.data.clone();
            if let Ok(val) = OwnedValue::try_from(zbus::zvariant::Value::from(bytes)) {
                map.insert(entry.ad_type, val);
            }
            Ok(map)
        }
    }

    /// Discoverable flag — always present (C line 685).
    #[zbus(property, name = "Discoverable")]
    fn discoverable(&self) -> bool {
        AD_STATE.lock().unwrap().discoverable
    }

    /// Discoverable timeout (conditional — exists when non-zero).
    #[zbus(property, name = "DiscoverableTimeout")]
    fn discoverable_timeout(&self) -> zbus::fdo::Result<u16> {
        let state = AD_STATE.lock().unwrap();
        if state.discoverable_to == 0 {
            Err(zbus::fdo::Error::UnknownProperty("DiscoverableTimeout not set".into()))
        } else {
            Ok(state.discoverable_to)
        }
    }

    /// Includes list — conditional based on tx_power/name/appearance/rsi flags.
    ///
    /// Replaces C `get_includes` (lines 460-495).
    #[zbus(property, name = "Includes")]
    fn includes(&self) -> zbus::fdo::Result<Vec<String>> {
        let state = AD_STATE.lock().unwrap();
        if !state.tx_power && !state.name && !state.appearance && !state.rsi {
            return Err(zbus::fdo::Error::UnknownProperty("Includes not set".into()));
        }
        let mut list = Vec::new();
        if state.tx_power {
            list.push("tx-power".to_string());
        }
        if state.name {
            list.push("local-name".to_string());
        }
        if state.appearance {
            list.push("appearance".to_string());
        }
        if state.rsi {
            list.push("rsi".to_string());
        }
        Ok(list)
    }

    /// Local name override — conditional (exists when set).
    #[zbus(property, name = "LocalName")]
    fn local_name(&self) -> zbus::fdo::Result<String> {
        let state = AD_STATE.lock().unwrap();
        match &state.local_name {
            Some(name) => Ok(name.clone()),
            None => Err(zbus::fdo::Error::UnknownProperty("LocalName not set".into())),
        }
    }

    /// Appearance value — conditional (exists when != u16::MAX).
    #[zbus(property, name = "Appearance")]
    fn appearance(&self) -> zbus::fdo::Result<u16> {
        let state = AD_STATE.lock().unwrap();
        if state.local_appearance == u16::MAX {
            Err(zbus::fdo::Error::UnknownProperty("Appearance not set".into()))
        } else {
            Ok(state.local_appearance)
        }
    }

    /// Duration in seconds — conditional (exists when non-zero).
    #[zbus(property, name = "Duration")]
    fn duration(&self) -> zbus::fdo::Result<u16> {
        let state = AD_STATE.lock().unwrap();
        if state.duration == 0 {
            Err(zbus::fdo::Error::UnknownProperty("Duration not set".into()))
        } else {
            Ok(state.duration)
        }
    }

    /// Timeout in seconds — conditional (exists when non-zero).
    #[zbus(property, name = "Timeout")]
    fn timeout(&self) -> zbus::fdo::Result<u16> {
        let state = AD_STATE.lock().unwrap();
        if state.timeout == 0 {
            Err(zbus::fdo::Error::UnknownProperty("Timeout not set".into()))
        } else {
            Ok(state.timeout)
        }
    }

    /// Minimum advertising interval — conditional (exists when non-zero).
    #[zbus(property, name = "MinInterval")]
    fn min_interval(&self) -> zbus::fdo::Result<u32> {
        let state = AD_STATE.lock().unwrap();
        if state.min_interval == 0 {
            Err(zbus::fdo::Error::UnknownProperty("MinInterval not set".into()))
        } else {
            Ok(state.min_interval)
        }
    }

    /// Maximum advertising interval — conditional (exists when non-zero).
    #[zbus(property, name = "MaxInterval")]
    fn max_interval(&self) -> zbus::fdo::Result<u32> {
        let state = AD_STATE.lock().unwrap();
        if state.max_interval == 0 {
            Err(zbus::fdo::Error::UnknownProperty("MaxInterval not set".into()))
        } else {
            Ok(state.max_interval)
        }
    }

    /// Secondary advertising channel — conditional (exists when set).
    #[zbus(property, name = "SecondaryChannel")]
    fn secondary_channel(&self) -> zbus::fdo::Result<String> {
        let state = AD_STATE.lock().unwrap();
        match &state.secondary {
            Some(ch) => Ok(ch.clone()),
            None => Err(zbus::fdo::Error::UnknownProperty("SecondaryChannel not set".into())),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Print / Display Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Print a UUID with an optional human-readable name prefix.
///
/// Replaces C `print_uuid` (lines 117-139).  Truncates the name to 25
/// characters with `..` ellipsis, matching the original snprintf+truncation.
fn print_uuid(prefix: &str, uuid: &str) {
    if let Some(text) = bt_uuidstr_to_str(uuid) {
        let mut display = String::with_capacity(25);
        let mut chars = text.chars();
        for _ in 0..25 {
            match chars.next() {
                Some(c) => display.push(c),
                None => break,
            }
        }
        if chars.next().is_some() {
            // Truncate with ellipsis matching C snprintf behavior
            let len = display.len();
            if len >= 2 {
                display.replace_range((len - 2).., "..");
                if len >= 3 && display.as_bytes()[len - 3] == b' ' {
                    let pos = len - 3;
                    display.replace_range(pos..=pos, ".");
                }
            }
        }
        bt_shell_printf(format_args!("{prefix}: {display}({uuid})\n"));
    } else {
        let safe_uuid = uuid;
        bt_shell_printf(format_args!("{prefix}: ({safe_uuid})\n"));
    }
}

/// Print all solicit UUIDs of the given ad type.
///
/// Replaces C `print_ad_solicit` (lines 163-169).
fn print_ad_solicit(ad_type: usize) {
    let state = AD_STATE.lock().unwrap();
    let uuids: Vec<String> = state.solicit[ad_type].clone();
    let prefix = AD_NAMES.solicit[ad_type];
    drop(state);
    for uuid in &uuids {
        print_uuid(prefix, uuid);
    }
}

/// Print the complete advertising state summary.
///
/// Replaces C `print_ad` (lines 171-229).
fn print_ad() {
    for ad_type in AD_TYPE_AD..=AD_TYPE_SRD {
        print_ad_uuids_all(ad_type);
        print_ad_solicit(ad_type);

        let state = AD_STATE.lock().unwrap();

        // Service data
        if let Some(ref uuid) = state.service[ad_type].uuid {
            let prefix = AD_NAMES.service[ad_type];
            let uuid_clone = uuid.clone();
            let data_clone = state.service[ad_type].data.data.clone();
            drop(state);
            print_uuid(prefix, &uuid_clone);
            bt_shell_hexdump(&data_clone);
        } else {
            drop(state);
        }

        let state = AD_STATE.lock().unwrap();

        // Manufacturer data
        if !state.manufacturer[ad_type].data.data.is_empty() {
            let prefix = AD_NAMES.manufacturer[ad_type];
            let id = state.manufacturer[ad_type].id;
            let data_clone = state.manufacturer[ad_type].data.data.clone();
            drop(state);
            bt_shell_printf(format_args!("{prefix}: {id}\n"));
            bt_shell_hexdump(&data_clone);
        } else {
            drop(state);
        }

        let state = AD_STATE.lock().unwrap();

        // Raw AD type data
        if state.data_entries[ad_type].valid {
            let prefix = AD_NAMES.data[ad_type];
            let dtype = state.data_entries[ad_type].ad_type;
            let data_clone = state.data_entries[ad_type].data.data.clone();
            drop(state);
            bt_shell_printf(format_args!("{prefix} Type: 0x{dtype:02x}\n"));
            bt_shell_hexdump(&data_clone);
        } else {
            drop(state);
        }
    }

    let state = AD_STATE.lock().unwrap();
    let tx_power_str = if state.tx_power { "on" } else { "off" };
    bt_shell_printf(format_args!("Tx Power: {tx_power_str}\n"));

    match &state.local_name {
        Some(name) => {
            let name_clone = name.clone();
            drop(state);
            bt_shell_printf(format_args!("LocalName: {name_clone}\n"));
        }
        None => {
            let name_str = if state.name { "on" } else { "off" };
            drop(state);
            bt_shell_printf(format_args!("Name: {name_str}\n"));
        }
    }

    let state = AD_STATE.lock().unwrap();
    if state.local_appearance != u16::MAX {
        let app = state.local_appearance;
        drop(state);
        let app_name = bt_appear_to_str(app);
        bt_shell_printf(format_args!("Appearance: {app_name} (0x{app:04x})\n"));
    } else {
        let app_str = if state.appearance { "on" } else { "off" };
        drop(state);
        bt_shell_printf(format_args!("Appearance: {app_str}\n"));
    }

    let state = AD_STATE.lock().unwrap();
    let disc_str = if state.discoverable { "on" } else { "off" };
    bt_shell_printf(format_args!("Discoverable: {disc_str}\n"));
    let rsi_str = if state.rsi { "on" } else { "off" };
    bt_shell_printf(format_args!("RSI: {rsi_str}\n"));

    if state.duration != 0 {
        bt_shell_printf(format_args!("Duration: {} sec\n", state.duration));
    }
    if state.timeout != 0 {
        bt_shell_printf(format_args!("Timeout: {} sec\n", state.timeout));
    }
    if state.min_interval != 0 {
        bt_shell_printf(format_args!(
            "Interval: {}-{} msec\n",
            state.min_interval, state.max_interval
        ));
    }
}

/// Print all UUIDs for the given ad type (helper that doesn't split iteration).
fn print_ad_uuids_all(ad_type: usize) {
    let state = AD_STATE.lock().unwrap();
    let uuids: Vec<String> = state.uuids[ad_type].clone();
    let prefix = AD_NAMES.uuid[ad_type];
    drop(state);
    for uuid in &uuids {
        print_uuid(prefix, uuid);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a string as an integer, supporting 0x hex prefix and 0 octal prefix.
///
/// Mirrors C `strtol(s, &endptr, 0)` behaviour.
fn parse_integer(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else if s.starts_with('0') && s.len() > 1 && s.chars().skip(1).all(|c| c.is_ascii_digit()) {
        // Octal
        i64::from_str_radix(s, 8).ok()
    } else {
        s.parse::<i64>().ok()
    }
}

/// Parse command arguments into a byte vector.
///
/// Replaces C `ad_add_data` (lines 880-906).  Each argument is parsed as an
/// integer (supporting 0x/octal prefixes) and must fit in a `u8`.
fn parse_data_bytes(args: &[&str]) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if data.len() >= AD_DATA_MAX_LEN {
            bt_shell_printf(format_args!("Too much data\n"));
            return None;
        }
        match parse_integer(arg) {
            Some(v) if (0..=i64::from(u8::MAX)).contains(&v) => {
                data.push(v as u8);
            }
            _ => {
                bt_shell_printf(format_args!("Invalid value at index {i}\n"));
                return None;
            }
        }
    }
    Some(data)
}

/// Attempt to emit a D-Bus PropertiesChanged signal for the given property.
///
/// This spawns an async task to handle the emission.  If no tokio runtime is
/// available or the advertisement is not registered, the emission is silently
/// skipped.  This matches the C `g_dbus_emit_property_changed` behaviour of
/// queuing the emission for the next mainloop iteration.
fn emit_property_changed(conn: &Connection, property: &str) {
    {
        let state = AD_STATE.lock().unwrap();
        if !state.registered {
            return;
        }
    }
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let conn = conn.clone();
        let property = property.to_string();
        handle.spawn(async move {
            let _ = emit_property_changed_async(&conn, &property).await;
        });
    }
}

/// Async implementation of property change emission.
///
/// Emits a `org.freedesktop.DBus.Properties.PropertiesChanged` signal with
/// the property in the invalidated list, telling D-Bus clients to re-read it.
async fn emit_property_changed_async(conn: &Connection, property: &str) -> zbus::Result<()> {
    let changed: HashMap<&str, OwnedValue> = HashMap::new();
    let invalidated: Vec<&str> = vec![property];
    conn.emit_signal(
        None::<zbus::names::BusName<'_>>,
        AD_PATH,
        "org.freedesktop.DBus.Properties",
        "PropertiesChanged",
        &(AD_IFACE, changed, invalidated),
    )
    .await
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — Registration / Unregistration
// ─────────────────────────────────────────────────────────────────────────────

/// Register the advertisement with the LEAdvertisingManager1.
///
/// Registers the LEAdvertisement1 D-Bus object at [`AD_PATH`], then calls
/// `RegisterAdvertisement` on the manager proxy.  The reply is handled
/// asynchronously — success prints the current advertising state; failure
/// unregisters the object and reports the error.
///
/// Replaces C `ad_register` (lines 699-724).
pub fn ad_register(conn: &Connection, manager_path: &str, ad_type: &str) {
    {
        let state = AD_STATE.lock().unwrap();
        if state.registered {
            bt_shell_printf(format_args!("Advertisement is already registered\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    }

    {
        let mut state = AD_STATE.lock().unwrap();
        state.ad_type = Some(ad_type.to_string());
        if ad_type.eq_ignore_ascii_case("Broadcast") {
            state.discoverable = false;
        }
    }

    let conn = conn.clone();
    let manager_path = manager_path.to_string();

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            // Register the D-Bus advertising object
            if let Err(e) = conn.object_server().at(AD_PATH, AdInterface).await {
                bt_shell_printf(format_args!("Failed to register advertising object: {e}\n"));
                bt_shell_noninteractive_quit(EXIT_FAILURE);
                return;
            }

            // Build the options dict (empty, matching C register_setup)
            let options: HashMap<String, OwnedValue> = HashMap::new();

            // Call RegisterAdvertisement on the manager
            let result = conn
                .call_method(
                    Some("org.bluez"),
                    manager_path.as_str(),
                    Some("org.bluez.LEAdvertisingManager1"),
                    "RegisterAdvertisement",
                    &(
                        zbus::zvariant::ObjectPath::try_from(AD_PATH)
                            .expect("constant path is valid"),
                        options,
                    ),
                )
                .await;

            match result {
                Ok(_) => {
                    AD_STATE.lock().unwrap().registered = true;
                    bt_shell_printf(format_args!("Advertising object registered\n"));
                    print_ad();
                    bt_shell_noninteractive_quit(NEG_EINPROGRESS);
                }
                Err(e) => {
                    bt_shell_printf(format_args!("Failed to register advertisement: {e}\n"));
                    let _ = conn.object_server().remove::<AdInterface, _>(AD_PATH).await;
                    bt_shell_noninteractive_quit(EXIT_FAILURE);
                }
            }
        });
    } else {
        bt_shell_printf(format_args!("Failed to register advertising object\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
    }
}

/// Unregister the advertisement from the LEAdvertisingManager1.
///
/// Calls `UnregisterAdvertisement` on the manager proxy, then removes the
/// D-Bus object.  If `manager_path` is `None`, the object is released
/// directly without a D-Bus call (matching C behaviour when manager is NULL).
///
/// Replaces C `ad_unregister` (lines 756-773).
pub fn ad_unregister(conn: &Connection, manager_path: Option<&str>) {
    if manager_path.is_none() {
        // Direct release (no manager to call)
        let mut state = AD_STATE.lock().unwrap();
        state.registered = false;
        drop(state);
        let conn = conn.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = conn.object_server().remove::<AdInterface, _>(AD_PATH).await;
            });
        }
        return;
    }

    {
        let state = AD_STATE.lock().unwrap();
        if !state.registered {
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
            return;
        }
    }

    {
        let mut state = AD_STATE.lock().unwrap();
        state.ad_type = None;
    }

    let conn = conn.clone();
    let manager_path = manager_path.unwrap().to_string();

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let result = conn
                .call_method(
                    Some("org.bluez"),
                    manager_path.as_str(),
                    Some("org.bluez.LEAdvertisingManager1"),
                    "UnregisterAdvertisement",
                    &(zbus::zvariant::ObjectPath::try_from(AD_PATH)
                        .expect("constant path is valid"),),
                )
                .await;

            match result {
                Ok(_) => {
                    AD_STATE.lock().unwrap().registered = false;
                    bt_shell_printf(format_args!("Advertising object unregistered\n"));
                    let _ = conn.object_server().remove::<AdInterface, _>(AD_PATH).await;
                    bt_shell_noninteractive_quit(EXIT_SUCCESS);
                }
                Err(e) => {
                    bt_shell_printf(format_args!("Failed to unregister advertisement: {e}\n"));
                    bt_shell_noninteractive_quit(EXIT_FAILURE);
                }
            }
        });
    } else {
        bt_shell_printf(format_args!("Failed to unregister advertisement method\n"));
        bt_shell_noninteractive_quit(EXIT_FAILURE);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — UUID Commands
// ─────────────────────────────────────────────────────────────────────────────

/// Set or display service UUIDs for the given ad type.
///
/// When called with no arguments (empty `args`), prints the current UUIDs.
/// Otherwise, replaces the UUID list with the given values and emits a
/// property change notification.
///
/// Replaces C `ad_advertise_uuids` (lines 796-817).
pub fn ad_advertise_uuids(conn: &Connection, ad_type: usize, args: &[&str]) {
    if args.is_empty() || (args.len() == 1 && args[0].is_empty()) {
        print_ad_uuids_all(ad_type);
        bt_shell_noninteractive_quit(EXIT_SUCCESS);
        return;
    }

    let uuids: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();

    {
        let mut state = AD_STATE.lock().unwrap();
        state.uuids[ad_type] = uuids;
    }

    emit_property_changed(conn, PROP_NAMES.uuid[ad_type]);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Clear service UUIDs for the given ad type.
///
/// Replaces C `ad_disable_uuids` (lines 819-829).
pub fn ad_disable_uuids(conn: &Connection, ad_type: usize) {
    {
        let state = AD_STATE.lock().unwrap();
        if state.uuids[ad_type].is_empty() {
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
            return;
        }
    }

    AD_STATE.lock().unwrap().uuids[ad_type].clear();
    emit_property_changed(conn, PROP_NAMES.uuid[ad_type]);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — Solicit UUID Commands
// ─────────────────────────────────────────────────────────────────────────────

/// Set or display solicit UUIDs for the given ad type.
///
/// Replaces C `ad_advertise_solicit` (lines 838-860).
pub fn ad_advertise_solicit(conn: &Connection, ad_type: usize, args: &[&str]) {
    if args.is_empty() || (args.len() == 1 && args[0].is_empty()) {
        print_ad_solicit(ad_type);
        bt_shell_noninteractive_quit(EXIT_SUCCESS);
        return;
    }

    let uuids: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();

    {
        let mut state = AD_STATE.lock().unwrap();
        state.solicit[ad_type] = uuids;
    }

    emit_property_changed(conn, PROP_NAMES.solicit[ad_type]);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Clear solicit UUIDs for the given ad type.
///
/// Replaces C `ad_disable_solicit` (lines 862-872).
pub fn ad_disable_solicit(conn: &Connection, ad_type: usize) {
    {
        let state = AD_STATE.lock().unwrap();
        if state.solicit[ad_type].is_empty() {
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
            return;
        }
    }

    AD_STATE.lock().unwrap().solicit[ad_type].clear();
    emit_property_changed(conn, PROP_NAMES.solicit[ad_type]);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — Service Data Commands
// ─────────────────────────────────────────────────────────────────────────────

/// Set or display service data for the given ad type.
///
/// `args[0]` is the UUID string, `args[1..]` are byte values.
/// With no arguments, prints the current service data.
///
/// Replaces C `ad_advertise_service` (lines 908-935).
pub fn ad_advertise_service(conn: &Connection, ad_type: usize, args: &[&str]) {
    if args.is_empty() || (args.len() == 1 && args[0].is_empty()) {
        let state = AD_STATE.lock().unwrap();
        if let Some(ref uuid) = state.service[ad_type].uuid {
            let prefix = AD_NAMES.service[ad_type];
            let uuid_clone = uuid.clone();
            let data_clone = state.service[ad_type].data.data.clone();
            drop(state);
            print_uuid(prefix, &uuid_clone);
            bt_shell_hexdump(&data_clone);
        }
        bt_shell_noninteractive_quit(EXIT_SUCCESS);
        return;
    }

    let uuid = args[0].to_string();
    let data_args = if args.len() > 1 { &args[1..] } else { &[] };
    let data = match parse_data_bytes(data_args) {
        Some(d) => d,
        None => {
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    {
        let mut state = AD_STATE.lock().unwrap();
        state.service[ad_type] = ServiceDataEntry { uuid: Some(uuid), data: AdData { data } };
    }

    emit_property_changed(conn, PROP_NAMES.service[ad_type]);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Clear service data for the given ad type.
///
/// Replaces C `ad_disable_service` (lines 937-947).
pub fn ad_disable_service(conn: &Connection, ad_type: usize) {
    {
        let state = AD_STATE.lock().unwrap();
        if state.service[ad_type].uuid.is_none() {
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
            return;
        }
    }

    AD_STATE.lock().unwrap().service[ad_type] = ServiceDataEntry::default();
    emit_property_changed(conn, PROP_NAMES.service[ad_type]);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — Manufacturer Data Commands
// ─────────────────────────────────────────────────────────────────────────────

/// Set or display manufacturer-specific data for the given ad type.
///
/// `args[0]` is the company ID (integer), `args[1..]` are byte values.
/// With no arguments, prints the current manufacturer data.
///
/// Replaces C `ad_advertise_manufacturer` (lines 954-1000).
pub fn ad_advertise_manufacturer(conn: &Connection, ad_type: usize, args: &[&str]) {
    if args.is_empty() || (args.len() == 1 && args[0].is_empty()) {
        let state = AD_STATE.lock().unwrap();
        if !state.manufacturer[ad_type].data.data.is_empty() {
            let prefix = AD_NAMES.manufacturer[ad_type];
            let id = state.manufacturer[ad_type].id;
            let data_clone = state.manufacturer[ad_type].data.data.clone();
            drop(state);
            bt_shell_printf(format_args!("{prefix}: {id}\n"));
            bt_shell_hexdump(&data_clone);
        }
        bt_shell_noninteractive_quit(EXIT_SUCCESS);
        return;
    }

    let id_val = match parse_integer(args[0]) {
        Some(v) if (0..=i64::from(u16::MAX)).contains(&v) => v as u16,
        _ => {
            bt_shell_printf(format_args!("Invalid manufacture id\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    let data_args = if args.len() > 1 { &args[1..] } else { &[] };
    let data = match parse_data_bytes(data_args) {
        Some(d) => d,
        None => {
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    {
        let mut state = AD_STATE.lock().unwrap();
        state.manufacturer[ad_type] = ManufacturerDataEntry { id: id_val, data: AdData { data } };
    }

    emit_property_changed(conn, PROP_NAMES.manufacturer[ad_type]);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Clear manufacturer data for the given ad type.
///
/// Replaces C `ad_disable_manufacturer` (lines 991-1001).
pub fn ad_disable_manufacturer(conn: &Connection, ad_type: usize) {
    {
        let state = AD_STATE.lock().unwrap();
        if state.manufacturer[ad_type].id == 0 && state.manufacturer[ad_type].data.data.is_empty() {
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
            return;
        }
    }

    AD_STATE.lock().unwrap().manufacturer[ad_type] = ManufacturerDataEntry::default();
    emit_property_changed(conn, PROP_NAMES.manufacturer[ad_type]);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — Raw AD Data Commands
// ─────────────────────────────────────────────────────────────────────────────

/// Set or display raw AD type data for the given ad type.
///
/// `args[0]` is the AD type code (integer), `args[1..]` are byte values.
/// With no arguments, prints the current data.
///
/// Replaces C `ad_advertise_data` (lines 1008-1044).
pub fn ad_advertise_data(conn: &Connection, ad_type: usize, args: &[&str]) {
    if args.is_empty() || (args.len() == 1 && args[0].is_empty()) {
        let state = AD_STATE.lock().unwrap();
        if !state.data_entries[ad_type].data.data.is_empty() {
            let prefix = AD_NAMES.data[ad_type];
            let dtype = state.data_entries[ad_type].ad_type;
            let data_clone = state.data_entries[ad_type].data.data.clone();
            drop(state);
            bt_shell_printf(format_args!("{prefix} Type: 0x{dtype:02x}\n"));
            bt_shell_hexdump(&data_clone);
        }
        bt_shell_noninteractive_quit(EXIT_SUCCESS);
        return;
    }

    let type_val = match parse_integer(args[0]) {
        Some(v) if (0..=i64::from(u8::MAX)).contains(&v) => v as u8,
        _ => {
            bt_shell_printf(format_args!("Invalid type\n"));
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    let data_args = if args.len() > 1 { &args[1..] } else { &[] };
    let data = match parse_data_bytes(data_args) {
        Some(d) => d,
        None => {
            bt_shell_noninteractive_quit(EXIT_FAILURE);
            return;
        }
    };

    {
        let mut state = AD_STATE.lock().unwrap();
        state.data_entries[ad_type] =
            DataEntry { valid: true, ad_type: type_val, data: AdData { data } };
    }

    emit_property_changed(conn, PROP_NAMES.data[ad_type]);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Clear raw AD type data for the given ad type.
///
/// Replaces C `ad_disable_data` (lines 1046-1056).
pub fn ad_disable_data(conn: &Connection, ad_type: usize) {
    {
        let state = AD_STATE.lock().unwrap();
        if state.data_entries[ad_type].ad_type == 0
            && state.data_entries[ad_type].data.data.is_empty()
        {
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
            return;
        }
    }

    AD_STATE.lock().unwrap().data_entries[ad_type] = DataEntry::default();
    emit_property_changed(conn, PROP_NAMES.data[ad_type]);
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — Boolean Toggle Commands
// ─────────────────────────────────────────────────────────────────────────────

/// Set or display the discoverable flag.
///
/// Pass `None` to query; `Some(bool)` to set.
///
/// Replaces C `ad_advertise_discoverable` (lines 1058-1074).
pub fn ad_advertise_discoverable(conn: &Connection, value: Option<bool>) {
    match value {
        None => {
            let state = AD_STATE.lock().unwrap();
            let s = if state.discoverable { "on" } else { "off" };
            bt_shell_printf(format_args!("Discoverable: {s}\n"));
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Some(v) => {
            let changed = {
                let mut state = AD_STATE.lock().unwrap();
                if state.discoverable == v {
                    false
                } else {
                    state.discoverable = v;
                    true
                }
            };
            if changed {
                emit_property_changed(conn, "Discoverable");
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
    }
}

/// Set or display the discoverable timeout.
///
/// Replaces C `ad_advertise_discoverable_timeout` (lines 1076-1094).
pub fn ad_advertise_discoverable_timeout(conn: &Connection, value: Option<u16>) {
    match value {
        None => {
            let state = AD_STATE.lock().unwrap();
            if state.discoverable_to != 0 {
                bt_shell_printf(format_args!("Timeout: {} sec\n", state.discoverable_to));
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Some(v) => {
            let changed = {
                let mut state = AD_STATE.lock().unwrap();
                if state.discoverable_to == v {
                    false
                } else {
                    state.discoverable_to = v;
                    true
                }
            };
            if changed {
                emit_property_changed(conn, "DiscoverableTimeout");
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
    }
}

/// Set or display the TX power inclusion flag.
///
/// Pass `None` to query; `Some(bool)` to set.
///
/// Replaces C `ad_advertise_tx_power` (lines 1096-1111).
pub fn ad_advertise_tx_power(conn: &Connection, value: Option<bool>) {
    match value {
        None => {
            let state = AD_STATE.lock().unwrap();
            let s = if state.tx_power { "on" } else { "off" };
            bt_shell_printf(format_args!("Tx Power: {s}\n"));
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Some(v) => {
            let changed = {
                let mut state = AD_STATE.lock().unwrap();
                if state.tx_power == v {
                    false
                } else {
                    state.tx_power = v;
                    true
                }
            };
            if changed {
                emit_property_changed(conn, "Includes");
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
    }
}

/// Toggle the local-name inclusion flag.
///
/// When `value` is `false`, also clears any custom local name.
///
/// Replaces C `ad_advertise_name` (lines 1113-1128).
pub fn ad_advertise_name(conn: &Connection, value: bool) {
    let changed = {
        let mut state = AD_STATE.lock().unwrap();
        if state.name == value {
            false
        } else {
            state.name = value;
            if !value {
                state.local_name = None;
            }
            true
        }
    };
    if changed {
        emit_property_changed(conn, "Includes");
    }
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Toggle the appearance inclusion flag.
///
/// When `value` is `false`, resets `local_appearance` to `u16::MAX` (unset).
///
/// Replaces C `ad_advertise_appearance` (lines 1159-1172).
pub fn ad_advertise_appearance(conn: &Connection, value: bool) {
    let changed = {
        let mut state = AD_STATE.lock().unwrap();
        if state.appearance == value {
            false
        } else {
            state.appearance = value;
            if !value {
                state.local_appearance = u16::MAX;
            }
            true
        }
    };
    if changed {
        emit_property_changed(conn, "Includes");
    }
    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

/// Set or display the RSI (Resolvable Set Identifier) inclusion flag.
///
/// Pass `None` to query; `Some(bool)` to set.
///
/// Replaces C `ad_advertise_rsi` (lines 1285-1300).
pub fn ad_advertise_rsi(conn: &Connection, value: Option<bool>) {
    match value {
        None => {
            let state = AD_STATE.lock().unwrap();
            let s = if state.rsi { "on" } else { "off" };
            bt_shell_printf(format_args!("RSI: {s}\n"));
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Some(v) => {
            let changed = {
                let mut state = AD_STATE.lock().unwrap();
                if state.rsi == v {
                    false
                } else {
                    state.rsi = v;
                    true
                }
            };
            if changed {
                emit_property_changed(conn, "Includes");
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — String / Numeric Value Commands
// ─────────────────────────────────────────────────────────────────────────────

/// Set or display the custom local name.
///
/// Pass `None` to query current state; `Some(name)` to set.  Setting a custom
/// local name removes `"local-name"` from the Includes list (matching C
/// behaviour at lines 1150-1154).
///
/// Replaces C `ad_advertise_local_name` (lines 1130-1157).
pub fn ad_advertise_local_name(conn: &Connection, name_opt: Option<&str>) {
    match name_opt {
        None => {
            let state = AD_STATE.lock().unwrap();
            match &state.local_name {
                Some(name) => {
                    bt_shell_printf(format_args!("LocalName: {name}\n"));
                }
                None => {
                    let s = if state.name { "on" } else { "off" };
                    bt_shell_printf(format_args!("Name: {s}\n"));
                }
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Some(name) => {
            let (name_changed, includes_changed) = {
                let mut state = AD_STATE.lock().unwrap();
                // Check if already set to same value
                if state.local_name.as_deref() == Some(name) {
                    return;
                }
                state.local_name = Some(name.to_string());
                let inc_changed = state.name;
                if state.name {
                    state.name = false;
                }
                (true, inc_changed)
            };

            if name_changed {
                emit_property_changed(conn, "LocalName");
            }
            if includes_changed {
                emit_property_changed(conn, "Includes");
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
    }
}

/// Set or display the local appearance value.
///
/// Pass `None` to query; `Some(value)` to set.
///
/// Replaces C `ad_advertise_local_appearance` (lines 1174-1196).
pub fn ad_advertise_local_appearance(conn: &Connection, value: Option<u16>) {
    match value {
        None => {
            let state = AD_STATE.lock().unwrap();
            if state.local_appearance != u16::MAX {
                let app = state.local_appearance;
                drop(state);
                let name = bt_appear_to_str(app);
                bt_shell_printf(format_args!("Appearance: {name} (0x{app:04x})\n"));
            } else {
                let s = if state.appearance { "on" } else { "off" };
                bt_shell_printf(format_args!("Appearance: {s}\n"));
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Some(v) => {
            let changed = {
                let mut state = AD_STATE.lock().unwrap();
                if state.local_appearance == v {
                    false
                } else {
                    state.local_appearance = v;
                    true
                }
            };
            if changed {
                emit_property_changed(conn, "Appearance");
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
    }
}

/// Set or display the advertising duration.
///
/// Replaces C `ad_advertise_duration` (lines 1198-1214).
pub fn ad_advertise_duration(conn: &Connection, value: Option<u16>) {
    match value {
        None => {
            let state = AD_STATE.lock().unwrap();
            if state.duration != 0 {
                bt_shell_printf(format_args!("Duration: {} sec\n", state.duration));
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Some(v) => {
            let changed = {
                let mut state = AD_STATE.lock().unwrap();
                if state.duration == v {
                    false
                } else {
                    state.duration = v;
                    true
                }
            };
            if changed {
                emit_property_changed(conn, "Duration");
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
    }
}

/// Set or display the advertising timeout.
///
/// Replaces C `ad_advertise_timeout` (lines 1216-1232).
pub fn ad_advertise_timeout(conn: &Connection, value: Option<u16>) {
    match value {
        None => {
            let state = AD_STATE.lock().unwrap();
            if state.timeout != 0 {
                bt_shell_printf(format_args!("Timeout: {} sec\n", state.timeout));
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Some(v) => {
            let changed = {
                let mut state = AD_STATE.lock().unwrap();
                if state.timeout == v {
                    false
                } else {
                    state.timeout = v;
                    true
                }
            };
            if changed {
                emit_property_changed(conn, "Timeout");
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
    }
}

/// Set or display the secondary advertising channel.
///
/// Pass `None` to query; `Some(value)` to set.  An empty string clears the
/// secondary channel setting.
///
/// Replaces C `ad_advertise_secondary` (lines 1234-1259).
pub fn ad_advertise_secondary(conn: &Connection, value: Option<&str>) {
    match value {
        None => {
            let state = AD_STATE.lock().unwrap();
            if let Some(ref sec) = state.secondary {
                bt_shell_printf(format_args!("Secondary Channel: {sec}\n"));
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
        Some(v) => {
            let changed = {
                let mut state = AD_STATE.lock().unwrap();
                if state.secondary.as_deref() == Some(v) {
                    false
                } else if v.is_empty() {
                    state.secondary = None;
                    bt_shell_noninteractive_quit(EXIT_SUCCESS);
                    return;
                } else {
                    state.secondary = Some(v.to_string());
                    true
                }
            };
            if changed {
                emit_property_changed(conn, "SecondaryChannel");
            }
            bt_shell_noninteractive_quit(EXIT_SUCCESS);
        }
    }
}

/// Set or display the advertising interval range.
///
/// Pass `(None, None)` to query; `(Some(min), Some(max))` to set both,
/// or set either individually.
///
/// Replaces C `ad_advertise_interval` (lines 1261-1283).
pub fn ad_advertise_interval(conn: &Connection, min: Option<u32>, max: Option<u32>) {
    if min.is_none() && max.is_none() {
        let state = AD_STATE.lock().unwrap();
        if state.min_interval != 0 && state.max_interval != 0 {
            bt_shell_printf(format_args!(
                "Interval: {}-{} msec\n",
                state.min_interval, state.max_interval
            ));
        }
        bt_shell_noninteractive_quit(EXIT_SUCCESS);
        return;
    }

    if let Some(min_val) = min {
        let changed = {
            let mut state = AD_STATE.lock().unwrap();
            if state.min_interval != min_val {
                state.min_interval = min_val;
                true
            } else {
                false
            }
        };
        if changed {
            emit_property_changed(conn, "MinInterval");
        }
    }

    if let Some(max_val) = max {
        let changed = {
            let mut state = AD_STATE.lock().unwrap();
            if state.max_interval != max_val {
                state.max_interval = max_val;
                true
            } else {
                false
            }
        };
        if changed {
            emit_property_changed(conn, "MaxInterval");
        }
    }

    bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(AD_TYPE_AD, 0);
        assert_eq!(AD_TYPE_SRD, 1);
        assert_eq!(AD_TYPE_COUNT, 2);
    }

    #[test]
    fn test_ad_type_count_covers_both() {
        assert_eq!(AD_TYPE_COUNT, AD_TYPE_SRD + 1);
    }

    #[test]
    fn test_ad_state_defaults() {
        let state = AdState::default();
        assert!(!state.registered);
        assert!(state.ad_type.is_none());
        assert!(state.local_name.is_none());
        assert!(state.secondary.is_none());
        assert_eq!(state.min_interval, 0);
        assert_eq!(state.max_interval, 0);
        assert_eq!(state.local_appearance, u16::MAX);
        assert_eq!(state.duration, 0);
        assert_eq!(state.timeout, 0);
        assert_eq!(state.discoverable_to, 0);
        assert!(state.discoverable);
        assert!(!state.tx_power);
        assert!(!state.name);
        assert!(!state.appearance);
        assert!(state.rsi);
        for i in 0..AD_TYPE_COUNT {
            assert!(state.uuids[i].is_empty());
            assert!(state.solicit[i].is_empty());
            assert!(state.service[i].uuid.is_none());
            assert_eq!(state.manufacturer[i].id, 0);
            assert!(!state.data_entries[i].valid);
        }
    }

    #[test]
    fn test_parse_integer_decimal() {
        assert_eq!(parse_integer("42"), Some(42));
        assert_eq!(parse_integer("0"), Some(0));
        assert_eq!(parse_integer("-1"), Some(-1));
    }

    #[test]
    fn test_parse_integer_hex() {
        assert_eq!(parse_integer("0xff"), Some(255));
        assert_eq!(parse_integer("0xFF"), Some(255));
        assert_eq!(parse_integer("0x10"), Some(16));
    }

    #[test]
    fn test_parse_integer_octal() {
        assert_eq!(parse_integer("010"), Some(8));
        assert_eq!(parse_integer("077"), Some(63));
    }

    #[test]
    fn test_parse_integer_invalid() {
        assert_eq!(parse_integer(""), None);
        assert_eq!(parse_integer("abc"), None);
        assert_eq!(parse_integer("0xzz"), None);
    }

    #[test]
    fn test_parse_data_bytes_valid() {
        let result = parse_data_bytes(&["0x01", "0x02", "0xff"]);
        assert_eq!(result, Some(vec![0x01, 0x02, 0xff]));
    }

    #[test]
    fn test_parse_data_bytes_empty() {
        let result = parse_data_bytes(&[]);
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn test_parse_data_bytes_overflow() {
        let result = parse_data_bytes(&["256"]);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_data_bytes_negative() {
        let result = parse_data_bytes(&["-1"]);
        assert!(result.is_none());
    }

    #[test]
    fn test_ad_data_default() {
        let data = AdData::default();
        assert!(data.data.is_empty());
    }

    #[test]
    fn test_service_data_entry_default() {
        let svc = ServiceDataEntry::default();
        assert!(svc.uuid.is_none());
        assert!(svc.data.data.is_empty());
    }

    #[test]
    fn test_manufacturer_data_entry_default() {
        let mfr = ManufacturerDataEntry::default();
        assert_eq!(mfr.id, 0);
        assert!(mfr.data.data.is_empty());
    }

    #[test]
    fn test_data_entry_default() {
        let entry = DataEntry::default();
        assert!(!entry.valid);
        assert_eq!(entry.ad_type, 0);
        assert!(entry.data.data.is_empty());
    }

    #[test]
    fn test_global_state_accessible() {
        let state = AD_STATE.lock().unwrap();
        let _ = state.registered;
    }

    #[test]
    fn test_prop_names_arrays() {
        assert_eq!(PROP_NAMES.uuid[AD_TYPE_AD], "ServiceUUIDs");
        assert_eq!(PROP_NAMES.uuid[AD_TYPE_SRD], "ScanResponseServiceUUIDs");
        assert_eq!(PROP_NAMES.solicit[AD_TYPE_AD], "SolicitUUIDs");
        assert_eq!(PROP_NAMES.solicit[AD_TYPE_SRD], "ScanResponseSolicitUUIDs");
        assert_eq!(PROP_NAMES.service[AD_TYPE_AD], "ServiceData");
        assert_eq!(PROP_NAMES.service[AD_TYPE_SRD], "ScanResponseServiceData");
        assert_eq!(PROP_NAMES.manufacturer[AD_TYPE_AD], "ManufacturerData");
        assert_eq!(PROP_NAMES.manufacturer[AD_TYPE_SRD], "ScanResponseManufacturerData");
        assert_eq!(PROP_NAMES.data[AD_TYPE_AD], "Data");
        assert_eq!(PROP_NAMES.data[AD_TYPE_SRD], "ScanResponseData");
    }

    #[test]
    fn test_ad_names_arrays() {
        assert_eq!(AD_NAMES.uuid[AD_TYPE_AD], "UUID");
        assert_eq!(AD_NAMES.uuid[AD_TYPE_SRD], "Scan Response UUID");
        assert_eq!(AD_NAMES.manufacturer[AD_TYPE_AD], "Manufacturer");
        assert_eq!(AD_NAMES.manufacturer[AD_TYPE_SRD], "Scan Response Manufacturer");
    }
}
