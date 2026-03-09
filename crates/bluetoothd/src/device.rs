// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Rust rewrite
//
// Replaces src/device.c — Bluetooth device representation and D-Bus interface.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use bluez_shared::addr::BdAddr;

use crate::error::BtdError;

// ---------------------------------------------------------------------------
// EIR / AD type constants (from Core Spec Supplement Part A)
// ---------------------------------------------------------------------------

/// Flags
const EIR_FLAGS: u8 = 0x01;
/// Incomplete list of 16-bit Service UUIDs
const EIR_UUID16_SOME: u8 = 0x02;
/// Complete list of 16-bit Service UUIDs
const EIR_UUID16_ALL: u8 = 0x03;
/// Incomplete list of 128-bit Service UUIDs
const EIR_UUID128_SOME: u8 = 0x06;
/// Complete list of 128-bit Service UUIDs
const EIR_UUID128_ALL: u8 = 0x07;
/// Shortened Local Name
const EIR_NAME_SHORT: u8 = 0x08;
/// Complete Local Name
const EIR_NAME_COMPLETE: u8 = 0x09;
/// TX Power Level
const EIR_TX_POWER: u8 = 0x0A;
/// Class of Device
const EIR_CLASS_OF_DEV: u8 = 0x0D;
/// GAP Appearance
const EIR_APPEARANCE: u8 = 0x19;
/// Manufacturer Specific Data
const EIR_MANUFACTURER_DATA: u8 = 0xFF;
/// Service Data - 16-bit UUID
const EIR_SERVICE_DATA16: u8 = 0x16;

// ---------------------------------------------------------------------------
// ConnectionState — state machine for device connection
// ---------------------------------------------------------------------------

/// Connection state machine for a Bluetooth device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected.
    Disconnected,
    /// Connection in progress.
    Connecting,
    /// Fully connected.
    Connected,
    /// Disconnection in progress.
    Disconnecting,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => write!(f, "disconnected"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Disconnecting => write!(f, "disconnecting"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceInner — mutable state behind Arc<Mutex<>>
// ---------------------------------------------------------------------------

/// Internal state for a Bluetooth device.
///
/// Mirrors the fields exposed via the org.bluez.Device1 D-Bus interface plus
/// bookkeeping data previously held in `struct btd_device` (src/device.c).
pub(crate) struct DeviceInner {
    adapter_path: String,
    address: BdAddr,
    address_type: u8,
    name: Option<String>,
    alias: Option<String>,
    class: u32,
    appearance: u16,
    rssi: Option<i8>,
    tx_power: Option<i8>,
    paired: bool,
    bonded: bool,
    trusted: bool,
    blocked: bool,
    conn_state: ConnectionState,
    temporary: bool,
    uuids: Vec<String>,
    manufacturer_data: HashMap<u16, Vec<u8>>,
    service_data: HashMap<String, Vec<u8>>,
    path: String,
    /// IO capability for pairing (default: NoInputNoOutput = 0x03).
    io_capability: u8,
}

// ---------------------------------------------------------------------------
// BtdDevice — thread-safe handle
// ---------------------------------------------------------------------------

/// Thread-safe handle to a Bluetooth device.
///
/// Wraps `DeviceInner` behind `Arc<Mutex<_>>` so it can be shared across
/// async tasks and D-Bus method handlers.
#[derive(Clone)]
pub struct BtdDevice {
    inner: Arc<Mutex<DeviceInner>>,
}

/// Build the D-Bus object path for a device.
///
/// Example: adapter_path = "/org/bluez/hci0", address displays as
/// "AA:BB:CC:DD:EE:FF" -> "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF".
fn device_path(adapter_path: &str, address: &BdAddr) -> String {
    let addr_str = address.to_string().replace(':', "_");
    format!("{}/dev_{}", adapter_path, addr_str)
}

impl BtdDevice {
    /// Create a new device associated with `adapter_path`.
    ///
    /// The D-Bus object path is derived from the adapter path and the device
    /// address (colons replaced with underscores).
    pub fn new(adapter_path: &str, address: BdAddr, address_type: u8) -> Self {
        let path = device_path(adapter_path, &address);
        Self {
            inner: Arc::new(Mutex::new(DeviceInner {
                adapter_path: adapter_path.to_string(),
                address,
                address_type,
                name: None,
                alias: None,
                class: 0,
                appearance: 0,
                rssi: None,
                tx_power: None,
                paired: false,
                bonded: false,
                trusted: false,
                blocked: false,
                conn_state: ConnectionState::Disconnected,
                temporary: true,
                uuids: Vec::new(),
                manufacturer_data: HashMap::new(),
                service_data: HashMap::new(),
                path,
                io_capability: 0x03, // NoInputNoOutput
            })),
        }
    }

    // -- Getters ----------------------------------------------------------

    /// D-Bus object path for this device.
    pub fn path(&self) -> String {
        self.inner.lock().unwrap().path.clone()
    }

    /// Bluetooth address.
    pub fn address(&self) -> BdAddr {
        self.inner.lock().unwrap().address
    }

    /// Address type (public / random / etc.).
    pub fn address_type(&self) -> u8 {
        self.inner.lock().unwrap().address_type
    }

    /// Adapter D-Bus path this device belongs to.
    pub fn adapter_path(&self) -> String {
        self.inner.lock().unwrap().adapter_path.clone()
    }

    /// User-friendly name (may be `None` if not yet discovered).
    pub fn name(&self) -> Option<String> {
        self.inner.lock().unwrap().name.clone()
    }

    /// Locally-set alias, falls back to name or address string.
    pub fn alias(&self) -> Option<String> {
        self.inner.lock().unwrap().alias.clone()
    }

    /// Class of Device (CoD) value.
    pub fn class_of_device(&self) -> u32 {
        self.inner.lock().unwrap().class
    }

    /// GAP Appearance value.
    pub fn appearance(&self) -> u16 {
        self.inner.lock().unwrap().appearance
    }

    /// Whether the device is paired.
    pub fn paired(&self) -> bool {
        self.inner.lock().unwrap().paired
    }

    /// Whether the device is bonded (keys stored).
    pub fn bonded(&self) -> bool {
        self.inner.lock().unwrap().bonded
    }

    /// Whether the device is marked trusted.
    pub fn trusted(&self) -> bool {
        self.inner.lock().unwrap().trusted
    }

    /// Whether the device is blocked.
    pub fn blocked(&self) -> bool {
        self.inner.lock().unwrap().blocked
    }

    /// Whether the device is currently connected.
    pub fn connected(&self) -> bool {
        self.inner.lock().unwrap().conn_state == ConnectionState::Connected
    }

    /// Current connection state.
    pub fn connection_state(&self) -> ConnectionState {
        self.inner.lock().unwrap().conn_state
    }

    /// Whether the device is temporary (not yet stored).
    pub fn is_temporary(&self) -> bool {
        self.inner.lock().unwrap().temporary
    }

    /// Most recent RSSI reading, if available.
    pub fn rssi(&self) -> Option<i8> {
        self.inner.lock().unwrap().rssi
    }

    /// TX Power Level, if available.
    pub fn tx_power(&self) -> Option<i8> {
        self.inner.lock().unwrap().tx_power
    }

    /// IO capability for pairing.
    pub fn io_capability(&self) -> u8 {
        self.inner.lock().unwrap().io_capability
    }

    /// Service UUIDs.
    pub fn uuids(&self) -> Vec<String> {
        self.inner.lock().unwrap().uuids.clone()
    }

    /// Manufacturer data.
    pub fn manufacturer_data(&self) -> HashMap<u16, Vec<u8>> {
        self.inner.lock().unwrap().manufacturer_data.clone()
    }

    /// Service data.
    pub fn service_data(&self) -> HashMap<String, Vec<u8>> {
        self.inner.lock().unwrap().service_data.clone()
    }

    // -- Setters / actions ------------------------------------------------

    pub fn set_name(&self, name: Option<&str>) {
        self.inner.lock().unwrap().name = name.map(String::from);
    }

    pub fn set_alias(&self, alias: Option<&str>) {
        self.inner.lock().unwrap().alias = alias.map(String::from);
    }

    pub fn set_paired(&self, paired: bool) {
        self.inner.lock().unwrap().paired = paired;
    }

    pub fn set_bonded(&self, bonded: bool) {
        self.inner.lock().unwrap().bonded = bonded;
    }

    pub fn set_trusted(&self, trusted: bool) {
        self.inner.lock().unwrap().trusted = trusted;
    }

    pub fn set_blocked(&self, blocked: bool) {
        self.inner.lock().unwrap().blocked = blocked;
    }

    pub fn set_connected(&self, connected: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.conn_state = if connected {
            ConnectionState::Connected
        } else {
            ConnectionState::Disconnected
        };
    }

    pub fn set_temporary(&self, temporary: bool) {
        self.inner.lock().unwrap().temporary = temporary;
    }

    pub fn set_rssi(&self, rssi: Option<i8>) {
        self.inner.lock().unwrap().rssi = rssi;
    }

    pub fn set_class(&self, class: u32) {
        self.inner.lock().unwrap().class = class;
    }

    pub fn set_io_capability(&self, io_cap: u8) {
        self.inner.lock().unwrap().io_capability = io_cap;
    }

    /// Register a service UUID with this device.
    pub fn add_uuid(&self, uuid: &str) {
        let mut inner = self.inner.lock().unwrap();
        let s = uuid.to_string();
        if !inner.uuids.contains(&s) {
            inner.uuids.push(s);
        }
    }

    /// Update RSSI from a scan result or connection info.
    pub fn update_rssi(&self, rssi: i8) {
        self.inner.lock().unwrap().rssi = Some(rssi);
    }

    /// Parse EIR/AD data and update device properties.
    ///
    /// EIR (Extended Inquiry Response) and AD (Advertising Data) share the same
    /// TLV format: [length][type][data...] repeated until length == 0 or end of buffer.
    pub fn update_from_eir(&self, eir_data: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        let mut offset = 0;

        while offset < eir_data.len() {
            let field_len = eir_data[offset] as usize;
            if field_len == 0 {
                break;
            }
            offset += 1;

            if offset + field_len > eir_data.len() {
                break;
            }

            let field_type = eir_data[offset];
            let field_data = &eir_data[offset + 1..offset + field_len];
            offset += field_len;

            match field_type {
                EIR_NAME_COMPLETE | EIR_NAME_SHORT => {
                    if let Ok(name) = std::str::from_utf8(field_data) {
                        // Complete name always wins; short name only if no name yet
                        if field_type == EIR_NAME_COMPLETE || inner.name.is_none() {
                            inner.name = Some(name.to_string());
                        }
                    }
                }
                EIR_FLAGS => {
                    // Flags byte — informational, no state to update currently.
                }
                EIR_UUID16_SOME | EIR_UUID16_ALL => {
                    // 16-bit UUIDs, each 2 bytes LE
                    let mut i = 0;
                    while i + 2 <= field_data.len() {
                        let uuid16 =
                            u16::from_le_bytes([field_data[i], field_data[i + 1]]);
                        let uuid_str = format!(
                            "{:08x}-0000-1000-8000-00805f9b34fb",
                            uuid16
                        );
                        if !inner.uuids.contains(&uuid_str) {
                            inner.uuids.push(uuid_str);
                        }
                        i += 2;
                    }
                }
                EIR_UUID128_SOME | EIR_UUID128_ALL => {
                    // 128-bit UUIDs, each 16 bytes LE
                    let mut i = 0;
                    while i + 16 <= field_data.len() {
                        let uuid_bytes = &field_data[i..i + 16];
                        let uuid_str = format!(
                            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                            uuid_bytes[15], uuid_bytes[14], uuid_bytes[13], uuid_bytes[12],
                            uuid_bytes[11], uuid_bytes[10],
                            uuid_bytes[9], uuid_bytes[8],
                            uuid_bytes[7], uuid_bytes[6],
                            uuid_bytes[5], uuid_bytes[4], uuid_bytes[3], uuid_bytes[2], uuid_bytes[1], uuid_bytes[0],
                        );
                        if !inner.uuids.contains(&uuid_str) {
                            inner.uuids.push(uuid_str);
                        }
                        i += 16;
                    }
                }
                EIR_TX_POWER => {
                    if !field_data.is_empty() {
                        inner.tx_power = Some(field_data[0] as i8);
                    }
                }
                EIR_CLASS_OF_DEV => {
                    if field_data.len() >= 3 {
                        inner.class = u32::from(field_data[0])
                            | (u32::from(field_data[1]) << 8)
                            | (u32::from(field_data[2]) << 16);
                    }
                }
                EIR_APPEARANCE => {
                    if field_data.len() >= 2 {
                        inner.appearance =
                            u16::from_le_bytes([field_data[0], field_data[1]]);
                    }
                }
                EIR_MANUFACTURER_DATA => {
                    if field_data.len() >= 2 {
                        let company_id =
                            u16::from_le_bytes([field_data[0], field_data[1]]);
                        inner
                            .manufacturer_data
                            .insert(company_id, field_data[2..].to_vec());
                    }
                }
                EIR_SERVICE_DATA16 => {
                    if field_data.len() >= 2 {
                        let uuid16 =
                            u16::from_le_bytes([field_data[0], field_data[1]]);
                        let uuid_str = format!(
                            "{:08x}-0000-1000-8000-00805f9b34fb",
                            uuid16
                        );
                        inner
                            .service_data
                            .insert(uuid_str, field_data[2..].to_vec());
                    }
                }
                _ => {
                    // Unknown EIR type — ignore.
                }
            }
        }
    }

    // -- Connection state machine -----------------------------------------

    /// Initiate a connection to this device (sync version for local state).
    pub fn connect(&self) -> Result<(), BtdError> {
        let mut inner = self.inner.lock().unwrap();
        match inner.conn_state {
            ConnectionState::Connected => {
                Err(BtdError::already_connected("Device is already connected"))
            }
            ConnectionState::Connecting => {
                Err(BtdError::in_progress("Connection already in progress"))
            }
            ConnectionState::Disconnecting => {
                Err(BtdError::failed("Device is disconnecting"))
            }
            ConnectionState::Disconnected => {
                inner.conn_state = ConnectionState::Connected;
                Ok(())
            }
        }
    }

    /// Disconnect from this device (sync version for local state).
    pub fn disconnect(&self) -> Result<(), BtdError> {
        let mut inner = self.inner.lock().unwrap();
        match inner.conn_state {
            ConnectionState::Disconnected => {
                Err(BtdError::not_connected("Device is not connected"))
            }
            ConnectionState::Disconnecting => {
                Err(BtdError::in_progress("Disconnection already in progress"))
            }
            ConnectionState::Connecting | ConnectionState::Connected => {
                inner.conn_state = ConnectionState::Disconnected;
                Ok(())
            }
        }
    }

    /// Transition to Connecting state. Returns error if already connected.
    pub fn begin_connect(&self) -> Result<(), BtdError> {
        let mut inner = self.inner.lock().unwrap();
        match inner.conn_state {
            ConnectionState::Connected => {
                Err(BtdError::already_connected("Device is already connected"))
            }
            ConnectionState::Connecting => {
                Err(BtdError::in_progress("Connection already in progress"))
            }
            _ => {
                inner.conn_state = ConnectionState::Connecting;
                Ok(())
            }
        }
    }

    /// Transition to Disconnecting state. Returns error if not connected.
    pub fn begin_disconnect(&self) -> Result<(), BtdError> {
        let mut inner = self.inner.lock().unwrap();
        match inner.conn_state {
            ConnectionState::Connected | ConnectionState::Connecting => {
                inner.conn_state = ConnectionState::Disconnecting;
                Ok(())
            }
            _ => Err(BtdError::not_connected("Device is not connected")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_addr() -> BdAddr {
        // Wire order (little-endian): [0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        // Display order: "11:22:33:44:55:66"
        BdAddr([0x66, 0x55, 0x44, 0x33, 0x22, 0x11])
    }

    #[test]
    fn test_device_new() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);
        assert_eq!(dev.address(), sample_addr());
        assert_eq!(dev.address_type(), 0);
        assert!(dev.name().is_none());
        assert!(dev.alias().is_none());
        assert!(!dev.paired());
        assert!(!dev.connected());
        assert!(dev.is_temporary());
    }

    #[test]
    fn test_device_path_format() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);
        assert_eq!(dev.path(), "/org/bluez/hci0/dev_11_22_33_44_55_66");
    }

    #[test]
    fn test_device_properties() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 1);

        dev.set_name(Some("TestDevice"));
        assert_eq!(dev.name().as_deref(), Some("TestDevice"));

        dev.set_alias(Some("MyAlias"));
        assert_eq!(dev.alias().as_deref(), Some("MyAlias"));

        dev.set_paired(true);
        assert!(dev.paired());

        dev.set_bonded(true);
        assert!(dev.bonded());

        dev.set_trusted(true);
        assert!(dev.trusted());

        dev.set_blocked(true);
        assert!(dev.blocked());

        dev.set_temporary(false);
        assert!(!dev.is_temporary());

        dev.set_rssi(Some(-42));
        assert_eq!(dev.rssi(), Some(-42));

        dev.set_class(0x240404);
        assert_eq!(dev.class_of_device(), 0x240404);
    }

    #[test]
    fn test_device_uuids() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);
        dev.add_uuid("0000110a-0000-1000-8000-00805f9b34fb");
        dev.add_uuid("0000110b-0000-1000-8000-00805f9b34fb");
        // Duplicate should not be added.
        dev.add_uuid("0000110a-0000-1000-8000-00805f9b34fb");

        let inner = dev.inner.lock().unwrap();
        assert_eq!(inner.uuids.len(), 2);
        assert!(inner.uuids.contains(&"0000110a-0000-1000-8000-00805f9b34fb".to_string()));
        assert!(inner.uuids.contains(&"0000110b-0000-1000-8000-00805f9b34fb".to_string()));
    }

    #[test]
    fn test_device_connect_disconnect() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);

        // Initially not connected; disconnect should fail.
        assert!(dev.disconnect().is_err());

        // Connect should succeed.
        assert!(dev.connect().is_ok());
        assert!(dev.connected());

        // Double-connect should fail.
        assert!(dev.connect().is_err());

        // Disconnect should succeed.
        assert!(dev.disconnect().is_ok());
        assert!(!dev.connected());
    }

    #[test]
    fn test_connection_state_machine() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);
        assert_eq!(dev.connection_state(), ConnectionState::Disconnected);

        // Disconnected -> Connecting
        assert!(dev.begin_connect().is_ok());
        assert_eq!(dev.connection_state(), ConnectionState::Connecting);

        // Connecting -> cannot begin_connect again
        assert!(dev.begin_connect().is_err());

        // Connecting -> Disconnecting (cancel)
        assert!(dev.begin_disconnect().is_ok());
        assert_eq!(dev.connection_state(), ConnectionState::Disconnecting);

        // Disconnecting -> cannot begin_disconnect again
        assert!(dev.begin_disconnect().is_err());

        // Reset to connected
        dev.set_connected(true);
        assert_eq!(dev.connection_state(), ConnectionState::Connected);

        // Connected -> Disconnecting
        assert!(dev.begin_disconnect().is_ok());
        assert_eq!(dev.connection_state(), ConnectionState::Disconnecting);

        // Complete disconnect
        dev.set_connected(false);
        assert_eq!(dev.connection_state(), ConnectionState::Disconnected);
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Disconnected.to_string(), "disconnected");
        assert_eq!(ConnectionState::Connecting.to_string(), "connecting");
        assert_eq!(ConnectionState::Connected.to_string(), "connected");
        assert_eq!(ConnectionState::Disconnecting.to_string(), "disconnecting");
    }

    #[test]
    fn test_update_rssi() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);
        assert!(dev.rssi().is_none());

        dev.update_rssi(-65);
        assert_eq!(dev.rssi(), Some(-65));

        dev.update_rssi(-30);
        assert_eq!(dev.rssi(), Some(-30));
    }

    #[test]
    fn test_update_from_eir_name() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);

        // Build EIR with complete local name "Hello"
        let name = b"Hello";
        let eir = vec![
            (1 + name.len()) as u8, // length
            EIR_NAME_COMPLETE,       // type
            b'H', b'e', b'l', b'l', b'o',
        ];
        dev.update_from_eir(&eir);
        assert_eq!(dev.name().as_deref(), Some("Hello"));
    }

    #[test]
    fn test_update_from_eir_multiple_fields() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);

        let mut eir = Vec::new();

        // Short name "Hi"
        eir.push(3); // len
        eir.push(EIR_NAME_SHORT);
        eir.extend_from_slice(b"Hi");

        // TX Power = -10
        eir.push(2); // len
        eir.push(EIR_TX_POWER);
        eir.push((-10i8) as u8);

        // Class of Device: 0x240404
        eir.push(4); // len
        eir.push(EIR_CLASS_OF_DEV);
        eir.push(0x04);
        eir.push(0x04);
        eir.push(0x24);

        // Appearance: 0x03C1 (Keyboard)
        eir.push(3); // len
        eir.push(EIR_APPEARANCE);
        eir.push(0xC1);
        eir.push(0x03);

        // 16-bit UUID: 0x110A (A2DP Audio Source)
        eir.push(3); // len
        eir.push(EIR_UUID16_ALL);
        eir.push(0x0A);
        eir.push(0x11);

        // Manufacturer data: company 0x004C (Apple), data [0x01, 0x02]
        eir.push(5); // len
        eir.push(EIR_MANUFACTURER_DATA);
        eir.push(0x4C);
        eir.push(0x00);
        eir.push(0x01);
        eir.push(0x02);

        // Service data: UUID 0x1801, data [0xAA]
        eir.push(4); // len
        eir.push(EIR_SERVICE_DATA16);
        eir.push(0x01);
        eir.push(0x18);
        eir.push(0xAA);

        dev.update_from_eir(&eir);

        assert_eq!(dev.name().as_deref(), Some("Hi"));
        assert_eq!(dev.tx_power(), Some(-10));
        assert_eq!(dev.class_of_device(), 0x240404);
        assert_eq!(dev.appearance(), 0x03C1);

        let uuids = dev.uuids();
        assert!(uuids.contains(&"0000110a-0000-1000-8000-00805f9b34fb".to_string()));

        let mfr = dev.manufacturer_data();
        assert_eq!(mfr.get(&0x004C), Some(&vec![0x01, 0x02]));

        let svc = dev.service_data();
        assert_eq!(
            svc.get("00001801-0000-1000-8000-00805f9b34fb"),
            Some(&vec![0xAA])
        );
    }

    #[test]
    fn test_update_from_eir_empty_and_malformed() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);

        // Empty EIR
        dev.update_from_eir(&[]);
        assert!(dev.name().is_none());

        // EIR with zero length field (terminator)
        dev.update_from_eir(&[0x00]);
        assert!(dev.name().is_none());

        // Truncated field (length extends beyond data)
        dev.update_from_eir(&[0x05, EIR_NAME_COMPLETE, b'A']); // claims 5 but only 2 more bytes
        assert!(dev.name().is_none()); // should not crash, field is skipped
    }

    #[test]
    fn test_update_from_eir_complete_name_overrides_short() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);

        let mut eir = Vec::new();
        // Short name first
        eir.push(3);
        eir.push(EIR_NAME_SHORT);
        eir.extend_from_slice(b"Hi");
        // Then complete name
        eir.push(6);
        eir.push(EIR_NAME_COMPLETE);
        eir.extend_from_slice(b"Hello");

        dev.update_from_eir(&eir);
        assert_eq!(dev.name().as_deref(), Some("Hello"));
    }

    #[test]
    fn test_device_io_capability() {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);
        assert_eq!(dev.io_capability(), 0x03); // NoInputNoOutput default

        dev.set_io_capability(0x01); // DisplayYesNo
        assert_eq!(dev.io_capability(), 0x01);
    }

    // ---------------------------------------------------------------
    // EIR parsing tests ported from unit/test-eir.c
    // ---------------------------------------------------------------

    /// Helper: parse EIR data, check name and UUIDs.
    fn check_eir_parse(
        eir_data: &[u8],
        expected_name: Option<&str>,
        expected_tx_power: Option<i8>,
        expected_uuids: &[&str],
    ) {
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);
        dev.update_from_eir(eir_data);

        if let Some(name) = expected_name {
            assert_eq!(
                dev.name().as_deref(),
                Some(name),
                "Name mismatch"
            );
        }

        if let Some(tx) = expected_tx_power {
            assert_eq!(dev.tx_power(), Some(tx), "TX power mismatch");
        }

        let uuids = dev.uuids();
        for expected in expected_uuids {
            assert!(
                uuids.iter().any(|u| u.eq_ignore_ascii_case(expected)),
                "Missing UUID {} in {:?}",
                expected,
                uuids
            );
        }
    }

    /// test_basic from test-eir.c: all-zeros EIR should produce no name/UUIDs.
    #[test]
    fn test_c_eir_basic() {
        let buf = [0u8; 240];
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);
        dev.update_from_eir(&buf);
        assert!(dev.name().is_none());
        assert!(dev.uuids().is_empty());
    }

    /// test_parsing: MacBook Air from test-eir.c.
    #[test]
    fn test_c_eir_macbookair() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x17, 0x09, 0x4d, 0x61, 0x72, 0x63, 0x65, 0x6c,
            0xe2, 0x80, 0x99, 0x73, 0x20, 0x4d, 0x61, 0x63,
            0x42, 0x6f, 0x6f, 0x6b, 0x20, 0x41, 0x69, 0x72,
            0x11, 0x03, 0x12, 0x11, 0x0c, 0x11, 0x0a, 0x11,
            0x1f, 0x11, 0x01, 0x11, 0x00, 0x10, 0x0a, 0x11,
            0x17, 0x11,
        ];
        let uuids = [
            "00001112-0000-1000-8000-00805f9b34fb",
            "0000110c-0000-1000-8000-00805f9b34fb",
            "0000110a-0000-1000-8000-00805f9b34fb",
            "0000111f-0000-1000-8000-00805f9b34fb",
            "00001101-0000-1000-8000-00805f9b34fb",
            "00001000-0000-1000-8000-00805f9b34fb",
            "00001117-0000-1000-8000-00805f9b34fb",
        ];
        check_eir_parse(
            data,
            Some("Marcel\u{2019}s MacBook Air"),
            None,
            &uuids,
        );
    }

    /// test_parsing: BlueSC LE advertisement from test-eir.c.
    #[test]
    fn test_c_eir_bluesc() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x02, 0x01, 0x06, 0x03, 0x02, 0x16, 0x18, 0x12,
            0x09, 0x57, 0x61, 0x68, 0x6f, 0x6f, 0x20, 0x42,
            0x6c, 0x75, 0x65, 0x53, 0x43, 0x20, 0x76, 0x31,
            0x2e, 0x34,
        ];
        check_eir_parse(
            data,
            Some("Wahoo BlueSC v1.4"),
            None,
            &["00001816-0000-1000-8000-00805f9b34fb"],
        );
    }

    /// test_parsing: Mio Alpha from test-eir.c.
    #[test]
    fn test_c_eir_mio_alpha() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x02, 0x01, 0x06, 0x03, 0x02, 0x0d, 0x18, 0x06,
            0x09, 0x41, 0x4c, 0x50, 0x48, 0x41,
        ];
        check_eir_parse(
            data,
            Some("ALPHA"),
            None,
            &["0000180d-0000-1000-8000-00805f9b34fb"],
        );
    }

    /// test_parsing: COOKOO watch from test-eir.c.
    #[test]
    fn test_c_eir_cookoo() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x02, 0x01, 0x05, 0x05, 0x02, 0x02, 0x18, 0x0a,
            0x18, 0x0d, 0x09, 0x43, 0x4f, 0x4f, 0x4b, 0x4f,
            0x4f, 0x20, 0x77, 0x61, 0x74, 0x63, 0x68,
        ];
        check_eir_parse(
            data,
            Some("COOKOO watch"),
            None,
            &[
                "00001802-0000-1000-8000-00805f9b34fb",
                "0000180a-0000-1000-8000-00805f9b34fb",
            ],
        );
    }

    /// test_parsing: Nokia BH-907 from test-eir.c — includes TX power.
    #[test]
    fn test_c_eir_nokia_bh907() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x16, 0x09, 0x4e, 0x6f, 0x6b, 0x69, 0x61, 0x20,
            0x52, 0x65, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e,
            0x20, 0x42, 0x48, 0x2d, 0x39, 0x30, 0x37, 0x02,
            0x0a, 0x04, 0x0f, 0x02, 0x0d, 0x11, 0x0b, 0x11,
            0x0e, 0x11, 0x0f, 0x11, 0x1e, 0x11, 0x08, 0x11,
            0x31, 0x11,
        ];
        check_eir_parse(
            data,
            Some("Nokia Reaction BH-907"),
            Some(4),
            &[
                "0000110d-0000-1000-8000-00805f9b34fb",
                "0000110b-0000-1000-8000-00805f9b34fb",
                "0000110e-0000-1000-8000-00805f9b34fb",
                "0000110f-0000-1000-8000-00805f9b34fb",
                "0000111e-0000-1000-8000-00805f9b34fb",
                "00001108-0000-1000-8000-00805f9b34fb",
                "00001131-0000-1000-8000-00805f9b34fb",
            ],
        );
    }

    /// test_parsing: Nike+ FuelBand from test-eir.c — 128-bit UUID + TX power.
    #[test]
    fn test_c_eir_fuelband() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x0f, 0x09, 0x4e, 0x69, 0x6b, 0x65, 0x2b, 0x20,
            0x46, 0x75, 0x65, 0x6c, 0x42, 0x61, 0x6e, 0x64,
            0x11, 0x07, 0x00, 0x00, 0x00, 0x00, 0xde, 0xca,
            0xfa, 0xde, 0xde, 0xca, 0xde, 0xaf, 0xde, 0xca,
            0xca, 0xff, 0x02, 0x0a, 0x00,
        ];
        check_eir_parse(
            data,
            Some("Nike+ FuelBand"),
            Some(0),
            &["ffcacade-afde-cade-defa-cade00000000"],
        );
    }

    /// test_parsing: Citizen scan response from test-eir.c — 128-bit UUID + TX power.
    #[test]
    fn test_c_eir_citizen_scan() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x02, 0x0a, 0x00, 0x11, 0x07, 0x1b, 0xc5, 0xd5,
            0xa5, 0x02, 0x00, 0x46, 0x9a, 0xe1, 0x11, 0xb7,
            0x8d, 0x60, 0xb4, 0x45, 0x2d,
        ];
        check_eir_parse(
            data,
            None,
            Some(0),
            &["2d45b460-8db7-11e1-9a46-0002a5d5c51b"],
        );
    }

    /// test_parsing: Wahoo Scale from test-eir.c — manufacturer data.
    #[test]
    fn test_c_eir_wahoo_scale() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x02, 0x01, 0x06, 0x03, 0x02, 0x01, 0x19, 0x11,
            0x09, 0x57, 0x61, 0x68, 0x6f, 0x6f, 0x20, 0x53,
            0x63, 0x61, 0x6c, 0x65, 0x20, 0x76, 0x31, 0x2e,
            0x33, 0x05, 0xff, 0x00, 0x00, 0x00, 0x9c,
        ];
        let dev = BtdDevice::new("/org/bluez/hci0", sample_addr(), 0);
        dev.update_from_eir(data);
        assert_eq!(dev.name().as_deref(), Some("Wahoo Scale v1.3"));
        let uuids = dev.uuids();
        assert!(uuids.iter().any(|u| u.eq_ignore_ascii_case("00001901-0000-1000-8000-00805f9b34fb")));
        let mfr = dev.manufacturer_data();
        assert!(mfr.contains_key(&0x0000));
    }
}
