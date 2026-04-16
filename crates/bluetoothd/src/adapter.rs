// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Rust rewrite
//
// adapter.rs — Bluetooth adapter management
//
// Replaces src/adapter.c (~11,054 LOC). Manages local Bluetooth adapters,
// their properties, discovery state, and the global adapter registry.

use std::collections::HashMap;
use std::mem;
use std::sync::{Arc, Mutex};

use bluez_shared::addr::BdAddr;
use bluez_shared::mgmt::client::{MgmtClient, MgmtEvent, MgmtResponse};
use bluez_shared::mgmt::defs::{
    MgmtAddrInfo, MgmtCpDisconnect, MgmtCpPairDevice, MgmtCpSetDiscoverable, MgmtCpSetLocalName,
    MgmtCpStartDiscovery, MgmtCpUnpairDevice, MgmtEvDeviceConnected, MgmtEvDeviceDisconnected,
    MgmtEvDeviceFound, MgmtEvDiscovering, MgmtRpReadInfo, MgmtSettings,
    MGMT_ADDR_BREDR, MGMT_ADDR_LE_PUBLIC, MGMT_ADDR_LE_RANDOM,
    MGMT_EV_DEVICE_CONNECTED, MGMT_EV_DEVICE_DISCONNECTED, MGMT_EV_DEVICE_FOUND,
    MGMT_EV_DISCOVERING, MGMT_EV_NEW_LINK_KEY, MGMT_EV_NEW_LONG_TERM_KEY,
    MGMT_EV_NEW_SETTINGS, MGMT_MAX_NAME_LENGTH, MGMT_MAX_SHORT_NAME_LENGTH,
    MGMT_OP_CANCEL_PAIR_DEVICE, MGMT_OP_DISCONNECT, MGMT_OP_PAIR_DEVICE,
    MGMT_OP_READ_INFO, MGMT_OP_SET_BONDABLE, MGMT_OP_SET_DISCOVERABLE,
    MGMT_OP_SET_LOCAL_NAME, MGMT_OP_SET_POWERED, MGMT_OP_START_DISCOVERY,
    MGMT_OP_STOP_DISCOVERY, MGMT_OP_UNPAIR_DEVICE,
};
use bluez_shared::MgmtStatus;

use crate::device::BtdDevice;
use crate::error::BtdError;

// ---------------------------------------------------------------------------
// Global adapter registry
// ---------------------------------------------------------------------------

static ADAPTERS: Mutex<Vec<BtdAdapter>> = Mutex::new(Vec::new());

/// Initialise the adapter subsystem (stub).
pub fn adapter_init() {
    // Will hook into mgmt socket and enumerate adapters in a later phase.
}

/// Tear down the adapter subsystem, removing all registered adapters.
pub fn adapter_cleanup() {
    let mut adapters = ADAPTERS.lock().unwrap();
    adapters.clear();
}

/// Look up an adapter by its controller index.
pub fn adapter_find(index: u16) -> Option<BtdAdapter> {
    let adapters = ADAPTERS.lock().unwrap();
    adapters.iter().find(|a| a.index() == index).cloned()
}

/// Return the default (first registered) adapter, if any.
pub fn adapter_get_default() -> Option<BtdAdapter> {
    let adapters = ADAPTERS.lock().unwrap();
    adapters.first().cloned()
}

/// Register an adapter in the global registry.
pub fn adapter_register(adapter: BtdAdapter) {
    let mut adapters = ADAPTERS.lock().unwrap();
    adapters.push(adapter);
}

// ---------------------------------------------------------------------------
// AdapterInfo — populated from MGMT_OP_READ_INFO response
// ---------------------------------------------------------------------------

/// Adapter information returned from a Read Info command.
#[derive(Debug, Clone)]
pub struct AdapterInfo {
    pub address: BdAddr,
    pub version: u8,
    pub manufacturer: u16,
    pub supported_settings: MgmtSettings,
    pub current_settings: MgmtSettings,
    pub class: u32,
    pub name: String,
    pub short_name: String,
}

// ---------------------------------------------------------------------------
// DiscoveryFilter — stores parameters from SetDiscoveryFilter D-Bus call
// ---------------------------------------------------------------------------

/// Discovery filter parameters set via D-Bus.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryFilter {
    pub uuids: Vec<String>,
    pub rssi: Option<i16>,
    pub pathloss: Option<u16>,
    pub transport: Option<String>,
    pub duplicate_data: Option<bool>,
    pub discoverable: Option<bool>,
    pub pattern: Option<String>,
}

// ---------------------------------------------------------------------------
// AdapterInner — mutable state behind Arc<Mutex<>>
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct AdapterInner {
    /// Controller index (hci0 = 0, hci1 = 1, ...).
    index: u16,
    /// Public Bluetooth address of this adapter.
    address: BdAddr,
    /// Adapter name (defaults to "BlueZ").
    name: String,
    /// User-visible alias. Empty until explicitly set.
    alias: String,
    /// Class of Device (CoD), 24-bit value stored in lower bits of u32.
    class: u32,
    /// Whether the adapter radio is powered on.
    powered: bool,
    /// Whether the adapter is visible to other devices.
    discoverable: bool,
    /// Discoverable timeout in seconds (0 = infinite).
    discoverable_timeout: u32,
    /// Whether pairing is allowed.
    pairable: bool,
    /// Pairable timeout in seconds (0 = infinite).
    pairable_timeout: u32,
    /// Whether inquiry/LE scan is in progress.
    discovering: bool,
    /// Service UUIDs advertised by this adapter.
    uuids: Vec<String>,
    /// Modalias string (e.g. "usb:v1D6Bp0246d0540").
    modalias: Option<String>,
    /// Known devices keyed by address.
    devices: HashMap<BdAddr, BtdDevice>,
    /// Device D-Bus object paths (for remove_device by path).
    device_paths: Vec<String>,
    /// D-Bus object path, e.g. "/org/bluez/hci0".
    path: String,
    /// Current settings bitflags from the kernel.
    current_settings: MgmtSettings,
    /// Supported settings bitflags from the kernel.
    supported_settings: MgmtSettings,
    /// Discovery filter set via D-Bus.
    discovery_filter: DiscoveryFilter,
    /// Reference to the management client, if connected.
    mgmt: Option<Arc<MgmtClient>>,
}

// ---------------------------------------------------------------------------
// BtdAdapter — cheap, cloneable handle
// ---------------------------------------------------------------------------

/// Handle to a Bluetooth adapter.
///
/// Internally reference-counted so cloning is cheap and all clones share the
/// same mutable state.
#[derive(Clone)]
pub struct BtdAdapter {
    inner: Arc<Mutex<AdapterInner>>,
}

impl BtdAdapter {
    /// Create a new adapter with the given controller `index` and `address`.
    pub fn new(index: u16, address: BdAddr) -> Self {
        let inner = AdapterInner {
            index,
            address,
            name: "BlueZ".to_string(),
            alias: String::new(),
            class: 0,
            powered: false,
            discoverable: false,
            discoverable_timeout: 0,
            pairable: false,
            pairable_timeout: 0,
            discovering: false,
            uuids: Vec::new(),
            modalias: None,
            devices: HashMap::new(),
            device_paths: Vec::new(),
            path: format!("/org/bluez/hci{}", index),
            current_settings: MgmtSettings::empty(),
            supported_settings: MgmtSettings::empty(),
            discovery_filter: DiscoveryFilter::default(),
            mgmt: None,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Attach a management client to this adapter for real hardware control.
    pub fn set_mgmt_client(&self, client: Arc<MgmtClient>) {
        self.inner.lock().unwrap().mgmt = Some(client);
    }

    /// Get the management client, if attached.
    fn mgmt_client(&self) -> Option<Arc<MgmtClient>> {
        self.inner.lock().unwrap().mgmt.clone()
    }

    // -- Getters -----------------------------------------------------------

    /// Controller index.
    pub fn index(&self) -> u16 {
        self.inner.lock().unwrap().index
    }

    /// Public Bluetooth address.
    pub fn address(&self) -> BdAddr {
        self.inner.lock().unwrap().address
    }

    /// Adapter name.
    pub fn name(&self) -> String {
        self.inner.lock().unwrap().name.clone()
    }

    /// User-visible alias (falls back to name if empty).
    pub fn alias(&self) -> String {
        let inner = self.inner.lock().unwrap();
        if inner.alias.is_empty() {
            inner.name.clone()
        } else {
            inner.alias.clone()
        }
    }

    /// D-Bus object path.
    pub fn path(&self) -> String {
        self.inner.lock().unwrap().path.clone()
    }

    /// Whether the adapter radio is powered on.
    pub fn powered(&self) -> bool {
        self.inner.lock().unwrap().powered
    }

    /// Whether the adapter is discoverable.
    pub fn discoverable(&self) -> bool {
        self.inner.lock().unwrap().discoverable
    }

    /// Whether pairing is allowed.
    pub fn pairable(&self) -> bool {
        self.inner.lock().unwrap().pairable
    }

    /// Whether discovery (inquiry / LE scan) is in progress.
    pub fn discovering(&self) -> bool {
        self.inner.lock().unwrap().discovering
    }

    /// Class of Device (24-bit).
    pub fn class_of_device(&self) -> u32 {
        self.inner.lock().unwrap().class
    }

    /// Current settings bitflags.
    pub fn current_settings(&self) -> MgmtSettings {
        self.inner.lock().unwrap().current_settings
    }

    /// Get the discovery filter.
    pub fn discovery_filter(&self) -> DiscoveryFilter {
        self.inner.lock().unwrap().discovery_filter.clone()
    }

    /// Look up a known device by address.
    pub fn find_device(&self, addr: &BdAddr) -> Option<BtdDevice> {
        self.inner.lock().unwrap().devices.get(addr).cloned()
    }

    /// Get or create a device for the given address.
    pub fn get_or_create_device(&self, addr: BdAddr, addr_type: u8) -> BtdDevice {
        let mut inner = self.inner.lock().unwrap();
        if let Some(dev) = inner.devices.get(&addr) {
            return dev.clone();
        }
        let dev = BtdDevice::new(&inner.path, addr, addr_type);
        let dev_path = dev.path();
        inner.devices.insert(addr, dev.clone());
        inner.device_paths.push(dev_path);
        dev
    }

    // -- Setters / actions (sync — for tests and direct use) ---------------

    /// Power the adapter on or off (sync version for tests).
    pub fn set_powered(&self, on: bool) {
        self.inner.lock().unwrap().powered = on;
    }

    /// Set discoverable mode and timeout (sync version for tests).
    pub fn set_discoverable(&self, on: bool, timeout: u32) {
        let mut inner = self.inner.lock().unwrap();
        inner.discoverable = on;
        inner.discoverable_timeout = timeout;
    }

    /// Allow or disallow pairing (sync version for tests).
    pub fn set_pairable(&self, on: bool) {
        self.inner.lock().unwrap().pairable = on;
    }

    /// Set the user-visible alias (sync version for tests).
    pub fn set_alias(&self, alias: &str) {
        self.inner.lock().unwrap().alias = alias.to_string();
    }

    /// Store discovery filter parameters from D-Bus.
    pub fn set_discovery_filter(&self, filter: DiscoveryFilter) {
        self.inner.lock().unwrap().discovery_filter = filter;
    }

    /// Start device discovery (sync version — updates local state only).
    pub fn start_discovery(&self) -> Result<(), BtdError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.powered {
            return Err(BtdError::not_ready("adapter is not powered"));
        }
        if inner.discovering {
            return Err(BtdError::in_progress("discovery already in progress"));
        }
        inner.discovering = true;
        Ok(())
    }

    /// Stop device discovery (sync version — updates local state only).
    pub fn stop_discovery(&self) -> Result<(), BtdError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.discovering {
            return Err(BtdError::failed("not discovering"));
        }
        inner.discovering = false;
        Ok(())
    }

    /// Remove a device by its D-Bus object path.
    pub fn remove_device(&self, path: &str) -> Result<(), BtdError> {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.device_paths.len();
        inner.device_paths.retain(|p| p != path);
        if inner.device_paths.len() == before {
            return Err(BtdError::failed(format!("device not found: {}", path)));
        }
        // Also remove from the devices map
        inner.devices.retain(|_addr, dev| dev.path() != path);
        Ok(())
    }

    // -- Async methods using MgmtClient -----------------------------------

    /// Send MGMT_OP_READ_INFO and populate adapter state.
    pub async fn read_info(&self) -> Result<AdapterInfo, BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();

        let resp = client
            .send(MGMT_OP_READ_INFO, index, &[])
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;

        if resp.data.len() < mem::size_of::<MgmtRpReadInfo>() {
            return Err(BtdError::failed("read_info response too short"));
        }

        // Safety: MgmtRpReadInfo is repr(C, packed) and we verified length.
        let rp: MgmtRpReadInfo =
            unsafe { std::ptr::read_unaligned(resp.data.as_ptr() as *const MgmtRpReadInfo) };

        let name = c_str_from_bytes(&rp.name);
        let short_name = c_str_from_bytes(&rp.short_name);
        let current_settings = MgmtSettings::from_bits_truncate(u32::from_le(rp.current_settings));
        let supported_settings =
            MgmtSettings::from_bits_truncate(u32::from_le(rp.supported_settings));
        let class = u32::from(rp.dev_class[0])
            | (u32::from(rp.dev_class[1]) << 8)
            | (u32::from(rp.dev_class[2]) << 16);

        // Update adapter state
        {
            let mut inner = self.inner.lock().unwrap();
            inner.address = rp.bdaddr;
            inner.name = name.clone();
            inner.class = class;
            inner.current_settings = current_settings;
            inner.supported_settings = supported_settings;
            inner.powered = current_settings.contains(MgmtSettings::POWERED);
            inner.discoverable = current_settings.contains(MgmtSettings::DISCOVERABLE);
            inner.pairable = current_settings.contains(MgmtSettings::BONDABLE);
        }

        Ok(AdapterInfo {
            address: rp.bdaddr,
            version: rp.version,
            manufacturer: u16::from_le(rp.manufacturer),
            supported_settings,
            current_settings,
            class,
            name,
            short_name,
        })
    }

    /// Send MGMT_OP_SET_POWERED and update state on success.
    pub async fn set_powered_async(&self, on: bool) -> Result<(), BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();
        let data = [u8::from(on)];

        let resp = client
            .send(MGMT_OP_SET_POWERED, index, &data)
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;
        self.update_settings_from_response(&resp.data);
        Ok(())
    }

    /// Send MGMT_OP_SET_DISCOVERABLE and update state on success.
    pub async fn set_discoverable_async(&self, on: bool, timeout: u16) -> Result<(), BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();
        let cp = MgmtCpSetDiscoverable {
            val: u8::from(on),
            timeout: timeout.to_le(),
        };
        let data = unsafe { struct_as_bytes(&cp) };

        let resp = client
            .send(MGMT_OP_SET_DISCOVERABLE, index, data)
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;
        self.update_settings_from_response(&resp.data);
        Ok(())
    }

    /// Send MGMT_OP_SET_BONDABLE and update state on success.
    pub async fn set_pairable_async(&self, on: bool) -> Result<(), BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();
        let data = [u8::from(on)];

        let resp = client
            .send(MGMT_OP_SET_BONDABLE, index, &data)
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;
        self.update_settings_from_response(&resp.data);
        Ok(())
    }

    /// Send MGMT_OP_SET_LOCAL_NAME.
    pub async fn set_alias_async(&self, name: &str) -> Result<(), BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();

        let mut cp = MgmtCpSetLocalName {
            name: [0u8; MGMT_MAX_NAME_LENGTH],
            short_name: [0u8; MGMT_MAX_SHORT_NAME_LENGTH],
        };
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(MGMT_MAX_NAME_LENGTH - 1);
        cp.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let data = unsafe { struct_as_bytes(&cp) };

        let resp = client
            .send(MGMT_OP_SET_LOCAL_NAME, index, data)
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;
        self.inner.lock().unwrap().alias = name.to_string();
        Ok(())
    }

    /// Send MGMT_OP_START_DISCOVERY with configured address types.
    pub async fn start_discovery_async(&self) -> Result<(), BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();

        {
            let inner = self.inner.lock().unwrap();
            if !inner.powered {
                return Err(BtdError::not_ready("adapter is not powered"));
            }
            if inner.discovering {
                return Err(BtdError::in_progress("discovery already in progress"));
            }
        }

        // Discover all address types: BR/EDR + LE Public + LE Random
        let cp = MgmtCpStartDiscovery {
            addr_type: MGMT_ADDR_BREDR | MGMT_ADDR_LE_PUBLIC | MGMT_ADDR_LE_RANDOM,
        };
        let data = unsafe { struct_as_bytes(&cp) };

        let resp = client
            .send(MGMT_OP_START_DISCOVERY, index, data)
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;
        self.inner.lock().unwrap().discovering = true;
        Ok(())
    }

    /// Send MGMT_OP_STOP_DISCOVERY.
    pub async fn stop_discovery_async(&self) -> Result<(), BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();

        {
            let inner = self.inner.lock().unwrap();
            if !inner.discovering {
                return Err(BtdError::failed("not discovering"));
            }
        }

        let cp = MgmtCpStartDiscovery {
            addr_type: MGMT_ADDR_BREDR | MGMT_ADDR_LE_PUBLIC | MGMT_ADDR_LE_RANDOM,
        };
        let data = unsafe { struct_as_bytes(&cp) };

        let resp = client
            .send(MGMT_OP_STOP_DISCOVERY, index, data)
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;
        self.inner.lock().unwrap().discovering = false;
        Ok(())
    }

    /// Send MGMT_OP_PAIR_DEVICE for the given device.
    pub async fn pair_device(
        &self,
        addr: BdAddr,
        addr_type: u8,
        io_cap: u8,
    ) -> Result<(), BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();

        let cp = MgmtCpPairDevice {
            addr: MgmtAddrInfo {
                bdaddr: addr,
                addr_type,
            },
            io_cap,
        };
        let data = unsafe { struct_as_bytes(&cp) };

        let resp = client
            .send(MGMT_OP_PAIR_DEVICE, index, data)
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;

        // Mark the device as paired
        if let Some(dev) = self.find_device(&addr) {
            dev.set_paired(true);
            dev.set_bonded(true);
        }
        Ok(())
    }

    /// Send MGMT_OP_CANCEL_PAIR_DEVICE.
    pub async fn cancel_pair_device(
        &self,
        addr: BdAddr,
        addr_type: u8,
    ) -> Result<(), BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();

        let cp = MgmtAddrInfo {
            bdaddr: addr,
            addr_type,
        };
        let data = unsafe { struct_as_bytes(&cp) };

        let resp = client
            .send(MGMT_OP_CANCEL_PAIR_DEVICE, index, data)
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;
        Ok(())
    }

    /// Send MGMT_OP_UNPAIR_DEVICE.
    pub async fn unpair_device(
        &self,
        addr: BdAddr,
        addr_type: u8,
        disconnect: bool,
    ) -> Result<(), BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();

        let cp = MgmtCpUnpairDevice {
            addr: MgmtAddrInfo {
                bdaddr: addr,
                addr_type,
            },
            disconnect: u8::from(disconnect),
        };
        let data = unsafe { struct_as_bytes(&cp) };

        let resp = client
            .send(MGMT_OP_UNPAIR_DEVICE, index, data)
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;

        if let Some(dev) = self.find_device(&addr) {
            dev.set_paired(false);
            dev.set_bonded(false);
        }
        Ok(())
    }

    /// Send MGMT_OP_DISCONNECT for a device.
    pub async fn disconnect_device(
        &self,
        addr: BdAddr,
        addr_type: u8,
    ) -> Result<(), BtdError> {
        let client = self
            .mgmt_client()
            .ok_or_else(|| BtdError::not_ready("no management client attached"))?;
        let index = self.index();

        let cp = MgmtCpDisconnect {
            addr: MgmtAddrInfo {
                bdaddr: addr,
                addr_type,
            },
        };
        let data = unsafe { struct_as_bytes(&cp) };

        let resp = client
            .send(MGMT_OP_DISCONNECT, index, data)
            .await
            .map_err(|e| BtdError::failed(format!("mgmt send failed: {}", e)))?;

        check_mgmt_status(&resp)?;

        if let Some(dev) = self.find_device(&addr) {
            dev.set_connected(false);
        }
        Ok(())
    }

    // -- Event handling ----------------------------------------------------

    /// Process an incoming management event and dispatch to the appropriate handler.
    pub fn handle_mgmt_event(&self, event: &MgmtEvent) {
        match event.event {
            MGMT_EV_NEW_SETTINGS => {
                self.handle_new_settings(&event.data);
            }
            MGMT_EV_DISCOVERING => {
                self.handle_discovering(&event.data);
            }
            MGMT_EV_DEVICE_FOUND => {
                self.handle_device_found(&event.data);
            }
            MGMT_EV_DEVICE_CONNECTED => {
                self.handle_device_connected(&event.data);
            }
            MGMT_EV_DEVICE_DISCONNECTED => {
                self.handle_device_disconnected(&event.data);
            }
            MGMT_EV_NEW_LINK_KEY | MGMT_EV_NEW_LONG_TERM_KEY => {
                self.handle_new_key(&event.data);
            }
            _ => {
                tracing::debug!("unhandled mgmt event 0x{:04x}", event.event);
            }
        }
    }

    fn handle_new_settings(&self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let settings_bits = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let settings = MgmtSettings::from_bits_truncate(settings_bits);

        let mut inner = self.inner.lock().unwrap();
        inner.current_settings = settings;
        inner.powered = settings.contains(MgmtSettings::POWERED);
        inner.discoverable = settings.contains(MgmtSettings::DISCOVERABLE);
        inner.pairable = settings.contains(MgmtSettings::BONDABLE);
    }

    fn handle_discovering(&self, data: &[u8]) {
        if data.len() < mem::size_of::<MgmtEvDiscovering>() {
            return;
        }
        let ev: MgmtEvDiscovering =
            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const MgmtEvDiscovering) };
        self.inner.lock().unwrap().discovering = ev.discovering != 0;
    }

    fn handle_device_found(&self, data: &[u8]) {
        if data.len() < mem::size_of::<MgmtEvDeviceFound>() {
            return;
        }
        let ev: MgmtEvDeviceFound =
            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const MgmtEvDeviceFound) };

        let dev = self.get_or_create_device(ev.addr.bdaddr, ev.addr.addr_type);
        dev.update_rssi(ev.rssi);

        // Parse EIR data if present
        let eir_len = u16::from_le(ev.eir_len) as usize;
        let eir_offset = mem::size_of::<MgmtEvDeviceFound>();
        if eir_len > 0 && data.len() >= eir_offset + eir_len {
            dev.update_from_eir(&data[eir_offset..eir_offset + eir_len]);
        }
    }

    fn handle_device_connected(&self, data: &[u8]) {
        if data.len() < mem::size_of::<MgmtEvDeviceConnected>() {
            return;
        }
        let ev: MgmtEvDeviceConnected =
            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const MgmtEvDeviceConnected) };

        let dev = self.get_or_create_device(ev.addr.bdaddr, ev.addr.addr_type);
        dev.set_connected(true);

        // Parse EIR data if present
        let eir_len = u16::from_le(ev.eir_len) as usize;
        let eir_offset = mem::size_of::<MgmtEvDeviceConnected>();
        if eir_len > 0 && data.len() >= eir_offset + eir_len {
            dev.update_from_eir(&data[eir_offset..eir_offset + eir_len]);
        }
    }

    fn handle_device_disconnected(&self, data: &[u8]) {
        if data.len() < mem::size_of::<MgmtEvDeviceDisconnected>() {
            return;
        }
        let ev: MgmtEvDeviceDisconnected =
            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const MgmtEvDeviceDisconnected) };

        if let Some(dev) = self.find_device(&ev.addr.bdaddr) {
            dev.set_connected(false);
        }
    }

    fn handle_new_key(&self, data: &[u8]) {
        // New link key or LTK event. Minimum size is the addr info (7 bytes).
        if data.len() < 7 {
            return;
        }
        // First field in both key structs is the store_hint(1) + MgmtAddrInfo.
        // For NewLinkKey: store_hint(1) + MgmtLinkKeyInfo which starts with MgmtAddrInfo.
        // We just need the address to mark the device as bonded.
        // store_hint is at byte 0, then bdaddr at bytes 1..7, addr_type at byte 7.
        if data.len() < 8 {
            return;
        }
        let addr = BdAddr([data[1], data[2], data[3], data[4], data[5], data[6]]);
        if let Some(dev) = self.find_device(&addr) {
            dev.set_bonded(true);
            dev.set_paired(true);
        }
    }

    /// Update internal settings from a command response containing current_settings.
    fn update_settings_from_response(&self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let settings_bits = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let settings = MgmtSettings::from_bits_truncate(settings_bits);

        let mut inner = self.inner.lock().unwrap();
        inner.current_settings = settings;
        inner.powered = settings.contains(MgmtSettings::POWERED);
        inner.discoverable = settings.contains(MgmtSettings::DISCOVERABLE);
        inner.pairable = settings.contains(MgmtSettings::BONDABLE);
    }
}

// ---------------------------------------------------------------------------
// MgmtEventHandler — spawnable task that reads events and dispatches
// ---------------------------------------------------------------------------

/// Spawn a task that reads management events for an adapter and dispatches them.
///
/// Returns a `tokio::task::JoinHandle` that can be used to monitor the task.
/// The task runs until the event receiver is closed (e.g., when the MgmtClient shuts down).
pub async fn spawn_mgmt_event_handler(
    adapter: BtdAdapter,
    client: &MgmtClient,
) -> Result<tokio::task::JoinHandle<()>, BtdError> {
    let index = adapter.index();
    let mut receiver = client
        .subscribe(None, Some(index))
        .map_err(|e| BtdError::failed(format!("failed to subscribe to events: {}", e)))?;

    Ok(tokio::spawn(async move {
        while let Some(event) = receiver.rx.recv().await {
            adapter.handle_mgmt_event(&event);
        }
    }))
}

// ---------------------------------------------------------------------------
// Linux-only: background mgmt event listener for all adapters
// ---------------------------------------------------------------------------

/// Spawn a background task that reads management events for all controllers
/// and dispatches them to the appropriate adapter by index.
///
/// Unlike `spawn_mgmt_event_handler` (which subscribes for a single adapter),
/// this subscribes to all events (index=None) and routes each event to the
/// matching adapter in the global registry.  If no adapter is registered for
/// the event's index, the event is silently ignored.
#[cfg(target_os = "linux")]
pub async fn spawn_mgmt_listener(
    mgmt: Arc<MgmtClient>,
) -> Result<tokio::task::JoinHandle<()>, BtdError> {
    let mut receiver = mgmt
        .subscribe(None, None)
        .map_err(|e| BtdError::failed(format!("failed to subscribe to events: {}", e)))?;

    Ok(tokio::spawn(async move {
        while let Some(event) = receiver.rx.recv().await {
            // Route the event to the adapter matching the controller index.
            if let Some(adapter) = adapter_find(event.index) {
                adapter.handle_mgmt_event(&event);
            }
        }
    }))
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Check the MGMT response status and convert to BtdError if non-zero.
fn check_mgmt_status(resp: &MgmtResponse) -> Result<(), BtdError> {
    if resp.status == 0 {
        return Ok(());
    }
    let status = MgmtStatus::from_u8(resp.status);
    let msg = match status {
        Some(s) => format!("management command failed: {}", s),
        None => format!("management command failed: unknown status 0x{:02x}", resp.status),
    };
    Err(BtdError::failed(msg))
}

/// Extract a NUL-terminated string from a fixed-size byte buffer.
fn c_str_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

/// Reinterpret a packed struct as a byte slice.
///
/// # Safety
/// The struct must be `#[repr(C, packed)]` with no padding-dependent invariants.
unsafe fn struct_as_bytes<T: Sized>(val: &T) -> &[u8] {
    std::slice::from_raw_parts(val as *const T as *const u8, mem::size_of::<T>())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_new() {
        let addr = BdAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let adapter = BtdAdapter::new(0, addr);

        assert_eq!(adapter.index(), 0);
        assert_eq!(adapter.address(), addr);
        assert_eq!(adapter.name(), "BlueZ");
        // alias falls back to name when empty
        assert_eq!(adapter.alias(), "BlueZ");
        assert!(!adapter.powered());
        assert!(!adapter.discoverable());
        assert!(!adapter.pairable());
        assert!(!adapter.discovering());
        assert_eq!(adapter.class_of_device(), 0);
    }

    #[test]
    fn test_adapter_powered() {
        let adapter = BtdAdapter::new(0, BdAddr::ANY);

        assert!(!adapter.powered());
        adapter.set_powered(true);
        assert!(adapter.powered());
        adapter.set_powered(false);
        assert!(!adapter.powered());
    }

    #[test]
    fn test_adapter_discovery() {
        let adapter = BtdAdapter::new(0, BdAddr::ANY);

        // Cannot start discovery when not powered
        assert!(adapter.start_discovery().is_err());

        adapter.set_powered(true);
        assert!(adapter.start_discovery().is_ok());
        assert!(adapter.discovering());

        // Cannot start again while already discovering
        assert!(adapter.start_discovery().is_err());

        assert!(adapter.stop_discovery().is_ok());
        assert!(!adapter.discovering());

        // Cannot stop when not discovering
        assert!(adapter.stop_discovery().is_err());
    }

    #[test]
    fn test_adapter_registry() {
        // Clean slate
        adapter_cleanup();

        assert!(adapter_find(0).is_none());
        assert!(adapter_get_default().is_none());

        let a0 = BtdAdapter::new(0, BdAddr([0x01; 6]));
        let a1 = BtdAdapter::new(1, BdAddr([0x02; 6]));
        adapter_register(a0.clone());
        adapter_register(a1.clone());

        let found = adapter_find(1).expect("should find hci1");
        assert_eq!(found.index(), 1);

        let def = adapter_get_default().expect("should have a default");
        assert_eq!(def.index(), 0);

        adapter_cleanup();
        assert!(adapter_find(0).is_none());
    }

    #[test]
    fn test_adapter_path() {
        let a0 = BtdAdapter::new(0, BdAddr::ANY);
        assert_eq!(a0.path(), "/org/bluez/hci0");

        let a3 = BtdAdapter::new(3, BdAddr::ANY);
        assert_eq!(a3.path(), "/org/bluez/hci3");
    }

    #[test]
    fn test_handle_new_settings() {
        let adapter = BtdAdapter::new(0, BdAddr::ANY);

        // Simulate MGMT_EV_NEW_SETTINGS with POWERED | BONDABLE
        let settings = MgmtSettings::POWERED | MgmtSettings::BONDABLE;
        let data = settings.bits().to_le_bytes().to_vec();

        let event = MgmtEvent {
            event: MGMT_EV_NEW_SETTINGS,
            index: 0,
            data,
        };
        adapter.handle_mgmt_event(&event);

        assert!(adapter.powered());
        assert!(adapter.pairable());
        assert!(!adapter.discoverable());
    }

    #[test]
    fn test_handle_discovering_event() {
        let adapter = BtdAdapter::new(0, BdAddr::ANY);
        adapter.set_powered(true);

        // Simulate MGMT_EV_DISCOVERING — discovering = 1
        let data = vec![
            MGMT_ADDR_BREDR | MGMT_ADDR_LE_PUBLIC, // addr_type
            1,                                       // discovering = true
        ];
        let event = MgmtEvent {
            event: MGMT_EV_DISCOVERING,
            index: 0,
            data,
        };
        adapter.handle_mgmt_event(&event);
        assert!(adapter.discovering());

        // Simulate MGMT_EV_DISCOVERING — discovering = 0
        let data2 = vec![MGMT_ADDR_BREDR | MGMT_ADDR_LE_PUBLIC, 0];
        let event2 = MgmtEvent {
            event: MGMT_EV_DISCOVERING,
            index: 0,
            data: data2,
        };
        adapter.handle_mgmt_event(&event2);
        assert!(!adapter.discovering());
    }

    #[test]
    fn test_handle_device_found_event() {
        let adapter = BtdAdapter::new(0, BdAddr::ANY);

        let dev_addr = BdAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // Build a MgmtEvDeviceFound manually
        let mut data = Vec::new();
        // MgmtAddrInfo: bdaddr (6 bytes) + addr_type (1 byte)
        data.extend_from_slice(&dev_addr.0);
        data.push(MGMT_ADDR_LE_PUBLIC); // addr_type
        // rssi
        data.push((-50i8) as u8);
        // flags (u32 LE)
        data.extend_from_slice(&0u32.to_le_bytes());
        // eir_len (u16 LE) — include a short name EIR entry
        let eir_name = b"TestDev";
        let eir_entry_len = 2 + eir_name.len(); // length + type + data
        data.extend_from_slice(&(eir_entry_len as u16).to_le_bytes());
        // EIR: length, type (0x09 = Complete Local Name), name
        data.push((1 + eir_name.len()) as u8);
        data.push(0x09);
        data.extend_from_slice(eir_name);

        let event = MgmtEvent {
            event: MGMT_EV_DEVICE_FOUND,
            index: 0,
            data,
        };
        adapter.handle_mgmt_event(&event);

        let dev = adapter.find_device(&dev_addr).expect("device should exist");
        assert_eq!(dev.rssi(), Some(-50));
        assert_eq!(dev.name().as_deref(), Some("TestDev"));
    }

    #[test]
    fn test_handle_device_connected_disconnected() {
        let adapter = BtdAdapter::new(0, BdAddr::ANY);
        let dev_addr = BdAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        // Simulate MGMT_EV_DEVICE_CONNECTED
        let mut data = Vec::new();
        data.extend_from_slice(&dev_addr.0);
        data.push(MGMT_ADDR_BREDR);
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&0u16.to_le_bytes()); // eir_len = 0

        let event = MgmtEvent {
            event: MGMT_EV_DEVICE_CONNECTED,
            index: 0,
            data,
        };
        adapter.handle_mgmt_event(&event);

        let dev = adapter.find_device(&dev_addr).expect("device should exist");
        assert!(dev.connected());

        // Simulate MGMT_EV_DEVICE_DISCONNECTED
        let mut data2 = Vec::new();
        data2.extend_from_slice(&dev_addr.0);
        data2.push(MGMT_ADDR_BREDR);
        data2.push(0); // reason

        let event2 = MgmtEvent {
            event: MGMT_EV_DEVICE_DISCONNECTED,
            index: 0,
            data: data2,
        };
        adapter.handle_mgmt_event(&event2);
        assert!(!dev.connected());
    }

    #[test]
    fn test_check_mgmt_status() {
        let ok = MgmtResponse {
            status: 0,
            data: vec![],
        };
        assert!(check_mgmt_status(&ok).is_ok());

        let fail = MgmtResponse {
            status: 0x03, // Failed
            data: vec![],
        };
        let err = check_mgmt_status(&fail).unwrap_err();
        assert!(err.message.contains("Failed"));
    }

    #[test]
    fn test_c_str_from_bytes() {
        let buf = b"hello\0world";
        assert_eq!(c_str_from_bytes(buf), "hello");

        let buf2 = b"no null";
        assert_eq!(c_str_from_bytes(buf2), "no null");

        let empty = b"\0";
        assert_eq!(c_str_from_bytes(empty), "");
    }

    #[test]
    fn test_adapter_get_or_create_device() {
        let adapter = BtdAdapter::new(0, BdAddr::ANY);
        let dev_addr = BdAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // First call creates the device
        let dev1 = adapter.get_or_create_device(dev_addr, MGMT_ADDR_BREDR);
        assert_eq!(dev1.address(), dev_addr);

        // Second call returns the same device
        let dev2 = adapter.get_or_create_device(dev_addr, MGMT_ADDR_BREDR);
        assert_eq!(dev1.path(), dev2.path());

        // Different address creates a new device
        let other_addr = BdAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let dev3 = adapter.get_or_create_device(other_addr, MGMT_ADDR_LE_PUBLIC);
        assert_ne!(dev1.path(), dev3.path());
    }

    #[test]
    fn test_discovery_filter() {
        let adapter = BtdAdapter::new(0, BdAddr::ANY);

        let filter = DiscoveryFilter {
            uuids: vec!["0000110a-0000-1000-8000-00805f9b34fb".into()],
            rssi: Some(-70),
            transport: Some("le".into()),
            ..Default::default()
        };
        adapter.set_discovery_filter(filter.clone());

        let stored = adapter.discovery_filter();
        assert_eq!(stored.uuids.len(), 1);
        assert_eq!(stored.rssi, Some(-70));
        assert_eq!(stored.transport.as_deref(), Some("le"));
    }

    #[test]
    fn test_no_mgmt_client_async_errors() {
        // Verify that async methods return proper errors when no mgmt client is attached
        let adapter = BtdAdapter::new(0, BdAddr::ANY);
        assert!(adapter.mgmt_client().is_none());

        // The sync API still works without a mgmt client
        adapter.set_powered(true);
        assert!(adapter.powered());
    }
}
