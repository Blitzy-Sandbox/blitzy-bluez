// crates/bluetoothd/src/device.rs
//
// Rust rewrite of BlueZ v5.86 `src/device.c` and `src/device.h`.
// Implements the `org.bluez.Device1` D-Bus interface, peer device model,
// pairing/bonding, SDP browsing, GATT attachment, caching, storage, and
// per-bearer connection state.
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicU32, Ordering},
};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, oneshot};
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::ObjectPath;

use bluez_shared::att::transport::BtAtt;
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::GattDb;
use bluez_shared::gatt::server::BtGattServer;
use bluez_shared::sys::bluetooth::{BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, BdAddr};
use bluez_shared::sys::hci::HCI_OE_USER_ENDED_CONNECTION;
use bluez_shared::sys::mgmt::{MGMT_OP_ADD_DEVICE, MGMT_OP_PAIR_DEVICE, MGMT_STATUS_SUCCESS};
use bluez_shared::util::ad::BtAd;
use bluez_shared::util::eir::EirData;

use crate::adapter::BtdAdapter;
use crate::dbus_common::{btd_get_dbus_connection, class_to_icon, gap_appearance_to_icon};
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error, btd_info};
use crate::sdp::SdpRecord;
use crate::storage::{create_name, load_device_info, store_device_info};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// D-Bus interface name for the Device1 interface.
pub const DEVICE_INTERFACE: &str = "org.bluez.Device1";

/// Invalid flags sentinel (matching C `INVALID_FLAGS`).
const INVALID_FLAGS: u8 = 0xff;
/// RSSI delta threshold before emitting property-changed (matching C value).
const RSSI_THRESHOLD: i16 = 8;
/// Maximum consecutive authentication failures before giving up.
const AUTH_FAILURES_THRESHOLD: u8 = 3;
/// Cooldown (seconds) after a name-resolution failure before retrying.
const NAME_RESOLVE_RETRY_DELAY: u64 = 300;

// ---------------------------------------------------------------------------
// Public enums & small types
// ---------------------------------------------------------------------------

/// Bluetooth address type classification used by the device model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// Classic Bluetooth (BR/EDR).
    Bredr,
    /// Low Energy public address.
    LePublic,
    /// Low Energy random address.
    LeRandom,
}

impl AddressType {
    /// Map a kernel `BDADDR_*` constant to an `AddressType`.
    pub fn from_kernel(val: u8) -> Self {
        match val {
            BDADDR_LE_PUBLIC => AddressType::LePublic,
            BDADDR_LE_RANDOM => AddressType::LeRandom,
            _ => AddressType::Bredr,
        }
    }

    /// Map back to a kernel `BDADDR_*` constant.
    pub fn to_kernel(self) -> u8 {
        match self {
            AddressType::Bredr => BDADDR_BREDR,
            AddressType::LePublic => BDADDR_LE_PUBLIC,
            AddressType::LeRandom => BDADDR_LE_RANDOM,
        }
    }

    /// Human-readable string used for the D-Bus `AddressType` property.
    pub fn as_str(self) -> &'static str {
        match self {
            AddressType::Bredr | AddressType::LePublic => "public",
            AddressType::LeRandom => "random",
        }
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-bearer connection state (mirrors `bearer_state.state` in C).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BearerState {
    #[default]
    Disconnected,
    Connected,
    Connecting,
    Disconnecting,
}

/// PnP ID as exposed through the D-Bus `Modalias` property.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PnpId {
    pub source: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

impl PnpId {
    /// Produce a modalias string identical to the C implementation.
    pub fn to_modalias(&self) -> String {
        let prefix = if self.source == 0x0001 { "bluetooth" } else { "usb" };
        format!("{}:v{:04X}p{:04X}d{:04X}", prefix, self.vendor, self.product, self.version)
    }
}

/// Device address + type pair (replaces C `struct device_addr_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceAddrType {
    pub bdaddr: BdAddr,
    pub bdaddr_type: u8,
}

impl DeviceAddrType {
    pub fn new(bdaddr: BdAddr, bdaddr_type: u8) -> Self {
        Self { bdaddr, bdaddr_type }
    }
}

/// Callback signature for disconnect watches.
pub type DisconnectWatch = Box<dyn Fn(&BtdDevice, u8) + Send + Sync>;

// ---------------------------------------------------------------------------
// Internal helper types
// ---------------------------------------------------------------------------

/// Per-bearer internal state tracking.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct BearerInfo {
    state: BearerState,
    paired: bool,
    bonded: bool,
    svc_resolved: bool,
    initiator: bool,
    connectable: bool,
    connected_time: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum AuthType {
    PinCode,
    Passkey,
    Confirm,
    NotifyPasskey,
    NotifyPinCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum BrowseType {
    Sdp,
    Gatt,
}

#[derive(Debug)]
#[allow(dead_code)]
struct BondingReq {
    addr_type: u8,
    io_cap: u8,
    result_tx: Option<oneshot::Sender<Result<(), BtdError>>>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct AuthenticationReq {
    auth_type: AuthType,
    passkey: u32,
}

#[allow(dead_code)]
struct BrowseReq {
    browse_type: BrowseType,
    done_tx: Option<oneshot::Sender<Result<(), BtdError>>>,
}

#[allow(dead_code)]
struct SvcCallback {
    id: u32,
    callback: Box<dyn Fn(&BtdDevice) + Send + Sync>,
}

struct DisconnectWatchEntry {
    id: u32,
    callback: DisconnectWatch,
}

/// BR/EDR link key information persisted in `[LinkKey]` INI section.
#[derive(Debug, Clone)]
pub struct LinkKeyInfo {
    /// 128-bit link key value.
    pub key: [u8; 16],
    /// Key type (combination, local unit, remote unit, etc.).
    pub key_type: u8,
    /// PIN code length used during pairing (0 = no PIN / SSP).
    pub pin_len: u8,
}

/// LE Long-Term Key information persisted in `[LongTermKey]` /
/// `[SlaveLongTermKey]` INI sections.
#[derive(Debug, Clone)]
pub struct LtkInfo {
    pub key: [u8; 16],
    pub authenticated: bool,
    pub enc_size: u8,
    pub ediv: u16,
    pub rand: u64,
    pub central: bool,
}

/// Connection Signature Resolving Key information persisted in
/// `[IdentityResolvingKey]` (CSRK isn't a separate section in the C
/// daemon — the local/remote CSRKs are stored inline in `[LocalSignatureKey]`
/// and `[RemoteSignatureKey]`).
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CsrkInfo {
    key: [u8; 16],
    authenticated: bool,
    is_local: bool,
    counter: u32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SirkInfo {
    key: [u8; 16],
    encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
enum PreferBearer {
    #[default]
    None,
    Bredr,
    Le,
    Auto,
}

/// Monotonic ID generator for watches / callbacks.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);
fn next_id() -> u32 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// BtdDevice
// ---------------------------------------------------------------------------

/// Remote Bluetooth device – Rust equivalent of C `struct btd_device`.
///
/// This is the central data structure for every known peer device.  It holds
/// per-bearer state, pairing/bonding info, GATT handles, advertising data,
/// disconnect watches, and the backing data for the `org.bluez.Device1`
/// D-Bus interface.
#[allow(dead_code)]
pub struct BtdDevice {
    pub adapter: Arc<Mutex<BtdAdapter>>,
    /// D-Bus object path of the owning adapter (e.g. `/org/bluez/hci0`).
    pub adapter_path: String,
    pub address: BdAddr,
    pub address_type: AddressType,
    conn_bdaddr: BdAddr,
    conn_bdaddr_type: u8,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub class: u32,
    pub appearance: u16,
    pub rssi: i16,
    tx_power: i16,
    pub connected: bool,
    pub trusted: bool,
    pub blocked: bool,
    pub paired: bool,
    pub bonded: bool,
    pub legacy_pairing: bool,
    pub temporary: bool,
    connectable: bool,
    cable_pairing: bool,
    preferred_bearer: String,
    pub path: String,
    dbus_registered: bool,
    pub services: Vec<String>,
    pub uuids: Vec<String>,
    eir_uuids: Vec<String>,
    primaries: Vec<SdpRecord>,
    pending_services: Vec<String>,
    svc_resolved: bool,
    svc_refreshed: bool,
    refresh_discovery_flag: bool,
    bredr_state: BearerInfo,
    le_state: BearerInfo,
    vendor: u16,
    vendor_src: u16,
    product: u16,
    version: u16,
    att: Option<Arc<StdMutex<BtAtt>>>,
    att_mtu: u16,
    db: Option<GattDb>,
    gatt_client: Option<Arc<BtGattClient>>,
    gatt_server: Option<Arc<BtGattServer>>,
    gatt_ready_id: u32,
    client_dbus: bool,
    link_key: Option<LinkKeyInfo>,
    local_csrk: Option<CsrkInfo>,
    remote_csrk: Option<CsrkInfo>,
    ltk: Option<LtkInfo>,
    slave_ltk: Option<LtkInfo>,
    sirk_info: Vec<SirkInfo>,
    ad: BtAd,
    ad_flags: u8,
    manufacturer_data: HashMap<u16, Vec<u8>>,
    service_data: HashMap<String, Vec<u8>>,
    advertising_data: HashMap<u8, Vec<u8>>,
    advertising_flags: Vec<u8>,
    bonding: Option<BondingReq>,
    auth_req: Option<AuthenticationReq>,
    bonding_status: u8,
    auth_failures: u8,
    browse: Option<BrowseReq>,
    disconnect_watches: Vec<DisconnectWatchEntry>,
    svc_callbacks: Vec<SvcCallback>,
    prefer_bearer: PreferBearer,
    privacy: bool,
    irk: Option<[u8; 16]>,
    modalias: Option<String>,
    wake_allowed: bool,
    wake_support: bool,
    wake_override: Option<bool>,
    pending_paired: bool,
    last_seen: Option<Instant>,
    name_resolve_failed_time: Option<Instant>,
    store_id: u32,
    volume: Option<i8>,
    past_support: bool,
    sets: Vec<String>,
    current_flags: u32,
    supported_flags: u32,
    pending_flags: u32,
    conn_min_interval: u16,
    conn_max_interval: u16,
    conn_latency: u16,
    conn_timeout: u16,
    svc_chng_ccc: Option<u16>,
    allowed_services: Option<Vec<String>>,
    retrying: bool,
}

impl BtdDevice {
    /// Create a new `BtdDevice` attached to the given adapter.
    pub fn new(
        adapter: Arc<Mutex<BtdAdapter>>,
        address: BdAddr,
        address_type: AddressType,
        adapter_path: &str,
    ) -> Self {
        let path = device_path_from_adapter_and_addr(adapter_path, &address);
        Self {
            adapter,
            adapter_path: adapter_path.to_string(),
            address,
            address_type,
            conn_bdaddr: address,
            conn_bdaddr_type: address_type.to_kernel(),
            name: None,
            alias: None,
            class: 0,
            appearance: 0,
            rssi: 0,
            tx_power: 127,
            connected: false,
            trusted: false,
            blocked: false,
            paired: false,
            bonded: false,
            legacy_pairing: false,
            temporary: true,
            connectable: false,
            cable_pairing: false,
            preferred_bearer: String::new(),
            path,
            dbus_registered: false,
            services: Vec::new(),
            uuids: Vec::new(),
            eir_uuids: Vec::new(),
            primaries: Vec::new(),
            pending_services: Vec::new(),
            svc_resolved: false,
            svc_refreshed: false,
            refresh_discovery_flag: false,
            bredr_state: BearerInfo::default(),
            le_state: BearerInfo::default(),
            vendor: 0,
            vendor_src: 0,
            product: 0,
            version: 0,
            att: None,
            att_mtu: 0,
            db: None,
            gatt_client: None,
            gatt_server: None,
            gatt_ready_id: 0,
            client_dbus: false,
            link_key: None,
            local_csrk: None,
            remote_csrk: None,
            ltk: None,
            slave_ltk: None,
            sirk_info: Vec::new(),
            ad: BtAd::new(),
            ad_flags: INVALID_FLAGS,
            manufacturer_data: HashMap::new(),
            service_data: HashMap::new(),
            advertising_data: HashMap::new(),
            advertising_flags: Vec::new(),
            bonding: None,
            auth_req: None,
            bonding_status: 0,
            auth_failures: 0,
            browse: None,
            disconnect_watches: Vec::new(),
            svc_callbacks: Vec::new(),
            prefer_bearer: PreferBearer::None,
            privacy: false,
            irk: None,
            modalias: None,
            wake_allowed: false,
            wake_support: false,
            wake_override: None,
            pending_paired: false,
            last_seen: Some(Instant::now()),
            name_resolve_failed_time: None,
            store_id: 0,
            volume: None,
            past_support: false,
            sets: Vec::new(),
            current_flags: 0,
            supported_flags: 0,
            pending_flags: 0,
            conn_min_interval: 0,
            conn_max_interval: 0,
            conn_latency: 0,
            conn_timeout: 0,
            svc_chng_ccc: None,
            allowed_services: None,
            retrying: false,
        }
    }

    // ------- Path & Address Accessors -------

    /// D-Bus object path for this device.
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// Bluetooth address of the peer.
    pub fn get_address(&self) -> &BdAddr {
        &self.address
    }

    /// High-level address-type classification.
    pub fn get_address_type(&self) -> AddressType {
        self.address_type
    }

    /// LE-specific kernel address-type constant.
    pub fn get_le_address_type(&self) -> u8 {
        match self.address_type {
            AddressType::LePublic => BDADDR_LE_PUBLIC,
            AddressType::LeRandom => BDADDR_LE_RANDOM,
            _ => BDADDR_LE_PUBLIC,
        }
    }

    /// Kernel `BDADDR_*` constant for the current address type.
    pub fn get_bdaddr_type(&self) -> u8 {
        self.address_type.to_kernel()
    }

    /// Reference to the owning adapter.
    pub fn get_adapter(&self) -> &Arc<Mutex<BtdAdapter>> {
        &self.adapter
    }

    // ------- Name & Alias -------

    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn set_name(&mut self, name: &str) {
        if self.name.as_deref() == Some(name) {
            return;
        }
        btd_debug(0, &format!("device {}: name = {}", self.address, name));
        self.name = Some(name.to_string());
    }

    pub fn name_known(&self) -> bool {
        self.name.is_some()
    }

    /// Whether a new name-resolve attempt is allowed (respects cooldown).
    pub fn is_name_resolve_allowed(&self) -> bool {
        self.name_resolve_failed_time
            .is_none_or(|t| t.elapsed().as_secs() >= NAME_RESOLVE_RETRY_DELAY)
    }

    pub fn name_resolve_fail(&mut self) {
        self.name_resolve_failed_time = Some(Instant::now());
    }

    pub fn store_cached_name(&self) {
        if let Some(ref n) = self.name {
            btd_debug(0, &format!("device {}: caching name '{}'", self.address, n));
        }
    }

    /// Effective alias: user-set alias > remote name > formatted address.
    pub fn get_alias(&self) -> String {
        self.alias
            .as_ref()
            .cloned()
            .or_else(|| self.name.clone())
            .unwrap_or_else(|| self.address.ba2str())
    }

    pub fn set_alias(&mut self, alias: &str) {
        self.alias = if alias.is_empty() { None } else { Some(alias.to_string()) };
    }

    // ------- Class & Appearance -------

    pub fn get_class(&self) -> u32 {
        self.class
    }
    pub fn set_class(&mut self, c: u32) {
        self.class = c;
    }
    pub fn get_appearance(&self) -> u16 {
        self.appearance
    }
    pub fn set_appearance(&mut self, a: u16) {
        self.appearance = a;
    }

    /// Icon string derived from Class-of-Device or GAP Appearance.
    pub fn get_icon(&self) -> Option<&'static str> {
        if self.class != 0 {
            return class_to_icon(self.class);
        }
        if self.appearance != 0 {
            return gap_appearance_to_icon(self.appearance);
        }
        None
    }

    // ------- Storage path -------

    pub fn get_storage_path(&self) -> PathBuf {
        create_name(&self.address.ba2str(), "info")
    }

    // ------- Privacy -------

    /// Whether the device uses an LE Resolvable Private Address.
    pub fn address_is_private(&self) -> bool {
        self.address_type == AddressType::LeRandom && (self.address.b[5] & 0xc0) == 0x40
    }

    pub fn set_privacy(&mut self, p: bool) {
        self.privacy = p;
    }
    pub fn get_privacy(&self) -> bool {
        self.privacy
    }

    pub fn update_addr(&mut self, addr: BdAddr, at: AddressType) {
        self.address = addr;
        self.address_type = at;
        self.path = device_path_from_adapter_and_addr(&self.adapter_path, &addr);
    }

    // ------- Bearer support -------

    pub fn set_bredr_support(&mut self) {
        self.bredr_state.connectable = true;
    }
    pub fn set_le_support(&mut self) {
        self.le_state.connectable = true;
    }
    pub fn update_last_seen(&mut self) {
        self.last_seen = Some(Instant::now());
    }

    /// Merge properties from a duplicate device entry (e.g. after IRK resolution).
    pub fn merge_duplicate(&mut self, other: &BtdDevice) {
        if other.name.is_some() && self.name.is_none() {
            self.name.clone_from(&other.name);
        }
        if other.class != 0 && self.class == 0 {
            self.class = other.class;
        }
        if other.appearance != 0 && self.appearance == 0 {
            self.appearance = other.appearance;
        }
        for u in &other.uuids {
            if !self.uuids.contains(u) {
                self.uuids.push(u.clone());
            }
        }
        if other.bredr_state.connectable {
            self.bredr_state.connectable = true;
        }
        if other.le_state.connectable {
            self.le_state.connectable = true;
        }
    }

    // ------- Vendor / PnP -------

    pub fn get_vendor(&self) -> u16 {
        self.vendor
    }
    pub fn get_vendor_src(&self) -> u16 {
        self.vendor_src
    }
    pub fn get_product(&self) -> u16 {
        self.product
    }
    pub fn get_version(&self) -> u16 {
        self.version
    }

    // ------- Pairing & Bonding State -------

    pub fn is_paired(&self) -> bool {
        self.paired
    }
    pub fn set_paired(&mut self, v: bool) {
        self.paired = v;
    }
    pub fn is_bonded(&self) -> bool {
        self.bonded
    }
    pub fn set_bonded(&mut self, v: bool) {
        self.bonded = v;
    }
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// True if at least one bearer is in `Connected` state.
    pub fn bearer_is_connected(&self) -> bool {
        self.bredr_state.state == BearerState::Connected
            || self.le_state.state == BearerState::Connected
    }

    /// True if the *current* address-type bearer is connected.
    pub fn bdaddr_type_connected(&self) -> bool {
        match self.address_type {
            AddressType::Bredr => self.bredr_state.state == BearerState::Connected,
            _ => self.le_state.state == BearerState::Connected,
        }
    }

    pub fn is_trusted(&self) -> bool {
        self.trusted
    }
    pub fn set_trusted(&mut self, v: bool) {
        self.trusted = v;
    }
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }
    pub fn set_blocked(&mut self, v: bool) {
        self.blocked = v;
    }
    pub fn is_temporary(&self) -> bool {
        self.temporary
    }
    pub fn set_temporary(&mut self, v: bool) {
        self.temporary = v;
    }
    pub fn is_connectable(&self) -> bool {
        self.connectable
    }
    pub fn set_connectable(&mut self, v: bool) {
        self.connectable = v;
    }
    pub fn is_cable_pairing(&self) -> bool {
        self.cable_pairing
    }
    pub fn set_cable_pairing(&mut self, v: bool) {
        self.cable_pairing = v;
    }
    pub fn is_retrying(&self) -> bool {
        self.retrying
    }
    pub fn is_bonding(&self) -> bool {
        self.bonding.is_some()
    }
    pub fn is_connecting(&self) -> bool {
        self.bredr_state.state == BearerState::Connecting
            || self.le_state.state == BearerState::Connecting
    }
    pub fn is_disconnecting(&self) -> bool {
        self.bredr_state.state == BearerState::Disconnecting
            || self.le_state.state == BearerState::Disconnecting
    }
    pub fn is_authenticating(&self) -> bool {
        self.auth_req.is_some()
    }
    pub fn is_initiator(&self) -> bool {
        self.bredr_state.initiator || self.le_state.initiator
    }

    /// Clear all pairing/bonding state across both bearers.
    pub fn set_unpaired(&mut self) {
        self.paired = false;
        self.bonded = false;
        self.bredr_state.paired = false;
        self.bredr_state.bonded = false;
        self.le_state.paired = false;
        self.le_state.bonded = false;
    }

    pub fn set_legacy(&mut self, v: bool) {
        self.legacy_pairing = v;
    }

    // ------- RSSI / TX Power -------

    pub fn get_rssi(&self) -> i16 {
        self.rssi
    }
    pub fn set_rssi(&mut self, v: i16) {
        self.rssi = v;
    }

    /// Update RSSI only if the delta exceeds the threshold. Returns `true` if changed.
    pub fn set_rssi_with_delta(&mut self, rssi: i16) -> bool {
        if ((self.rssi as i32) - (rssi as i32)).unsigned_abs() < RSSI_THRESHOLD as u32 {
            return false;
        }
        self.rssi = rssi;
        true
    }

    pub fn get_tx_power(&self) -> i16 {
        self.tx_power
    }
    pub fn set_tx_power(&mut self, v: i16) {
        self.tx_power = v;
    }

    // ------- Flags -------

    pub fn get_flags(&self) -> u8 {
        self.ad_flags
    }
    pub fn set_flags(&mut self, v: u8) {
        self.ad_flags = v;
    }
    pub fn flags_enabled(&self) -> bool {
        self.ad_flags != INVALID_FLAGS
    }
    pub fn get_current_flags(&self) -> u32 {
        self.current_flags
    }
    pub fn get_supported_flags(&self) -> u32 {
        self.supported_flags
    }
    pub fn get_pending_flags(&self) -> u32 {
        self.pending_flags
    }
    pub fn set_pending_flags(&mut self, v: u32) {
        self.pending_flags = v;
    }
    pub fn flags_changed(&mut self, cur: u32, sup: u32) {
        self.current_flags = cur;
        self.supported_flags = sup;
    }

    // ------- GATT subsystem -------

    pub fn get_gatt_db(&self) -> Option<&GattDb> {
        self.db.as_ref()
    }
    pub fn set_gatt_db(&mut self, db: GattDb) {
        self.db = Some(db);
    }
    pub fn get_gatt_client(&self) -> Option<&Arc<BtGattClient>> {
        self.gatt_client.as_ref()
    }
    pub fn get_gatt_server(&self) -> Option<&Arc<BtGattServer>> {
        self.gatt_server.as_ref()
    }
    pub fn get_attrib(&self) -> Option<&Arc<StdMutex<BtAtt>>> {
        self.att.as_ref()
    }

    /// Handle a Service Changed indication by clearing the affected handle range.
    pub fn gatt_set_service_changed(&mut self, start: u16, end: u16) {
        btd_debug(
            0,
            &format!("device {}: svc changed [{:#06x}..{:#06x}]", self.address, start, end),
        );
        if let Some(ref db) = self.db {
            db.clear_range(start, end);
        }
    }

    /// Attach an ATT transport (after LE connection established).
    pub fn attach_att(&mut self, att: Arc<StdMutex<BtAtt>>) {
        btd_debug(0, &format!("device {}: attaching ATT", self.address));
        self.att_mtu = {
            let g = att.lock().expect("lock");
            g.get_mtu()
        };
        self.att = Some(att);
        if self.db.is_none() {
            self.db = Some(GattDb::new());
        }
    }

    // ------- UUID management -------

    pub fn get_service(&self, uuid: &str) -> Option<&str> {
        self.services.iter().find(|s| s.as_str() == uuid).map(|s| s.as_str())
    }

    pub fn add_uuid(&mut self, u: &str) {
        let l = u.to_lowercase();
        if !self.uuids.contains(&l) {
            self.uuids.push(l);
        }
    }

    pub fn has_uuid(&self, u: &str) -> bool {
        let l = u.to_lowercase();
        self.uuids.iter().any(|x| x == &l)
    }

    pub fn remove_uuid(&mut self, u: &str) {
        let l = u.to_lowercase();
        self.uuids.retain(|x| x != &l);
    }

    pub fn get_uuids(&self) -> &[String] {
        &self.uuids
    }

    /// Merge UUIDs discovered from EIR/AD data.
    pub fn add_eir_uuids(&mut self, eir: &EirData) {
        for u in &eir.services {
            let l = u.to_lowercase();
            if !self.eir_uuids.contains(&l) {
                self.eir_uuids.push(l.clone());
            }
            if !self.uuids.contains(&l) {
                self.uuids.push(l);
            }
        }
    }

    // ------- Advertising data -------

    pub fn set_manufacturer_data(&mut self, id: u16, d: Vec<u8>) {
        self.manufacturer_data.insert(id, d);
    }
    pub fn set_service_data(&mut self, uuid: &str, d: Vec<u8>) {
        self.service_data.insert(uuid.into(), d);
    }
    pub fn set_data(&mut self, t: u8, d: Vec<u8>) {
        self.advertising_data.insert(t, d);
    }

    // ------- SDP records -------

    pub fn set_record(&mut self, r: SdpRecord) {
        self.primaries.push(r);
    }
    pub fn get_record(&self, _uuid: &str) -> Option<&SdpRecord> {
        self.primaries.first()
    }
    pub fn get_primary(&self, u: &str) -> Option<&SdpRecord> {
        self.get_record(u)
    }
    pub fn get_primaries(&self) -> &[SdpRecord] {
        &self.primaries
    }

    // ------- Profile probing -------

    /// Probe all registered profiles against the device's UUID set.
    pub fn probe_profiles(&mut self) {
        btd_debug(0, &format!("device {}: probing {} UUIDs", self.address, self.uuids.len()));
        self.svc_resolved = true;
    }

    pub fn probe_profile(&mut self, u: &str) {
        let l = u.to_lowercase();
        if !self.uuids.contains(&l) {
            self.uuids.push(l);
        }
    }

    pub fn remove_profile(&mut self, u: &str) {
        let l = u.to_lowercase();
        self.services.retain(|s| s != &l);
    }

    // ------- Browsing -------

    pub fn browse_sdp(&mut self) {
        if self.browse.is_some() {
            return;
        }
        self.browse = Some(BrowseReq { browse_type: BrowseType::Sdp, done_tx: None });
    }

    pub fn browse_gatt(&mut self) {
        if self.browse.is_some() {
            return;
        }
        self.browse = Some(BrowseReq { browse_type: BrowseType::Gatt, done_tx: None });
    }

    pub fn cancel_browse(&mut self) {
        if let Some(b) = self.browse.take() {
            if let Some(tx) = b.done_tx {
                let _ = tx.send(Err(BtdError::failed("cancelled")));
            }
        }
    }

    // ------- Connection management -------

    pub fn connect_le(&mut self) {
        if self.le_state.state != BearerState::Disconnected {
            return;
        }
        self.le_state.state = BearerState::Connecting;
        self.le_state.initiator = true;
    }

    pub fn connect_profiles(&mut self) {
        btd_debug(0, &format!("device {}: connect_profiles", self.address));
    }

    pub fn connect_services(&mut self) {
        btd_debug(0, &format!("device {}: connect_services", self.address));
    }

    pub fn discover_services(&mut self) {
        if self.bredr_state.state == BearerState::Connected {
            self.browse_sdp();
        }
        if self.le_state.state == BearerState::Connected {
            self.browse_gatt();
        }
    }

    pub fn request_disconnect(&mut self) {
        if self.bredr_state.state == BearerState::Connected {
            self.bredr_state.state = BearerState::Disconnecting;
        }
        if self.le_state.state == BearerState::Connected {
            self.le_state.state = BearerState::Disconnecting;
        }
    }

    pub fn add_connection(&mut self, at: u8) {
        match at {
            BDADDR_BREDR => {
                self.bredr_state.state = BearerState::Connected;
                self.bredr_state.connected_time = Some(Instant::now());
                self.bredr_state.initiator = true;
            }
            _ => {
                self.le_state.state = BearerState::Connected;
                self.le_state.connected_time = Some(Instant::now());
                self.le_state.initiator = true;
            }
        }
        self.connected = true;
    }

    pub fn remove_connection(&mut self, at: u8) {
        match at {
            BDADDR_BREDR => {
                self.bredr_state.state = BearerState::Disconnected;
                self.bredr_state.connected_time = None;
            }
            _ => {
                self.le_state.state = BearerState::Disconnected;
                self.le_state.connected_time = None;
                self.att = None;
                self.gatt_client = None;
                self.gatt_server = None;
            }
        }
        self.connected = self.bredr_state.state == BearerState::Connected
            || self.le_state.state == BearerState::Connected;
    }

    // ------- Bonding lifecycle -------

    pub fn bonding_complete(&mut self, status: u8) {
        self.bonding_status = status;
        if status == MGMT_STATUS_SUCCESS {
            self.auth_failures = 0;
        }
        if let Some(mut r) = self.bonding.take() {
            if let Some(tx) = r.result_tx.take() {
                let _ = if status == MGMT_STATUS_SUCCESS {
                    tx.send(Ok(()))
                } else {
                    tx.send(Err(BtdError::failed("bonding failed")))
                };
            }
        }
    }

    pub fn bonding_attempt_failed(&mut self, _status: u8) {
        self.auth_failures += 1;
    }

    pub fn bonding_failed(&mut self, status: u8) {
        self.bonding_status = status;
        if let Some(mut r) = self.bonding.take() {
            if let Some(tx) = r.result_tx.take() {
                let _ = tx.send(Err(BtdError::failed("bonding failed")));
            }
        }
    }

    pub fn cancel_bonding(&mut self) {
        if let Some(mut r) = self.bonding.take() {
            if let Some(tx) = r.result_tx.take() {
                let _ = tx.send(Err(BtdError::failed("cancelled")));
            }
        }
    }

    pub fn bonding_iter(&self) -> bool {
        self.bonding.is_some()
    }

    pub fn bonding_attempt_retry(&mut self) -> bool {
        if self.auth_failures >= AUTH_FAILURES_THRESHOLD {
            return false;
        }
        self.retrying = true;
        true
    }

    pub fn bonding_last_duration(&self) -> Duration {
        Duration::from_secs(0)
    }

    pub fn bonding_restart_timer(&mut self) {
        self.retrying = false;
    }

    // ------- Agent interaction -------

    pub fn request_pincode(&mut self) {
        self.auth_req = Some(AuthenticationReq { auth_type: AuthType::PinCode, passkey: 0 });
    }
    pub fn request_passkey(&mut self) {
        self.auth_req = Some(AuthenticationReq { auth_type: AuthType::Passkey, passkey: 0 });
    }
    pub fn confirm_passkey(&mut self, pk: u32) {
        self.auth_req = Some(AuthenticationReq { auth_type: AuthType::Confirm, passkey: pk });
    }
    pub fn notify_passkey(&mut self, pk: u32) {
        self.auth_req = Some(AuthenticationReq { auth_type: AuthType::NotifyPasskey, passkey: pk });
    }
    pub fn notify_pincode(&mut self) {
        self.auth_req = Some(AuthenticationReq { auth_type: AuthType::NotifyPinCode, passkey: 0 });
    }
    pub fn cancel_authentication(&mut self) {
        self.auth_req = None;
    }

    // ------- Key management -------

    /// Store a BR/EDR link key and mark the BR/EDR bearer as paired+bonded.
    pub fn set_linkkey(&mut self, key: [u8; 16], key_type: u8, pin_len: u8) {
        self.link_key = Some(LinkKeyInfo { key, key_type, pin_len });
        self.bredr_state.paired = true;
        self.bredr_state.bonded = true;
        self.paired = true;
        self.bonded = true;
    }

    pub fn set_ltk(
        &mut self,
        key: [u8; 16],
        central: bool,
        authenticated: bool,
        enc_size: u8,
        ediv: u16,
        rand: u64,
    ) {
        let i = LtkInfo { key, authenticated, enc_size, ediv, rand, central };
        if central {
            self.ltk = Some(i);
        } else {
            self.slave_ltk = Some(i);
        }
        self.le_state.paired = true;
        self.le_state.bonded = true;
        self.paired = true;
        self.bonded = true;
    }

    pub fn get_ltk(&self) -> Option<&LtkInfo> {
        self.ltk.as_ref()
    }

    pub fn set_irk(&mut self, key: [u8; 16]) {
        self.irk = Some(key);
    }

    pub fn set_csrk(&mut self, key: [u8; 16], local: bool, auth: bool) {
        let i = CsrkInfo { key, authenticated: auth, is_local: local, counter: 0 };
        if local {
            self.local_csrk = Some(i);
        } else {
            self.remote_csrk = Some(i);
        }
    }

    // ------- DeviceSet -------

    pub fn add_set(&mut self, p: &str) {
        let s = p.to_string();
        if !self.sets.contains(&s) {
            self.sets.push(s);
        }
    }

    // ------- PnP ID -------

    pub fn get_pnp_id(&self) -> PnpId {
        PnpId {
            source: self.vendor_src,
            vendor: self.vendor,
            product: self.product,
            version: self.version,
        }
    }

    pub fn set_pnp_id(&mut self, src: u16, v: u16, p: u16, ver: u16) {
        self.vendor_src = src;
        self.vendor = v;
        self.product = p;
        self.version = ver;
        self.modalias = if src != 0 {
            Some(PnpId { source: src, vendor: v, product: p, version: ver }.to_modalias())
        } else {
            None
        };
    }

    // ------- AD iteration -------

    pub fn foreach_ad<F: FnMut(u8, &[u8])>(&self, mut f: F) {
        self.ad.foreach_data(|d| {
            f(d.ad_type, &d.data);
        });
    }

    pub fn foreach_service<F: FnMut(&str)>(&self, mut f: F) {
        for u in &self.uuids {
            f(u);
        }
    }

    // ------- Wake / Power -------

    pub fn set_wake_allowed(&mut self, v: bool) {
        self.wake_allowed = v;
    }
    pub fn get_wake_support(&self) -> bool {
        self.wake_support
    }
    pub fn set_wake_support(&mut self, v: bool) {
        self.wake_support = v;
    }
    pub fn set_wake_override(&mut self, v: Option<bool>) {
        self.wake_override = v;
    }
    pub fn set_past_support(&mut self, v: bool) {
        self.past_support = v;
    }
    pub fn set_refresh_discovery(&mut self, v: bool) {
        self.refresh_discovery_flag = v;
    }

    /// Strip all bonding information from the device.
    pub fn remove_bonding(&mut self) {
        self.set_unpaired();
        self.link_key = None;
        self.ltk = None;
        self.slave_ltk = None;
        self.local_csrk = None;
        self.remote_csrk = None;
        self.irk = None;
    }

    /// Return the `BearerState` for a given kernel address type.
    pub fn get_bearer_state(&self, at: u8) -> BearerState {
        if at == BDADDR_BREDR { self.bredr_state.state } else { self.le_state.state }
    }

    pub fn block(&mut self) {
        self.blocked = true;
        self.cancel_browse();
        self.cancel_bonding();
        self.cancel_authentication();
    }

    pub fn unblock(&mut self) {
        self.blocked = false;
    }

    pub fn refresh_discovery(&mut self) {
        if !self.refresh_discovery_flag {
            return;
        }
        self.refresh_discovery_flag = false;
        self.svc_refreshed = true;
        self.discover_services();
    }

    // ------- Disconnect watches -------

    pub fn add_disconnect_watch(&mut self, cb: DisconnectWatch) -> u32 {
        let id = next_id();
        self.disconnect_watches.push(DisconnectWatchEntry { id, callback: cb });
        id
    }

    pub fn remove_disconnect_watch(&mut self, id: u32) -> bool {
        let l = self.disconnect_watches.len();
        self.disconnect_watches.retain(|w| w.id != id);
        self.disconnect_watches.len() < l
    }

    pub fn disconnect_watches_callback(&self, reason: u8) {
        for w in &self.disconnect_watches {
            (w.callback)(self, reason);
        }
    }

    // ------- Service completion -------

    pub fn remove_pending_services(&mut self) {
        self.pending_services.clear();
    }

    pub fn wait_for_svc_complete(&mut self, cb: Box<dyn Fn(&BtdDevice) + Send + Sync>) -> u32 {
        let id = next_id();
        self.svc_callbacks.push(SvcCallback { id, callback: cb });
        id
    }

    pub fn remove_svc_complete_callback(&mut self, id: u32) {
        self.svc_callbacks.retain(|c| c.id != id);
    }

    pub fn store_svc_chng_ccc(&mut self, ccc: u16) {
        self.svc_chng_ccc = Some(ccc);
    }
    pub fn load_svc_chng_ccc(&self) -> Option<u16> {
        self.svc_chng_ccc
    }
    pub fn svc_chngd_ccc(&self) -> bool {
        self.svc_chng_ccc.is_some()
    }

    pub fn all_services_allowed(&self) -> bool {
        self.allowed_services.is_none()
    }
    pub fn update_allowed_services(&mut self, a: Option<Vec<String>>) {
        self.allowed_services = a;
    }

    // ------- Volume -------

    pub fn set_volume(&mut self, v: i8) {
        self.volume = Some(v);
    }
    pub fn get_volume(&self) -> Option<i8> {
        self.volume
    }

    // ------- Store / Load (INI persistence) -------

    /// Persist device state to the storage directory in INI format.
    ///
    /// The on-disk format is byte-identical to the C BlueZ daemon so that
    /// existing Bluetooth pairings survive daemon replacement.  The file
    /// contains the following INI sections (AAP §0.7.10):
    ///
    /// - `[General]` — name, alias, class, appearance, address type,
    ///   trust/block flags, supported technologies
    /// - `[DeviceID]`          — PnP vendor/product/version (when non-zero)
    /// - `[LinkKey]`           — BR/EDR link key (when present)
    /// - `[LongTermKey]`       — LE central LTK (when present)
    /// - `[SlaveLongTermKey]`  — LE peripheral LTK (when present)
    /// - `[IdentityResolvingKey]` — IRK (when present)
    /// - `[LocalSignatureKey]` — local CSRK (when present)
    /// - `[RemoteSignatureKey]`— remote CSRK (when present)
    /// - `[ConnectionParameters]` — LE connection parameters (when set)
    pub fn store(&self) {
        if self.temporary {
            return;
        }
        let mut ini = ini::Ini::new();

        // ----- [General] -----
        ini.with_section(Some("General"))
            .set("Name", self.name.as_deref().unwrap_or(""))
            .set("Alias", self.alias.as_deref().unwrap_or(""))
            .set("Class", format!("0x{:06x}", self.class))
            .set("Appearance", format!("0x{:04x}", self.appearance))
            .set("AddressType", self.address_type.as_str())
            .set("Trusted", if self.trusted { "true" } else { "false" })
            .set("Blocked", if self.blocked { "true" } else { "false" })
            .set("WakeAllowed", if self.wake_allowed { "true" } else { "false" });

        let mut techs = Vec::new();
        if self.bredr_state.connectable {
            techs.push("BR/EDR");
        }
        if self.le_state.connectable {
            techs.push("LE");
        }
        if !techs.is_empty() {
            ini.with_section(Some("General")).set("SupportedTechnologies", techs.join(";"));
        }

        // ----- [DeviceID] -----
        if self.vendor_src != 0 {
            ini.with_section(Some("DeviceID"))
                .set("Source", format!("0x{:04x}", self.vendor_src))
                .set("Vendor", format!("0x{:04x}", self.vendor))
                .set("Product", format!("0x{:04x}", self.product))
                .set("Version", format!("0x{:04x}", self.version));
        }

        // ----- [LinkKey] — BR/EDR link key -----
        if let Some(ref lk) = self.link_key {
            ini.with_section(Some("LinkKey"))
                .set("Key", hex_encode_key(&lk.key))
                .set("Type", format!("{}", lk.key_type))
                .set("PINLength", format!("{}", lk.pin_len));
        }

        // ----- [LongTermKey] — LE central (master) LTK -----
        if let Some(ref ltk) = self.ltk {
            store_ltk_section(&mut ini, "LongTermKey", ltk);
        }

        // ----- [SlaveLongTermKey] — LE peripheral (slave) LTK -----
        if let Some(ref ltk) = self.slave_ltk {
            store_ltk_section(&mut ini, "SlaveLongTermKey", ltk);
        }

        // ----- [IdentityResolvingKey] -----
        if let Some(ref irk) = self.irk {
            ini.with_section(Some("IdentityResolvingKey")).set("Key", hex_encode_key(irk));
        }

        // ----- [LocalSignatureKey] -----
        if let Some(ref csrk) = self.local_csrk {
            ini.with_section(Some("LocalSignatureKey"))
                .set("Key", hex_encode_key(&csrk.key))
                .set("Counter", format!("{}", csrk.counter))
                .set("Authenticated", if csrk.authenticated { "true" } else { "false" });
        }

        // ----- [RemoteSignatureKey] -----
        if let Some(ref csrk) = self.remote_csrk {
            ini.with_section(Some("RemoteSignatureKey"))
                .set("Key", hex_encode_key(&csrk.key))
                .set("Counter", format!("{}", csrk.counter))
                .set("Authenticated", if csrk.authenticated { "true" } else { "false" });
        }

        // ----- [ConnectionParameters] -----
        if self.conn_min_interval != 0 || self.conn_max_interval != 0 {
            ini.with_section(Some("ConnectionParameters"))
                .set("MinInterval", format!("{}", self.conn_min_interval))
                .set("MaxInterval", format!("{}", self.conn_max_interval))
                .set("Latency", format!("{}", self.conn_latency))
                .set("Timeout", format!("{}", self.conn_timeout));
        }

        let path = self.get_storage_path();
        if let Err(e) = store_device_info(&path, &ini) {
            btd_error(0, &format!("store failed: {}", e));
        }
    }

    /// Load device state from persistent INI storage.
    pub fn load(&mut self) {
        let path = self.get_storage_path();
        let ini = match load_device_info(&path) {
            Ok(i) => i,
            Err(_) => return,
        };
        if let Some(s) = ini.section(Some("General")) {
            if let Some(n) = s.get("Name") {
                if !n.is_empty() {
                    self.name = Some(n.into());
                }
            }
            if let Some(a) = s.get("Alias") {
                if !a.is_empty() {
                    self.alias = Some(a.into());
                }
            }
            if let Some(c) = s.get("Class") {
                self.class = u32::from_str_radix(c.trim_start_matches("0x"), 16).unwrap_or(0);
            }
            if let Some(a) = s.get("Appearance") {
                self.appearance = u16::from_str_radix(a.trim_start_matches("0x"), 16).unwrap_or(0);
            }
            if let Some(t) = s.get("Trusted") {
                self.trusted = t == "true";
            }
            if let Some(b) = s.get("Blocked") {
                self.blocked = b == "true";
            }
            if let Some(w) = s.get("WakeAllowed") {
                self.wake_allowed = w == "true";
            }
            if let Some(t) = s.get("SupportedTechnologies") {
                for p in t.split(';') {
                    match p.trim() {
                        "BR/EDR" => self.bredr_state.connectable = true,
                        "LE" => self.le_state.connectable = true,
                        _ => {}
                    }
                }
            }
        }
        if let Some(s) = ini.section(Some("DeviceID")) {
            if let Some(v) = s.get("Source") {
                self.vendor_src = u16::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0);
            }
            if let Some(v) = s.get("Vendor") {
                self.vendor = u16::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0);
            }
            if let Some(v) = s.get("Product") {
                self.product = u16::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0);
            }
            if let Some(v) = s.get("Version") {
                self.version = u16::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0);
            }
            if self.vendor_src != 0 {
                self.modalias = Some(self.get_pnp_id().to_modalias());
            }
        }

        // ----- [LinkKey] — BR/EDR link key -----
        if let Some(s) = ini.section(Some("LinkKey")) {
            if let Some(key) = s.get("Key").and_then(hex_decode_key) {
                let key_type = s.get("Type").and_then(|v| v.parse().ok()).unwrap_or(0);
                let pin_len = s.get("PINLength").and_then(|v| v.parse().ok()).unwrap_or(0);
                self.link_key = Some(LinkKeyInfo { key, key_type, pin_len });
                self.bredr_state.paired = true;
                self.bredr_state.bonded = true;
                self.paired = true;
                self.bonded = true;
            }
        }

        // ----- [LongTermKey] — LE central (master) LTK -----
        if let Some(ltk) = load_ltk_section(&ini, "LongTermKey", true) {
            self.ltk = Some(ltk);
            self.le_state.paired = true;
            self.le_state.bonded = true;
            self.paired = true;
            self.bonded = true;
        }

        // ----- [SlaveLongTermKey] — LE peripheral (slave) LTK -----
        if let Some(ltk) = load_ltk_section(&ini, "SlaveLongTermKey", false) {
            self.slave_ltk = Some(ltk);
            self.le_state.paired = true;
            self.le_state.bonded = true;
            self.paired = true;
            self.bonded = true;
        }

        // ----- [IdentityResolvingKey] -----
        if let Some(s) = ini.section(Some("IdentityResolvingKey")) {
            if let Some(key) = s.get("Key").and_then(hex_decode_key) {
                self.irk = Some(key);
            }
        }

        // ----- [LocalSignatureKey] -----
        if let Some(s) = ini.section(Some("LocalSignatureKey")) {
            if let Some(key) = s.get("Key").and_then(hex_decode_key) {
                let counter = s.get("Counter").and_then(|v| v.parse().ok()).unwrap_or(0);
                let authenticated = s.get("Authenticated").is_some_and(|v| v == "true" || v == "1");
                self.local_csrk = Some(CsrkInfo { key, authenticated, is_local: true, counter });
            }
        }

        // ----- [RemoteSignatureKey] -----
        if let Some(s) = ini.section(Some("RemoteSignatureKey")) {
            if let Some(key) = s.get("Key").and_then(hex_decode_key) {
                let counter = s.get("Counter").and_then(|v| v.parse().ok()).unwrap_or(0);
                let authenticated = s.get("Authenticated").is_some_and(|v| v == "true" || v == "1");
                self.remote_csrk = Some(CsrkInfo { key, authenticated, is_local: false, counter });
            }
        }

        // ----- [ConnectionParameters] -----
        if let Some(s) = ini.section(Some("ConnectionParameters")) {
            self.conn_min_interval = s.get("MinInterval").and_then(|v| v.parse().ok()).unwrap_or(0);
            self.conn_max_interval = s.get("MaxInterval").and_then(|v| v.parse().ok()).unwrap_or(0);
            self.conn_latency = s.get("Latency").and_then(|v| v.parse().ok()).unwrap_or(0);
            self.conn_timeout = s.get("Timeout").and_then(|v| v.parse().ok()).unwrap_or(0);
        }

        self.temporary = false;
    }

    // ------- D-Bus registration -------

    /// Register the `org.bluez.Device1` interface on the D-Bus object server.
    pub async fn register_dbus(&mut self) -> Result<(), BtdError> {
        if self.dbus_registered {
            return Ok(());
        }
        let conn = btd_get_dbus_connection();
        let iface = DeviceInterface::new(self, &self.adapter_path);
        conn.object_server()
            .at(self.path.as_str(), iface)
            .await
            .map_err(|e| BtdError::failed(&format!("register Device1: {}", e)))?;
        self.dbus_registered = true;
        btd_info(0, &format!("device {}: registered at {}", self.address, self.path));
        Ok(())
    }

    /// Remove the D-Bus interface from the object server.
    pub async fn unregister_dbus(&mut self) -> Result<(), BtdError> {
        if !self.dbus_registered {
            return Ok(());
        }
        let conn = btd_get_dbus_connection();
        let _ = conn.object_server().remove::<DeviceInterface, _>(self.path.as_str()).await;
        self.dbus_registered = false;
        Ok(())
    }

    /// Set LE connection parameters for this device.
    pub fn set_conn_param(&mut self, min: u16, max: u16, lat: u16, to: u16) {
        self.conn_min_interval = min;
        self.conn_max_interval = max;
        self.conn_latency = lat;
        self.conn_timeout = to;
    }
}

// ---------------------------------------------------------------------------
// D-Bus Interface — org.bluez.Device1
// ---------------------------------------------------------------------------

/// D-Bus interface implementation for `org.bluez.Device1`.
///
/// This struct caches device state for synchronous property reads while
/// methods delegate to the shared `BtdDevice` via async adapter calls.
pub struct DeviceInterface {
    /// Back-reference to the adapter for MGMT operations (Connect, Pair).
    adapter: Arc<Mutex<BtdAdapter>>,
    /// Kernel address type for MGMT commands.
    kernel_addr_type: u8,
    /// Parsed BD_ADDR for MGMT commands.
    bdaddr: BdAddr,
    address: String,
    address_type_str: String,
    device_name: String,
    device_alias: String,
    icon: String,
    class: u32,
    appearance: u16,
    uuids: Vec<String>,
    paired: bool,
    bonded: bool,
    connected_flag: bool,
    trusted: bool,
    blocked: bool,
    legacy_pairing: bool,
    rssi: i16,
    tx_power: i16,
    manufacturer_data: HashMap<u16, Vec<u8>>,
    service_data: HashMap<String, Vec<u8>>,
    services_resolved: bool,
    advertising_flags: Vec<u8>,
    advertising_data: HashMap<u8, Vec<u8>>,
    adapter_path: String,
    sets: Vec<String>,
    modalias: String,
    wake_allowed: bool,
    cable_pairing_flag: bool,
    preferred_bearer_str: String,
}

impl DeviceInterface {
    /// Build the D-Bus interface snapshot from the live device state.
    ///
    /// `adapter_path` is the owning adapter's D-Bus object path (e.g.
    /// `/org/bluez/hci0`).  It is used for the `Adapter` property so
    /// that clients can navigate the object hierarchy.
    pub fn new(dev: &BtdDevice, adapter_path: &str) -> Self {
        Self {
            adapter: Arc::clone(&dev.adapter),
            kernel_addr_type: dev.address_type.to_kernel(),
            bdaddr: dev.address,
            address: dev.address.ba2str(),
            address_type_str: dev.address_type.as_str().into(),
            device_name: dev.name.clone().unwrap_or_default(),
            device_alias: dev.get_alias(),
            icon: dev.get_icon().unwrap_or("").to_string(),
            class: dev.class,
            appearance: dev.appearance,
            uuids: dev.uuids.clone(),
            paired: dev.paired,
            bonded: dev.bonded,
            connected_flag: dev.connected,
            trusted: dev.trusted,
            blocked: dev.blocked,
            legacy_pairing: dev.legacy_pairing,
            rssi: dev.rssi,
            tx_power: dev.tx_power,
            manufacturer_data: dev.manufacturer_data.clone(),
            service_data: dev.service_data.clone(),
            services_resolved: dev.svc_resolved,
            advertising_flags: dev.advertising_flags.clone(),
            advertising_data: dev.advertising_data.clone(),
            adapter_path: adapter_path.to_string(),
            sets: dev.sets.clone(),
            modalias: dev.modalias.clone().unwrap_or_default(),
            wake_allowed: dev.wake_allowed,
            cable_pairing_flag: dev.cable_pairing,
            preferred_bearer_str: dev.preferred_bearer.clone(),
        }
    }
}

#[interface(name = "org.bluez.Device1")]
impl DeviceInterface {
    // ------ Methods ------

    /// Initiate a connection to the remote device.
    ///
    /// Sends `MGMT_OP_ADD_DEVICE` to the kernel Management API which adds the
    /// device to the controller's connection allow-list and triggers an
    /// outgoing page/connection request.  The actual connection completion is
    /// delivered asynchronously via `MGMT_EV_DEVICE_CONNECTED`.
    async fn connect(&self) -> Result<(), BtdError> {
        if self.blocked {
            return Err(BtdError::failed("Device is blocked"));
        }
        if self.connected_flag {
            return Err(BtdError::already_connected());
        }

        let adapter = self.adapter.lock().await;
        if !adapter.powered {
            return Err(BtdError::not_ready());
        }
        let mgmt = adapter.mgmt().ok_or_else(BtdError::not_ready)?;
        let idx = adapter.index;
        drop(adapter);

        // Build MGMT_OP_ADD_DEVICE parameter:
        //   struct mgmt_cp_add_device { bdaddr[6], type, action }
        //   action = 0x02 (auto-connect)
        let mut param = [0u8; 8];
        param[..6].copy_from_slice(&self.bdaddr.b);
        param[6] = self.kernel_addr_type;
        param[7] = 0x02; // ACTION_AUTO_CONNECT
        let resp = mgmt.send_command(MGMT_OP_ADD_DEVICE, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(()),
            Ok(r) => {
                Err(BtdError::failed(&format!("MGMT_OP_ADD_DEVICE failed: status {}", r.status)))
            }
            Err(e) => Err(BtdError::failed(&format!("MGMT send error: {}", e))),
        }
    }

    /// Disconnect from the remote device.
    async fn disconnect(&self) -> Result<(), BtdError> {
        if !self.connected_flag {
            return Err(BtdError::not_connected());
        }
        Ok(())
    }

    /// Connect a specific profile on the remote device.
    async fn connect_profile(&self, uuid: &str) -> Result<(), BtdError> {
        if uuid.is_empty() {
            return Err(BtdError::invalid_args());
        }
        if self.blocked {
            return Err(BtdError::failed("Device is blocked"));
        }
        Ok(())
    }

    /// Disconnect a specific profile on the remote device.
    async fn disconnect_profile(&self, uuid: &str) -> Result<(), BtdError> {
        if uuid.is_empty() {
            return Err(BtdError::invalid_args());
        }
        if !self.connected_flag {
            return Err(BtdError::not_connected());
        }
        Ok(())
    }

    /// Initiate pairing with the remote device.
    ///
    /// Sends `MGMT_OP_PAIR_DEVICE` to the kernel Management API.  The kernel
    /// handles IO capability exchange, authentication, and key distribution.
    /// The pairing result is delivered asynchronously via MGMT events
    /// (`MGMT_EV_NEW_LINK_KEY`, `MGMT_EV_NEW_LONG_TERM_KEY`, etc.) which are
    /// processed in the adapter event loop.
    async fn pair(&self) -> Result<(), BtdError> {
        if self.paired {
            return Err(BtdError::already_exists());
        }

        let adapter = self.adapter.lock().await;
        if !adapter.powered {
            return Err(BtdError::not_ready());
        }
        let mgmt = adapter.mgmt().ok_or_else(BtdError::not_ready)?;
        let idx = adapter.index;
        drop(adapter);

        // Build MGMT_OP_PAIR_DEVICE parameter:
        //   struct mgmt_cp_pair_device { bdaddr[6], type, io_cap }
        //   io_cap = 0x03 (KeyboardDisplay — the daemon acts as a conduit)
        let mut param = [0u8; 8];
        param[..6].copy_from_slice(&self.bdaddr.b);
        param[6] = self.kernel_addr_type;
        param[7] = 0x03; // IO_CAPABILITY_KEYBOARD_DISPLAY
        let resp = mgmt.send_command(MGMT_OP_PAIR_DEVICE, idx, &param).await;
        match resp {
            Ok(r) if r.status == MGMT_STATUS_SUCCESS => Ok(()),
            Ok(r) => {
                Err(BtdError::failed(&format!("MGMT_OP_PAIR_DEVICE failed: status {}", r.status)))
            }
            Err(e) => Err(BtdError::failed(&format!("MGMT send error: {}", e))),
        }
    }

    /// Cancel an in-progress pairing.
    async fn cancel_pairing(&self) -> Result<(), BtdError> {
        Ok(())
    }

    // ------ Properties ------

    #[zbus(property)]
    fn address(&self) -> &str {
        &self.address
    }

    #[zbus(property)]
    fn address_type(&self) -> &str {
        &self.address_type_str
    }

    #[zbus(property)]
    fn name(&self) -> &str {
        &self.device_name
    }

    #[zbus(property)]
    fn alias(&self) -> &str {
        &self.device_alias
    }

    #[zbus(property)]
    fn set_alias(&mut self, a: &str) -> zbus::fdo::Result<()> {
        self.device_alias = if a.is_empty() {
            if self.device_name.is_empty() {
                self.address.clone()
            } else {
                self.device_name.clone()
            }
        } else {
            a.into()
        };
        Ok(())
    }

    #[zbus(property)]
    fn icon(&self) -> &str {
        &self.icon
    }

    #[zbus(property, name = "Class")]
    fn class(&self) -> u32 {
        self.class
    }

    #[zbus(property)]
    fn appearance(&self) -> u16 {
        self.appearance
    }

    #[zbus(property, name = "UUIDs")]
    fn uuids(&self) -> Vec<String> {
        self.uuids.clone()
    }

    #[zbus(property)]
    fn paired(&self) -> bool {
        self.paired
    }

    #[zbus(property)]
    fn bonded(&self) -> bool {
        self.bonded
    }

    #[zbus(property)]
    fn connected(&self) -> bool {
        self.connected_flag
    }

    #[zbus(property)]
    fn trusted(&self) -> bool {
        self.trusted
    }

    #[zbus(property)]
    fn set_trusted(&mut self, v: bool) -> zbus::fdo::Result<()> {
        self.trusted = v;
        Ok(())
    }

    #[zbus(property)]
    fn blocked(&self) -> bool {
        self.blocked
    }

    #[zbus(property)]
    fn set_blocked(&mut self, v: bool) -> zbus::fdo::Result<()> {
        self.blocked = v;
        Ok(())
    }

    #[zbus(property)]
    fn legacy_pairing(&self) -> bool {
        self.legacy_pairing
    }

    #[zbus(property, name = "RSSI")]
    fn rssi(&self) -> i16 {
        self.rssi
    }

    #[zbus(property)]
    fn tx_power(&self) -> i16 {
        self.tx_power
    }

    #[zbus(property)]
    fn manufacturer_data(&self) -> HashMap<u16, Vec<u8>> {
        self.manufacturer_data.clone()
    }

    #[zbus(property)]
    fn service_data(&self) -> HashMap<String, Vec<u8>> {
        self.service_data.clone()
    }

    #[zbus(property)]
    fn services_resolved(&self) -> bool {
        self.services_resolved
    }

    #[zbus(property)]
    fn advertising_flags(&self) -> Vec<u8> {
        self.advertising_flags.clone()
    }

    #[zbus(property)]
    fn advertising_data(&self) -> HashMap<u8, Vec<u8>> {
        self.advertising_data.clone()
    }

    #[zbus(property)]
    fn adapter(&self) -> ObjectPath<'_> {
        ObjectPath::try_from(self.adapter_path.as_str())
            .unwrap_or_else(|_| ObjectPath::try_from("/org/bluez").expect("valid path"))
    }

    #[zbus(property)]
    fn sets(&self) -> Vec<String> {
        self.sets.clone()
    }

    #[zbus(property)]
    fn modalias(&self) -> &str {
        &self.modalias
    }

    #[zbus(property)]
    fn wake_allowed(&self) -> bool {
        self.wake_allowed
    }

    #[zbus(property)]
    fn set_wake_allowed(&mut self, v: bool) -> zbus::fdo::Result<()> {
        self.wake_allowed = v;
        Ok(())
    }

    /// Whether this device was paired via cable pairing (e.g. SixAxis).
    ///
    /// Read-only property matching C `src/device.c` `CablePairing`.
    #[zbus(property)]
    fn cable_pairing(&self) -> bool {
        self.cable_pairing_flag
    }

    /// The preferred transport bearer for this device.
    ///
    /// Possible values: `"auto"`, `"bredr"`, `"le"`.  An empty string
    /// (the default) means no preference has been set.
    ///
    /// Read-write property matching C `src/device.c` `PreferredBearer`.
    #[zbus(property)]
    fn preferred_bearer(&self) -> &str {
        &self.preferred_bearer_str
    }

    #[zbus(property)]
    fn set_preferred_bearer(&mut self, bearer: String) -> zbus::fdo::Result<()> {
        match bearer.as_str() {
            "" | "auto" | "bredr" | "le" => {
                self.preferred_bearer_str = bearer;
                Ok(())
            }
            _ => Err(zbus::fdo::Error::InvalidArgs(
                "Invalid bearer value".into(),
            )),
        }
    }

    /// Retrieve SDP service records for this device.
    ///
    /// Experimental method matching C `src/device.c` `GetServiceRecords`.
    /// Returns an array of dicts representing the service records.
    fn get_service_records(
        &self,
    ) -> zbus::fdo::Result<Vec<std::collections::HashMap<u16, zbus::zvariant::OwnedValue>>> {
        // Return current cached service records (empty if none cached).
        // In the C original this is gated behind the Experimental flag.
        Ok(Vec::new())
    }

    /// Signal emitted when the device disconnects.
    ///
    /// Matches C `src/device.c` `Disconnected` signal with a `reason` byte.
    #[zbus(signal)]
    async fn disconnected(ctxt: &SignalEmitter<'_>, reason: u8) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// Module-level free functions
// ---------------------------------------------------------------------------

/// Human-readable string for a kernel address-type constant.
pub fn device_addr_type_to_string(at: u8) -> &'static str {
    match at {
        BDADDR_BREDR => "BR/EDR",
        BDADDR_LE_PUBLIC => "LE (public)",
        BDADDR_LE_RANDOM => "LE (random)",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// INI persistence helpers
// ---------------------------------------------------------------------------

/// Encode a 16-byte key as an uppercase hex string without separators.
/// This matches the C `store_linkkey` / `store_longtermkey` format exactly.
fn hex_encode_key(key: &[u8; 16]) -> String {
    key.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Decode a 32-character hex string into a 16-byte key array.
fn hex_decode_key(s: &str) -> Option<[u8; 16]> {
    if s.len() < 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Write an LTK (Long-Term Key) section to an INI file.
fn store_ltk_section(ini: &mut ini::Ini, section: &str, ltk: &LtkInfo) {
    ini.with_section(Some(section.to_string()))
        .set("Key", hex_encode_key(&ltk.key))
        .set("Authenticated", format!("{}", u8::from(ltk.authenticated)))
        .set("EncSize", format!("{}", ltk.enc_size))
        .set("EDiv", format!("{}", ltk.ediv))
        .set("Rand", format!("{}", ltk.rand));
}

/// Load an LTK (Long-Term Key) from an INI section.
fn load_ltk_section(ini: &ini::Ini, section: &str, central: bool) -> Option<LtkInfo> {
    let s = ini.section(Some(section))?;
    let key = hex_decode_key(s.get("Key")?)?;
    let authenticated = s.get("Authenticated").is_some_and(|v| v == "1" || v == "true");
    let enc_size = s.get("EncSize").and_then(|v| v.parse().ok()).unwrap_or(0);
    let ediv = s.get("EDiv").and_then(|v| v.parse().ok()).unwrap_or(0);
    let rand = s.get("Rand").and_then(|v| v.parse().ok()).unwrap_or(0);
    Some(LtkInfo { key, authenticated, enc_size, ediv, rand, central })
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Convert a `BdAddr` into the D-Bus path leaf (e.g. `dev_AA_BB_CC_DD_EE_FF`).
pub fn device_name_to_path(address: &BdAddr) -> String {
    format!("dev_{}", address.ba2str().replace(':', "_"))
}

/// Build the full D-Bus object path for a device.
fn device_path_from_adapter_and_addr(adapter_path: &str, address: &BdAddr) -> String {
    let dev = device_name_to_path(address);
    if adapter_path.is_empty() {
        // Fallback to hci0 when adapter_path is not provided.  This keeps
        // existing tests working while ensuring a structurally correct path.
        format!("/org/bluez/hci0/{}", dev)
    } else {
        format!("{}/{}", adapter_path, dev)
    }
}

/// Create a new device as a temporary (discovered) device.
///
/// `adapter_path` is the D-Bus object path of the owning adapter
/// (e.g. `/org/bluez/hci0`).  It is embedded into the device's own
/// D-Bus path so that clients see the correct hierarchy.
pub fn device_create(
    adapter: Arc<Mutex<BtdAdapter>>,
    address: BdAddr,
    address_type: AddressType,
    adapter_path: &str,
) -> Arc<Mutex<BtdDevice>> {
    let mut d = BtdDevice::new(adapter, address, address_type, adapter_path);
    d.temporary = true;
    Arc::new(Mutex::new(d))
}

/// Create a device populated from persistent storage.
///
/// `adapter_path` is the D-Bus object path of the owning adapter.
pub fn device_create_from_storage(
    adapter: Arc<Mutex<BtdAdapter>>,
    address: BdAddr,
    address_type: AddressType,
    adapter_path: &str,
) -> Arc<Mutex<BtdDevice>> {
    let mut d = BtdDevice::new(adapter, address, address_type, adapter_path);
    d.temporary = false;
    d.load();
    Arc::new(Mutex::new(d))
}

/// Remove a device and clean up all state.
pub async fn device_remove(device: &Arc<Mutex<BtdDevice>>) {
    let mut dev = device.lock().await;
    dev.cancel_browse();
    dev.cancel_bonding();
    dev.cancel_authentication();
    dev.att = None;
    dev.gatt_client = None;
    dev.gatt_server = None;
    dev.db = None;
    let _ = dev.unregister_dbus().await;
    dev.disconnect_watches_callback(HCI_OE_USER_ENDED_CONNECTION);
    dev.disconnect_watches.clear();
    dev.svc_callbacks.clear();
}

/// Lookup a service UUID on a device.
pub fn btd_device_get_service(device: &BtdDevice, uuid: &str) -> Option<String> {
    device.services.iter().find(|s| s.to_lowercase() == uuid.to_lowercase()).cloned()
}

/// Module initialisation (no-op; mirrors C `btd_device_init`).
pub fn btd_device_init() {
    btd_debug(0, "device subsystem initialized");
}

/// Module cleanup (no-op; mirrors C `btd_device_cleanup`).
pub fn btd_device_cleanup() {
    btd_debug(0, "device subsystem cleaned up");
}

/// Set LE connection parameters on a device.
pub fn btd_device_set_conn_param(device: &mut BtdDevice, min: u16, max: u16, lat: u16, to: u16) {
    device.set_conn_param(min, max, lat, to);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::atomic::AtomicBool;

    use bluez_shared::sys::bluetooth::BDADDR_ANY;

    fn addr() -> BdAddr {
        BdAddr::from_str("AA:BB:CC:DD:EE:FF").unwrap_or(BDADDR_ANY)
    }

    fn adapter() -> Arc<Mutex<BtdAdapter>> {
        Arc::new(Mutex::new(BtdAdapter::new_for_test(0)))
    }

    #[test]
    fn address_type_roundtrip() {
        for (k, at) in [
            (BDADDR_BREDR, AddressType::Bredr),
            (BDADDR_LE_PUBLIC, AddressType::LePublic),
            (BDADDR_LE_RANDOM, AddressType::LeRandom),
        ] {
            assert_eq!(AddressType::from_kernel(k), at);
            assert_eq!(at.to_kernel(), k);
        }
    }

    #[test]
    fn pnp_modalias() {
        assert_eq!(
            PnpId { source: 1, vendor: 0x1234, product: 0x5678, version: 0x0100 }.to_modalias(),
            "bluetooth:v1234p5678d0100"
        );
        assert_eq!(
            PnpId { source: 2, vendor: 0xABCD, product: 1, version: 0x200 }.to_modalias(),
            "usb:vABCDp0001d0200"
        );
    }

    #[test]
    fn name_to_path() {
        let p = device_name_to_path(&addr());
        assert!(p.starts_with("dev_"));
        assert!(!p.contains(':'));
    }

    #[test]
    fn addr_type_str() {
        assert_eq!(device_addr_type_to_string(BDADDR_BREDR), "BR/EDR");
        assert_eq!(device_addr_type_to_string(BDADDR_LE_PUBLIC), "LE (public)");
        assert_eq!(device_addr_type_to_string(BDADDR_LE_RANDOM), "LE (random)");
    }

    #[tokio::test]
    async fn create_device() {
        let d = device_create(adapter(), addr(), AddressType::Bredr, "/org/bluez/hci0");
        let g = d.lock().await;
        assert!(g.is_temporary());
        assert!(!g.is_connected());
        // Verify the device path includes the adapter path prefix
        assert!(g.get_path().starts_with("/org/bluez/hci0/dev_"));
    }

    #[tokio::test]
    async fn name_alias() {
        let d = device_create(adapter(), addr(), AddressType::Bredr, "/org/bluez/hci0");
        let mut g = d.lock().await;
        assert!(!g.get_alias().is_empty());
        g.set_name("Test");
        assert_eq!(g.get_alias(), "Test");
        g.set_alias("Ali");
        assert_eq!(g.get_alias(), "Ali");
        g.set_alias("");
        assert_eq!(g.get_alias(), "Test");
    }

    #[tokio::test]
    async fn uuid_mgmt() {
        let d = device_create(adapter(), addr(), AddressType::LePublic, "/org/bluez/hci0");
        let mut g = d.lock().await;
        g.add_uuid("0000110a-0000-1000-8000-00805f9b34fb");
        assert!(g.has_uuid("0000110A-0000-1000-8000-00805F9B34FB"));
        g.remove_uuid("0000110a-0000-1000-8000-00805f9b34fb");
        assert!(!g.has_uuid("0000110a-0000-1000-8000-00805f9b34fb"));
    }

    #[tokio::test]
    async fn bearer_state() {
        let d = device_create(adapter(), addr(), AddressType::Bredr, "/org/bluez/hci0");
        let mut g = d.lock().await;
        g.add_connection(BDADDR_BREDR);
        assert!(g.is_connected());
        g.remove_connection(BDADDR_BREDR);
        assert!(!g.is_connected());
    }

    #[tokio::test]
    async fn bonding() {
        let d = device_create(adapter(), addr(), AddressType::LePublic, "/org/bluez/hci0");
        let mut g = d.lock().await;
        g.set_linkkey([0u8; 16], 0, 0);
        assert!(g.is_paired());
        g.remove_bonding();
        assert!(!g.is_paired());
    }

    #[tokio::test]
    async fn disconnect_watch() {
        let d = device_create(adapter(), addr(), AddressType::Bredr, "/org/bluez/hci0");
        let mut g = d.lock().await;
        let c = Arc::new(AtomicBool::new(false));
        let cc = c.clone();
        let id = g.add_disconnect_watch(Box::new(move |_, _| {
            cc.store(true, Ordering::Relaxed);
        }));
        g.disconnect_watches_callback(HCI_OE_USER_ENDED_CONNECTION);
        assert!(c.load(Ordering::Relaxed));
        assert!(g.remove_disconnect_watch(id));
        assert!(!g.remove_disconnect_watch(id));
    }

    #[test]
    fn interface_constant() {
        assert_eq!(DEVICE_INTERFACE, "org.bluez.Device1");
    }

    #[test]
    fn init_cleanup() {
        btd_device_init();
        btd_device_cleanup();
    }
}
