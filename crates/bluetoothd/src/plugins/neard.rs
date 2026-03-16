// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2012–2013  Intel Corporation
//
// NFC pairing bridge plugin — Rust rewrite of `plugins/neard.c` (897 lines).
//
// Exports `org.neard.HandoverAgent` for Bluetooth NFC handover / OOB pairing
// with the neard daemon.  Watches for the `org.neard` D-Bus service and
// registers / unregisters the handover agent accordingly.
//
// The agent supports:
//
// - **RequestOOB** — Parse incoming OOB data (standard EIR or Nokia
//   `nokia.com:bt` proprietary format), initiate OOB pairing, and return
//   local OOB data to the remote NFC peer.
// - **PushOOB** — Parse incoming OOB data and initiate pairing without
//   returning local OOB data.
// - **Release** — Handle agent release notification from neard.
//
// ## Plugin registration
//
// Registered via `inventory::submit!` with `PluginPriority::Default` (0),
// matching C's `BLUETOOTH_PLUGIN_DEFINE(neard, VERSION,
// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, neard_init, neard_exit)`.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, error, info, warn};
use zbus::zvariant::{OwnedValue, Value};

use bluez_shared::sys::bluetooth::{BDADDR_ANY, BDADDR_BREDR, BdAddr, bdaddr_t};
use bluez_shared::util::eir::{EirData, EirOobParams, eir_create_oob, eir_parse_oob};

use crate::adapter::{
    BtdAdapter, OobHandler, adapter_create_bonding, btd_adapter_add_remote_oob_data,
    btd_adapter_check_oob_handler, btd_adapter_get_address, btd_adapter_get_class,
    btd_adapter_get_connectable, btd_adapter_get_default, btd_adapter_get_device,
    btd_adapter_get_name, btd_adapter_get_pairable, btd_adapter_get_powered,
    btd_adapter_get_services, btd_adapter_read_local_oob_data, btd_adapter_set_oob_handler,
    btd_adapter_ssp_enabled,
};
use crate::agent::{agent_get, agent_get_io_capability};
use crate::dbus_common::btd_get_dbus_connection;
use crate::device::{AddressType, BtdDevice};
use crate::plugin::{BluetoothPlugin, PluginPriority};

// ===========================================================================
// Constants (from C lines 35–48)
// ===========================================================================

/// D-Bus well-known name of the neard daemon.
const NEARD_NAME: &str = "org.neard";

/// D-Bus object path of the neard Manager interface.
const NEARD_PATH: &str = "/";

/// D-Bus interface name for the neard Manager.
const NEARD_MANAGER_INTERFACE: &str = "org.neard.Manager";

/// D-Bus interface name for the NFC handover agent.
#[allow(dead_code)]
const AGENT_INTERFACE: &str = "org.neard.HandoverAgent";

/// D-Bus object path where our handover agent is registered.
const AGENT_PATH: &str = "/org/bluez/neard_handover_agent";

/// Carrier type string for Bluetooth NFC handover.
const AGENT_CARRIER_TYPE: &str = "bluetooth";

/// D-Bus error interface prefix for handover agent errors.
const ERROR_INTERFACE: &str = "org.neard.HandoverAgent.Error";

/// Maximum EIR data length for NFC OOB (matches UINT8_MAX in C).
#[allow(dead_code)]
const NFC_OOB_EIR_MAX: usize = 255;

// ===========================================================================
// Nokia NFC BT record type constants (from C lines 42–48)
// ===========================================================================

/// Nokia NFC record type "long format": includes CoD, hash, name.
const NOKIA_BT_TYPE_LONG: u8 = 0x02;

/// Nokia NFC record type "short format": includes CoD and name.
const NOKIA_BT_TYPE_SHORT: u8 = 0x01;

/// Nokia NFC record type "extra-short format": address-only.
const NOKIA_BT_TYPE_EXTRA_SHORT: u8 = 0x04;

// ===========================================================================
// Connection Power State enum (from C lines 50–55)
// ===========================================================================

/// Connection Power State — indicates whether the device is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cps {
    /// Device is active and ready.
    Active,
    /// Device is inactive / powered down.
    Inactive,
    /// Device is transitioning to active.
    Activating,
    /// Connection power state is unknown.
    Unknown,
}

impl Cps {
    /// Parse from the D-Bus "State" string value.
    fn from_str_val(s: &str) -> Self {
        match s {
            "active" => Cps::Active,
            "inactive" => Cps::Inactive,
            "activating" => Cps::Activating,
            _ => Cps::Unknown,
        }
    }
}

// ===========================================================================
// OobParams — parsed NFC OOB parameters (from C lines 57–67)
// ===========================================================================

/// Parsed out-of-band pairing parameters extracted from neard D-Bus method
/// calls.  Replaces C `struct oob_params` with owned Rust types.
#[derive(Debug, Clone)]
struct OobParams {
    /// Bluetooth address of the remote device.
    address: BdAddr,
    /// Class of Device (3-byte packed value).
    class: u32,
    /// Optional device name.
    name: Option<String>,
    /// List of discovered service UUID strings.
    services: Vec<String>,
    /// SSP Hash C-192 (16 bytes), if present.
    hash: Option<Vec<u8>>,
    /// SSP Randomizer R-192 (16 bytes), if present.
    randomizer: Option<Vec<u8>>,
    /// PIN code (for legacy pairing), if present.
    #[allow(dead_code)]
    pin: Option<Vec<u8>>,
    /// Connection power state.
    power_state: Cps,
}

impl Default for OobParams {
    fn default() -> Self {
        Self {
            address: BDADDR_ANY,
            class: 0,
            name: None,
            services: Vec::new(),
            hash: None,
            randomizer: None,
            pin: None,
            power_state: Cps::Unknown,
        }
    }
}

// ===========================================================================
// Module-level shared state (replaces C file-scope globals)
// ===========================================================================

/// Module-level state protected by a tokio Mutex for safe async access.
#[derive(Default)]
struct NeardState {
    /// Current neard D-Bus unique name (`:1.xx`), or `None` if neard is absent.
    neard_service: Option<String>,
    /// Whether the next `RegisterHandoverAgent` call should omit the carrier
    /// type argument (compatibility with older neard versions).
    agent_register_postpone: bool,
    /// Handle to the background task that watches neard service
    /// appearance / disappearance.
    watcher_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Lazily initialised module state.  Populated by `neard_init()`.
static STATE: std::sync::OnceLock<Arc<tokio::sync::Mutex<NeardState>>> = std::sync::OnceLock::new();

/// Helper: obtain a reference to the shared state.
fn get_state() -> &'static Arc<tokio::sync::Mutex<NeardState>> {
    STATE.get().expect("neard plugin not initialised")
}

// ===========================================================================
// Error mapping (from C lines 78–110)
// ===========================================================================

/// Map a `nix::errno::Errno` code to a D-Bus error name under the
/// `org.neard.HandoverAgent.Error.*` namespace.
fn neard_error_name(err: nix::errno::Errno) -> String {
    let suffix = match err {
        nix::errno::Errno::ENOTSUP => "NotSupported",
        nix::errno::Errno::ENOENT | nix::errno::Errno::ESRCH | nix::errno::Errno::ENONET => {
            "NotFound"
        }
        nix::errno::Errno::EINVAL => "InvalidArguments",
        nix::errno::Errno::EALREADY => "AlreadyExists",
        nix::errno::Errno::EINPROGRESS => "InProgress",
        _ => "Failed",
    };
    format!("{ERROR_INTERFACE}.{suffix}")
}

/// Build a `zbus::fdo::Error` from a `nix::errno::Errno`.
fn error_reply(err: nix::errno::Errno, msg: &str) -> zbus::fdo::Error {
    let name = neard_error_name(err);
    // Use ZBus generic error with the proper name.
    zbus::fdo::Error::ZBus(zbus::Error::Failure(format!("{name}: {msg}")))
}

// ===========================================================================
// Nokia NFC proprietary format parsing (from C lines 366–495)
// ===========================================================================

/// Parse the Nokia "long" BT record format (`type == 0x02`).
///
/// The `payload` slice starts AFTER the 4-byte header (version[1] + dlen[2] +
/// type[1]) — i.e. it begins with the BD_ADDR.  Layout:
///   [0..6]  BD_ADDR (6 bytes, big-endian → byte-swapped)
///   [6..9]  Class of Device (3 bytes, little-endian packed)
///   [9]     Authentication hash length (1 byte)
///   [10..]  Hash bytes, then name length (1 byte) + name bytes
///
/// Matches C `process_nokia_long()` (lines 386–426).
fn process_nokia_long(payload: &[u8], params: &mut OobParams) {
    // Need at least 6 (addr) + 3 (cod) = 9 bytes.
    if payload.len() < 9 {
        debug!("Nokia long format: too short for addr + CoD");
        return;
    }

    // BD_ADDR — byte-swapped (Nokia uses big-endian address order).
    let raw_addr =
        bdaddr_t { b: [payload[0], payload[1], payload[2], payload[3], payload[4], payload[5]] };
    params.address = raw_addr.baswap();

    // Class of Device — 3 bytes at offset 6, little-endian packed.
    params.class =
        u32::from(payload[6]) | (u32::from(payload[7]) << 8) | (u32::from(payload[8]) << 16);

    let mut offset: usize = 9;

    // Authentication hash (variable length).
    if offset < payload.len() {
        let hash_len = payload[offset] as usize;
        offset += 1;
        if hash_len > 0 && offset + hash_len <= payload.len() {
            params.hash = Some(payload[offset..offset + hash_len].to_vec());
            offset += hash_len;
            debug!("Nokia long: hash len {}", hash_len);
        }
    }

    // Name (variable length).
    if offset < payload.len() {
        let name_len = payload[offset] as usize;
        offset += 1;
        if name_len > 0 && offset + name_len <= payload.len() {
            if let Ok(name) = std::str::from_utf8(&payload[offset..offset + name_len]) {
                params.name = Some(name.to_owned());
                debug!("Nokia long: name \"{}\"", name);
            }
        }
    }
}

/// Parse the Nokia "short" BT record format (`type == 0x01`).
///
/// Payload starts after the header.  Layout:
///   [0..6]  BD_ADDR   [6..9] CoD   [9] name_len   [10..] name
///
/// Matches C `process_nokia_short()` (lines 428–461).
fn process_nokia_short(payload: &[u8], params: &mut OobParams) {
    if payload.len() < 9 {
        debug!("Nokia short format: too short for addr + CoD");
        return;
    }

    let raw_addr =
        bdaddr_t { b: [payload[0], payload[1], payload[2], payload[3], payload[4], payload[5]] };
    params.address = raw_addr.baswap();

    params.class =
        u32::from(payload[6]) | (u32::from(payload[7]) << 8) | (u32::from(payload[8]) << 16);

    let mut offset: usize = 9;

    // Name (variable length).
    if offset < payload.len() {
        let name_len = payload[offset] as usize;
        offset += 1;
        if name_len > 0 && offset + name_len <= payload.len() {
            if let Ok(name) = std::str::from_utf8(&payload[offset..offset + name_len]) {
                params.name = Some(name.to_owned());
                debug!("Nokia short: name \"{}\"", name);
            }
        }
    }
}

/// Parse the Nokia "extra-short" BT record format (`type == 0x04`).
///
/// Contains only the BD_ADDR (6 bytes) — no class, name, or hash.
/// Payload starts after the header.
///
/// Matches C `process_nokia_extra_short()` (lines 463–477).
fn process_nokia_extra_short(payload: &[u8], params: &mut OobParams) {
    if payload.len() < 6 {
        debug!("Nokia extra-short format: too short");
        return;
    }

    let raw_addr =
        bdaddr_t { b: [payload[0], payload[1], payload[2], payload[3], payload[4], payload[5]] };
    params.address = raw_addr.baswap();
}

/// Top-level Nokia `nokia.com:bt` parser.
///
/// Reads the 4-byte header (version[1] + dlen[2] + type[1]) and dispatches
/// to long / short / extra-short based on the type byte.
///
/// Matches C `process_nokia_com_bt()` (lines 479–495).
fn process_nokia_com_bt(data: &[u8], params: &mut OobParams) {
    // Header: version(1) + dlen(2) + type(1) = 4 bytes minimum.
    if data.len() < 4 {
        debug!("Nokia BT record: too short for header");
        return;
    }

    let _version = data[0];
    let dlen = u16::from_le_bytes([data[1], data[2]]) as usize;
    let record_type = data[3];

    debug!("Nokia BT record: version={}, dlen={}, type=0x{:02x}", _version, dlen, record_type);

    // dlen includes the type byte; payload starts at byte 4.
    if data.len() < 4 + dlen.saturating_sub(1) {
        debug!("Nokia BT record: truncated payload");
        return;
    }

    // Payload is everything after the header.
    let payload = &data[4..];

    match record_type {
        NOKIA_BT_TYPE_LONG => process_nokia_long(payload, params),
        NOKIA_BT_TYPE_SHORT => process_nokia_short(payload, params),
        NOKIA_BT_TYPE_EXTRA_SHORT => process_nokia_extra_short(payload, params),
        _ => {
            warn!("Unknown Nokia BT record type: 0x{:02x}", record_type);
        }
    }
}

// ===========================================================================
// EIR OOB data parsing wrapper (from C lines 334–364)
// ===========================================================================

/// Parse standard EIR OOB data and populate `OobParams`.
///
/// Wraps `eir_parse_oob()` and copies the parsed fields into the params
/// struct.  Matches C `process_eir()` (lines 334–364).
fn process_eir(data: &[u8], params: &mut OobParams) -> bool {
    match eir_parse_oob(data) {
        Ok(eir) => {
            params.address = bdaddr_t { b: eir.addr };
            params.class = eir.class;
            params.name = eir.name.clone();
            params.services = eir.services.clone();
            params.hash = eir.hash.clone();
            params.randomizer = eir.randomizer.clone();
            debug!(
                "EIR OOB: addr={} class=0x{:06x} name={:?}",
                params.address.ba2str(),
                params.class,
                params.name
            );
            true
        }
        Err(e) => {
            error!("Failed to parse EIR OOB data: {}", e);
            false
        }
    }
}

// ===========================================================================
// D-Bus dictionary parsing (from C lines 497–608)
// ===========================================================================

/// Parse the `State` value from the neard handover properties.
///
/// Matches C `process_state()` (lines 497–513).
fn process_state(val: &str, params: &mut OobParams) {
    params.power_state = Cps::from_str_val(val);
    debug!("Connection power state: {:?}", params.power_state);
}

/// Parse the full D-Bus `a{sv}` dictionary from a neard HandoverAgent method
/// call.
///
/// Recognised keys:
/// - `"EIR"` — Standard EIR OOB data blob (`ay`).
/// - `"nokia.com:bt"` — Nokia proprietary NFC BT handover format (`ay`).
/// - `"State"` — Connection power state string (`s`).
///
/// Matches C `process_message()` (lines 515–608).
fn process_message(
    properties: &HashMap<String, OwnedValue>,
    params: &mut OobParams,
) -> Result<(), nix::errno::Errno> {
    let mut has_eir = false;
    let mut has_nokia = false;

    for (key, value) in properties {
        match key.as_str() {
            "EIR" => {
                if let Ok(data) = <Vec<u8>>::try_from(value.clone()) {
                    debug!("Found EIR key ({} bytes)", data.len());
                    if process_eir(&data, params) {
                        has_eir = true;
                    }
                } else {
                    debug!("EIR key: failed to extract byte array");
                }
            }
            "nokia.com:bt" => {
                if let Ok(data) = <Vec<u8>>::try_from(value.clone()) {
                    debug!("Found nokia.com:bt key ({} bytes)", data.len());
                    process_nokia_com_bt(&data, params);
                    has_nokia = true;
                } else {
                    debug!("nokia.com:bt key: failed to extract byte array");
                }
            }
            "State" => {
                if let Ok(s) = <String>::try_from(value.clone()) {
                    process_state(&s, params);
                }
            }
            other => {
                debug!("Ignoring unknown OOB property: {}", other);
            }
        }
    }

    if !has_eir && !has_nokia {
        error!("No EIR or Nokia OOB data found in properties");
        return Err(nix::errno::Errno::EINVAL);
    }

    if params.address == BDADDR_ANY {
        error!("OOB data did not contain a valid BD_ADDR");
        return Err(nix::errno::Errno::EINVAL);
    }

    Ok(())
}

// ===========================================================================
// Adapter helpers (from C lines 610–648)
// ===========================================================================

/// Check that the default adapter is available, powered, and connectable.
///
/// Matches C `check_adapter()` (lines 610–625).
async fn check_adapter() -> Result<Arc<tokio::sync::Mutex<BtdAdapter>>, nix::errno::Errno> {
    let adapter = btd_adapter_get_default().await.ok_or(nix::errno::Errno::ENONET)?;

    let powered = btd_adapter_get_powered(&adapter).await;
    if !powered {
        return Err(nix::errno::Errno::ENONET);
    }

    let connectable = btd_adapter_get_connectable(&adapter).await;
    if !connectable {
        debug!("Adapter not connectable — NFC handover may fail");
    }

    Ok(adapter)
}

/// Store parsed OOB parameters on the adapter/device.
///
/// Creates the device entry via `btd_adapter_get_device`, sets Class of
/// Device, name, and service UUIDs from the OOB data, then adds remote OOB
/// data so the subsequent bonding attempt can use it.
///
/// Matches C `store_params()` (lines 627–648).
async fn store_params(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>, params: &OobParams) {
    // Ensure the device is known to the adapter.
    let _dev_addr = btd_adapter_get_device(adapter, &params.address, BDADDR_BREDR).await;

    // Construct a temporary BtdDevice to apply OOB-sourced metadata.
    let mut device = BtdDevice::new(Arc::clone(adapter), params.address, AddressType::Bredr);

    // Set Class of Device from OOB data.
    if params.class != 0 {
        device.set_class(params.class);
    }

    // Set the device name from OOB data.
    if let Some(ref name) = params.name {
        device.set_name(name);
        device.store_cached_name();
    }

    // Add service UUIDs discovered from OOB EIR data.
    if !params.services.is_empty() {
        let eir_for_uuids = EirData { services: params.services.clone(), ..EirData::default() };
        device.add_eir_uuids(&eir_for_uuids);
    }

    // Retrieve device address for logging.
    let dev_addr = device.get_address();
    debug!("Stored OOB params for device {}", dev_addr.ba2str());

    // Add remote OOB data (hash + randomizer concatenated as flat bytes).
    if let Some(ref hash) = params.hash {
        let mut oob_data = hash.clone();
        if let Some(ref rand) = params.randomizer {
            oob_data.extend_from_slice(rand);
        }
        if let Err(e) = btd_adapter_add_remote_oob_data(adapter, &params.address, &oob_data).await {
            error!("Failed to add remote OOB data: {}", e);
        }
    }
}

// ===========================================================================
// Bonding helpers (from C lines 251–332)
// ===========================================================================

/// Initiate OOB pairing with the remote device.
///
/// Checks device-level state (already paired, bonding in progress), verifies
/// adapter pairability, retrieves the agent IO capability, sets up the OOB
/// handler, and calls `adapter_create_bonding`.  Treats `EALREADY` (already
/// paired) as success.
///
/// Matches C `create_paired_device()` + `bonding_complete()` (lines 251–332).
async fn create_paired_device(
    adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>,
    params: &OobParams,
) -> Result<(), nix::errno::Errno> {
    // Construct a BtdDevice to query pairing/bonding state.
    let device = BtdDevice::new(Arc::clone(adapter), params.address, AddressType::Bredr);

    // Skip if the device is already paired.
    if device.is_paired() {
        info!("Device {} is already paired, skipping OOB bonding", params.address.ba2str());
        return Ok(());
    }

    // Skip if bonding is already in progress.
    if device.is_bonding() {
        debug!("Device {} bonding already in progress", params.address.ba2str());
        return Err(nix::errno::Errno::EINPROGRESS);
    }

    // Verify the adapter is pairable.
    let pairable = btd_adapter_get_pairable(adapter).await;
    if !pairable {
        warn!("Adapter not pairable — OOB bonding may be rejected");
    }

    // Check whether an OOB handler is already active.
    if btd_adapter_check_oob_handler(adapter).await {
        debug!("OOB handler already active — replacing");
    }

    // Set up the OOB handler for async completion callbacks.
    let oob_handler = OobHandler {
        read_local_cb: None,
        bonding_cb: Some(Box::new(|success| {
            if success {
                info!("NFC OOB bonding completed successfully (callback)");
            } else {
                error!("NFC OOB bonding failed (callback)");
            }
        })),
        remote_addr: params.address,
    };
    btd_adapter_set_oob_handler(adapter, oob_handler).await;

    // Get IO capability from the default agent.
    let io_cap: u8 = if let Some(agent) = agent_get(None).await {
        agent_get_io_capability(&agent) as u8
    } else {
        // NoInputNoOutput as fallback (0x03).
        0x03
    };

    match adapter_create_bonding(adapter, &params.address, BDADDR_BREDR, io_cap).await {
        Ok(()) => {
            info!("OOB bonding succeeded for {}", params.address.ba2str());
            Ok(())
        }
        Err(e) => {
            let err_str = e.to_string();
            // Treat "already paired" as success.
            if err_str.contains("AlreadyExists") || err_str.contains("Already") {
                info!("Device {} is already paired, treating as success", params.address.ba2str());
                Ok(())
            } else {
                error!("OOB bonding failed for {}: {}", params.address.ba2str(), e);
                Err(nix::errno::Errno::EIO)
            }
        }
    }
}

/// Build the local OOB reply dictionary.
///
/// Reads local OOB data from the adapter and constructs an EIR blob
/// containing the local adapter address, class, name, Device ID information,
/// service UUIDs, and SSP hash/randomizer.
///
/// Matches C `create_request_oob_reply()` (lines 196–249).
async fn create_request_oob_reply(
    adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>,
) -> Result<HashMap<String, OwnedValue>, nix::errno::Errno> {
    let addr = btd_adapter_get_address(adapter).await;
    let name = btd_adapter_get_name(adapter).await;
    let class = btd_adapter_get_class(adapter).await;
    let services = btd_adapter_get_services(adapter).await;
    let ssp = btd_adapter_ssp_enabled(adapter).await;

    // Read local OOB data only if SSP is available.
    let local_oob = if ssp {
        btd_adapter_read_local_oob_data(adapter).await.map_err(|e| {
            error!("Failed to read local OOB data: {}", e);
            nix::errno::Errno::EIO
        })?
    } else {
        debug!("SSP not enabled — no local OOB hash/randomizer available");
        Vec::new()
    };

    // Build UUID string list from adapter services.
    let uuids: Vec<String> = services.iter().map(|rec| format!("{:08x}", rec.handle)).collect();

    // Parse hash and randomizer from MGMT response.
    // MGMT_OP_READ_LOCAL_OOB_DATA returns: hash_192[16] + randomizer_192[16].
    let (hash, randomizer) = if local_oob.len() >= 32 {
        (Some(&local_oob[0..16]), Some(&local_oob[16..32]))
    } else {
        (None, None)
    };

    // Device ID fields — zero defaults (DID not globally accessible here).
    let oob_params = EirOobParams {
        addr: &addr.b,
        name: if name.is_empty() { None } else { Some(&name) },
        cod: class,
        hash,
        randomizer,
        did_vendor: 0,
        did_product: 0,
        did_version: 0,
        did_source: 0,
        uuids: &uuids,
    };

    let eir_data = eir_create_oob(&oob_params);

    let mut reply: HashMap<String, OwnedValue> = HashMap::new();
    reply.insert(
        "EIR".to_string(),
        OwnedValue::try_from(Value::from(eir_data)).expect("byte array to OwnedValue"),
    );

    Ok(reply)
}

// ===========================================================================
// D-Bus Interface — org.neard.HandoverAgent (from C lines 650–831)
// ===========================================================================

/// The NFC handover agent D-Bus object.
///
/// Registered at [`AGENT_PATH`] when neard appears on the bus.
struct HandoverAgent;

#[zbus::interface(name = "org.neard.HandoverAgent")]
impl HandoverAgent {
    /// Handle a RequestOOB call from neard.
    ///
    /// Parses incoming OOB data, initiates bonding, and returns local OOB data.
    ///
    /// Matches C `request_oob()` (lines 733–804).
    async fn request_oob(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        properties: HashMap<String, OwnedValue>,
    ) -> Result<HashMap<String, OwnedValue>, zbus::fdo::Error> {
        debug!("RequestOOB called");

        authorize_sender(&header).await?;

        let adapter = check_adapter().await.map_err(|e| error_reply(e, "Adapter not available"))?;

        let mut params = OobParams::default();
        process_message(&properties, &mut params)
            .map_err(|e| error_reply(e, "Failed to parse OOB properties"))?;

        store_params(&adapter, &params).await;

        if params.address != BDADDR_ANY {
            if let Err(e) = create_paired_device(&adapter, &params).await {
                warn!("RequestOOB bonding attempt failed: {:?}", e);
            }
        }

        create_request_oob_reply(&adapter)
            .await
            .map_err(|e| error_reply(e, "Failed to build OOB reply"))
    }

    /// Handle a PushOOB call from neard.
    ///
    /// Parses incoming OOB data and initiates bonding.
    ///
    /// Matches C `push_oob()` (lines 650–731).
    async fn push_oob(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        properties: HashMap<String, OwnedValue>,
    ) -> Result<(), zbus::fdo::Error> {
        debug!("PushOOB called");

        authorize_sender(&header).await?;

        let adapter = check_adapter().await.map_err(|e| error_reply(e, "Adapter not available"))?;

        let mut params = OobParams::default();
        process_message(&properties, &mut params)
            .map_err(|e| error_reply(e, "Failed to parse OOB properties"))?;

        store_params(&adapter, &params).await;

        if params.address != BDADDR_ANY {
            create_paired_device(&adapter, &params)
                .await
                .map_err(|e| error_reply(e, "Bonding failed"))?;
        } else {
            return Err(error_reply(nix::errno::Errno::EINVAL, "No valid address in OOB data"));
        }

        Ok(())
    }

    /// Handle agent release notification from neard.
    ///
    /// Matches C `release()` (lines 806–818).
    async fn release(&self) {
        info!("HandoverAgent released by neard");
    }
}

// ===========================================================================
// Sender authorisation
// ===========================================================================

/// Verify that the D-Bus method caller is the current neard service owner.
async fn authorize_sender(header: &zbus::message::Header<'_>) -> Result<(), zbus::fdo::Error> {
    let state = get_state().lock().await;

    if let Some(ref neard_name) = state.neard_service {
        if let Some(sender) = header.sender() {
            if sender.as_str() != neard_name.as_str() {
                error!("Rejecting request from {} (expected {})", sender, neard_name);
                return Err(zbus::fdo::Error::AccessDenied(
                    "Not the neard service owner".to_string(),
                ));
            }
        }
    }

    Ok(())
}

// ===========================================================================
// Agent registration / unregistration (from C lines 90–194)
// ===========================================================================

/// Register the handover agent with the neard Manager.
///
/// First tries `RegisterHandoverAgent(path, carrier_type)`.  If neard returns
/// `UnknownMethod`, falls back to `RegisterHandoverAgent(path)`.
///
/// Matches C `register_agent()` + `register_agent_cb()` (lines 90–163).
async fn register_agent(conn: &zbus::Connection) {
    let state_ref = get_state();

    // Register the HandoverAgent object on our side first.
    if let Err(e) = conn.object_server().at(AGENT_PATH, HandoverAgent).await {
        debug!("HandoverAgent object at {}: {}", AGENT_PATH, e);
    }

    let postpone = {
        let s = state_ref.lock().await;
        s.agent_register_postpone
    };

    let proxy = match zbus::Proxy::new(conn, NEARD_NAME, NEARD_PATH, NEARD_MANAGER_INTERFACE).await
    {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to create neard Manager proxy: {}", e);
            return;
        }
    };

    if !postpone {
        let result: Result<(), zbus::Error> =
            proxy.call("RegisterHandoverAgent", &(AGENT_PATH, AGENT_CARRIER_TYPE)).await;

        match result {
            Ok(()) => {
                info!("Registered handover agent at {} (with carrier type)", AGENT_PATH);
                return;
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("UnknownMethod")
                    || err_str.contains("unknown method")
                    || err_str.contains("No such method")
                {
                    warn!(
                        "RegisterHandoverAgent with carrier type not supported, \
                         falling back to legacy call"
                    );
                    let mut s = state_ref.lock().await;
                    s.agent_register_postpone = true;
                } else {
                    error!("RegisterHandoverAgent failed: {}", e);
                    return;
                }
            }
        }
    }

    let result: Result<(), zbus::Error> = proxy.call("RegisterHandoverAgent", &(AGENT_PATH,)).await;

    match result {
        Ok(()) => {
            info!("Registered handover agent at {} (legacy)", AGENT_PATH);
        }
        Err(e) => {
            error!("RegisterHandoverAgent (legacy) failed: {}", e);
        }
    }
}

/// Unregister the handover agent from the neard Manager.
///
/// Matches C `unregister_agent()` (lines 165–194).
async fn unregister_agent(conn: &zbus::Connection) {
    let state_ref = get_state();
    let postpone = {
        let s = state_ref.lock().await;
        s.agent_register_postpone
    };

    let proxy = match zbus::Proxy::new(conn, NEARD_NAME, NEARD_PATH, NEARD_MANAGER_INTERFACE).await
    {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to create neard Manager proxy for unregister: {}", e);
            return;
        }
    };

    if !postpone {
        let result: Result<(), zbus::Error> =
            proxy.call("UnregisterHandoverAgent", &(AGENT_PATH, AGENT_CARRIER_TYPE)).await;

        match result {
            Ok(()) => {
                info!("Unregistered handover agent (with carrier type)");
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("UnknownMethod")
                    || err_str.contains("unknown method")
                    || err_str.contains("No such method")
                {
                    warn!(
                        "UnregisterHandoverAgent with carrier type not supported, \
                         trying legacy"
                    );
                    let mut s = state_ref.lock().await;
                    s.agent_register_postpone = true;
                } else {
                    error!("UnregisterHandoverAgent failed: {}", e);
                    return;
                }
            }
        }
    }

    if postpone || {
        let s = state_ref.lock().await;
        s.agent_register_postpone
    } {
        let result: Result<(), zbus::Error> =
            proxy.call("UnregisterHandoverAgent", &(AGENT_PATH,)).await;

        match result {
            Ok(()) => {
                info!("Unregistered handover agent (legacy)");
            }
            Err(e) => {
                error!("UnregisterHandoverAgent (legacy) failed: {}", e);
            }
        }
    }

    let _ = conn.object_server().remove::<HandoverAgent, _>(AGENT_PATH).await;
}

// ===========================================================================
// Neard service watch (from C lines 833–870)
// ===========================================================================

/// Called when the neard D-Bus service appears on the bus.
///
/// Matches C `neard_appeared()` (lines 833–851).
async fn neard_appeared(conn: &zbus::Connection, name: &str) {
    info!("neard service appeared: {}", name);

    {
        let mut s = get_state().lock().await;
        s.neard_service = Some(name.to_owned());
    }

    register_agent(conn).await;
}

/// Called when the neard D-Bus service vanishes from the bus.
///
/// Matches C `neard_vanished()` (lines 853–870).
async fn neard_vanished(conn: &zbus::Connection) {
    info!("neard service vanished");

    let had_service = {
        let mut s = get_state().lock().await;
        let had = s.neard_service.is_some();
        s.neard_service = None;
        had
    };

    if had_service {
        let _ = conn.object_server().remove::<HandoverAgent, _>(AGENT_PATH).await;
    }
}

/// Background task that monitors neard service name ownership changes.
///
/// Replaces C's `g_dbus_add_service_watch()` with a zbus
/// `NameOwnerChanged` signal subscription.
async fn neard_service_watch(conn: zbus::Connection) {
    use futures::StreamExt;

    let dbus_proxy = match zbus::fdo::DBusProxy::new(&conn).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to create D-Bus proxy for service watch: {}", e);
            return;
        }
    };

    // Check if neard is already running.
    if let Ok(owner) = dbus_proxy.get_name_owner(NEARD_NAME.try_into().unwrap()).await {
        neard_appeared(&conn, owner.as_str()).await;
    } else {
        debug!("neard not currently running");
    }

    // Subscribe to NameOwnerChanged for org.neard.
    let mut stream = match dbus_proxy.receive_name_owner_changed().await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to subscribe to NameOwnerChanged: {}", e);
            return;
        }
    };

    while let Some(signal) = stream.next().await {
        if let Ok(args) = signal.args() {
            if args.name.as_str() != NEARD_NAME {
                continue;
            }

            let old_owner = args.old_owner.as_ref().map(|o| o.as_str()).unwrap_or("");
            let new_owner = args.new_owner.as_ref().map(|o| o.as_str()).unwrap_or("");

            if new_owner.is_empty() && !old_owner.is_empty() {
                neard_vanished(&conn).await;
            } else if !new_owner.is_empty() {
                neard_appeared(&conn, new_owner).await;
            }
        }
    }
}

// ===========================================================================
// Plugin init / exit (from C lines 872–897)
// ===========================================================================

/// Initialise the neard NFC pairing bridge plugin.
///
/// Matches C `neard_init()` (lines 872–883).
fn neard_init() -> Result<(), Box<dyn std::error::Error>> {
    info!("neard plugin initialising");

    let state = Arc::new(tokio::sync::Mutex::new(NeardState::default()));
    STATE.set(state.clone()).map_err(|_| "neard plugin already initialised")?;

    let conn = btd_get_dbus_connection().clone();

    let handle = tokio::spawn(neard_service_watch(conn));

    // Store the watcher handle for cleanup.
    let state_clone = state.clone();
    tokio::spawn(async move {
        let mut s = state_clone.lock().await;
        s.watcher_handle = Some(handle);
    });

    Ok(())
}

/// Clean up the neard plugin.
///
/// Matches C `neard_exit()` (lines 885–897).
fn neard_exit() {
    info!("neard plugin shutting down");

    let conn = btd_get_dbus_connection().clone();

    tokio::spawn(async move {
        let state_ref = get_state();
        let mut s = state_ref.lock().await;

        if let Some(handle) = s.watcher_handle.take() {
            handle.abort();
        }

        if s.neard_service.is_some() {
            s.neard_service = None;
            drop(s);
            unregister_agent(&conn).await;
        }
    });
}

// ===========================================================================
// Plugin registration  (replaces BLUETOOTH_PLUGIN_DEFINE)
// ===========================================================================

/// The `NeardPlugin` struct implements [`BluetoothPlugin`] for the neard NFC
/// pairing bridge.
pub struct NeardPlugin;

impl BluetoothPlugin for NeardPlugin {
    fn name(&self) -> &str {
        "neard"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn priority(&self) -> PluginPriority {
        PluginPriority::Default
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        neard_init()
    }

    fn exit(&self) {
        neard_exit();
    }
}

/// Register the neard plugin at link time so that `plugin_init()` discovers
/// it via `inventory::iter::<PluginDesc>()`.
#[allow(unsafe_code)]
mod _neard_inventory {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "neard",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::Default,
            init: super::neard_init,
            exit: super::neard_exit,
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(NEARD_NAME, "org.neard");
        assert_eq!(NEARD_PATH, "/");
        assert_eq!(NEARD_MANAGER_INTERFACE, "org.neard.Manager");
        assert_eq!(AGENT_INTERFACE, "org.neard.HandoverAgent");
        assert_eq!(AGENT_PATH, "/org/bluez/neard_handover_agent");
        assert_eq!(AGENT_CARRIER_TYPE, "bluetooth");
        assert_eq!(ERROR_INTERFACE, "org.neard.HandoverAgent.Error");
        assert_eq!(NFC_OOB_EIR_MAX, 255);
    }

    #[test]
    fn test_cps_from_str() {
        assert_eq!(Cps::from_str_val("active"), Cps::Active);
        assert_eq!(Cps::from_str_val("inactive"), Cps::Inactive);
        assert_eq!(Cps::from_str_val("activating"), Cps::Activating);
        assert_eq!(Cps::from_str_val("unknown"), Cps::Unknown);
        assert_eq!(Cps::from_str_val(""), Cps::Unknown);
        assert_eq!(Cps::from_str_val("garbage"), Cps::Unknown);
    }

    #[test]
    fn test_oob_params_default() {
        let params = OobParams::default();
        assert_eq!(params.address, BDADDR_ANY);
        assert_eq!(params.class, 0);
        assert!(params.name.is_none());
        assert!(params.services.is_empty());
        assert!(params.hash.is_none());
        assert!(params.randomizer.is_none());
        assert!(params.pin.is_none());
        assert_eq!(params.power_state, Cps::Unknown);
    }

    #[test]
    fn test_neard_error_name_mapping() {
        assert_eq!(
            neard_error_name(nix::errno::Errno::ENOTSUP),
            "org.neard.HandoverAgent.Error.NotSupported"
        );
        // On Linux, EOPNOTSUPP == ENOTSUP, so we test only ENOTSUP.
        assert_eq!(
            neard_error_name(nix::errno::Errno::ENOENT),
            "org.neard.HandoverAgent.Error.NotFound"
        );
        assert_eq!(
            neard_error_name(nix::errno::Errno::ESRCH),
            "org.neard.HandoverAgent.Error.NotFound"
        );
        assert_eq!(
            neard_error_name(nix::errno::Errno::ENONET),
            "org.neard.HandoverAgent.Error.NotFound"
        );
        assert_eq!(
            neard_error_name(nix::errno::Errno::EINVAL),
            "org.neard.HandoverAgent.Error.InvalidArguments"
        );
        assert_eq!(
            neard_error_name(nix::errno::Errno::EALREADY),
            "org.neard.HandoverAgent.Error.AlreadyExists"
        );
        assert_eq!(
            neard_error_name(nix::errno::Errno::EINPROGRESS),
            "org.neard.HandoverAgent.Error.InProgress"
        );
        assert_eq!(
            neard_error_name(nix::errno::Errno::ENOMEM),
            "org.neard.HandoverAgent.Error.Failed"
        );
    }

    #[test]
    fn test_nokia_extra_short_parse() {
        // Sub-parser receives payload only (after the 4-byte header).
        let payload: Vec<u8> = vec![
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // BD_ADDR
        ];
        let mut params = OobParams::default();
        process_nokia_extra_short(&payload, &mut params);

        let expected = bdaddr_t { b: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] }.baswap();
        assert_eq!(params.address, expected);
    }

    #[test]
    fn test_nokia_short_parse_cod() {
        // Sub-parser receives payload only.
        let name = b"TestDev";
        let mut payload: Vec<u8> = vec![
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // BD_ADDR
            0x04, 0x05, 0x06, // CoD
        ];
        payload.push(name.len() as u8);
        payload.extend_from_slice(name);

        let mut params = OobParams::default();
        process_nokia_short(&payload, &mut params);

        assert_eq!(params.class, 0x060504);
        assert_eq!(params.name.as_deref(), Some("TestDev"));
    }

    #[test]
    fn test_nokia_long_parse_hash_and_name() {
        // Sub-parser receives payload only.
        let hash = [0xDE, 0xAD, 0xBE, 0xEF];
        let name = b"MyPhone";
        let mut payload: Vec<u8> = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // BD_ADDR
            0x0A, 0x0B, 0x0C, // CoD
        ];
        payload.push(hash.len() as u8);
        payload.extend_from_slice(&hash);
        payload.push(name.len() as u8);
        payload.extend_from_slice(name);

        let mut params = OobParams::default();
        process_nokia_long(&payload, &mut params);

        assert_eq!(params.class, 0x0C0B0A);
        assert_eq!(params.hash.as_deref(), Some(hash.as_slice()));
        assert_eq!(params.name.as_deref(), Some("MyPhone"));
    }

    #[test]
    fn test_nokia_com_bt_full_dispatch() {
        // End-to-end: header [version(1) + dlen(2,LE) + type(1)] + payload.
        let addr_bytes = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
        // Extra-short: payload = 6 bytes addr; dlen = 1 (type) + 6 = 7.
        let data: Vec<u8> = vec![
            0x01, // version
            0x07,
            0x00,                      // dlen = 7 (LE16)
            NOKIA_BT_TYPE_EXTRA_SHORT, // type = 0x04
            addr_bytes[0],
            addr_bytes[1],
            addr_bytes[2],
            addr_bytes[3],
            addr_bytes[4],
            addr_bytes[5],
        ];
        let mut params = OobParams::default();
        process_nokia_com_bt(&data, &mut params);

        let expected = bdaddr_t { b: addr_bytes }.baswap();
        assert_eq!(params.address, expected);
    }

    #[test]
    fn test_process_state() {
        let mut params = OobParams::default();
        process_state("active", &mut params);
        assert_eq!(params.power_state, Cps::Active);

        process_state("inactive", &mut params);
        assert_eq!(params.power_state, Cps::Inactive);

        process_state("activating", &mut params);
        assert_eq!(params.power_state, Cps::Activating);

        process_state("foobar", &mut params);
        assert_eq!(params.power_state, Cps::Unknown);
    }

    #[test]
    fn test_plugin_name_and_priority() {
        let plugin = NeardPlugin;
        assert_eq!(plugin.name(), "neard");
        assert_eq!(plugin.priority(), PluginPriority::Default);
        assert!(!plugin.version().is_empty());
    }
}
