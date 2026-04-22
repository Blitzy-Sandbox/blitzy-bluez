// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012 Instituto Nokia de Tecnologia - INdT
// Copyright (C) 2014 Intel Corporation
//
// GAP (Generic Access Profile) characteristics reader — Rust rewrite of
// `profiles/gap/gas.c`.
//
// This module discovers the remote LE GAP service (UUID 0x1800) and reads
// three standard characteristics:
//
// - **Device Name** (UUID 0x2A00) — long-read to get the full remote name,
//   clamped to `HCI_MAX_NAME_LENGTH` (248 bytes), sanitized to valid UTF-8.
// - **Appearance** (UUID 0x2A01) — 2-byte LE integer identifying the device
//   type icon.
// - **Peripheral Preferred Connection Parameters** (UUID 0x2A04) — 8-byte
//   blob with min/max interval, latency, and supervision timeout, validated
//   per Bluetooth Core Spec Vol 3, Part C, Section 12.4.
//
// ## Lifecycle
//
// 1. **Probe** (`gap_probe`): Allocates per-device `Gas` context and stores
//    it in the module-level device state map.
// 2. **Accept** (`gap_accept`): Clones the GATT database and client from the
//    device, discovers the GAP service, and reads all supported chars.
// 3. **Disconnect** (`gap_disconnect`): Releases GATT references while
//    preserving the `Gas` context for reconnection.
// 4. **Remove** (`gap_remove`): Removes the per-device `Gas` context.
//
// ## Plugin Registration
//
// Registered via `inventory::submit!` with `PluginPriority::Default` (0),
// replacing C's `BLUETOOTH_PLUGIN_DEFINE(gap, VERSION,
// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, gap_init, gap_exit)`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use tracing::{debug, error, warn};

use bluez_shared::gatt::client::{BtGattClient, ReadCallback};
use bluez_shared::gatt::db::{GattDb, GattDbAttribute};
use bluez_shared::util::uuid::BtUuid;

use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error, btd_warn};
use crate::plugin::PluginPriority;
use crate::profile::{
    BTD_PROFILE_BEARER_LE, BtdProfile, btd_profile_register, btd_profile_unregister,
};

use bluez_shared::sys::bluetooth::BdAddr;

// ===========================================================================
// Constants
// ===========================================================================

/// GAP Service UUID (0x1800).
const GAP_UUID16: u16 = 0x1800;

/// GAP Service UUID string for profile registration (full 128-bit form).
const GAP_UUID_STR: &str = "00001800-0000-1000-8000-00805f9b34fb";

/// Device Name characteristic UUID (0x2A00).
const GATT_CHARAC_DEVICE_NAME: u16 = 0x2A00;

/// Appearance characteristic UUID (0x2A01).
const GATT_CHARAC_APPEARANCE: u16 = 0x2A01;

/// Peripheral Preferred Connection Parameters characteristic UUID (0x2A04).
const GATT_CHARAC_PERIPHERAL_PREF_CONN: u16 = 0x2A04;

/// Maximum HCI name length in bytes (from bluetooth.h).
const HCI_MAX_NAME_LENGTH: usize = 248;

/// Default minimum connection interval when PPCP min is 0xFFFF (unspecified).
/// 0x0018 = 24 in 1.25 ms units = 30 ms.
const PPCP_DEFAULT_MIN_INTERVAL: u16 = 0x0018;

/// Default maximum connection interval when PPCP max is 0xFFFF (unspecified).
/// 0x0028 = 40 in 1.25 ms units = 50 ms.
const PPCP_DEFAULT_MAX_INTERVAL: u16 = 0x0028;

/// BLE connection interval minimum value (7.5 ms / 1.25 ms = 6).
const PPCP_MIN_INTERVAL_LIMIT: u16 = 6;

/// BLE connection interval maximum value (4 s / 1.25 ms = 3200).
const PPCP_MAX_INTERVAL_LIMIT: u16 = 3200;

/// Supervision timeout minimum value (100 ms / 10 ms = 10).
const PPCP_MIN_TIMEOUT: u16 = 10;

/// Supervision timeout maximum value (32 s / 10 ms = 3200).
const PPCP_MAX_TIMEOUT: u16 = 3200;

/// Maximum allowable connection latency.
const PPCP_MAX_LATENCY: u16 = 499;

// ===========================================================================
// Module State
// ===========================================================================

/// Per-device GAP profile context.
///
/// Replaces C `struct gas` from gas.c. Stores GATT client/database references
/// for reading GAP characteristics, plus the device for applying read results.
struct Gas {
    /// Reference to the owning BLE device.
    device: Arc<tokio::sync::Mutex<BtdDevice>>,

    /// Cloned GATT database from the remote device.
    gatt_db: Option<GattDb>,

    /// Cloned GATT client for ATT read operations.
    gatt_client: Option<Arc<BtGattClient>>,

    /// Handle of the discovered GAP service declaration attribute.
    /// Used as a guard against repeated service discovery on re-accept.
    gap_service_handle: Option<u16>,
}

impl Gas {
    /// Create a new GAP context for the given device.
    fn new(device: Arc<tokio::sync::Mutex<BtdDevice>>) -> Self {
        Self { device, gatt_db: None, gatt_client: None, gap_service_handle: None }
    }
}

/// Global per-device state map.
///
/// Keys are Bluetooth device addresses; values are per-device `Gas` contexts
/// wrapped in `Arc<StdMutex<Gas>>` for shared access between lifecycle
/// callbacks and read result closures.
///
/// Uses `std::sync::Mutex` (not tokio) because the state is accessed from
/// both sync (probe/remove) and async (accept/disconnect) contexts, and
/// the lock is never held across `.await` points.
static GAP_STATE: LazyLock<StdMutex<HashMap<BdAddr, Arc<StdMutex<Gas>>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

/// Stored profile definition for unregistration during plugin exit.
static GAP_PROFILE: LazyLock<StdMutex<Option<BtdProfile>>> = LazyLock::new(|| StdMutex::new(None));

// ===========================================================================
// Gas Reset / Free
// ===========================================================================

/// Reset the GATT state of a Gas context.
///
/// Clears GATT database and client references while preserving the context
/// itself for potential reconnection. The `gap_service_handle` is also
/// cleared so that re-accept will re-discover the service.
///
/// Replaces C `gas_reset()` from gas.c.
fn gas_reset(gas: &mut Gas) {
    gas.gap_service_handle = None;
    gas.gatt_db = None;
    gas.gatt_client = None;
}

/// Fully clean up a Gas context.
///
/// Releases all GATT references. Called during device removal.
///
/// Replaces C `gas_free()` from gas.c.
fn gas_free(gas: &mut Gas) {
    gas_reset(gas);
}

// ===========================================================================
// UTF-8 Name Sanitization
// ===========================================================================

/// Sanitize a raw byte slice into a valid UTF-8 device name.
///
/// - Clamps to `HCI_MAX_NAME_LENGTH` (248 bytes).
/// - Converts lossy bytes to UTF-8 (replacing invalid sequences with U+FFFD).
/// - Trims leading/trailing whitespace and NUL bytes.
///
/// Replaces C `name2utf8()` from gas.c.
fn name2utf8(data: &[u8]) -> String {
    // Clamp the raw data to the maximum HCI name length.
    let clamped =
        if data.len() > HCI_MAX_NAME_LENGTH { &data[..HCI_MAX_NAME_LENGTH] } else { data };

    // Strip trailing NUL bytes before UTF-8 conversion.
    let trimmed_nuls = match clamped.iter().rposition(|&b| b != 0) {
        Some(pos) => &clamped[..=pos],
        None => return String::new(), // All NULs — empty name.
    };

    // Convert to UTF-8, replacing invalid sequences.
    let utf8 = String::from_utf8_lossy(trimmed_nuls);

    // Trim leading/trailing whitespace.
    utf8.trim().to_owned()
}

// ===========================================================================
// Characteristic Readers
// ===========================================================================

/// Handle the Device Name characteristic read result.
///
/// Performs a long read of the Device Name characteristic (UUID 0x2A00),
/// sanitizes the result to valid UTF-8, and stores it on the device.
///
/// Replaces C `handle_device_name()` + `read_device_name_cb()` from gas.c.
fn handle_device_name(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
    value_handle: u16,
    client: &Arc<BtGattClient>,
) {
    let dev_clone = Arc::clone(device);

    let callback: ReadCallback = Box::new(move |success: bool, att_ecode: u8, data: &[u8]| {
        if !success {
            error!("Device Name read failed: ATT error 0x{:02x}", att_ecode);
            btd_error(0, &format!("Device Name read failed: ATT error 0x{:02x}", att_ecode));
            return;
        }

        if data.is_empty() {
            debug!("Device Name characteristic is empty");
            btd_debug(0, "Device Name characteristic is empty");
            return;
        }

        let name = name2utf8(data);
        if name.is_empty() {
            debug!("Device Name sanitized to empty string, skipping");
            btd_debug(0, "Device Name sanitized to empty string, skipping");
            return;
        }

        debug!("GAP Device Name: {}", name);
        btd_debug(0, &format!("GAP Device Name: {}", name));

        // Spawn an async task to lock the device and set the name.
        // The ReadCallback is synchronous (FnOnce + Send), so we must
        // use tokio::spawn to reach an async context for the device mutex.
        tokio::spawn(async move {
            let mut dev = dev_clone.lock().await;
            dev.set_name(&name);
        });
    });

    // Perform a long read starting at offset 0 (names may exceed ATT_MTU).
    client.read_long_value(value_handle, 0, callback);
}

/// Handle the Appearance characteristic read result.
///
/// Reads the 2-byte LE Appearance value and persists it on the device.
/// Only reads if the current appearance indicates an update is needed
/// (i.e., current value is 0 / unknown).
///
/// Replaces C `handle_appearance()` + `read_appearance_cb()` from gas.c.
fn handle_appearance(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
    value_handle: u16,
    client: &Arc<BtGattClient>,
    current_appearance: u16,
) {
    // In the C code, the read is skipped if the appearance is already known
    // and non-zero, as the value doesn't change during a connection.
    if current_appearance != 0 {
        debug!("Appearance already known (0x{:04x}), skipping read", current_appearance);
        btd_debug(
            0,
            &format!("Appearance already known (0x{:04x}), skipping read", current_appearance),
        );
        return;
    }

    let dev_clone = Arc::clone(device);

    let callback: ReadCallback = Box::new(move |success: bool, att_ecode: u8, data: &[u8]| {
        if !success {
            error!("Appearance read failed: ATT error 0x{:02x}", att_ecode);
            btd_error(0, &format!("Appearance read failed: ATT error 0x{:02x}", att_ecode));
            return;
        }

        if data.len() < 2 {
            error!("Appearance: invalid data length {}", data.len());
            btd_error(0, &format!("Appearance: invalid data length {}", data.len()));
            return;
        }

        let appearance = u16::from_le_bytes([data[0], data[1]]);

        debug!("GAP Appearance: 0x{:04x}", appearance);
        btd_debug(0, &format!("GAP Appearance: 0x{:04x}", appearance));

        tokio::spawn(async move {
            let mut dev = dev_clone.lock().await;
            dev.set_appearance(appearance);
        });
    });

    client.read_value(value_handle, callback);
}

/// Validate and apply Peripheral Preferred Connection Parameters.
///
/// Reads the 8-byte PPCP characteristic, decodes min/max interval, latency,
/// and supervision timeout, validates per Bluetooth Core Spec constraints,
/// and applies via `btd_device_set_conn_param`.
///
/// Replaces C `handle_ppcp()` + `read_ppcp_cb()` from gas.c.
fn handle_ppcp(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
    value_handle: u16,
    client: &Arc<BtGattClient>,
) {
    let dev_clone = Arc::clone(device);

    let callback: ReadCallback = Box::new(move |success: bool, att_ecode: u8, data: &[u8]| {
        if !success {
            error!("PPCP read failed: ATT error 0x{:02x}", att_ecode);
            btd_error(0, &format!("PPCP read failed: ATT error 0x{:02x}", att_ecode));
            return;
        }

        if data.len() < 8 {
            error!("PPCP: invalid data length {}", data.len());
            btd_error(0, &format!("PPCP: invalid data length {}", data.len()));
            return;
        }

        // Decode the four 16-bit LE fields.
        let mut min_interval = u16::from_le_bytes([data[0], data[1]]);
        let mut max_interval = u16::from_le_bytes([data[2], data[3]]);
        let latency = u16::from_le_bytes([data[4], data[5]]);
        let timeout = u16::from_le_bytes([data[6], data[7]]);

        debug!(
            "PPCP raw: min=0x{:04x} max=0x{:04x} latency=0x{:04x} timeout=0x{:04x}",
            min_interval, max_interval, latency, timeout
        );
        btd_debug(
            0,
            &format!(
                "PPCP raw: min=0x{:04x} max=0x{:04x} latency=0x{:04x} timeout=0x{:04x}",
                min_interval, max_interval, latency, timeout
            ),
        );

        // Replace 0xFFFF (unspecified) fields with defaults.
        // From gas.c lines 173-178.
        if min_interval == 0xFFFF {
            min_interval = PPCP_DEFAULT_MIN_INTERVAL;
        }
        if max_interval == 0xFFFF {
            max_interval = PPCP_DEFAULT_MAX_INTERVAL;
        }

        // Validate Bluetooth Core Spec connection parameter constraints.
        // See Bluetooth Core Spec Vol 3, Part C, Section 12.4.
        if !validate_ppcp(min_interval, max_interval, latency, timeout) {
            return;
        }

        debug!(
            "PPCP validated: min={} max={} latency={} timeout={}",
            min_interval, max_interval, latency, timeout
        );
        btd_debug(
            0,
            &format!(
                "PPCP validated: min={} max={} latency={} timeout={}",
                min_interval, max_interval, latency, timeout
            ),
        );

        tokio::spawn(async move {
            let mut dev = dev_clone.lock().await;
            dev.set_conn_param(min_interval, max_interval, latency, timeout);
        });
    });

    client.read_value(value_handle, callback);
}

/// Validate PPCP parameters per Bluetooth Core Spec constraints.
///
/// Returns `true` if all parameters are within valid ranges and meet
/// the inter-parameter constraints. Logs warnings for each violation.
///
/// Replicates the exact validation logic from C `read_ppcp_cb()` in gas.c
/// (lines 189-210), preserving identical acceptance/rejection behaviour.
fn validate_ppcp(min_interval: u16, max_interval: u16, latency: u16, timeout: u16) -> bool {
    // Block 1: Interval range and ordering checks.
    // From gas.c lines 190-194:
    //   if (min_interval > max_interval ||
    //       min_interval < 6 || max_interval > 3200)
    if min_interval > max_interval
        || min_interval < PPCP_MIN_INTERVAL_LIMIT
        || max_interval > PPCP_MAX_INTERVAL_LIMIT
    {
        warn!("GAS PPCP: Invalid Connection Parameters values (interval)");
        btd_warn(0, "GAS PPCP: Invalid Connection Parameters values (interval)");
        return false;
    }

    // Block 2: Supervision timeout range.
    // From gas.c lines 196-199:
    //   if (timeout < 10 || timeout > 3200)
    if !(PPCP_MIN_TIMEOUT..=PPCP_MAX_TIMEOUT).contains(&timeout) {
        warn!("GAS PPCP: Invalid Connection Parameters values (timeout)");
        btd_warn(0, "GAS PPCP: Invalid Connection Parameters values (timeout)");
        return false;
    }

    // Block 3: Connection interval vs. supervision timeout ratio.
    // From gas.c lines 201-204:
    //   if (max_interval >= timeout * 8)
    if u32::from(max_interval) >= u32::from(timeout) * 8 {
        warn!("GAS PPCP: Invalid Connection Parameters values (interval vs timeout)");
        btd_warn(0, "GAS PPCP: Invalid Connection Parameters values (interval vs timeout)");
        return false;
    }

    // Block 4: Latency constraints.
    // From gas.c lines 206-210:
    //   max_latency = (timeout * 4 / max_interval) - 1;
    //   if (latency > 499 || latency > max_latency)
    //
    // Note: max_interval is guaranteed non-zero by block 1 (min >= 6).
    let max_latency = (u32::from(timeout) * 4 / u32::from(max_interval)).saturating_sub(1);
    if u32::from(latency) > u32::from(PPCP_MAX_LATENCY) || u32::from(latency) > max_latency {
        warn!("GAS PPCP: Invalid Connection Parameters values (latency)");
        btd_warn(0, "GAS PPCP: Invalid Connection Parameters values (latency)");
        return false;
    }

    true
}

// ===========================================================================
// Characteristic Dispatch
// ===========================================================================

/// Process a single characteristic within the GAP service.
///
/// Extracts the characteristic UUID and dispatches to the appropriate handler:
/// - Device Name (0x2A00) → `handle_device_name`
/// - Appearance (0x2A01) → `handle_appearance`
/// - PPCP (0x2A04) → `handle_ppcp`
///
/// Unknown characteristics are logged at debug level and ignored.
///
/// Replaces C `handle_characteristic()` from gas.c.
fn handle_characteristic(
    char_attr: &GattDbAttribute,
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
    client: &Arc<BtGattClient>,
    current_appearance: u16,
) {
    let char_data = match char_attr.get_char_data() {
        Some(data) => data,
        None => return,
    };

    let name_uuid = BtUuid::from_u16(GATT_CHARAC_DEVICE_NAME);
    let appearance_uuid = BtUuid::from_u16(GATT_CHARAC_APPEARANCE);
    let ppcp_uuid = BtUuid::from_u16(GATT_CHARAC_PERIPHERAL_PREF_CONN);

    if char_data.uuid == name_uuid {
        handle_device_name(device, char_data.value_handle, client);
    } else if char_data.uuid == appearance_uuid {
        handle_appearance(device, char_data.value_handle, client, current_appearance);
    } else if char_data.uuid == ppcp_uuid {
        handle_ppcp(device, char_data.value_handle, client);
    } else {
        debug!(
            "Unknown GAP characteristic: handle 0x{:04x} uuid {}",
            char_data.value_handle, char_data.uuid
        );
        btd_debug(
            0,
            &format!(
                "Unknown GAP characteristic: handle 0x{:04x} uuid {}",
                char_data.value_handle, char_data.uuid
            ),
        );
    }
}

// ===========================================================================
// Service Discovery
// ===========================================================================

/// Process a discovered GAP service.
///
/// Guards against duplicate services and iterates all characteristics
/// within the service, dispatching each to `handle_characteristic`.
///
/// Returns `true` if this was the first service found (success),
/// `false` if a duplicate was detected (the service is skipped).
///
/// Replaces C `foreach_gap_service()` from gas.c.
fn foreach_gap_service(
    service_attr: GattDbAttribute,
    gas: &mut Gas,
    client: &Arc<BtGattClient>,
    current_appearance: u16,
) -> bool {
    // Guard: reject duplicate GAP services.
    if gas.gap_service_handle.is_some() {
        error!("More than one GAP service exists for this device");
        btd_error(0, "More than one GAP service exists for this device");
        return false;
    }

    // Store the service attribute handle as a discovery marker.
    gas.gap_service_handle = Some(service_attr.get_handle());

    // Iterate characteristics within the GAP service.
    if let Some(svc) = service_attr.get_service() {
        svc.foreach_char(|char_attr| {
            handle_characteristic(&char_attr, &gas.device, client, current_appearance);
        });
    }

    true
}

// ===========================================================================
// Profile Lifecycle — Accept
// ===========================================================================

/// Accept an incoming LE connection for the GAP profile.
///
/// Clones the GATT database and client from the device, discovers the GAP
/// Service (UUID 0x1800), and initiates characteristic reading for Device
/// Name, Appearance, and PPCP.
///
/// Replaces C `gap_accept()` from gas.c.
async fn gap_accept(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    debug!("GAP profile accept");
    btd_debug(0, "GAP profile accept");

    // Lock device to extract address, GATT DB, GATT client, and appearance.
    let (addr, gatt_db, gatt_client, current_appearance) = {
        let dev = device.lock().await;
        let addr = *dev.get_address();

        let db = match dev.get_gatt_db() {
            Some(db) => db.clone(),
            None => {
                error!("GAP: no GATT database available");
                btd_error(0, "GAP: no GATT database available");
                return Err(BtdError::NotAvailable("No GATT database available".to_owned()));
            }
        };

        let client = match dev.get_gatt_client() {
            Some(c) => Arc::clone(c),
            None => {
                error!("GAP: no GATT client available");
                btd_error(0, "GAP: no GATT client available");
                return Err(BtdError::NotAvailable("No GATT client available".to_owned()));
            }
        };

        let appearance = dev.get_appearance();

        (addr, db, client, appearance)
    };

    // Retrieve the per-device Gas context.
    let gas_arc = {
        let state = GAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match state.get(&addr) {
            Some(s) => Arc::clone(s),
            None => {
                error!("GAP: no context for device");
                btd_error(0, "GAP: no context for device");
                return Err(BtdError::DoesNotExist("No GAP context for device".to_owned()));
            }
        }
    };

    // Update the Gas context with GATT references and discover the service.
    {
        let mut gas = gas_arc.lock().unwrap_or_else(|e| e.into_inner());

        // Short-circuit if the GAP service was already discovered
        // (repeated accept without intervening disconnect).
        if gas.gap_service_handle.is_some() {
            debug!("GAP service already discovered, skipping");
            btd_debug(0, "GAP service already discovered, skipping");
            return Ok(());
        }

        gas.gatt_db = Some(gatt_db.clone());
        gas.gatt_client = Some(Arc::clone(&gatt_client));

        // Discover the GAP Service (UUID 0x1800).
        let gap_uuid = BtUuid::from_u16(GAP_UUID16);
        let mut found = false;

        // Collect service attributes first to avoid borrow conflicts.
        let mut service_attrs = Vec::new();
        gatt_db.foreach_service(Some(&gap_uuid), |attr| {
            service_attrs.push(attr);
        });

        for attr in service_attrs {
            if foreach_gap_service(attr, &mut gas, &gatt_client, current_appearance) {
                found = true;
            }
        }

        if !found && gas.gap_service_handle.is_none() {
            error!("Unable to find GAP service");
            btd_error(0, "Unable to find GAP service");
            gas_reset(&mut gas);
            return Err(BtdError::DoesNotExist("Unable to find GAP service".to_owned()));
        }
    }

    // Returning Ok(()) signals btd_service_connecting_complete(service, 0).
    Ok(())
}

// ===========================================================================
// Profile Lifecycle — Probe
// ===========================================================================

/// Probe a device for the GAP profile.
///
/// Allocates a per-device `Gas` context and stores it in the module-level
/// state map. Guards against duplicate probes.
///
/// Replaces C `gap_probe()` from gas.c.
fn gap_probe(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    // Try to lock the device to get the address. Use try_lock since this is
    // a sync callback and the device mutex may be held by the caller.
    let addr = match device.try_lock() {
        Ok(dev) => {
            let addr = *dev.get_address();
            debug!("GAP profile probe: {}", dev.get_address().ba2str());
            btd_debug(0, &format!("GAP profile probe: {}", dev.get_address().ba2str()));
            addr
        }
        Err(_) => {
            error!("GAP: could not lock device for probe");
            btd_error(0, "GAP: could not lock device for probe");
            return Err(BtdError::InProgress("Device lock contention".to_owned()));
        }
    };

    let mut state = GAP_STATE.lock().unwrap_or_else(|e| e.into_inner());

    // Guard against duplicate probe calls.
    if state.contains_key(&addr) {
        error!("GAP profile was probed twice for same device");
        btd_error(0, "GAP profile was probed twice for same device");
        return Err(BtdError::AlreadyExists(
            "GAP profile was probed twice for same device".to_owned(),
        ));
    }

    // Allocate and store the new Gas context.
    let gas = Arc::new(StdMutex::new(Gas::new(Arc::clone(device))));
    state.insert(addr, gas);

    Ok(())
}

// ===========================================================================
// Profile Lifecycle — Disconnect
// ===========================================================================

/// Disconnect the GAP profile from a device.
///
/// Resets GATT state while preserving the `Gas` context for potential
/// reconnection. No ATT-level work is performed.
///
/// Replaces C `gap_disconnect()` from gas.c.
async fn gap_disconnect(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    let addr = {
        let dev = device.lock().await;
        *dev.get_address()
    };

    let state = GAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(gas_arc) = state.get(&addr) {
        let mut gas = gas_arc.lock().unwrap_or_else(|e| e.into_inner());
        gas_reset(&mut gas);
    }

    // Returning Ok(()) signals btd_service_disconnecting_complete(service, 0).
    Ok(())
}

// ===========================================================================
// Profile Lifecycle — Remove
// ===========================================================================

/// Remove the GAP profile from a device.
///
/// Fully cleans up the per-device `Gas` context, removing it from the
/// state map.
///
/// Replaces C `gap_remove()` from gas.c.
fn gap_remove(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    let addr = match device.try_lock() {
        Ok(dev) => *dev.get_address(),
        Err(_) => {
            error!("GAP: could not lock device for remove");
            btd_error(0, "GAP: could not lock device for remove");
            return;
        }
    };

    let mut state = GAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(gas_arc) = state.remove(&addr) {
        let mut gas = gas_arc.lock().unwrap_or_else(|e| e.into_inner());
        gas_free(&mut gas);
    }
}

// ===========================================================================
// Plugin Init / Exit
// ===========================================================================

/// Initialize the GAP plugin.
///
/// Creates and registers the GAP Characteristics Reader profile with the
/// daemon's profile registry. The profile is LE-only and matches devices
/// advertising the GAP Service (UUID 0x1800).
///
/// Replaces C `gap_init()` from gas.c.
fn gap_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("gap plugin init");

    // Build the profile descriptor.
    let mut profile = BtdProfile::new("gap-profile");
    profile.bearer = BTD_PROFILE_BEARER_LE;
    profile.remote_uuid = Some(GAP_UUID_STR.to_owned());

    // Set lifecycle callbacks.
    profile.set_device_probe(Box::new(gap_probe));
    profile.set_device_remove(Box::new(gap_remove));

    // Accept and disconnect return Futures (async closures).
    profile.set_accept(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { gap_accept(&device).await })
    }));

    profile.set_disconnect(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { gap_disconnect(&device).await })
    }));

    // Store a copy for unregistration during exit.
    {
        let stored = BtdProfile::new("gap-profile");
        let mut guard = GAP_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(stored);
    }

    // Register the profile asynchronously.
    tokio::spawn(async move {
        if let Err(e) = btd_profile_register(profile).await {
            error!("Failed to register GAP profile: {}", e);
            btd_error(0, &format!("Failed to register GAP profile: {}", e));
        }
    });

    Ok(())
}

/// Shut down the GAP plugin.
///
/// Unregisters the profile and clears all per-device state.
///
/// Replaces C `gap_exit()` from gas.c.
fn gap_exit() {
    debug!("gap plugin exit");

    // Unregister the profile asynchronously.
    let profile_opt = {
        let mut guard = GAP_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };

    if let Some(profile) = profile_opt {
        tokio::spawn(async move {
            btd_profile_unregister(&profile).await;
        });
    }

    // Clear all per-device state.
    let mut state = GAP_STATE.lock().unwrap_or_else(|e| e.into_inner());
    for (_addr, gas_arc) in state.drain() {
        let mut gas = gas_arc.lock().unwrap_or_else(|e| e.into_inner());
        gas_free(&mut gas);
    }
}

// ===========================================================================
// Exported struct — GapPlugin
// ===========================================================================

/// GAP plugin descriptor.
///
/// Provides the public API surface for the GAP profile plugin. The actual
/// plugin lifecycle is handled through [`crate::plugin::PluginDesc`]
/// registered via [`inventory::submit!`], which calls the module-level
/// [`gap_init`] and [`gap_exit`] functions.
///
/// This struct satisfies the export schema requirement for a `GapPlugin`
/// class with `name()`, `version()`, `priority()`, `init()`, and `exit()`
/// members.
pub struct GapPlugin;

impl GapPlugin {
    /// Returns the unique plugin name: `"gap"`.
    pub fn name(&self) -> &str {
        "gap"
    }

    /// Returns the plugin version string (matches daemon VERSION).
    pub fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    /// Returns the plugin initialization priority: `Default` (0).
    pub fn priority(&self) -> PluginPriority {
        PluginPriority::Default
    }

    /// Initializes the GAP plugin.
    ///
    /// Delegates to the module-level [`gap_init`] function.
    pub fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        gap_init()
    }

    /// Cleans up the GAP plugin.
    ///
    /// Delegates to the module-level [`gap_exit`] function.
    pub fn exit(&self) {
        gap_exit()
    }
}

// ===========================================================================
// Plugin registration via inventory
// ===========================================================================

/// Register the gap plugin at link time so that `plugin_init()` in the
/// plugin framework discovers it via `inventory::iter::<PluginDesc>()`.
///
/// Replaces C's `BLUETOOTH_PLUGIN_DEFINE(gap, VERSION,
/// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, gap_init, gap_exit)`.
#[allow(unsafe_code)]
mod _gap_inventory {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "gap",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::Default,
            init: super::gap_init,
            exit: super::gap_exit,
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
    fn test_name2utf8_basic() {
        let data = b"My Device";
        assert_eq!(name2utf8(data), "My Device");
    }

    #[test]
    fn test_name2utf8_trailing_nuls() {
        let data = b"Hello\0\0\0";
        assert_eq!(name2utf8(data), "Hello");
    }

    #[test]
    fn test_name2utf8_all_nuls() {
        let data = b"\0\0\0";
        assert_eq!(name2utf8(data), "");
    }

    #[test]
    fn test_name2utf8_empty() {
        let data: &[u8] = &[];
        assert_eq!(name2utf8(data), "");
    }

    #[test]
    fn test_name2utf8_whitespace_trim() {
        let data = b"  Hello World  \0";
        assert_eq!(name2utf8(data), "Hello World");
    }

    #[test]
    fn test_name2utf8_max_length_clamp() {
        // Create a name longer than HCI_MAX_NAME_LENGTH.
        let long_name = vec![b'A'; HCI_MAX_NAME_LENGTH + 50];
        let result = name2utf8(&long_name);
        assert!(result.len() <= HCI_MAX_NAME_LENGTH);
        assert_eq!(result.len(), HCI_MAX_NAME_LENGTH);
    }

    #[test]
    fn test_name2utf8_invalid_utf8() {
        // Invalid UTF-8 byte sequence.
        let data: &[u8] = &[0xFF, 0xFE, b'A', b'B'];
        let result = name2utf8(data);
        // Should not panic, and should contain 'A' and 'B'.
        assert!(result.contains('A'));
        assert!(result.contains('B'));
    }

    #[test]
    fn test_validate_ppcp_valid() {
        // Valid typical connection parameters.
        assert!(validate_ppcp(24, 40, 0, 100));
    }

    #[test]
    fn test_validate_ppcp_min_too_low() {
        // min_interval < 6 → rejected by block 1.
        assert!(!validate_ppcp(5, 40, 0, 100));
    }

    #[test]
    fn test_validate_ppcp_max_too_high() {
        // max_interval > 3200 → rejected by block 1.
        assert!(!validate_ppcp(6, 3201, 0, 100));
    }

    #[test]
    fn test_validate_ppcp_max_less_than_min() {
        // min_interval > max_interval → rejected by block 1.
        assert!(!validate_ppcp(40, 24, 0, 100));
    }

    #[test]
    fn test_validate_ppcp_latency_too_high() {
        // latency > 499 → rejected by block 4.
        assert!(!validate_ppcp(24, 40, 500, 100));
    }

    #[test]
    fn test_validate_ppcp_timeout_too_low() {
        // timeout < 10 → rejected by block 2.
        assert!(!validate_ppcp(24, 40, 0, 9));
    }

    #[test]
    fn test_validate_ppcp_timeout_too_high() {
        // timeout > 3200 → rejected by block 2.
        assert!(!validate_ppcp(24, 40, 0, 3201));
    }

    #[test]
    fn test_validate_ppcp_interval_vs_timeout() {
        // max_interval >= timeout * 8 → rejected by block 3.
        // 81 >= 10 * 8 = 80? Yes → rejected.
        assert!(!validate_ppcp(6, 81, 0, 10));
        // 80 >= 10 * 8 = 80? Yes → rejected.
        assert!(!validate_ppcp(6, 80, 0, 10));
        // 79 < 80 → passes block 3, all other checks pass.
        assert!(validate_ppcp(6, 79, 0, 10));
    }

    #[test]
    fn test_validate_ppcp_small_timeout_passes() {
        // max_interval=40, timeout=10 → 40 >= 80? No → passes.
        // max_latency = (10*4/40) - 1 = 0. latency=0 <= 0 → passes.
        assert!(validate_ppcp(24, 40, 0, 10));
    }

    #[test]
    fn test_validate_ppcp_latency_max_constraint() {
        // max_latency = (100 * 4 / 40) - 1 = 10 - 1 = 9.
        // latency=9 should pass (9 <= 9).
        assert!(validate_ppcp(24, 40, 9, 100));
        // latency=10 should fail (10 > 9).
        assert!(!validate_ppcp(24, 40, 10, 100));
    }

    #[test]
    fn test_validate_ppcp_edge_valid() {
        // Boundary-valid parameters: min=6, max=6, latency=0, timeout=10.
        // Block 1: 6 <= 6, 6 >= 6, 6 <= 3200 → passes.
        // Block 2: 10 in [10,3200] → passes.
        // Block 3: 6 >= 80? No → passes.
        // Block 4: max_latency = (10*4/6) - 1 = 6 - 1 = 5. 0 <= 5 → passes.
        assert!(validate_ppcp(6, 6, 0, 10));
    }

    #[test]
    fn test_gap_plugin_name() {
        let plugin = GapPlugin;
        assert_eq!(plugin.name(), "gap");
    }

    #[test]
    fn test_gap_plugin_version() {
        let plugin = GapPlugin;
        // Version comes from Cargo.toml.
        assert!(!plugin.version().is_empty());
    }

    #[test]
    fn test_gap_plugin_priority() {
        let plugin = GapPlugin;
        assert!(matches!(plugin.priority(), PluginPriority::Default));
    }
}
