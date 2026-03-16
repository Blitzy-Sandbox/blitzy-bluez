// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012 Texas Instruments, Inc.
// Copyright (C) 2015 Google Inc.
//
// Device Information Service (DIS) PnP ID reader — Rust rewrite consolidating
// `profiles/deviceinfo/deviceinfo.c`, `profiles/deviceinfo/dis.c`, and
// `profiles/deviceinfo/dis.h`.
//
// This module discovers the remote GATT Device Information Service (UUID
// 0x180A) and reads the PnP ID characteristic (UUID 0x2A50) to populate the
// BlueZ device object's vendor/product/version identifiers used for the
// `Modalias` D-Bus property on `org.bluez.Device1`.
//
// ## Lifecycle
//
// 1. **Probe** (`deviceinfo_probe`): No-op — no persistent per-device state
//    is needed for the DIS reader (all work is performed during accept).
// 2. **Accept** (`deviceinfo_accept`): Acquires the remote GATT database and
//    client, discovers the DIS service, locates the PnP ID characteristic
//    by UUID, reads its 7-byte value, decodes source/vendor/product/version,
//    and stores the result on the device via `set_pnp_id`.
// 3. **Disconnect** (`deviceinfo_disconnect`): Signals disconnecting complete
//    immediately — no teardown required.
// 4. **Remove** (`deviceinfo_remove`): No-op — no persistent per-device
//    state to release.
//
// ## PnP ID Characteristic Format (7 bytes)
//
// | Offset | Length | Field    | Encoding     |
// |--------|--------|----------|--------------|
// | 0      | 1      | source   | u8           |
// | 1      | 2      | vendor   | u16 LE       |
// | 3      | 2      | product  | u16 LE       |
// | 5      | 2      | version  | u16 LE       |
//
// ## Plugin Registration
//
// Registered via `inventory::submit!` with `PluginPriority::Default` (0),
// replacing C's `BLUETOOTH_PLUGIN_DEFINE(deviceinfo, VERSION,
// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, deviceinfo_init, deviceinfo_exit)`.

use std::sync::Arc;

use tracing::{debug, error};

use bluez_shared::gatt::client::{BtGattClient, ReadCallback};
use bluez_shared::gatt::db::GattDbAttribute;
use bluez_shared::util::uuid::BtUuid;

use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error};
use crate::plugin::PluginPriority;
use crate::profile::{
    BTD_PROFILE_BEARER_ANY, BtdProfile, btd_profile_register, btd_profile_unregister,
};

// ===========================================================================
// Constants
// ===========================================================================

/// Device Information Service UUID (0x180A).
const DIS_UUID16: u16 = 0x180A;

/// Device Information Service UUID in full 128-bit string form, used for
/// profile registration as `remote_uuid`.
const DEVICE_INFORMATION_UUID: &str = "0000180a-0000-1000-8000-00805f9b34fb";

/// PnP ID Characteristic UUID (0x2A50).
const PNPID_UUID16: u16 = 0x2A50;

/// Expected minimum length of the PnP ID characteristic value in bytes.
/// Format: source(1) + vendor(2) + product(2) + version(2) = 7.
const PNP_ID_SIZE: usize = 7;

// ===========================================================================
// Global state — stored profile for unregistration
// ===========================================================================

/// Mutex-protected storage for the registered profile descriptor, used by
/// `deviceinfo_exit` to unregister the profile during daemon shutdown.
///
/// This follows the same pattern as `GAP_PROFILE` in `gap.rs`.
static DEVICEINFO_PROFILE: std::sync::Mutex<Option<BtdProfile>> =
    std::sync::Mutex::new(None);

// ===========================================================================
// PnP ID Read Handler
// ===========================================================================

/// Read the PnP ID characteristic value and store the decoded result on the
/// device object.
///
/// Equivalent to the C `handle_pnpid()` + `read_pnpid_cb()` from
/// `deviceinfo.c`. The GATT client read is asynchronous — the callback fires
/// when the ATT READ response arrives.
///
/// # Arguments
///
/// * `device` — Shared reference to the device whose PnP ID will be set.
/// * `value_handle` — ATT handle of the PnP ID characteristic value.
/// * `client` — GATT client for performing the read operation.
fn handle_pnpid(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
    value_handle: u16,
    client: &Arc<BtGattClient>,
) {
    let device_clone = Arc::clone(device);

    let callback: ReadCallback = Box::new(
        move |success: bool, att_ecode: u8, data: &[u8]| {
            if !success {
                error!("Error reading PNP_ID value: ATT error 0x{:02x}", att_ecode);
                btd_error(
                    0,
                    &format!(
                        "Error reading PNP_ID value: ATT error 0x{:02x}",
                        att_ecode
                    ),
                );
                return;
            }

            if data.len() < PNP_ID_SIZE {
                error!(
                    "Error reading PNP_ID: Invalid pdu length received (got {}, need {})",
                    data.len(),
                    PNP_ID_SIZE
                );
                btd_error(0, "Error reading PNP_ID: Invalid pdu length received");
                return;
            }

            // Decode the 7-byte PnP ID value:
            //   offset 0: source (u8)
            //   offset 1..3: vendor (u16 LE)
            //   offset 3..5: product (u16 LE)
            //   offset 5..7: version (u16 LE)
            let source = data[0];
            let vendor = u16::from_le_bytes([data[1], data[2]]);
            let product = u16::from_le_bytes([data[3], data[4]]);
            let version = u16::from_le_bytes([data[5], data[6]]);

            debug!(
                "DIS PnP ID read complete: source=0x{:02X} vendor=0x{:04X} \
                 product=0x{:04X} version=0x{:04X}",
                source, vendor, product, version
            );
            btd_debug(
                0,
                &format!(
                    "DIS PnP ID: source=0x{:02X} vendor=0x{:04X} \
                     product=0x{:04X} version=0x{:04X}",
                    source, vendor, product, version
                ),
            );

            // Store the decoded PnP ID on the device. The source field is
            // widened to u16 to match the Rust BtdDevice::set_pnp_id()
            // signature (consistent with the device model's PnpId struct).
            let device_ref = device_clone.clone();
            tokio::spawn(async move {
                let mut dev = device_ref.lock().await;
                dev.set_pnp_id(u16::from(source), vendor, product, version);
            });
        },
    );

    if client.read_value(value_handle, callback) == 0 {
        debug!("Failed to send request to read PnP ID");
        btd_debug(0, "Failed to send request to read PnP ID");
    }
}

// ===========================================================================
// Characteristic Dispatcher
// ===========================================================================

/// Examine a single DIS characteristic and dispatch to the appropriate
/// handler if it is the PnP ID characteristic.
///
/// All other DIS characteristics (Manufacturer Name, Model Number, Serial
/// Number, Hardware Revision, Firmware Revision, Software Revision, System
/// ID, IEEE Regulatory Certification) are logged and ignored — only the PnP
/// ID is read by this plugin, exactly matching the C behavior.
///
/// Replaces C `handle_characteristic()` from `deviceinfo.c`.
fn handle_characteristic(
    char_attr: &GattDbAttribute,
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
    client: &Arc<BtGattClient>,
) {
    let char_data = match char_attr.get_char_data() {
        Some(data) => data,
        None => {
            error!("Failed to obtain characteristic data");
            btd_error(0, "Failed to obtain characteristic data");
            return;
        }
    };

    let pnpid_uuid = BtUuid::from_u16(PNPID_UUID16);

    if char_data.uuid == pnpid_uuid {
        handle_pnpid(device, char_data.value_handle, client);
    } else {
        let uuid_str = char_data.uuid.to_string();
        debug!(
            "Unsupported DIS characteristic: handle 0x{:04x} uuid {}",
            char_data.value_handle, uuid_str
        );
        btd_debug(
            0,
            &format!(
                "Unsupported DIS characteristic: handle 0x{:04x} uuid {}",
                char_data.value_handle, uuid_str
            ),
        );
    }
}

// ===========================================================================
// Service Discovery
// ===========================================================================

/// Process a discovered Device Information Service.
///
/// Iterates all characteristics within the service and dispatches each to
/// `handle_characteristic` for PnP ID identification.
///
/// Replaces C `foreach_deviceinfo_service()` from `deviceinfo.c`.
fn foreach_deviceinfo_service(
    service_attr: GattDbAttribute,
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
    client: &Arc<BtGattClient>,
) {
    if let Some(svc) = service_attr.get_service() {
        svc.foreach_char(|char_attr| {
            handle_characteristic(&char_attr, device, client);
        });
    }
}

// ===========================================================================
// Profile Lifecycle Callbacks
// ===========================================================================

/// Probe callback — invoked when a device with DIS is discovered.
///
/// Always returns `Ok(())` since the deviceinfo profile does not maintain
/// persistent per-device state. All work is performed during `accept`.
///
/// Replaces C `deviceinfo_probe()` from `deviceinfo.c`.
fn deviceinfo_probe(
    _device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> Result<(), BtdError> {
    debug!("deviceinfo profile probe");
    btd_debug(0, "deviceinfo profile probe");
    Ok(())
}

/// Remove callback — invoked when a previously-probed device is removed.
///
/// No-op — the deviceinfo profile has no persistent per-device state to
/// release.
///
/// Replaces C `deviceinfo_remove()` from `deviceinfo.c`.
fn deviceinfo_remove(_device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    debug!("deviceinfo profile remove");
    btd_debug(0, "deviceinfo profile remove");
}

/// Accept callback — invoked when a GATT connection is established to a
/// device exposing the DIS service.
///
/// Acquires the GATT database and client from the device, discovers the DIS
/// service (UUID 0x180A), iterates its characteristics, and reads the PnP ID
/// characteristic (UUID 0x2A50) if found.
///
/// Replaces C `deviceinfo_accept()` from `deviceinfo.c`.
async fn deviceinfo_accept(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> Result<(), BtdError> {
    debug!("deviceinfo profile accept");
    btd_debug(0, "deviceinfo profile accept");

    // Lock device to extract GATT DB and client references.
    let (gatt_db, gatt_client) = {
        let dev = device.lock().await;

        let db = match dev.get_gatt_db() {
            Some(db) => db.clone(),
            None => {
                error!("DIS: no GATT database available");
                btd_error(0, "DIS: no GATT database available");
                return Err(BtdError::NotAvailable(
                    "No GATT database available".to_owned(),
                ));
            }
        };

        let client = match dev.get_gatt_client() {
            Some(c) => Arc::clone(c),
            None => {
                error!("DIS: no GATT client available");
                btd_error(0, "DIS: no GATT client available");
                return Err(BtdError::NotAvailable(
                    "No GATT client available".to_owned(),
                ));
            }
        };

        (db, client)
    };

    // Discover the Device Information Service (UUID 0x180A).
    let dis_uuid = BtUuid::from_u16(DIS_UUID16);
    let mut service_attrs = Vec::new();
    gatt_db.foreach_service(Some(&dis_uuid), |attr| {
        service_attrs.push(attr);
    });

    if service_attrs.is_empty() {
        error!("Unable to find Device Information service");
        btd_error(0, "Unable to find Device Information service");
        // Return Ok(()) to match C behavior: deviceinfo_accept always returns
        // 0 and calls btd_service_connecting_complete(service, 0) even when
        // the DIS is not found. The C code logs the error but does not fail
        // the accept.
    }

    for attr in service_attrs {
        foreach_deviceinfo_service(attr, device, &gatt_client);
    }

    Ok(())
}

/// Disconnect callback — invoked when the GATT connection is torn down.
///
/// Signals disconnecting complete immediately since the deviceinfo profile
/// has no persistent connection state to clean up.
///
/// Replaces C `deviceinfo_disconnect()` from `deviceinfo.c`.
async fn deviceinfo_disconnect(
    _device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> Result<(), BtdError> {
    debug!("deviceinfo profile disconnect");
    btd_debug(0, "deviceinfo profile disconnect");
    Ok(())
}

// ===========================================================================
// Plugin Init / Exit
// ===========================================================================

/// Initialize the deviceinfo plugin.
///
/// Builds and registers a `BtdProfile` for the Device Information Service.
/// The profile matches `DEVICE_INFORMATION_UUID` (0x180A) on both LE and
/// BR/EDR bearers, since DIS can appear on either transport.
///
/// Replaces C `deviceinfo_init()` from `deviceinfo.c`.
fn deviceinfo_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("deviceinfo plugin init");

    // Build the profile descriptor.
    let mut profile = BtdProfile::new("deviceinfo");
    profile.bearer = BTD_PROFILE_BEARER_ANY;
    profile.remote_uuid = Some(DEVICE_INFORMATION_UUID.to_owned());

    // Set lifecycle callbacks.
    profile.set_device_probe(Box::new(deviceinfo_probe));
    profile.set_device_remove(Box::new(deviceinfo_remove));

    profile.set_accept(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { deviceinfo_accept(&device).await })
    }));

    profile.set_disconnect(Box::new(|device| {
        let device = Arc::clone(device);
        Box::pin(async move { deviceinfo_disconnect(&device).await })
    }));

    // Store a copy for unregistration during exit.
    {
        let stored = BtdProfile::new("deviceinfo");
        let mut guard = DEVICEINFO_PROFILE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(stored);
    }

    // Register the profile asynchronously (the daemon is already running
    // its tokio runtime when plugin_init is called).
    tokio::spawn(async move {
        if let Err(e) = btd_profile_register(profile).await {
            error!("Failed to register deviceinfo profile: {}", e);
            btd_error(
                0,
                &format!("Failed to register deviceinfo profile: {}", e),
            );
        }
    });

    Ok(())
}

/// Shut down the deviceinfo plugin.
///
/// Unregisters the profile descriptor from the daemon's profile registry.
///
/// Replaces C `deviceinfo_exit()` from `deviceinfo.c`.
fn deviceinfo_exit() {
    debug!("deviceinfo plugin exit");

    let profile_opt = {
        let mut guard = DEVICEINFO_PROFILE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.take()
    };

    if let Some(profile) = profile_opt {
        tokio::spawn(async move {
            btd_profile_unregister(&profile).await;
        });
    }
}

// ===========================================================================
// Exported struct — DeviceInfoPlugin
// ===========================================================================

/// Device Information Service plugin descriptor.
///
/// Provides the public API surface for the DIS PnP ID reader plugin. The
/// actual plugin lifecycle is handled through [`crate::plugin::PluginDesc`]
/// registered via [`inventory::submit!`], which calls the module-level
/// [`deviceinfo_init`] and [`deviceinfo_exit`] functions.
///
/// This struct satisfies the export schema requirement for a
/// `DeviceInfoPlugin` class with `name()`, `version()`, `priority()`,
/// `init()`, and `exit()` members.
pub struct DeviceInfoPlugin;

impl DeviceInfoPlugin {
    /// Returns the unique plugin name: `"deviceinfo"`.
    pub fn name(&self) -> &str {
        "deviceinfo"
    }

    /// Returns the plugin version string (matches daemon VERSION).
    pub fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    /// Returns the plugin initialization priority: `Default` (0).
    pub fn priority(&self) -> PluginPriority {
        PluginPriority::Default
    }

    /// Initializes the deviceinfo plugin.
    ///
    /// Delegates to the module-level [`deviceinfo_init`] function.
    pub fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        deviceinfo_init()
    }

    /// Cleans up the deviceinfo plugin.
    ///
    /// Delegates to the module-level [`deviceinfo_exit`] function.
    pub fn exit(&self) {
        deviceinfo_exit()
    }
}

// ===========================================================================
// Plugin registration via inventory
// ===========================================================================

/// Register the deviceinfo plugin at link time so that `plugin_init()` in
/// the plugin framework discovers it via `inventory::iter::<PluginDesc>()`.
///
/// Replaces C's `BLUETOOTH_PLUGIN_DEFINE(deviceinfo, VERSION,
/// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, deviceinfo_init, deviceinfo_exit)`.
#[allow(unsafe_code)]
mod _deviceinfo_inventory {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "deviceinfo",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::Default,
            init: super::deviceinfo_init,
            exit: super::deviceinfo_exit,
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
    fn test_plugin_name() {
        let plugin = DeviceInfoPlugin;
        assert_eq!(plugin.name(), "deviceinfo");
    }

    #[test]
    fn test_plugin_version() {
        let plugin = DeviceInfoPlugin;
        assert!(!plugin.version().is_empty());
    }

    #[test]
    fn test_plugin_priority() {
        let plugin = DeviceInfoPlugin;
        assert_eq!(plugin.priority(), PluginPriority::Default);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DIS_UUID16, 0x180A);
        assert_eq!(PNPID_UUID16, 0x2A50);
        assert_eq!(PNP_ID_SIZE, 7);
        assert_eq!(
            DEVICE_INFORMATION_UUID,
            "0000180a-0000-1000-8000-00805f9b34fb"
        );
    }

    #[test]
    fn test_pnpid_uuid_comparison() {
        let pnpid = BtUuid::from_u16(PNPID_UUID16);
        let other = BtUuid::from_u16(0x2A01); // Appearance
        assert_ne!(pnpid, other);
        assert_eq!(pnpid, BtUuid::from_u16(0x2A50));
    }

    #[test]
    fn test_dis_uuid_creation() {
        let dis_uuid = BtUuid::from_u16(DIS_UUID16);
        let expected = BtUuid::from_u16(0x180A);
        assert_eq!(dis_uuid, expected);
    }

    #[test]
    fn test_dis_uuid_string() {
        let dis_uuid = BtUuid::from_u16(DIS_UUID16);
        let s = dis_uuid.to_string();
        assert_eq!(s, "0000180a-0000-1000-8000-00805f9b34fb");
    }

    #[test]
    fn test_pnpid_uuid_string() {
        let pnpid = BtUuid::from_u16(PNPID_UUID16);
        let s = pnpid.to_string();
        assert_eq!(s, "00002a50-0000-1000-8000-00805f9b34fb");
    }
}
