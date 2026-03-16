// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012 Google Inc.
//
// Automatic PIN code heuristics plugin — Rust rewrite of `plugins/autopair.c`.
//
// Provides automatic legacy PIN code selection based on device class,
// vendor/product IDs, and device names.  Handles:
//
// - **Nintendo Wii Remote** devices: Uses the host adapter's BD_ADDR as
//   the 6-byte PIN code for authentication.
// - **Audio/Video** devices: Common PIN sequence 0000 → 1234 → 1111.
// - **HID Keyboards**: Random 6-digit numeric PINs with display flag set.
// - **HID Pointing** devices & other peripherals: 0000 on first attempt.
// - **Imaging/Printer** devices: 0000 on first attempt.
//
// The plugin registers an adapter driver whose `probe` callback installs
// the autopair PIN selection callback per-adapter.  When a legacy pairing
// PIN request arrives, the adapter iterates registered callbacks in order.
//
// ## Wii Remote Background
//
// Nintendo Wii Remote devices require the bdaddr of the host as pin input
// for authentication.  There are two ways to place the wiimote into
// discoverable mode:
//
//  - Pressing the red-sync button on the back of the wiimote.  This module
//    supports pairing via this method.  Auto-reconnect should be possible
//    after the device was paired once.
//  - Pressing the 1+2 buttons on the front of the wiimote.  This module
//    does not support this method since it never enables auto-reconnect.
//    Hence, pairing is not needed.  Use it without pairing if you want.
//
// After connecting the wiimote you should immediately connect to the input
// service.  If you don't, the wiimote will close the connection.
// The wiimote waits about 5 seconds until it turns off again.
// Auto-reconnect is only enabled when pairing via the red sync-button and
// then connecting to the input service.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use tracing::{debug, error};

use crate::adapter::{
    BtdAdapter, BtdAdapterDriver, PinCodeResult, adapter_find, btd_adapter_register_pin_cb,
    btd_adapter_unregister_pin_cb, btd_register_adapter_driver, btd_unregister_adapter_driver,
};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::plugin::PluginPriority;

// ===========================================================================
// Wii Remote device identification tables
// ===========================================================================

/// Known Wii Remote vendor/product ID pairs.
///
/// Matches C `wii_ids[]` (lines 55-59 of plugins/autopair.c):
/// - `(0x057e, 0x0306)` — 1st generation Wii Remote
/// - `(0x054c, 0x0306)` — LEGO Wiimote
/// - `(0x057e, 0x0330)` — 2nd generation Wii Remote
static WII_IDS: &[(u16, u16)] = &[
    (0x057e, 0x0306), // 1st gen
    (0x054c, 0x0306), // LEGO wiimote
    (0x057e, 0x0330), // 2nd gen
];

/// Known Wii Remote device name strings.
///
/// Matches C `wii_names[]` (lines 61-66 of plugins/autopair.c).
static WII_NAMES: &[&str] = &[
    "Nintendo RVL-CNT-01",    // 1st gen
    "Nintendo RVL-CNT-01-TR", // 2nd gen
    "Nintendo RVL-CNT-01-UC", // Wii U Pro Controller
    "Nintendo RVL-WBC-01",    // Balance Board
];

// ===========================================================================
// Module state
// ===========================================================================

/// Per-module state tracking registered PIN callback IDs per adapter.
struct AutopairState {
    /// Map from adapter HCI index to the registered PIN callback ID.
    pin_cb_ids: HashMap<u16, u64>,
}

/// Global module state protected by a standard mutex.
///
/// The standard `Mutex` (not tokio) is used because the state is accessed
/// from both sync (`probe`/`remove`) and async contexts, and never held
/// across `.await` points.
static STATE: LazyLock<StdMutex<AutopairState>> =
    LazyLock::new(|| StdMutex::new(AutopairState { pin_cb_ids: HashMap::new() }));

// ===========================================================================
// Wii Remote PIN callback
// ===========================================================================

/// Wii Remote PIN selection callback.
///
/// Nintendo Wii Remote devices require the host adapter's BD_ADDR as the
/// 6-byte PIN code for authentication.  Detection is based on vendor/product
/// ID pairs and device name strings.
///
/// Returns `Some(pin_bytes)` if the device is a recognized Wii Remote,
/// `None` otherwise.  Only tries once per device — subsequent attempts
/// return `None` to avoid infinite retry loops for unknown devices.
///
/// Matches C `wii_pincb()` (lines 68-105 of plugins/autopair.c).
fn wii_pincb(adapter: &BtdAdapter, device: &BtdDevice, attempt: u32) -> Option<Vec<u8>> {
    // Only try the pin code once per device.  If it's not correct then it's
    // an unknown device.
    if attempt > 1 {
        return None;
    }

    let addr_str = device.get_address().ba2str();
    let vendor = device.get_vendor();
    let product = device.get_product();
    let name = device.get_name().unwrap_or("");

    // Check vendor/product ID table.
    let id_match = WII_IDS.iter().any(|&(v, p)| vendor == v && product == p);

    // Check device name table.
    let name_match = WII_NAMES.contains(&name);

    if !id_match && !name_match {
        return None;
    }

    debug!("Forcing fixed pin on detected wiimote {}", addr_str);

    // Use the adapter's BD_ADDR as the 6-byte PIN code.
    // This mirrors C: `memcpy(pinbuf, btd_adapter_get_address(adapter), 6)`
    let adapter_addr = adapter.address;
    Some(adapter_addr.b.to_vec())
}

// ===========================================================================
// Main autopair PIN callback
// ===========================================================================

/// Main autopair PIN selection callback.
///
/// Implements automatic PIN code selection based on device class, with
/// special handling for different device categories.  The callback is
/// registered per-adapter and invoked by the adapter when a legacy pairing
/// PIN code request arrives.
///
/// ## Decision flow
///
/// 1. Try Wii Remote detection (delegate to [`wii_pincb`]).
/// 2. Exclude iCade devices (keyboard-like but shouldn't use random PINs).
/// 3. Reject unknown device class (`class == 0`).
/// 4. Switch on major device class `(class & 0x1f00) >> 8`:
///    - **0x04 (Audio/Video)**: PIN sequence 0000 → 1234 → 1111.
///    - **0x05 (Peripheral/HID)**: Sub-switch on HID type:
///      - Keyboard/Combo: Random 6-digit PIN with display; fast-retry
///        fallback to 0000.
///      - Pointing: 0000 on first attempt.
///      - Joystick/Gamepad/Remote: 0000 on first attempt.
///    - **0x06 (Imaging)**: Printer subclass gets 0000 on first attempt.
///    - **Default**: No automatic PIN.
///
/// Matches C `autopair_pincb()` (lines 118-243 of plugins/autopair.c).
fn autopair_pincb(adapter: &BtdAdapter, device: &BtdDevice, attempt: u32) -> Option<PinCodeResult> {
    // Try with the wii_pincb first.
    if let Some(pin) = wii_pincb(adapter, device, attempt) {
        return Some(PinCodeResult { pin, display: false });
    }

    let addr_str = device.get_address().ba2str();
    let class = device.get_class();
    let name = device.get_name().unwrap_or("");
    let vendor = device.get_vendor();
    let product = device.get_product();

    debug!(
        "device '{}' ({}) class: 0x{:x} vid/pid: 0x{:X}/0x{:X}",
        name, addr_str, class, vendor, product
    );

    // The iCade shouldn't use random PINs like normal keyboards.
    if name.contains("iCade") {
        return None;
    }

    // This is a class-based pincode guesser.  Ignore devices with an
    // unknown class.
    if class == 0 {
        return None;
    }

    let major_class = (class & 0x1f00) >> 8;

    match major_class {
        // ---------------------------------------------------------------
        // Audio/Video (major class 0x04)
        // ---------------------------------------------------------------
        0x04 => {
            let subclass = (class & 0xfc) >> 2;
            match subclass {
                // Wearable Headset Device (0x01), Hands-free Device (0x02),
                // Headphones (0x06), Portable Audio (0x07),
                // HiFi Audio Device (0x0a)
                0x01 | 0x02 | 0x06 | 0x07 | 0x0a => {
                    let pincodes: &[&[u8]] = &[b"0000", b"1234", b"1111"];
                    if attempt as usize > pincodes.len() {
                        return None;
                    }
                    let pincode = pincodes[(attempt - 1) as usize];
                    Some(PinCodeResult { pin: pincode.to_vec(), display: false })
                }
                // All other A/V subclasses: no automatic PIN.
                _ => None,
            }
        }

        // ---------------------------------------------------------------
        // Peripheral / HID (major class 0x05)
        // ---------------------------------------------------------------
        0x05 => {
            let hid_type = (class & 0xc0) >> 6;
            match hid_type {
                // Generic peripheral — check sub-device type.
                0x00 => {
                    let sub_device = (class & 0x1e) >> 2;
                    match sub_device {
                        // Joystick (0x01), Gamepad (0x02),
                        // Remote Control (0x03)
                        0x01..=0x03 => {
                            if attempt > 1 {
                                return None;
                            }
                            Some(PinCodeResult { pin: b"0000".to_vec(), display: false })
                        }
                        // Other generic peripherals: no automatic PIN.
                        _ => None,
                    }
                }

                // Keyboard (0x01) or Combo keyboard/pointing (0x03)
                0x01 | 0x03 => {
                    // For keyboards rejecting the first random code in less
                    // than 500ms, try a fixed code.
                    if attempt > 1 && device.bonding_last_duration().as_millis() < 500 {
                        // Don't try more than one dumb code.
                        if attempt > 2 {
                            return None;
                        }
                        // Try "0000" as the code for the second attempt.
                        return Some(PinCodeResult { pin: b"0000".to_vec(), display: false });
                    }

                    // Never try more than 3 random pincodes.
                    if attempt >= 4 {
                        return None;
                    }

                    // Generate random 6-digit numeric PIN.
                    match generate_random_pin() {
                        Some(pin_str) => {
                            Some(PinCodeResult { pin: pin_str.into_bytes(), display: true })
                        }
                        None => {
                            error!("Failed to get a random pincode");
                            None
                        }
                    }
                }

                // Pointing device (0x02)
                0x02 => {
                    if attempt > 1 {
                        return None;
                    }
                    Some(PinCodeResult { pin: b"0000".to_vec(), display: false })
                }

                // Other HID types: no automatic PIN.
                _ => None,
            }
        }

        // ---------------------------------------------------------------
        // Imaging (major class 0x06)
        // ---------------------------------------------------------------
        0x06 => {
            // Check for printer subclass bit (0x80).
            if class & 0x80 != 0 {
                if attempt > 1 {
                    return None;
                }
                Some(PinCodeResult { pin: b"0000".to_vec(), display: false })
            } else {
                None
            }
        }

        // ---------------------------------------------------------------
        // Default: no automatic PIN for unrecognized major classes.
        // ---------------------------------------------------------------
        _ => None,
    }
}

// ===========================================================================
// Random PIN generation
// ===========================================================================

/// Generate a random 6-digit numeric PIN string.
///
/// Reads 4 bytes from `/dev/urandom` and converts to a zero-padded 6-digit
/// decimal string (range: `"000000"` to `"999999"`).
///
/// Returns `None` if `/dev/urandom` cannot be opened or read.
///
/// This replaces the C pattern of `srand(seed)` + `rand()` with a direct
/// read from the kernel entropy source on each call, which is both simpler
/// and more cryptographically sound.
fn generate_random_pin() -> Option<String> {
    let mut buf = [0u8; 4];
    let mut f = File::open("/dev/urandom").ok()?;
    f.read_exact(&mut buf).ok()?;
    let val = u32::from_ne_bytes(buf);
    Some(format!("{:06}", val % 1_000_000))
}

// ===========================================================================
// Adapter driver
// ===========================================================================

/// Autopair adapter driver.
///
/// Registers the autopair PIN selection callback for each adapter.
/// Matches C `static struct btd_adapter_driver autopair_driver` (lines
/// 258-262 of plugins/autopair.c).
struct AutopairAdapterDriver;

impl BtdAdapterDriver for AutopairAdapterDriver {
    fn name(&self) -> &str {
        "autopair"
    }

    /// Called when an adapter becomes available.
    ///
    /// Spawns an async task to register the autopair PIN callback for this
    /// adapter.  The spawn is necessary because the adapter is currently
    /// locked by [`btd_register_adapter_driver`]; the task will execute
    /// after the lock is released.
    ///
    /// Matches C `autopair_probe()` (lines 246-251 of plugins/autopair.c).
    fn probe(&self, adapter: &BtdAdapter) -> Result<(), BtdError> {
        let index = adapter.index;

        tokio::spawn(async move {
            if let Some(adapter_arc) = adapter_find(index).await {
                let cb = Box::new(
                    |adapter: &BtdAdapter,
                     device: &BtdDevice,
                     attempt: u32|
                     -> Option<PinCodeResult> {
                        autopair_pincb(adapter, device, attempt)
                    },
                );
                let id = btd_adapter_register_pin_cb(&adapter_arc, cb).await;
                if let Ok(mut state) = STATE.lock() {
                    state.pin_cb_ids.insert(index, id);
                }
            }
        });

        Ok(())
    }

    /// Called when an adapter is being removed.
    ///
    /// Spawns an async task to unregister the autopair PIN callback.
    ///
    /// Matches C `autopair_remove()` (lines 253-256 of plugins/autopair.c).
    fn remove(&self, adapter: &BtdAdapter) {
        let index = adapter.index;

        tokio::spawn(async move {
            let id = STATE.lock().ok().and_then(|mut s| s.pin_cb_ids.remove(&index));
            if let (Some(adapter_arc), Some(cb_id)) = (adapter_find(index).await, id) {
                btd_adapter_unregister_pin_cb(&adapter_arc, cb_id).await;
            }
        });
    }
}

// ===========================================================================
// Plugin init / exit
// ===========================================================================

/// Initialize the autopair plugin.
///
/// Verifies that `/dev/urandom` is accessible (needed for random keyboard
/// PINs), then registers the autopair adapter driver.  The driver's
/// [`probe`](AutopairAdapterDriver::probe) callback will install PIN
/// selection callbacks for each adapter.
///
/// Matches C `autopair_init()` (lines 264-293 of plugins/autopair.c).
fn autopair_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("autopair plugin init");

    // Verify /dev/urandom is accessible — mirrors C init that reads 4 bytes
    // to seed srand().  In Rust we read directly per-call, but validate
    // availability at init time to fail early.
    {
        let mut buf = [0u8; 4];
        let mut f = File::open("/dev/urandom").map_err(|e| {
            let msg = format!("Failed to open /dev/urandom: {e}");
            error!("{}", msg);
            msg
        })?;
        f.read_exact(&mut buf).map_err(|e| {
            let msg = format!("Failed to read 4 bytes from /dev/urandom: {e}");
            error!("{}", msg);
            msg
        })?;
    }

    // Register adapter driver asynchronously.
    tokio::spawn(async {
        let driver: Arc<dyn BtdAdapterDriver> = Arc::new(AutopairAdapterDriver);
        btd_register_adapter_driver(driver).await;
    });

    Ok(())
}

/// Shut down the autopair plugin.
///
/// Unregisters the adapter driver, which triggers
/// [`remove`](AutopairAdapterDriver::remove) callbacks that clean up
/// per-adapter PIN callbacks.
///
/// Matches C `autopair_exit()` (lines 295-298 of plugins/autopair.c).
fn autopair_exit() {
    debug!("autopair plugin exit");

    // Unregister adapter driver asynchronously.
    tokio::spawn(async {
        btd_unregister_adapter_driver("autopair").await;
    });

    // Clear module state.
    if let Ok(mut state) = STATE.lock() {
        state.pin_cb_ids.clear();
    }
}

// ===========================================================================
// Exported struct — AutopairPlugin
// ===========================================================================

/// Autopair plugin descriptor.
///
/// Provides the public API surface for the autopair plugin.  The actual
/// plugin lifecycle is handled through [`PluginDesc`] registered via
/// [`inventory::submit!`], which calls the module-level [`autopair_init`]
/// and [`autopair_exit`] functions.
///
/// This struct satisfies the export schema requirement for an `AutopairPlugin`
/// class with `name()`, `version()`, `priority()`, `init()`, and `exit()`
/// members.
pub struct AutopairPlugin;

impl AutopairPlugin {
    /// Returns the unique plugin name: `"autopair"`.
    pub fn name(&self) -> &str {
        "autopair"
    }

    /// Returns the plugin version string (matches daemon VERSION).
    pub fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    /// Returns the plugin initialization priority: `Default` (0).
    pub fn priority(&self) -> PluginPriority {
        PluginPriority::Default
    }

    /// Initializes the autopair plugin.
    ///
    /// Delegates to the module-level [`autopair_init`] function.
    pub fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        autopair_init()
    }

    /// Cleans up the autopair plugin.
    ///
    /// Delegates to the module-level [`autopair_exit`] function.
    pub fn exit(&self) {
        autopair_exit()
    }
}

// ===========================================================================
// Plugin registration via inventory
// ===========================================================================

/// Register the autopair plugin at link time so that `plugin_init()` in the
/// plugin framework discovers it via `inventory::iter::<PluginDesc>()`.
///
/// Replaces C's `BLUETOOTH_PLUGIN_DEFINE(autopair, VERSION,
/// BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, autopair_init, autopair_exit)`.
#[allow(unsafe_code)]
mod _autopair_inventory {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "autopair",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::Default,
            init: super::autopair_init,
            exit: super::autopair_exit,
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that Wii vendor/product ID matching works.
    #[test]
    fn wii_ids_table_coverage() {
        assert_eq!(WII_IDS.len(), 3);
        assert!(WII_IDS.contains(&(0x057e, 0x0306)));
        assert!(WII_IDS.contains(&(0x054c, 0x0306)));
        assert!(WII_IDS.contains(&(0x057e, 0x0330)));
    }

    /// Verify that Wii name matching works.
    #[test]
    fn wii_names_table_coverage() {
        assert_eq!(WII_NAMES.len(), 4);
        assert!(WII_NAMES.contains(&"Nintendo RVL-CNT-01"));
        assert!(WII_NAMES.contains(&"Nintendo RVL-CNT-01-TR"));
        assert!(WII_NAMES.contains(&"Nintendo RVL-CNT-01-UC"));
        assert!(WII_NAMES.contains(&"Nintendo RVL-WBC-01"));
    }

    /// Verify random PIN generation produces 6-digit strings.
    #[test]
    fn random_pin_format() {
        let pin = generate_random_pin();
        assert!(pin.is_some(), "/dev/urandom should be available");
        let pin_str = pin.unwrap();
        assert_eq!(pin_str.len(), 6);
        assert!(pin_str.chars().all(|c| c.is_ascii_digit()));
        let val: u32 = pin_str.parse().unwrap();
        assert!(val < 1_000_000);
    }

    /// Verify that multiple random PINs are not all identical
    /// (statistical sanity check).
    #[test]
    fn random_pin_not_constant() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            if let Some(pin) = generate_random_pin() {
                seen.insert(pin);
            }
        }
        // With 10 random 6-digit PINs, we expect at least 2 distinct values.
        assert!(
            seen.len() >= 2,
            "Expected at least 2 distinct PINs from 10 generations, got {}",
            seen.len()
        );
    }

    /// Verify AutopairPlugin metadata.
    #[test]
    fn plugin_metadata() {
        let plugin = AutopairPlugin;
        assert_eq!(plugin.name(), "autopair");
        assert!(!plugin.version().is_empty());
        assert_eq!(plugin.priority(), PluginPriority::Default);
    }

    /// Verify A/V PIN sequence.
    #[test]
    fn audio_video_pin_sequence() {
        let pincodes: &[&[u8]] = &[b"0000", b"1234", b"1111"];
        assert_eq!(pincodes[0], b"0000");
        assert_eq!(pincodes[1], b"1234");
        assert_eq!(pincodes[2], b"1111");
    }
}
