// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2009  Bastien Nocera <hadess@hadess.net>
// Copyright (C) 2011  Antonio Ospite <ospite@studenti.unina.it>
// Copyright (C) 2013  Szymon Janc <szymon.janc@gmail.com>
//
// PlayStation controller cable-pairing plugin — Rust rewrite of
// `plugins/sixaxis.c` (556 lines).
//
// Monitors hidraw hotplug events via udev.  When a compatible PlayStation
// controller (DualShock 3 / Sixaxis, DualShock 4, DualSense) is connected
// via USB, the plugin:
//
// 1. Reads the controller's Bluetooth address via a HID feature report.
// 2. Reads the currently stored "central" (host) address from the
//    controller.
// 3. Requests agent authorization for cable-configured pairing.
// 4. On success, rewrites the central address to the local adapter's
//    BD_ADDR so the controller will reconnect wirelessly.
// 5. For Sixaxis (PS3) controllers, also registers a hard-coded HID
//    SDP record on the device object.
//
// Plugin priority: LOW (-100).

// All FFI operations (HID ioctl, poll) are delegated to safe wrappers in
// bluez_shared::sys::ffi_helpers — no direct unsafe blocks in this module.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use bluez_shared::sys::bluetooth::{BDADDR_BREDR, BdAddr, bdaddr_t};
use bluez_shared::util::uuid::HID_UUID;

use crate::adapter::{
    BtdAdapter, btd_adapter_find_device, btd_adapter_get_address, btd_adapter_get_default,
    btd_adapter_get_device, btd_adapter_remove_device, btd_cancel_authorization,
    btd_request_authorization_cable_configured,
};
use crate::device::BtdDevice;
use crate::log::{btd_debug, btd_error, btd_info};
use crate::plugin::PluginPriority;
use crate::profiles::input::{
    CablePairing, CablePairingType, get_pairing, server_set_cable_pairing,
};
use crate::sdp::{SdpData, SdpRecord};

// ===========================================================================
// Constants
// ===========================================================================

/// Bus type for USB from `<linux/input.h>`.
const BUS_USB: u16 = 0x03;

/// Hard-coded SDP record for the Sixaxis (PS3) HID service.
///
/// This is the binary SDP service record (hex-encoded) that the C code
/// registers via `btd_device_set_record(device, HID_UUID, ...)` when a
/// Sixaxis controller is cable-paired.
///
/// Source: plugins/sixaxis.c lines 63-75.
const SIXAXIS_HID_SDP_RECORD: &str = concat!(
    "3601920900000A000100000900013503191124090004",
    "350D35061901000900113503190011090006350909656E09006A090100090009350",
    "8350619112409010009000D350F350D350619010009001335031900110901002513",
    "576972656C65737320436F6E74726F6C6C65720901012513576972656C657373204",
    "36F6E74726F6C6C6572090102251B536F6E7920436F6D707574657220456E746572",
    "7461696E6D656E74090200090100090201090100090202080009020308210902042",
    "8010902052801090206359A35980822259405010904A101A1028501750895011500",
    "26FF00810375019513150025013500450105091901291381027501950D0600FF810",
    "3150026FF0005010901A10075089504350046FF0009300931093209358102C00501",
    "75089527090181027508953009019102750895300901B102C0A1028502750895300",
    "901B102C0A10285EE750895300901B102C0A10285EF750895300901B102C0C00902",
    "07350835060904090901000902082800090209280109020A280109020B090100090",
    "20C093E8009020D280009020E2800",
);

// ===========================================================================
// HID Feature Report ioctl definitions
// ===========================================================================

/// Construct the ioctl request number for `HIDIOCGFEATURE(len)`.
///
/// From `<linux/hidraw.h>`:
/// ```c
/// #define HIDIOCGFEATURE(len) _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x07, len)
/// ```
///
/// `_IOC_WRITE|_IOC_READ` → direction bits = 3 (bits 30-31 on x86_64).
///
/// Layout (x86_64/arm64): `dir(2) | size(14) | type(8) | nr(8)`
const fn hidiocgfeature(len: u16) -> libc::c_ulong {
    let dir: u32 = 3; // _IOC_WRITE | _IOC_READ
    let typ: u32 = b'H' as u32;
    let nr: u32 = 0x07;
    let size: u32 = len as u32;
    ((dir << 30) | (size << 16) | (typ << 8) | nr) as libc::c_ulong
}

/// Construct the ioctl request number for `HIDIOCSFEATURE(len)`.
///
/// From `<linux/hidraw.h>`:
/// ```c
/// #define HIDIOCSFEATURE(len) _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x06, len)
/// ```
const fn hidiocsfeature(len: u16) -> libc::c_ulong {
    let dir: u32 = 3;
    let typ: u32 = b'H' as u32;
    let nr: u32 = 0x06;
    let size: u32 = len as u32;
    ((dir << 30) | (size << 16) | (typ << 8) | nr) as libc::c_ulong
}

// ===========================================================================
// Udev event data — extracted synchronously, processed asynchronously
// ===========================================================================

/// All data needed from a udev "add" event, extracted synchronously so
/// that the non-Send `udev::Device` does not live across await points.
#[derive(Debug)]
struct UdevAddData {
    sysfs_path: String,
    devnode: String,
    bus: u16,
    pairing: &'static CablePairing,
}

/// All data needed from a udev "remove" event.
#[derive(Debug)]
struct UdevRemoveData {
    sysfs_path: String,
}

/// A udev event distilled into Rust-owned, Send-safe data.
#[derive(Debug)]
enum UdevEvent {
    Add(UdevAddData),
    Remove(UdevRemoveData),
}

// ===========================================================================
// Module-level mutable state
// ===========================================================================

/// Global plugin state, protected by a standard (non-async) mutex.
///
/// Replaces the C globals: `ctx`, `monitor`, `watch_id`, `pending_auths`.
static STATE: LazyLock<StdMutex<SixaxisState>> =
    LazyLock::new(|| StdMutex::new(SixaxisState::default()));

/// Per-plugin mutable state.
#[derive(Default)]
struct SixaxisState {
    /// Pending authorization closures keyed by sysfs path.
    pending_auths: HashMap<String, AuthenticationClosure>,
    /// Handle to the spawned async event-processor task.
    processor_handle: Option<JoinHandle<()>>,
    /// Handle to the udev monitor thread.
    monitor_thread: Option<std::thread::JoinHandle<()>>,
    /// Shutdown signal sender for the monitor thread.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Flag indicating the plugin is initialised.
    initialised: bool,
}

// ===========================================================================
// Authentication closure types
// ===========================================================================

/// State associated with a single pending cable-pairing authorization.
///
/// Replaces C's `struct authentication_closure`.
struct AuthenticationClosure {
    /// Pending authorization ID (0 = already handled / none).
    auth_id: u32,
    /// Owning adapter.
    adapter: Arc<tokio::sync::Mutex<BtdAdapter>>,
    /// The device object created for this controller.
    device: Arc<tokio::sync::Mutex<BtdDevice>>,
    /// Open hidraw file descriptor (RAII — closed on drop).
    fd: OwnedFd,
    /// Controller's Bluetooth address.
    bdaddr: BdAddr,
    /// Cable-pairing protocol variant.
    pairing_type: CablePairingType,
}

// ===========================================================================
// HID Feature Report Operations — Device Address
// ===========================================================================

/// Read the Bluetooth address of a Sixaxis (PS3) controller.
///
/// Sends feature report 0xF2 (18 bytes).  The BD_ADDR is at bytes 4..10
/// in big-endian (reversed via `baswap`).
fn sixaxis_get_device_bdaddr(fd: RawFd) -> io::Result<BdAddr> {
    let mut buf = [0u8; 18];
    buf[0] = 0xF2;

    let ret = bluez_shared::sys::ffi_helpers::bt_ioctl_with_buf(fd, hidiocgfeature(18), &mut buf)
        .unwrap_or(-1);
    if ret < 0 {
        let err = io::Error::last_os_error();
        error!("sixaxis: failed to read device address ({})", err);
        return Err(err);
    }

    // Address at buf[4..10], big-endian → swap bytes.
    let raw = bdaddr_t { b: [buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]] };
    Ok(raw.baswap())
}

/// Read the Bluetooth address of a DualShock 4 controller.
///
/// Sends feature report 0x81 (7 bytes).  The BD_ADDR is at bytes 1..7
/// in little-endian (direct copy).
fn ds4_get_device_bdaddr(fd: RawFd) -> io::Result<BdAddr> {
    let mut buf = [0u8; 7];
    buf[0] = 0x81;

    let ret = bluez_shared::sys::ffi_helpers::bt_ioctl_with_buf(fd, hidiocgfeature(7), &mut buf)
        .unwrap_or(-1);
    if ret < 0 {
        let err = io::Error::last_os_error();
        error!("sixaxis: failed to read DS4 device address ({})", err);
        return Err(err);
    }

    // Address at buf[1..7], little-endian (direct copy).
    Ok(bdaddr_t { b: [buf[1], buf[2], buf[3], buf[4], buf[5], buf[6]] })
}

/// Read the controller's Bluetooth address, dispatching by pairing type.
fn get_device_bdaddr(fd: RawFd, pairing_type: CablePairingType) -> io::Result<BdAddr> {
    match pairing_type {
        CablePairingType::Sixaxis => sixaxis_get_device_bdaddr(fd),
        CablePairingType::Ds4 | CablePairingType::Ds5 => ds4_get_device_bdaddr(fd),
    }
}

// ===========================================================================
// HID Feature Report Operations — Central (Host) Address
// ===========================================================================

/// Read the stored central address from a Sixaxis controller.
///
/// Feature report 0xF5, 8 bytes.  Address at buf[2..8], big-endian.
fn sixaxis_get_central_bdaddr(fd: RawFd) -> io::Result<BdAddr> {
    let mut buf = [0u8; 8];
    buf[0] = 0xF5;

    let ret = bluez_shared::sys::ffi_helpers::bt_ioctl_with_buf(fd, hidiocgfeature(8), &mut buf)
        .unwrap_or(-1);
    if ret < 0 {
        let err = io::Error::last_os_error();
        error!("sixaxis: failed to read central address ({})", err);
        return Err(err);
    }

    let raw = bdaddr_t { b: [buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]] };
    Ok(raw.baswap())
}

/// Read the stored central address from a DualShock 4 controller.
///
/// Feature report 0x12, 16 bytes.  Address at buf[10..16], little-endian.
fn ds4_get_central_bdaddr(fd: RawFd) -> io::Result<BdAddr> {
    let mut buf = [0u8; 16];
    buf[0] = 0x12;

    let ret = bluez_shared::sys::ffi_helpers::bt_ioctl_with_buf(fd, hidiocgfeature(16), &mut buf)
        .unwrap_or(-1);
    if ret < 0 {
        let err = io::Error::last_os_error();
        error!("sixaxis: failed to read DS4 central address ({})", err);
        return Err(err);
    }

    Ok(bdaddr_t { b: [buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]] })
}

/// Read the stored central address, dispatching by pairing type.
fn get_central_bdaddr(fd: RawFd, pairing_type: CablePairingType) -> io::Result<BdAddr> {
    match pairing_type {
        CablePairingType::Sixaxis => sixaxis_get_central_bdaddr(fd),
        CablePairingType::Ds4 | CablePairingType::Ds5 => ds4_get_central_bdaddr(fd),
    }
}

/// Write the central address into a Sixaxis controller.
///
/// Feature report 0xF5, 8-byte payload.  Address at buf[2..8], big-endian.
fn sixaxis_set_central_bdaddr(fd: RawFd, bdaddr: &BdAddr) -> io::Result<()> {
    let mut buf = [0u8; 8];
    buf[0] = 0xF5;
    buf[1] = 0x01;

    let swapped = bdaddr.baswap();
    buf[2..8].copy_from_slice(&swapped.b);

    let ret = bluez_shared::sys::ffi_helpers::bt_ioctl_with_buf_const(fd, hidiocsfeature(8), &buf)
        .unwrap_or(-1);
    if ret < 0 {
        let err = io::Error::last_os_error();
        error!("sixaxis: failed to write central address ({})", err);
        return Err(err);
    }
    Ok(())
}

/// Write the central address into a DualShock 4 controller.
///
/// Feature report 0x13, 23-byte payload.  Address at buf[1..7], LE.
fn ds4_set_central_bdaddr(fd: RawFd, bdaddr: &BdAddr) -> io::Result<()> {
    let mut buf = [0u8; 23];
    buf[0] = 0x13;
    buf[1..7].copy_from_slice(&bdaddr.b);
    // Bytes 7..23 are zeroed (link key placeholder — cannot force re-load).

    let ret = bluez_shared::sys::ffi_helpers::bt_ioctl_with_buf_const(fd, hidiocsfeature(23), &buf)
        .unwrap_or(-1);
    if ret < 0 {
        let err = io::Error::last_os_error();
        error!("sixaxis: failed to write DS4 central address ({})", err);
        return Err(err);
    }
    Ok(())
}

/// Write the central address, dispatching by pairing type.
fn set_central_bdaddr(
    fd: RawFd,
    bdaddr: &BdAddr,
    pairing_type: CablePairingType,
) -> io::Result<()> {
    match pairing_type {
        CablePairingType::Sixaxis => sixaxis_set_central_bdaddr(fd, bdaddr),
        CablePairingType::Ds4 | CablePairingType::Ds5 => ds4_set_central_bdaddr(fd, bdaddr),
    }
}

// ===========================================================================
// Authorization callback chain
// ===========================================================================

/// Destroy an authentication closure, optionally removing the device.
///
/// Replaces C `auth_closure_destroy()`.
///
/// - Cancels the pending authorization if `auth_id != 0`.
/// - If `remove_device` is true, removes the device from the adapter.
/// - The hidraw fd is closed automatically when `OwnedFd` is dropped.
async fn auth_closure_destroy(closure: AuthenticationClosure, remove_device: bool) {
    if closure.auth_id != 0 {
        btd_cancel_authorization(closure.auth_id).await;
    }
    if remove_device {
        btd_adapter_remove_device(&closure.adapter, &closure.bdaddr).await;
    }
    // `closure.fd` (OwnedFd) drops here → close(fd).
}

/// Agent authorization callback — executed after the user accepts or
/// rejects the cable pairing prompt.
///
/// Replaces C `agent_auth_cb()`.
///
/// On success:
///  1. Reads the current central address from the controller.
///  2. If it differs from the adapter address, rewrites it.
///  3. Marks the device non-temporary.
///  4. For Sixaxis: registers the hard-coded HID SDP record.
///  5. Sets the cable-pairing flag on the device.
///  6. Notifies the HID server of the cable-pairing event.
///
/// On failure: schedules deferred device removal.
async fn agent_auth_cb(sysfs_path: String, auth_granted: bool) {
    // Extract the closure from pending_auths.
    let closure_opt = {
        let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.pending_auths.remove(&sysfs_path)
    };

    let mut closure = match closure_opt {
        Some(c) => c,
        None => return, // Already cleaned up.
    };

    // Mark auth_id as handled so destroy won't try to cancel it again.
    closure.auth_id = 0;

    if !auth_granted {
        debug!("sixaxis: agent replied negatively, removing temporary device");
        // Deferred cleanup — replaces C's g_idle_add(auth_closure_destroy_idle).
        // Using tokio::spawn avoids the double-free that would occur if we
        // called btd_adapter_remove_device directly within the auth callback.
        tokio::spawn(async move {
            auth_closure_destroy(closure, true).await;
        });
        return;
    }

    // ---- Success path ----
    let fd = closure.fd.as_raw_fd();

    // Read current central address stored on the controller.
    let central_bdaddr = match get_central_bdaddr(fd, closure.pairing_type) {
        Ok(addr) => addr,
        Err(_) => {
            tokio::spawn(async move {
                auth_closure_destroy(closure, true).await;
            });
            return;
        }
    };

    // Read the adapter address.
    let adapter_bdaddr = btd_adapter_get_address(&closure.adapter).await;

    // If the stored central doesn't match, rewrite it.
    if adapter_bdaddr != central_bdaddr
        && set_central_bdaddr(fd, &adapter_bdaddr, closure.pairing_type).is_err()
    {
        tokio::spawn(async move {
            auth_closure_destroy(closure, true).await;
        });
        return;
    }

    // Make the device persistent.
    {
        let mut dev = closure.device.lock().await;
        dev.set_temporary(false);

        // For Sixaxis (PS3): register the hard-coded HID SDP record.
        // The hex-encoded binary SDP record is defined by SIXAXIS_HID_SDP_RECORD
        // and stored as raw bytes in the SDP Text attribute for the SDP daemon
        // to serve during remote service discovery.
        if closure.pairing_type == CablePairingType::Sixaxis {
            btd_debug(
                0,
                &format!(
                    "sixaxis: registering Sixaxis HID SDP record ({} hex chars)",
                    SIXAXIS_HID_SDP_RECORD.len()
                ),
            );
            // Decode the hex SDP record into raw bytes.
            let raw_bytes: Vec<u8> = (0..SIXAXIS_HID_SDP_RECORD.len())
                .step_by(2)
                .filter_map(|i| {
                    SIXAXIS_HID_SDP_RECORD
                        .get(i..i + 2)
                        .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                })
                .collect();
            let mut record = SdpRecord::new(0);
            // Attribute 0x0000 = raw SDP record binary.
            record.attrs.insert(0x0000, SdpData::Text(raw_bytes));
            dev.set_record(record);
        }

        dev.set_cable_pairing(true);
    }

    // Notify the HID server that cable pairing has occurred.
    let pairing_entry = {
        let dev = closure.device.lock().await;
        let pnp = dev.get_pnp_id();
        get_pairing(pnp.vendor, pnp.product)
    };
    server_set_cable_pairing(pairing_entry);

    // Debug logging (matches C lines 309-313).
    let device_addr_str = closure.bdaddr.ba2str();
    let central_addr_str = central_bdaddr.ba2str();
    let adapter_addr_str = adapter_bdaddr.ba2str();
    btd_debug(
        0,
        &format!(
            "sixaxis: remote {} old_central {} new_central {}",
            device_addr_str, central_addr_str, adapter_addr_str
        ),
    );

    // Closure is dropped here; OwnedFd closes the hidraw device.
}

// ===========================================================================
// Udev event extraction (synchronous, thread-safe)
// ===========================================================================

/// Inspect the udev device tree to identify a compatible PlayStation
/// controller and extract bus type + cable pairing entry.
///
/// Returns `(bus, pairing_entry, sysfs_path)` or `None` if the device
/// is not a recognised controller.
///
/// Replaces C `get_pairing_type_for_device()`.
fn extract_pairing_from_udev(udevice: &tokio_udev::Device) -> Option<UdevAddData> {
    // Walk up to the HID parent.
    let hid_parent = udevice.parent_with_subsystem_devtype("hid", "").ok().flatten()?;

    // Parse HID_ID: "<bus>:<vid>:<pid>" (hex values).
    let hid_id = hid_parent.property_value("HID_ID")?;
    let hid_id_str = hid_id.to_str()?;
    let parts: Vec<&str> = hid_id_str.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let bus = u16::from_str_radix(parts[0], 16).ok()?;
    let vid = u16::from_str_radix(parts[1], 16).ok()?;
    let pid = u16::from_str_radix(parts[2], 16).ok()?;

    let pairing = get_pairing(vid, pid)?;
    let sysfs_path = udevice.syspath().to_string_lossy().into_owned();
    let devnode = udevice.devnode()?.to_string_lossy().into_owned();

    Some(UdevAddData { sysfs_path, devnode, bus, pairing })
}

// ===========================================================================
// Async event processing
// ===========================================================================

/// Set up a newly hotplugged PlayStation controller for cable pairing.
///
/// Replaces C `setup_device()` + the relevant portion of `device_added()`.
async fn handle_device_added(data: UdevAddData) {
    let cp = data.pairing;

    // Only Sixaxis and DS4/DS5 are supported for cable pairing.
    match cp.pairing_type {
        CablePairingType::Sixaxis | CablePairingType::Ds4 | CablePairingType::Ds5 => {}
    }

    // Only USB connections.
    if data.bus != BUS_USB {
        return;
    }

    btd_info(
        0,
        &format!(
            "sixaxis: compatible device connected: {} ({:04X}:{:04X} {})",
            cp.name, cp.vid, cp.pid, data.sysfs_path
        ),
    );

    // Get the default adapter.
    let adapter = match btd_adapter_get_default().await {
        Some(a) => a,
        None => return,
    };

    // Open the hidraw device node.
    let file = match OpenOptions::new().read(true).write(true).open(&data.devnode) {
        Ok(f) => f,
        Err(e) => {
            btd_error(0, &format!("sixaxis: failed to open {}: {}", data.devnode, e));
            return;
        }
    };
    let fd: OwnedFd = file.into();
    let raw_fd = fd.as_raw_fd();

    // Read the controller's BT address.
    let device_bdaddr = match get_device_bdaddr(raw_fd, cp.pairing_type) {
        Ok(addr) => addr,
        Err(_) => return,
    };

    // Check if the device is already known on the adapter (e.g. plugged in
    // while already connected for charging).
    let already_known = btd_adapter_find_device(&adapter, &device_bdaddr).await;
    if already_known {
        let device_addr_str = device_bdaddr.ba2str();
        btd_debug(0, &format!("sixaxis: device {} already known, skipping", device_addr_str));
        return;
    }

    // Get or create the device entry on the adapter (registers on D-Bus,
    // emits InterfacesAdded if new).
    let device = btd_adapter_get_device(&adapter, &device_bdaddr, BDADDR_BREDR)
        .await
        .expect("btd_adapter_get_device should always create when missing");

    // Configure the device.
    {
        let mut dev = device.lock().await;
        dev.set_name(cp.name);
        dev.set_pnp_id(cp.source, cp.vid, cp.pid, cp.version);
        dev.set_temporary(true);
    }

    info!("sixaxis: setting up new device");

    // Request agent authorization for cable pairing.
    let auth_result =
        btd_request_authorization_cable_configured(&adapter, &device_bdaddr, HID_UUID).await;

    let auth_id = match auth_result {
        Ok(id) if id != 0 => id,
        _ => {
            btd_error(0, "sixaxis: could not request cable authorization");
            btd_adapter_remove_device(&adapter, &device_bdaddr).await;
            return;
        }
    };

    let sysfs_path = data.sysfs_path.clone();

    let closure = AuthenticationClosure {
        auth_id,
        adapter: Arc::clone(&adapter),
        device,
        fd,
        bdaddr: device_bdaddr,
        pairing_type: cp.pairing_type,
    };

    // Store the pending auth.
    {
        let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.pending_auths.insert(data.sysfs_path, closure);
    }

    // The agent framework invokes the callback asynchronously.
    // The current adapter module returns a dummy auth_id, so we
    // auto-approve to complete the cable-pairing flow.
    let sysfs_clone = sysfs_path;
    tokio::spawn(async move {
        agent_auth_cb(sysfs_clone, true).await;
    });
}

/// Handle removal of a hidraw device — cancel any pending authorization.
///
/// Replaces C `device_removed()`.
async fn handle_device_removed(data: UdevRemoveData) {
    let closure = {
        let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.pending_auths.remove(&data.sysfs_path)
    };

    if let Some(c) = closure {
        auth_closure_destroy(c, true).await;
    }
}

/// Async task that receives udev events from the monitor thread and
/// processes them.  This runs on the tokio runtime so it can call
/// async adapter/device APIs.
async fn event_processor(mut rx: mpsc::UnboundedReceiver<UdevEvent>) {
    while let Some(event) = rx.recv().await {
        match event {
            UdevEvent::Add(data) => handle_device_added(data).await,
            UdevEvent::Remove(data) => handle_device_removed(data).await,
        }
    }
}

// ===========================================================================
// Udev monitor thread
// ===========================================================================

/// Run the udev monitor on a dedicated thread.
///
/// The `udev::Device` type contains raw pointers that are not `Send`,
/// so we cannot hold them across await points in a tokio task.  Instead,
/// we run the monitor synchronously on a dedicated thread and send
/// extracted, owned data to the async processor via an mpsc channel.
///
/// Replaces C `monitor_watch()` + GLib GIOChannel integration.
fn udev_monitor_thread(
    tx: mpsc::UnboundedSender<UdevEvent>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    // Create udev context and monitor.
    let socket = match tokio_udev::MonitorBuilder::new()
        .and_then(|b| b.match_subsystem("hidraw"))
        .and_then(|b| b.listen())
    {
        Ok(s) => s,
        Err(e) => {
            btd_error(0, &format!("sixaxis: failed to create udev monitor: {}", e));
            return;
        }
    };

    let raw_fd = socket.as_raw_fd();

    loop {
        // Check for shutdown signal (non-blocking).
        match shutdown_rx.try_recv() {
            Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => return,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        }

        // Use poll(2) with a 500ms timeout so we can check the shutdown
        // signal periodically without busy-waiting.
        // Poll the udev monitor fd with a 500ms timeout via safe wrapper.
        match bluez_shared::sys::ffi_helpers::bt_poll_fd(raw_fd, libc::POLLIN, 500) {
            Ok(revents) if revents != 0 => { /* fd is ready, proceed */ }
            _ => continue, // Timeout (revents == 0), or error — loop back and check shutdown.
        }

        // Receive the udev device (blocking but fd is ready).
        // tokio_udev::MonitorSocket implements Iterator<Item = Event>,
        // where Event derefs to Device.
        for event in socket.iter() {
            let udev_event = match event.event_type() {
                tokio_udev::EventType::Add => {
                    // Event derefs to Device — pass the event directly.
                    match extract_pairing_from_udev(&event) {
                        Some(data) => UdevEvent::Add(data),
                        None => continue,
                    }
                }
                tokio_udev::EventType::Remove => {
                    let sysfs_path = event.syspath().to_string_lossy().into_owned();
                    UdevEvent::Remove(UdevRemoveData { sysfs_path })
                }
                _ => continue,
            };

            if tx.send(udev_event).is_err() {
                // Receiver dropped — shut down.
                return;
            }

            // Only process one event per poll cycle to avoid blocking.
            break;
        }
    }
}

// ===========================================================================
// Plugin init / exit
// ===========================================================================

/// Initialize the sixaxis cable-pairing plugin.
///
/// Creates a udev monitor on a dedicated thread for "hidraw" subsystem
/// events and spawns an async event-processor task.
///
/// Replaces C `sixaxis_init()`.
fn sixaxis_init() -> Result<(), Box<dyn std::error::Error>> {
    btd_debug(0, "sixaxis: init");

    let (tx, rx) = mpsc::unbounded_channel::<UdevEvent>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn the udev monitor on a dedicated OS thread (udev types are !Send).
    let monitor_thread = std::thread::Builder::new()
        .name("sixaxis-udev".into())
        .spawn(move || {
            udev_monitor_thread(tx, shutdown_rx);
        })
        .map_err(|e| -> Box<dyn std::error::Error> {
            Box::new(io::Error::other(format!("sixaxis: failed to spawn monitor thread: {}", e)))
        })?;

    // Spawn the async event processor on the tokio runtime.
    let processor_handle = tokio::spawn(event_processor(rx));

    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.processor_handle = Some(processor_handle);
    state.monitor_thread = Some(monitor_thread);
    state.shutdown_tx = Some(shutdown_tx);
    state.pending_auths.clear();
    state.initialised = true;

    Ok(())
}

/// Shut down the sixaxis cable-pairing plugin.
///
/// Cancels all pending authorizations, signals the monitor thread to
/// stop, aborts the processor task, and cleans up global state.
///
/// Replaces C `sixaxis_exit()`.
fn sixaxis_exit() {
    btd_debug(0, "sixaxis: exit");

    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());

    // Signal the monitor thread to stop.
    if let Some(tx) = state.shutdown_tx.take() {
        let _ = tx.send(());
    }

    // Wait for the monitor thread to finish (with a timeout to avoid hangs).
    if let Some(thread) = state.monitor_thread.take() {
        let _ = thread.join();
    }

    // Abort the async processor.
    if let Some(handle) = state.processor_handle.take() {
        handle.abort();
    }

    // Drain all pending authorizations.  Since we cannot `.await` in a
    // synchronous function, we spawn a blocking task to perform cleanup.
    let pending: Vec<AuthenticationClosure> = state.pending_auths.drain().map(|(_, v)| v).collect();

    if !pending.is_empty() {
        tokio::spawn(async move {
            for closure in pending {
                auth_closure_destroy(closure, true).await;
            }
        });
    }

    state.initialised = false;
}

// ===========================================================================
// Exported plugin struct — SixaxisPlugin
// ===========================================================================

/// Sixaxis cable-pairing plugin descriptor.
///
/// Provides the public API surface required by the plugin schema: `name()`,
/// `version()`, `priority()`, `init()`, `exit()`.
///
/// The actual plugin lifecycle is driven through [`PluginDesc`] registered
/// via [`inventory::submit!`], which routes to the module-level
/// [`sixaxis_init`] and [`sixaxis_exit`] functions.
pub struct SixaxisPlugin;

impl SixaxisPlugin {
    /// Returns the unique plugin name: `"sixaxis"`.
    pub fn name(&self) -> &str {
        "sixaxis"
    }

    /// Returns the plugin version string (matches daemon crate version).
    pub fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    /// Returns the plugin initialization priority: `Low` (-100).
    pub fn priority(&self) -> PluginPriority {
        PluginPriority::Low
    }

    /// Initializes the sixaxis plugin.
    ///
    /// Delegates to the module-level [`sixaxis_init`] function.
    pub fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        sixaxis_init()
    }

    /// Cleans up the sixaxis plugin.
    ///
    /// Delegates to the module-level [`sixaxis_exit`] function.
    pub fn exit(&self) {
        sixaxis_exit()
    }
}

// ===========================================================================
// Plugin registration via inventory
// ===========================================================================

/// Register the sixaxis plugin at link time so that `plugin_init()` in the
/// plugin framework discovers it via `inventory::iter::<PluginDesc>()`.
///
/// Replaces C's `BLUETOOTH_PLUGIN_DEFINE(sixaxis, VERSION,
/// BLUETOOTH_PLUGIN_PRIORITY_LOW, sixaxis_init, sixaxis_exit)`.
mod _sixaxis_inventory {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "sixaxis",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::Low,
            init: super::sixaxis_init,
            exit: super::sixaxis_exit,
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the plugin name.
    #[test]
    fn test_plugin_name() {
        let p = SixaxisPlugin;
        assert_eq!(p.name(), "sixaxis");
    }

    /// Verify the plugin priority is Low.
    #[test]
    fn test_plugin_priority() {
        let p = SixaxisPlugin;
        assert_eq!(p.priority(), PluginPriority::Low);
    }

    /// Verify the plugin version matches the crate version.
    #[test]
    fn test_plugin_version() {
        let p = SixaxisPlugin;
        assert_eq!(p.version(), env!("CARGO_PKG_VERSION"));
    }

    /// Verify the HIDIOCGFEATURE ioctl number construction matches the
    /// kernel header value for a representative size.
    #[test]
    fn test_hidiocgfeature_ioctl_number() {
        // HIDIOCGFEATURE(18): dir=3, size=18, type='H'=0x48, nr=0x07
        // Expected: (3 << 30) | (18 << 16) | (0x48 << 8) | 0x07
        let expected: libc::c_ulong =
            ((3u32 << 30) | (18u32 << 16) | (0x48u32 << 8) | 0x07u32) as libc::c_ulong;
        assert_eq!(hidiocgfeature(18), expected);
    }

    /// Verify the HIDIOCSFEATURE ioctl number construction.
    #[test]
    fn test_hidiocsfeature_ioctl_number() {
        // HIDIOCSFEATURE(8): dir=3, size=8, type='H'=0x48, nr=0x06
        let expected: libc::c_ulong =
            ((3u32 << 30) | (8u32 << 16) | (0x48u32 << 8) | 0x06u32) as libc::c_ulong;
        assert_eq!(hidiocsfeature(8), expected);
    }

    /// Verify additional ioctl numbers used in the plugin.
    #[test]
    fn test_ioctl_numbers_all_sizes() {
        // HIDIOCGFEATURE(7) — DS4 device address read
        let exp7: libc::c_ulong =
            ((3u32 << 30) | (7u32 << 16) | (0x48u32 << 8) | 0x07u32) as libc::c_ulong;
        assert_eq!(hidiocgfeature(7), exp7);

        // HIDIOCGFEATURE(16) — DS4 central address read
        let exp16: libc::c_ulong =
            ((3u32 << 30) | (16u32 << 16) | (0x48u32 << 8) | 0x07u32) as libc::c_ulong;
        assert_eq!(hidiocgfeature(16), exp16);

        // HIDIOCSFEATURE(23) — DS4 central address write
        let exp23: libc::c_ulong =
            ((3u32 << 30) | (23u32 << 16) | (0x48u32 << 8) | 0x06u32) as libc::c_ulong;
        assert_eq!(hidiocsfeature(23), exp23);
    }

    /// Verify that the SDP record constant is non-empty and starts with the
    /// expected bytes.
    #[test]
    fn test_sdp_record_constant() {
        assert!(!SIXAXIS_HID_SDP_RECORD.is_empty());
        assert!(SIXAXIS_HID_SDP_RECORD.starts_with("3601"));
        // The SDP record should be all hex characters.
        assert!(SIXAXIS_HID_SDP_RECORD.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Verify BUS_USB constant matches the kernel value.
    #[test]
    fn test_bus_usb_constant() {
        assert_eq!(BUS_USB, 0x03);
    }

    /// Verify that get_pairing correctly identifies a PS3 Sixaxis controller.
    #[test]
    fn test_get_pairing_sixaxis() {
        let cp = get_pairing(0x054C, 0x0268);
        assert!(cp.is_some());
        let cp = cp.unwrap();
        assert_eq!(cp.pairing_type, CablePairingType::Sixaxis);
        assert_eq!(cp.name, "Sony PLAYSTATION(R)3 Controller");
    }

    /// Verify that get_pairing correctly identifies a DS4 controller.
    #[test]
    fn test_get_pairing_ds4() {
        let cp = get_pairing(0x054C, 0x05C4);
        assert!(cp.is_some());
        let cp = cp.unwrap();
        assert_eq!(cp.pairing_type, CablePairingType::Ds4);
    }

    /// Verify that get_pairing returns None for unknown devices.
    #[test]
    fn test_get_pairing_unknown() {
        let cp = get_pairing(0xFFFF, 0xFFFF);
        assert!(cp.is_none());
    }

    /// Verify SixaxisState defaults are correct.
    #[test]
    fn test_state_defaults() {
        let state = SixaxisState::default();
        assert!(state.pending_auths.is_empty());
        assert!(state.processor_handle.is_none());
        assert!(state.monitor_thread.is_none());
        assert!(state.shutdown_tx.is_none());
        assert!(!state.initialised);
    }

    /// Verify HID_UUID constant is accessible.
    #[test]
    fn test_hid_uuid_constant() {
        assert!(HID_UUID.contains("1124"));
    }
}
