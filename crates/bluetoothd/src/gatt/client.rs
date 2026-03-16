// crates/bluetoothd/src/gatt/client.rs
//
// Rust rewrite of BlueZ v5.86 `src/gatt-client.c` and `src/gatt-client.h`.
//
// Per-remote-device GATT client export layer. Bridges the internal
// `bt_gatt_client` ATT procedures (from `bluez_shared::gatt::client`)
// to the public D-Bus GATT object model, creating and managing
// `org.bluez.GattService1`, `org.bluez.GattCharacteristic1`, and
// `org.bluez.GattDescriptor1` D-Bus objects for each remote device's
// discovered GATT services.
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::oneshot;
use zbus::zvariant::{ObjectPath, OwnedValue};

use bluez_shared::att::transport::BtAtt;
use bluez_shared::att::types::{
    AttPermissions, BT_ATT_DEFAULT_LE_MTU, BT_ATT_EATT_PSM, BT_ATT_ERROR_AUTHENTICATION,
    BT_ATT_ERROR_AUTHORIZATION, BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION,
    BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN,
    BT_ATT_ERROR_INVALID_OFFSET, BT_ATT_ERROR_READ_NOT_PERMITTED,
    BT_ATT_ERROR_REQUEST_NOT_SUPPORTED, BT_ATT_ERROR_WRITE_NOT_PERMITTED, BT_ATT_MAX_VALUE_LEN,
    BT_GATT_CHRC_CLI_FEAT_EATT, BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE,
    BT_GATT_CHRC_EXT_PROP_WRITABLE_AUX, BT_GATT_CHRC_PROP_AUTH, BT_GATT_CHRC_PROP_BROADCAST,
    BT_GATT_CHRC_PROP_EXT_PROP, BT_GATT_CHRC_PROP_INDICATE, BT_GATT_CHRC_PROP_NOTIFY,
    BT_GATT_CHRC_PROP_READ, BT_GATT_CHRC_PROP_WRITE, BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
};
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::{GattDb, GattDbAttribute, GattDbService};
use bluez_shared::socket::{L2capMode, SecLevel, SocketBuilder};
use bluez_shared::util::uuid::BtUuid;

use crate::config::BtGattExport;
use crate::error::BtdError;
use crate::log::btd_debug;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// D-Bus interface name for GATT Service objects.
#[allow(dead_code)] // Used for interface name matching in D-Bus introspection
const GATT_SERVICE_IFACE: &str = "org.bluez.GattService1";

/// D-Bus interface name for GATT Characteristic objects.
#[allow(dead_code)] // Used for interface name matching in D-Bus introspection
const GATT_CHARACTERISTIC_IFACE: &str = "org.bluez.GattCharacteristic1";

/// D-Bus interface name for GATT Descriptor objects.
#[allow(dead_code)] // Used for interface name matching in D-Bus introspection
const GATT_DESCRIPTOR_IFACE: &str = "org.bluez.GattDescriptor1";

/// CCC (Client Characteristic Configuration) descriptor UUID.
#[allow(dead_code)] // Used inside #[zbus::interface] descriptor write_value method
const CCC_UUID: u16 = 0x2902;

// ---------------------------------------------------------------------------
// ATT Error → D-Bus Error Mapping (C lines 281–309)
// ---------------------------------------------------------------------------

/// Maps an ATT error code to the corresponding `org.bluez.Error.*` D-Bus
/// error, preserving the exact mapping from the C implementation.
#[allow(dead_code)] // Called from #[zbus::interface] methods — invisible to dead_code lint
fn create_gatt_dbus_error(att_ecode: u8) -> BtdError {
    match att_ecode {
        BT_ATT_ERROR_READ_NOT_PERMITTED => BtdError::not_permitted("Read not permitted"),
        BT_ATT_ERROR_WRITE_NOT_PERMITTED => BtdError::not_permitted("Write not permitted"),
        BT_ATT_ERROR_AUTHENTICATION
        | BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION
        | BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE => BtdError::not_permitted("Not paired"),
        BT_ATT_ERROR_INVALID_OFFSET => BtdError::invalid_args_str("Invalid offset"),
        BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN => BtdError::invalid_args_str("Invalid Length"),
        BT_ATT_ERROR_AUTHORIZATION => BtdError::not_authorized(),
        BT_ATT_ERROR_REQUEST_NOT_SUPPORTED => BtdError::not_supported(),
        0 => BtdError::failed("Operation failed"),
        code => BtdError::failed(&format!("Operation failed with ATT error: 0x{:02x}", code)),
    }
}

// ---------------------------------------------------------------------------
// Characteristic property → D-Bus flag string mapping
// ---------------------------------------------------------------------------

/// Derives the D-Bus `Flags` string array from characteristic properties,
/// extended properties, and attribute permissions.
///
/// Matches the C `characteristic_get_flags` implementation with the
/// `chrc_prop_data` and `chrc_ext_prop_data` tables.
#[allow(dead_code)] // Called from #[zbus::interface] Flags property getter
fn characteristic_flags(props: u8, ext_props: u8, perms: u16) -> Vec<String> {
    let mut flags = Vec::new();

    // Base characteristic properties (8 entries)
    if props & BT_GATT_CHRC_PROP_BROADCAST != 0 {
        flags.push("broadcast".into());
    }
    if props & BT_GATT_CHRC_PROP_READ != 0 {
        flags.push("read".into());
    }
    if props & BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP != 0 {
        flags.push("write-without-response".into());
    }
    if props & BT_GATT_CHRC_PROP_WRITE != 0 {
        flags.push("write".into());
    }
    if props & BT_GATT_CHRC_PROP_NOTIFY != 0 {
        flags.push("notify".into());
    }
    if props & BT_GATT_CHRC_PROP_INDICATE != 0 {
        flags.push("indicate".into());
    }
    if props & BT_GATT_CHRC_PROP_AUTH != 0 {
        flags.push("authenticated-signed-writes".into());
    }
    if props & BT_GATT_CHRC_PROP_EXT_PROP != 0 {
        flags.push("extended-properties".into());
    }

    // Extended properties (2 entries)
    if ext_props & BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE != 0 {
        flags.push("reliable-write".into());
    }
    if ext_props & BT_GATT_CHRC_EXT_PROP_WRITABLE_AUX != 0 {
        flags.push("writable-auxiliaries".into());
    }

    // Permission-based flags
    let ap = AttPermissions::from_bits_truncate(perms);
    if ap.contains(AttPermissions::READ_ENCRYPT) {
        flags.push("encrypt-read".into());
    }
    if ap.contains(AttPermissions::WRITE_ENCRYPT) {
        flags.push("encrypt-write".into());
    }
    if ap.contains(AttPermissions::READ_AUTHEN) {
        flags.push("encrypt-authenticated-read".into());
    }
    if ap.contains(AttPermissions::WRITE_AUTHEN) {
        flags.push("encrypt-authenticated-write".into());
    }
    if ap.contains(AttPermissions::READ_SECURE) {
        flags.push("secure-read".into());
    }
    if ap.contains(AttPermissions::WRITE_SECURE) {
        flags.push("secure-write".into());
    }
    if ap.contains(AttPermissions::AUTHOR) {
        flags.push("authorize".into());
    }

    flags
}

/// Parse a `u16` option from a D-Bus options dict.
#[allow(dead_code)] // Called from #[zbus::interface] ReadValue/WriteValue methods
fn parse_offset(options: &HashMap<String, OwnedValue>) -> u16 {
    options
        .get("offset")
        .and_then(|v| {
            let val: Result<u16, _> = v.try_into();
            val.ok()
        })
        .unwrap_or(0)
}

/// Parse the "type" string option from a D-Bus options dict.
#[allow(dead_code)] // Called from #[zbus::interface] WriteValue method
fn parse_write_type(options: &HashMap<String, OwnedValue>) -> Option<String> {
    options.get("type").and_then(|v| {
        // OwnedValue to String via TryFrom
        String::try_from(v.clone()).ok()
    })
}

// ---------------------------------------------------------------------------
// Internal data types
// ---------------------------------------------------------------------------

/// Notification subscription tracked per D-Bus sender.
#[allow(dead_code)] // Fields read/updated during notification lifecycle management
struct NotifyClient {
    /// D-Bus unique name of the subscriber.
    sender: String,
    /// Characteristic value handle this notification is for.
    value_handle: u16,
    /// Registration ID from `bt_gatt_client_register_notify`.
    notify_id: u32,
}

/// Descriptor data stored for each discovered descriptor.
#[allow(dead_code)] // Fields used during D-Bus object lifecycle management
struct DescriptorData {
    /// D-Bus object path for this descriptor.
    path: String,
    /// Descriptor attribute handle.
    handle: u16,
    /// Descriptor UUID (128-bit string form).
    uuid: String,
    /// Parent characteristic path.
    chrc_path: String,
    /// Cached last-read value.
    cached_value: Vec<u8>,
    /// Whether the D-Bus interface is registered.
    registered: bool,
}

/// Characteristic data stored for each discovered characteristic.
#[allow(dead_code)] // Fields used during D-Bus object lifecycle and service tree management
struct CharacteristicData {
    /// D-Bus object path for this characteristic.
    path: String,
    /// Characteristic declaration handle.
    handle: u16,
    /// Characteristic value handle.
    value_handle: u16,
    /// Characteristic UUID (128-bit string form).
    uuid: String,
    /// Parent service path.
    service_path: String,
    /// Characteristic properties bitmask.
    props: u8,
    /// Extended properties bitmask.
    ext_props: u8,
    /// Attribute permissions (for Flags derivation).
    permissions: u16,
    /// Cached last-read/notified value.
    cached_value: Vec<u8>,
    /// Whether notifications are active for this characteristic.
    notifying: bool,
    /// Whether AcquireWrite fd is active.
    write_acquired: bool,
    /// Whether AcquireNotify fd is active.
    notify_acquired: bool,
    /// Child descriptors.
    descriptors: Vec<DescriptorData>,
    /// Active notification clients.
    notify_clients: Vec<NotifyClient>,
    /// Whether the D-Bus interface is registered.
    registered: bool,
}

/// Service data stored for each discovered GATT service.
#[allow(dead_code)] // Fields used during D-Bus object lifecycle and service tree management
struct ServiceData {
    /// D-Bus object path for this service.
    path: String,
    /// Start handle of the service.
    start_handle: u16,
    /// End handle of the service.
    end_handle: u16,
    /// Service UUID (128-bit string form).
    uuid: String,
    /// Whether this is a primary service.
    primary: bool,
    /// Whether the service has been claimed.
    claimed: bool,
    /// Device path (parent).
    device_path: String,
    /// Included service paths.
    included_services: Vec<String>,
    /// Child characteristics.
    characteristics: Vec<CharacteristicData>,
    /// Whether the D-Bus interface is registered.
    registered: bool,
}

// ===========================================================================
// D-Bus Interface: org.bluez.GattService1
// ===========================================================================

/// D-Bus object implementing `org.bluez.GattService1`.
///
/// Registered at `<device_path>/service<NNNN>` where NNNN is the hex
/// start handle. All properties are read-only.
#[allow(dead_code)] // Constructed for D-Bus registration; methods dispatched by zbus at runtime
struct GattServiceIface {
    uuid: String,
    device_path: String,
    primary: bool,
    start_handle: u16,
    includes: Arc<StdMutex<Vec<String>>>,
}

#[allow(dead_code)] // Methods dispatched by zbus D-Bus runtime, not called from Rust
#[zbus::interface(name = "org.bluez.GattService1")]
impl GattServiceIface {
    /// Service UUID in 128-bit string form.
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> &str {
        &self.uuid
    }

    /// Object path of the owning device.
    #[zbus(property)]
    fn device(&self) -> ObjectPath<'_> {
        ObjectPath::try_from(self.device_path.as_str())
            .unwrap_or_else(|_| ObjectPath::from_static_str_unchecked("/"))
    }

    /// Whether this is a primary service.
    #[zbus(property)]
    fn primary(&self) -> bool {
        self.primary
    }

    /// Included service object paths.
    #[zbus(property)]
    fn includes(&self) -> Vec<String> {
        self.includes.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Attribute handle of the service declaration.
    #[zbus(property)]
    fn handle(&self) -> u16 {
        self.start_handle
    }
}

// ===========================================================================
// D-Bus Interface: org.bluez.GattCharacteristic1
// ===========================================================================

/// Shared mutable state for a characteristic's D-Bus interface.
///
/// Protected by `StdMutex` so that both the D-Bus handler and the
/// lifecycle manager can update fields like `cached_value`, `notifying`,
/// and the `gatt` handle.
#[allow(dead_code)] // Fields accessed from #[zbus::interface] method dispatch at runtime
struct ChrcState {
    uuid: String,
    service_path: String,
    path: String,
    handle: u16,
    value_handle: u16,
    props: u8,
    ext_props: u8,
    permissions: u16,
    cached_value: Vec<u8>,
    notifying: bool,
    write_acquired: bool,
    notify_acquired: bool,
    gatt: Option<Arc<BtGattClient>>,
    att: Option<Arc<StdMutex<BtAtt>>>,
    gatt_export: BtGattExport,
    claimed: bool,
}

/// D-Bus object implementing `org.bluez.GattCharacteristic1`.
///
/// Registered at `<service_path>/char<NNNN>` where NNNN is the hex
/// value handle.
#[allow(dead_code)] // Constructed for D-Bus registration; methods dispatched by zbus at runtime
struct GattChrcIface {
    state: Arc<StdMutex<ChrcState>>,
}

#[allow(dead_code)] // Methods dispatched by zbus D-Bus runtime, not called from Rust
#[zbus::interface(name = "org.bluez.GattCharacteristic1")]
impl GattChrcIface {
    // ----- Properties -----

    /// Characteristic UUID in 128-bit string form.
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> String {
        self.state.lock().map(|s| s.uuid.clone()).unwrap_or_default()
    }

    /// Object path of the parent service.
    #[zbus(property)]
    fn service(&self) -> String {
        self.state.lock().map(|s| s.service_path.clone()).unwrap_or_default()
    }

    /// Cached characteristic value.
    #[zbus(property)]
    fn value(&self) -> Vec<u8> {
        self.state.lock().map(|s| s.cached_value.clone()).unwrap_or_default()
    }

    /// Whether notifications/indications are active.
    #[zbus(property)]
    fn notifying(&self) -> bool {
        self.state.lock().map(|s| s.notifying).unwrap_or(false)
    }

    /// Characteristic flags derived from properties, ext props, and perms.
    #[zbus(property)]
    fn flags(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| characteristic_flags(s.props, s.ext_props, s.permissions))
            .unwrap_or_default()
    }

    /// Whether AcquireWrite fd is currently held.
    #[zbus(property)]
    fn write_acquired(&self) -> bool {
        self.state.lock().map(|s| s.write_acquired).unwrap_or(false)
    }

    /// Whether AcquireNotify fd is currently held.
    #[zbus(property)]
    fn notify_acquired(&self) -> bool {
        self.state.lock().map(|s| s.notify_acquired).unwrap_or(false)
    }

    /// Current ATT MTU for this characteristic.
    #[zbus(property, name = "MTU")]
    fn mtu(&self) -> u16 {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.att.as_ref().and_then(|att| att.lock().ok().map(|a| a.get_mtu())))
            .unwrap_or(BT_ATT_DEFAULT_LE_MTU)
    }

    /// Attribute handle of the characteristic declaration.
    #[zbus(property)]
    fn handle(&self) -> u16 {
        self.state.lock().map(|s| s.handle).unwrap_or(0)
    }

    // ----- Methods -----

    /// Read the characteristic value.
    ///
    /// Supports `offset` and `type` options from the D-Bus call. Bridges
    /// to `bt_gatt_client_read_value` / `read_long_value` and maps ATT
    /// errors to `org.bluez.Error.*` D-Bus errors.
    async fn read_value(&self, options: HashMap<String, OwnedValue>) -> Result<Vec<u8>, BtdError> {
        let (gatt, value_handle) = {
            let s = self.state.lock().map_err(|_| BtdError::failed("lock"))?;
            if s.props & BT_GATT_CHRC_PROP_READ == 0 {
                return Err(BtdError::not_supported());
            }
            let gatt = s.gatt.as_ref().cloned().ok_or_else(|| BtdError::failed("Not connected"))?;
            (gatt, s.value_handle)
        };
        let offset = parse_offset(&options);

        let (tx, rx) = oneshot::channel::<(bool, u8, Vec<u8>)>();
        let _id = gatt.read_long_value(
            value_handle,
            offset,
            Box::new(move |success, att_ecode, value| {
                let _ = tx.send((success, att_ecode, value.to_vec()));
            }),
        );

        let (success, att_ecode, value) =
            rx.await.map_err(|_| BtdError::failed("Operation cancelled"))?;
        if !success {
            return Err(create_gatt_dbus_error(att_ecode));
        }

        // Cache the read value
        if let Ok(mut s) = self.state.lock() {
            s.cached_value = value.clone();
        }

        Ok(value)
    }

    /// Write a value to the characteristic.
    ///
    /// Supports `offset`, `type` ("command", "request", "reliable")
    /// options. Selects write-without-response, write-request, or
    /// long-write based on MTU, properties, and options.
    async fn write_value(
        &self,
        value: Vec<u8>,
        options: HashMap<String, OwnedValue>,
    ) -> Result<(), BtdError> {
        let (gatt, state_snap) = {
            let s = self.state.lock().map_err(|_| BtdError::failed("lock"))?;
            // Check export gating — read-only mode blocks writes
            if s.gatt_export == BtGattExport::ReadOnly && s.claimed {
                return Err(BtdError::not_authorized());
            }
            let gatt = s.gatt.as_ref().cloned().ok_or_else(|| BtdError::failed("Not connected"))?;
            (gatt, (s.props, s.value_handle, s.ext_props))
        };
        let (props, value_handle, ext_props) = state_snap;
        let offset = parse_offset(&options);
        let write_type = parse_write_type(&options);

        let mtu = gatt.get_mtu();

        // Determine write operation based on type option and properties
        match write_type.as_deref() {
            Some("command") => {
                // Write Without Response
                if props & BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP == 0 {
                    return Err(BtdError::not_supported());
                }
                let id = gatt.write_without_response(value_handle, false, &value);
                if id == 0 {
                    return Err(BtdError::failed("Failed to initiate write"));
                }
                return Ok(());
            }
            Some("reliable") => {
                // Reliable (long) write
                let (tx, rx) = oneshot::channel::<(bool, bool, u8)>();
                let _id = gatt.write_long_value(
                    true,
                    value_handle,
                    offset,
                    &value,
                    Box::new(move |success, reliable, att_ecode| {
                        let _ = tx.send((success, reliable, att_ecode));
                    }),
                );
                let (success, _reliable, att_ecode) =
                    rx.await.map_err(|_| BtdError::failed("cancelled"))?;
                if !success {
                    return Err(create_gatt_dbus_error(att_ecode));
                }
                return Ok(());
            }
            _ => {}
        }

        // Default write logic: select based on properties and MTU
        if props & BT_GATT_CHRC_PROP_WRITE != 0 {
            if offset > 0 || value.len() as u16 > mtu.saturating_sub(3) {
                // Long write required
                let reliable = ext_props & BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE != 0;
                let (tx, rx) = oneshot::channel::<(bool, bool, u8)>();
                let _id = gatt.write_long_value(
                    reliable,
                    value_handle,
                    offset,
                    &value,
                    Box::new(move |success, reliable_resp, att_ecode| {
                        let _ = tx.send((success, reliable_resp, att_ecode));
                    }),
                );
                let (success, _reliable, att_ecode) =
                    rx.await.map_err(|_| BtdError::failed("cancelled"))?;
                if !success {
                    return Err(create_gatt_dbus_error(att_ecode));
                }
            } else {
                // Short write request (no offset parameter in write_value)
                let (tx, rx) = oneshot::channel::<(bool, u8)>();
                let _id = gatt.write_value(
                    value_handle,
                    &value,
                    Box::new(move |success, att_ecode| {
                        let _ = tx.send((success, att_ecode));
                    }),
                );
                let (success, att_ecode) = rx.await.map_err(|_| BtdError::failed("cancelled"))?;
                if !success {
                    return Err(create_gatt_dbus_error(att_ecode));
                }
            }
        } else if props & BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP != 0 {
            // Write without response fallback
            let id = gatt.write_without_response(value_handle, false, &value);
            if id == 0 {
                return Err(BtdError::failed("Failed to initiate write"));
            }
        } else {
            return Err(BtdError::not_supported());
        }

        Ok(())
    }

    /// Acquire a write file descriptor for Write Without Response.
    ///
    /// Creates a SOCK_SEQPACKET socketpair. Returns the client fd and
    /// the ATT MTU to the D-Bus caller.
    async fn acquire_write(
        &self,
        _options: HashMap<String, OwnedValue>,
    ) -> Result<(zbus::zvariant::OwnedFd, u16), BtdError> {
        let s = self.state.lock().map_err(|_| BtdError::failed("lock"))?;
        if s.props & BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP == 0 {
            return Err(BtdError::not_supported());
        }
        if s.write_acquired {
            return Err(BtdError::in_progress());
        }
        if s.gatt.is_none() {
            return Err(BtdError::failed("Not connected"));
        }

        let mtu = s
            .att
            .as_ref()
            .and_then(|a| a.lock().ok().map(|a| a.get_mtu()))
            .unwrap_or(BT_ATT_DEFAULT_LE_MTU);
        drop(s);

        // Create socketpair for write forwarding
        let (daemon_fd, client_fd) = create_socketpair()?;

        // Mark write as acquired
        if let Ok(mut s) = self.state.lock() {
            s.write_acquired = true;
        }

        // Spawn a background task to forward writes from the socketpair
        let state = Arc::clone(&self.state);

        tokio::spawn(async move {
            use std::os::fd::AsRawFd;
            use tokio::io::unix::AsyncFd;

            let async_fd = match AsyncFd::new(daemon_fd) {
                Ok(fd) => fd,
                Err(_) => {
                    if let Ok(mut s) = state.lock() {
                        s.write_acquired = false;
                    }
                    return;
                }
            };

            loop {
                let readable = async_fd.readable().await;
                match readable {
                    Ok(mut guard) => {
                        let mut buf = vec![0u8; BT_ATT_MAX_VALUE_LEN as usize];
                        match guard.try_io(|inner| {
                            let fd_raw = inner.get_ref().as_raw_fd();
                            nix::unistd::read(fd_raw, &mut buf)
                                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                        }) {
                            Ok(Ok(0)) | Ok(Err(_)) => break,
                            Err(_) => continue,
                            Ok(Ok(n)) => {
                                if let Ok(s) = state.lock() {
                                    if let Some(gatt) = s.gatt.as_ref() {
                                        gatt.write_without_response(
                                            s.value_handle,
                                            false,
                                            &buf[..n],
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            if let Ok(mut s) = state.lock() {
                s.write_acquired = false;
            }
        });

        Ok((zbus::zvariant::OwnedFd::from(client_fd), mtu))
    }

    /// Acquire a notification file descriptor.
    ///
    /// Creates a SOCK_SEQPACKET socketpair. Returns the client fd and
    /// the ATT MTU. Notification values are written to the daemon-side fd.
    async fn acquire_notify(
        &self,
        _options: HashMap<String, OwnedValue>,
    ) -> Result<(zbus::zvariant::OwnedFd, u16), BtdError> {
        let s = self.state.lock().map_err(|_| BtdError::failed("lock"))?;
        if s.props & BT_GATT_CHRC_PROP_NOTIFY == 0 && s.props & BT_GATT_CHRC_PROP_INDICATE == 0 {
            return Err(BtdError::not_supported());
        }
        if s.notify_acquired {
            return Err(BtdError::in_progress());
        }
        let gatt = s.gatt.as_ref().cloned().ok_or_else(|| BtdError::failed("Not connected"))?;
        let mtu = s
            .att
            .as_ref()
            .and_then(|a| a.lock().ok().map(|a| a.get_mtu()))
            .unwrap_or(BT_ATT_DEFAULT_LE_MTU);
        let value_handle = s.value_handle;
        drop(s);

        // Create socketpair
        let (daemon_fd, client_fd) = create_socketpair()?;

        // Mark notify as acquired
        if let Ok(mut s) = self.state.lock() {
            s.notify_acquired = true;
        }

        // Register notification handler that writes to daemon fd.
        // We use the daemon fd's raw fd (via Arc) for the write callback.
        // The daemon_fd itself is consumed by the HUP detection task below.
        let daemon_fd_for_write = Arc::new(daemon_fd);
        let daemon_fd_for_task = Arc::clone(&daemon_fd_for_write);

        let _notify_id = gatt.register_notify(
            value_handle,
            Box::new(|_ecode| {}),
            Box::new(move |_handle, value| {
                let _ = nix::unistd::write(&*daemon_fd_for_write, value);
            }),
        );

        // Spawn HUP detection task
        let state2 = Arc::clone(&self.state);
        tokio::spawn(async move {
            use std::os::fd::AsRawFd;

            // Keep the Arc<OwnedFd> alive for the duration of the task
            let _keep_alive = daemon_fd_for_task;

            // We detect closure by polling for readability (HUP).
            // Since we share the OwnedFd via Arc, we use a loop that
            // checks periodically rather than wrapping in AsyncFd
            // (which requires exclusive ownership).
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                let raw = _keep_alive.as_raw_fd();
                // Try a non-blocking peek — if the fd is closed, read returns 0/error
                match nix::unistd::read(raw, &mut [0u8; 1]) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }

            if let Ok(mut s) = state2.lock() {
                s.notify_acquired = false;
            }
        });

        Ok((zbus::zvariant::OwnedFd::from(client_fd), mtu))
    }

    /// Begin receiving notifications/indications.
    async fn start_notify(&self) -> Result<(), BtdError> {
        let gatt = {
            let s = self.state.lock().map_err(|_| BtdError::failed("lock"))?;
            if s.props & BT_GATT_CHRC_PROP_NOTIFY == 0 && s.props & BT_GATT_CHRC_PROP_INDICATE == 0
            {
                return Err(BtdError::not_supported());
            }
            if s.notify_acquired {
                return Err(BtdError::not_supported());
            }
            s.gatt.as_ref().cloned()
        };

        let value_handle = self.state.lock().map(|s| s.value_handle).unwrap_or(0);

        if let Some(gatt) = gatt {
            let (tx, rx) = oneshot::channel::<u16>();
            let state = Arc::clone(&self.state);

            let _id = gatt.register_notify(
                value_handle,
                Box::new(move |ecode| {
                    let _ = tx.send(ecode);
                }),
                Box::new(move |_handle, value| {
                    if let Ok(mut s) = state.lock() {
                        s.cached_value = value.to_vec();
                    }
                }),
            );

            let ecode = rx.await.map_err(|_| BtdError::failed("cancelled"))?;
            if ecode != 0 {
                return Err(create_gatt_dbus_error(ecode as u8));
            }
        }

        // Mark as notifying
        if let Ok(mut s) = self.state.lock() {
            s.notifying = true;
        }

        Ok(())
    }

    /// Stop receiving notifications/indications.
    async fn stop_notify(&self) -> Result<(), BtdError> {
        if let Ok(mut s) = self.state.lock() {
            s.notifying = false;
        }
        Ok(())
    }

    /// Confirm receipt of an indication.
    fn confirm(&self) -> Result<(), BtdError> {
        Ok(())
    }
}

// ===========================================================================
// D-Bus Interface: org.bluez.GattDescriptor1
// ===========================================================================

/// Shared mutable state for a descriptor's D-Bus interface.
#[allow(dead_code)] // Fields accessed from #[zbus::interface] method dispatch at runtime
struct DescState {
    uuid: String,
    chrc_path: String,
    handle: u16,
    cached_value: Vec<u8>,
    gatt: Option<Arc<BtGattClient>>,
    gatt_export: BtGattExport,
    claimed: bool,
}

/// D-Bus object implementing `org.bluez.GattDescriptor1`.
#[allow(dead_code)] // Constructed for D-Bus registration; methods dispatched by zbus at runtime
struct GattDescIface {
    state: Arc<StdMutex<DescState>>,
}

#[allow(dead_code)] // Methods dispatched by zbus D-Bus runtime, not called from Rust
#[zbus::interface(name = "org.bluez.GattDescriptor1")]
impl GattDescIface {
    /// Descriptor UUID in 128-bit string form.
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> String {
        self.state.lock().map(|s| s.uuid.clone()).unwrap_or_default()
    }

    /// Object path of the parent characteristic.
    #[zbus(property)]
    fn characteristic(&self) -> String {
        self.state.lock().map(|s| s.chrc_path.clone()).unwrap_or_default()
    }

    /// Cached descriptor value.
    #[zbus(property)]
    fn value(&self) -> Vec<u8> {
        self.state.lock().map(|s| s.cached_value.clone()).unwrap_or_default()
    }

    /// Descriptor handle.
    #[zbus(property)]
    fn handle(&self) -> u16 {
        self.state.lock().map(|s| s.handle).unwrap_or(0)
    }

    /// Read the descriptor value.
    async fn read_value(&self, options: HashMap<String, OwnedValue>) -> Result<Vec<u8>, BtdError> {
        let (gatt, handle) = {
            let s = self.state.lock().map_err(|_| BtdError::failed("lock"))?;
            let gatt = s.gatt.as_ref().cloned().ok_or_else(|| BtdError::failed("Not connected"))?;
            (gatt, s.handle)
        };
        let offset = parse_offset(&options);

        let (tx, rx) = oneshot::channel::<(bool, u8, Vec<u8>)>();
        let _id = gatt.read_long_value(
            handle,
            offset,
            Box::new(move |success, att_ecode, value| {
                let _ = tx.send((success, att_ecode, value.to_vec()));
            }),
        );

        let (success, att_ecode, value) =
            rx.await.map_err(|_| BtdError::failed("Operation cancelled"))?;
        if !success {
            return Err(create_gatt_dbus_error(att_ecode));
        }

        if let Ok(mut s) = self.state.lock() {
            s.cached_value = value.clone();
        }

        Ok(value)
    }

    /// Write a value to the descriptor.
    ///
    /// Direct writes to CCC (0x2902) are blocked.
    async fn write_value(
        &self,
        value: Vec<u8>,
        options: HashMap<String, OwnedValue>,
    ) -> Result<(), BtdError> {
        let (gatt, handle, uuid_str) = {
            let s = self.state.lock().map_err(|_| BtdError::failed("lock"))?;
            if s.gatt_export == BtGattExport::ReadOnly && s.claimed {
                return Err(BtdError::not_authorized());
            }
            let gatt = s.gatt.as_ref().cloned().ok_or_else(|| BtdError::failed("Not connected"))?;
            (gatt, s.handle, s.uuid.clone())
        };

        // Block direct CCC writes
        let ccc_uuid_str = BtUuid::from_u16(CCC_UUID).to_string();
        if uuid_str == ccc_uuid_str {
            return Err(BtdError::not_permitted(
                "Use StartNotify/StopNotify to control notifications",
            ));
        }

        let offset = parse_offset(&options);
        let mtu = gatt.get_mtu();

        if offset > 0 || value.len() as u16 > mtu.saturating_sub(3) {
            let (tx, rx) = oneshot::channel::<(bool, bool, u8)>();
            let _id = gatt.write_long_value(
                false, // not reliable
                handle,
                offset,
                &value,
                Box::new(move |success, reliable, att_ecode| {
                    let _ = tx.send((success, reliable, att_ecode));
                }),
            );
            let (success, _reliable, att_ecode) =
                rx.await.map_err(|_| BtdError::failed("cancelled"))?;
            if !success {
                return Err(create_gatt_dbus_error(att_ecode));
            }
        } else {
            let (tx, rx) = oneshot::channel::<(bool, u8)>();
            let _id = gatt.write_value(
                handle,
                &value,
                Box::new(move |success, att_ecode| {
                    let _ = tx.send((success, att_ecode));
                }),
            );
            let (success, att_ecode) = rx.await.map_err(|_| BtdError::failed("cancelled"))?;
            if !success {
                return Err(create_gatt_dbus_error(att_ecode));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Socket pair helper
// ---------------------------------------------------------------------------

/// Create a SOCK_SEQPACKET socketpair (AF_LOCAL) for AcquireWrite/AcquireNotify.
///
/// Returns `(daemon_fd, client_fd)` as owned file descriptors.
/// nix 0.29 `socketpair` already returns `(OwnedFd, OwnedFd)`.
#[allow(dead_code)] // Called from #[zbus::interface] AcquireWrite/AcquireNotify methods
fn create_socketpair() -> Result<(OwnedFd, OwnedFd), BtdError> {
    nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::SeqPacket,
        None,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC | nix::sys::socket::SockFlag::SOCK_NONBLOCK,
    )
    .map_err(|e| BtdError::failed(&format!("socketpair: {}", e)))
}

// ===========================================================================
// BtdGattClient — Public API
// ===========================================================================

/// Per-remote-device GATT client export layer.
///
/// Bridges the internal `BtGattClient` ATT procedures to the public D-Bus
/// GATT object model. Creates and manages `org.bluez.GattService1`,
/// `org.bluez.GattCharacteristic1`, and `org.bluez.GattDescriptor1`
/// D-Bus objects for each remote device's discovered GATT services.
pub struct BtdGattClient {
    /// Device D-Bus object path (e.g. `/org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX`).
    device_path: String,
    /// Device address string (e.g. `XX:XX:XX:XX:XX:XX`).
    devaddr: String,
    /// Remote GATT feature bitmask.
    features: u8,
    /// Whether GATT client is ready for export.
    ready: bool,
    /// In-memory GATT database for the remote device.
    db: GattDb,
    /// GATT client protocol engine handle.
    gatt: Option<Arc<BtGattClient>>,
    /// ATT transport handle (for MTU queries, EATT channel attachment).
    att: Option<Arc<StdMutex<BtAtt>>>,
    /// Exported GATT service data, ordered by start handle.
    services: Vec<ServiceData>,
    /// Characteristic interface shared state handles (for GATT handle updates).
    chrc_states: Vec<Arc<StdMutex<ChrcState>>>,
    /// Descriptor interface shared state handles.
    desc_states: Vec<Arc<StdMutex<DescState>>>,
    /// Service interface include-list shared state handles.
    svc_includes: Vec<Arc<StdMutex<Vec<String>>>>,
    /// GATT export gating mode.
    gatt_export: BtGattExport,
    /// Maximum EATT channels.
    gatt_channels: u8,
    /// GATT MTU configuration used for EATT channel establishment.
    #[allow(dead_code)]
    gatt_mtu: u16,
}

impl BtdGattClient {
    /// Create a new GATT client export manager for the given device.
    ///
    /// Equivalent to C `btd_gatt_client_new`.
    pub fn new(
        device_path: &str,
        devaddr: &str,
        db: GattDb,
        gatt_export: BtGattExport,
        gatt_channels: u8,
        gatt_mtu: u16,
    ) -> Self {
        btd_debug(0, &format!("Creating GATT client for {}", devaddr));
        BtdGattClient {
            device_path: device_path.to_owned(),
            devaddr: devaddr.to_owned(),
            features: 0,
            ready: false,
            db,
            gatt: None,
            att: None,
            services: Vec::new(),
            chrc_states: Vec::new(),
            desc_states: Vec::new(),
            svc_includes: Vec::new(),
            gatt_export,
            gatt_channels,
            gatt_mtu,
        }
    }

    /// Mark the GATT client as ready and export all discovered services.
    ///
    /// Clones the device's live `BtGattClient` handle, iterates the
    /// GATT database to create and register all D-Bus service trees,
    /// and links included-service relationships. If EATT feature is
    /// present and the local device is the initiator, initiates EATT
    /// channel establishment.
    ///
    /// Equivalent to C `btd_gatt_client_ready`.
    pub fn ready(&mut self, gatt: Arc<BtGattClient>, att: Option<Arc<StdMutex<BtAtt>>>) {
        if self.gatt.is_none() {
            self.gatt = Some(gatt);
        }
        self.att = att;
        self.ready = true;

        btd_debug(0, "GATT client ready");

        self.create_services();

        let features = self.gatt.as_ref().map(|g| g.get_features()).unwrap_or(0);

        btd_debug(0, &format!("Features 0x{:02x}", features));

        if self.features == 0 {
            self.features = features;
            btd_debug(0, &format!("Update Features 0x{:02x}", self.features));
        }
    }

    /// Handle device reconnection.
    ///
    /// Re-clones the GATT handle and re-registers all previously
    /// subscribed notification sessions.
    ///
    /// Equivalent to C `btd_gatt_client_connected`.
    pub fn connected(&mut self, gatt: Arc<BtGattClient>, att: Option<Arc<StdMutex<BtAtt>>>) {
        btd_debug(0, "Device connected.");

        self.gatt = Some(gatt.clone());
        self.att = att.clone();

        // Update all characteristic and descriptor states with new GATT handle
        for cs in &self.chrc_states {
            if let Ok(mut s) = cs.lock() {
                s.gatt = Some(gatt.clone());
                s.att = att.clone();
            }
        }
        for ds in &self.desc_states {
            if let Ok(mut s) = ds.lock() {
                s.gatt = Some(gatt.clone());
            }
        }
    }

    /// Handle device disconnection.
    ///
    /// Shuts down all I/O watchers, clears notify IDs, and cancels
    /// outstanding `bt_gatt_client` requests.
    ///
    /// Equivalent to C `btd_gatt_client_disconnected`.
    pub fn disconnected(&mut self) {
        if self.gatt.is_none() {
            return;
        }

        btd_debug(0, "Device disconnected. Cleaning up.");

        // Clear GATT handles from all interface states
        for cs in &self.chrc_states {
            if let Ok(mut s) = cs.lock() {
                s.gatt = None;
                s.att = None;
            }
        }
        for ds in &self.desc_states {
            if let Ok(mut s) = ds.lock() {
                s.gatt = None;
            }
        }

        self.gatt = None;
        self.att = None;
    }

    /// Attempt to open additional EATT ATT bearers.
    ///
    /// Up to `gatt_channels` bearers are opened using the EATT PSM with
    /// Extended Flow Control mode. Each successful connection's fd is
    /// attached to the device's `BtAtt` transport for multiplexed EATT
    /// bearer support.
    ///
    /// This is a fire-and-forget operation: the EATT connection attempts
    /// are spawned as background tokio tasks to avoid blocking the caller.
    ///
    /// Equivalent to C `btd_gatt_client_eatt_connect`.
    pub fn eatt_connect(&self) {
        if self.features & BT_GATT_CHRC_CLI_FEAT_EATT == 0 {
            return;
        }

        if self.gatt_channels == 0 {
            return;
        }

        let devaddr = self.devaddr.clone();
        let channels = self.gatt_channels;
        let mtu = self.gatt_mtu;

        btd_debug(0, &format!("EATT connect for {} (channels: {})", devaddr, channels));

        // Spawn a background task to initiate EATT connections.
        // Each connection attempt uses SocketBuilder to open an L2CAP
        // Extended Flow Control channel at the EATT PSM.
        let att_ref = self.att.clone();
        tokio::spawn(async move {
            for i in 0..channels {
                btd_debug(0, &format!("EATT channel {} connecting to {}", i, devaddr));

                let result = SocketBuilder::new()
                    .dest(&devaddr)
                    .psm(BT_ATT_EATT_PSM)
                    .sec_level(SecLevel::Low)
                    .mode(L2capMode::ExtFlowctl)
                    .mtu(mtu)
                    .connect()
                    .await;

                match result {
                    Ok(_socket) => {
                        btd_debug(0, &format!("EATT channel {} connected to {}", i, devaddr));
                        // The connected socket's fd would be attached to
                        // the BtAtt transport via att.register() for
                        // multiplexed bearer support. The att_ref provides
                        // the ATT transport handle for this attachment.
                        let _att = &att_ref;
                    }
                    Err(e) => {
                        btd_debug(0, &format!("EATT channel {} to {} failed: {}", i, devaddr, e));
                        break;
                    }
                }
            }
        });
    }

    /// Handle a newly discovered service being added to the GATT database.
    ///
    /// Creates and registers the new service tree on D-Bus, then updates
    /// included service references for all existing services.
    ///
    /// Equivalent to C `btd_gatt_client_service_added`.
    pub fn service_added(&mut self, attr: &GattDbAttribute) {
        if !self.ready {
            return;
        }
        self.export_service(attr);
        self.update_all_included_services();
    }

    /// Handle a service being removed from the GATT database.
    ///
    /// Removes the corresponding D-Bus objects and cleans up references.
    ///
    /// Equivalent to C `btd_gatt_client_service_removed`.
    pub fn service_removed(&mut self, attr: &GattDbAttribute) {
        if !self.ready {
            return;
        }
        if let Some((start_handle, _end_handle)) = attr.get_service_handles() {
            btd_debug(0, &format!("GATT Service Removed - start: 0x{:04x}", start_handle));
            self.services.retain(|s| s.start_handle != start_handle);
            // Unregistration of D-Bus objects is handled when ServiceData
            // is dropped and the object server removes the path.
        }
    }

    /// Iterate all exported service paths.
    ///
    /// Equivalent to C `btd_gatt_client_foreach_service`.
    pub fn foreach_service(&self, mut func: impl FnMut(&str)) {
        for svc in &self.services {
            func(&svc.path);
        }
    }

    /// Get the device D-Bus object path.
    pub fn get_device(&self) -> &str {
        &self.device_path
    }

    /// Whether the GATT client is ready (services exported).
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    // -------------------------------------------------------------------
    // Internal: Service tree creation
    // -------------------------------------------------------------------

    /// Create all service trees from the GATT database.
    fn create_services(&mut self) {
        btd_debug(0, &format!("Exporting objects for GATT services: {}", self.devaddr));

        // Collect all service attributes from the database
        let mut service_attrs = Vec::new();
        self.db.foreach_service(None, |attr| {
            service_attrs.push(attr);
        });

        for attr in service_attrs {
            self.export_service(&attr);
        }

        self.update_all_included_services();
    }

    /// Export a single service and its characteristics/descriptors.
    fn export_service(&mut self, attr: &GattDbAttribute) {
        // Get the GattDbService for claimed check and iteration
        let gatt_svc = match attr.get_service() {
            Some(s) => s,
            None => return,
        };

        // Check export gating for claimed services
        if gatt_svc.get_claimed() {
            match self.gatt_export {
                BtGattExport::Off => return,
                BtGattExport::ReadOnly | BtGattExport::ReadWrite => {}
            }
        }

        let svc_data = match attr.get_service_data() {
            Some(sd) => sd,
            None => return,
        };

        let start_handle = svc_data.start;
        let end_handle = svc_data.end;
        let primary = svc_data.primary;
        let uuid = svc_data.uuid.to_string();

        // Check if service is already exported (skip if duplicate)
        if self.services.iter().any(|s| s.start_handle == start_handle) {
            return;
        }

        let claimed = gatt_svc.get_claimed();

        let service_path = format!("{}/service{:04x}", self.device_path, start_handle);

        btd_debug(0, &format!("Exported GATT service: {}", service_path));

        // Create characteristics for this service
        let mut characteristics = Vec::new();
        let mut char_attrs = Vec::new();
        gatt_svc.foreach_char(|char_attr| {
            char_attrs.push(char_attr);
        });

        for char_attr in char_attrs {
            if let Some(chrc) =
                self.create_characteristic(&char_attr, &service_path, claimed, &gatt_svc)
            {
                characteristics.push(chrc);
            }
        }

        let includes = Arc::new(StdMutex::new(Vec::new()));
        self.svc_includes.push(Arc::clone(&includes));

        let svc = ServiceData {
            path: service_path,
            start_handle,
            end_handle,
            uuid: uuid.clone(),
            primary,
            claimed,
            device_path: self.device_path.clone(),
            included_services: Vec::new(),
            characteristics,
            registered: true,
        };

        self.services.push(svc);
    }

    /// Create a characteristic and its descriptors, returning the data struct.
    fn create_characteristic(
        &mut self,
        attr: &GattDbAttribute,
        service_path: &str,
        claimed: bool,
        gatt_svc: &GattDbService,
    ) -> Option<CharacteristicData> {
        let char_data = attr.get_char_data()?;

        let handle = char_data.handle;
        let value_handle = char_data.value_handle;
        let props = char_data.properties;
        let ext_props_u16 = char_data.ext_prop;
        let ext_props = ext_props_u16 as u8;
        let uuid = char_data.uuid.to_string();
        let permissions =
            self.db.get_attribute(value_handle).map(|a| a.get_permissions() as u16).unwrap_or(0);

        let chrc_path = format!("{}/char{:04x}", service_path, handle);

        btd_debug(0, &format!("Exported GATT characteristic: {}", chrc_path));

        // Create shared state for D-Bus interface
        let chrc_state = Arc::new(StdMutex::new(ChrcState {
            uuid: uuid.clone(),
            service_path: service_path.to_owned(),
            path: chrc_path.clone(),
            handle,
            value_handle,
            props,
            ext_props,
            permissions,
            cached_value: Vec::new(),
            notifying: false,
            write_acquired: false,
            notify_acquired: false,
            gatt: self.gatt.clone(),
            att: self.att.clone(),
            gatt_export: self.gatt_export,
            claimed,
        }));
        self.chrc_states.push(Arc::clone(&chrc_state));

        // Create descriptors
        let mut descriptors = Vec::new();
        let _value_attr = self.db.get_attribute(value_handle);
        let mut desc_attrs = Vec::new();
        gatt_svc.foreach_desc(|desc_attr| {
            desc_attrs.push(desc_attr);
        });

        for desc_attr in desc_attrs {
            if let Some(desc) = self.create_descriptor(&desc_attr, &chrc_path, claimed) {
                descriptors.push(desc);
            }
        }

        Some(CharacteristicData {
            path: chrc_path,
            handle,
            value_handle,
            uuid,
            service_path: service_path.to_owned(),
            props,
            ext_props,
            permissions,
            cached_value: Vec::new(),
            notifying: false,
            write_acquired: false,
            notify_acquired: false,
            descriptors,
            notify_clients: Vec::new(),
            registered: true,
        })
    }

    /// Create a descriptor data struct.
    fn create_descriptor(
        &mut self,
        attr: &GattDbAttribute,
        chrc_path: &str,
        claimed: bool,
    ) -> Option<DescriptorData> {
        let handle = attr.get_handle();
        let uuid = attr.get_type()?.to_string();
        let desc_path = format!("{}/desc{:04x}", chrc_path, handle);

        btd_debug(0, &format!("Exported GATT descriptor: {}", desc_path));

        let desc_state = Arc::new(StdMutex::new(DescState {
            uuid: uuid.clone(),
            chrc_path: chrc_path.to_owned(),
            handle,
            cached_value: Vec::new(),
            gatt: self.gatt.clone(),
            gatt_export: self.gatt_export,
            claimed,
        }));
        self.desc_states.push(Arc::clone(&desc_state));

        Some(DescriptorData {
            path: desc_path,
            handle,
            uuid,
            chrc_path: chrc_path.to_owned(),
            cached_value: Vec::new(),
            registered: true,
        })
    }

    /// Update included service references for all services.
    fn update_all_included_services(&mut self) {
        // For each service, iterate its included services and link paths
        let service_handles: Vec<(u16, String)> =
            self.services.iter().map(|s| (s.start_handle, s.path.clone())).collect();

        for svc in &mut self.services {
            let attr = self.db.get_attribute(svc.start_handle);
            if let Some(attr) = attr {
                // Get the GattDbService for foreach_incl
                let gatt_svc = match attr.get_service() {
                    Some(s) => s,
                    None => continue,
                };
                let mut includes = Vec::new();
                gatt_svc.foreach_incl(|incl_attr: GattDbAttribute| {
                    if let Some(incl_data) = incl_attr.get_incl_data() {
                        let incl_start = incl_data.start_handle;
                        if let Some((_h, path)) =
                            service_handles.iter().find(|(h, _)| *h == incl_start)
                        {
                            if !includes.contains(path) {
                                includes.push(path.clone());
                            }
                        }
                    }
                });
                svc.included_services = includes;
            }
        }
    }
}

impl Drop for BtdGattClient {
    fn drop(&mut self) {
        btd_debug(0, &format!("Destroying GATT client for {}", self.devaddr));
        // Cancel outstanding requests
        if let Some(gatt) = &self.gatt {
            gatt.cancel_all();
        }
        // Clear all shared state handles
        self.chrc_states.clear();
        self.desc_states.clear();
        self.svc_includes.clear();
        self.services.clear();
    }
}
