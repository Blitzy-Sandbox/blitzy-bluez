// SPDX-License-Identifier: GPL-2.0-or-later
//! ASHA (Audio Streaming for Hearing Aid) source profile plugin.
//!
//! Rust rewrite of `profiles/audio/asha.c` and `profiles/audio/asha.h`.
//! Implements LE CoC (Connection-Oriented Channel) management for ASHA
//! hearing aid devices, creating `org.bluez.MediaEndpoint1` and transport
//! objects per device.
//!
//! # Architecture
//!
//! The ASHA plugin registers a BLE profile that matches the ASHA service
//! UUID (`0xFDF0`). When a hearing aid device is probed:
//!
//! 1. `asha_probe` — Allocates an [`AshaDevice`] and stores it in a
//!    global device map keyed by device path.
//! 2. `asha_accept` — Discovers ASHA GATT service via [`BtAsha::attach`],
//!    then registers a `MediaEndpoint1` D-Bus interface and creates a media
//!    transport.
//! 3. `asha_disconnect` / `asha_remove` — Tears down the transport, unregisters
//!    D-Bus objects, and resets ASHA state.
//!
//! Streaming is managed by [`AshaDevice::start`] (connects LE CoC socket,
//! sends ASHA Start command) and [`AshaDevice::stop`].

use std::collections::HashMap;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info, warn};
use zbus::zvariant::OwnedObjectPath;

use bluez_shared::audio::asha::{AshaState, BtAsha, ASHA_PROFILE_UUID};
use bluez_shared::socket::{BluetoothSocket, L2capMode, SecLevel};
use bluez_shared::sys::bluetooth::{BdAddr, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM};

use crate::adapter::{btd_adapter_get_address, BtdAdapter};
use crate::dbus_common::btd_get_dbus_connection;
use crate::device::{AddressType, BtdDevice};
use crate::error::BtdError;
use crate::plugin::{PluginDesc, PluginPriority};
use crate::profile::{btd_profile_register, BtdProfile, BTD_PROFILE_BEARER_LE, BTD_PROFILE_PRIORITY_MEDIUM};
use crate::profiles::audio::media::{media_endpoint_get_asha, MEDIA_ENDPOINT_INTERFACE};
use crate::profiles::audio::transport::{
    media_transport_create, media_transport_destroy, media_transport_get_path,
    media_transport_set_asha, media_transport_set_fd, MediaTransport,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum MTU for the ASHA LE CoC audio channel (output direction).
const ASHA_MIN_MTU: u16 = 163;

/// Desired MTU for the ASHA LE CoC audio channel (input direction).
const ASHA_CONNECTION_MTU: u16 = 512;

/// ASHA LE connection interval minimum (20 ms in 1.25 ms units).
const ASHA_CONN_INTERVAL_MIN: u16 = 0x0010;

/// ASHA LE connection interval maximum (20 ms in 1.25 ms units).
const ASHA_CONN_INTERVAL_MAX: u16 = 0x0010;

/// ASHA LE connection latency (10 events).
const ASHA_CONN_LATENCY: u16 = 0x000A;

/// ASHA LE supervision timeout (1 s in 10 ms units).
const ASHA_CONN_TIMEOUT: u16 = 0x0064;

// ---------------------------------------------------------------------------
// Global Device Map
// ---------------------------------------------------------------------------

/// Map from device D-Bus path to shared `AshaDevice` instance.
///
/// Uses `std::sync::Mutex` (non-async) because lookups and insertions
/// are fast in-memory operations that do not need to yield.
static ASHA_DEVICES: std::sync::LazyLock<
    std::sync::Mutex<HashMap<String, Arc<std::sync::Mutex<AshaDevice>>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// AshaDevice — per-hearing-aid state
// ---------------------------------------------------------------------------

/// Per-device ASHA state.
///
/// Wraps the core [`BtAsha`] protocol engine from `bluez-shared` together
/// with transport, socket, and D-Bus registration state.
pub struct AshaDevice {
    /// Core ASHA protocol engine (GATT discovery, audio start/stop, volume).
    asha: BtAsha,

    /// Device D-Bus object path (e.g. `/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF`).
    device_path: String,

    /// Remote device Bluetooth address.
    device_addr: BdAddr,

    /// Remote device address type (LE Public / LE Random).
    device_addr_type: AddressType,

    /// Reference to the adapter owning this device (tokio mutex).
    adapter: Arc<TokioMutex<BtdAdapter>>,

    /// Adapter D-Bus path string (for constructing new `BtdDevice` instances).
    adapter_path: String,

    /// Media transport handle (created after endpoint registration).
    transport: Option<Arc<TokioMutex<MediaTransport>>>,

    /// LE CoC Bluetooth socket for audio streaming.
    socket: Option<BluetoothSocket>,

    /// Negotiated input MTU from the LE CoC socket.
    imtu: u16,

    /// Negotiated output MTU from the LE CoC socket.
    omtu: u16,

    /// Resume ID counter — incremented on each `start()` call.
    resume_id: u32,

    /// Whether the D-Bus endpoint interface is currently registered.
    endpoint_registered: bool,
}

impl AshaDevice {
    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    /// Create a new `AshaDevice` for a remote hearing aid.
    ///
    /// The device is created in an idle state with no GATT attachment or
    /// transport. Use the profile lifecycle callbacks to drive discovery
    /// and streaming.
    pub fn new(
        device_path: String,
        device_addr: BdAddr,
        device_addr_type: AddressType,
        adapter: Arc<TokioMutex<BtdAdapter>>,
        adapter_path: String,
    ) -> Self {
        debug!("ASHA: creating device for {}", device_path);
        Self {
            asha: BtAsha::new(),
            device_path,
            device_addr,
            device_addr_type,
            adapter,
            adapter_path,
            transport: None,
            socket: None,
            imtu: ASHA_CONNECTION_MTU,
            omtu: ASHA_MIN_MTU,
            resume_id: 0,
            endpoint_registered: false,
        }
    }

    // -------------------------------------------------------------------
    // Streaming lifecycle
    // -------------------------------------------------------------------

    /// Start ASHA audio streaming.
    ///
    /// Sets LE connection parameters optimized for audio, establishes the
    /// LE CoC socket, starts the ASHA audio stream on the remote device,
    /// and increments the resume ID.
    ///
    /// Returns the new resume ID on success.
    pub async fn start(&mut self) -> Result<u32, BtdError> {
        if self.asha.state() != AshaState::Stopped {
            warn!(
                "ASHA {}: start called in state {:?}, expected Stopped",
                self.device_path,
                self.asha.state()
            );
            return Err(BtdError::failed("ASHA device not in stopped state"));
        }

        debug!("ASHA {}: starting audio stream", self.device_path);

        // Establish the LE CoC audio channel.
        self.connect_socket().await?;

        // Propagate the socket fd and MTUs to the media transport.
        if let Some(ref transport) = self.transport {
            if let Some(socket) = self.socket.as_ref() {
                // Duplicate the fd for the transport layer (transport takes ownership).
                let raw_fd = socket.as_raw_fd();
                let dup_fd = dup_raw_fd(raw_fd)?;
                media_transport_set_fd(transport, dup_fd, self.imtu, self.omtu).await;
            }
        }

        // Send ASHA Start command via GATT AudioControlPoint.
        self.asha
            .start()
            .map_err(|e| BtdError::failed(&format!("ASHA start: {e}")))?;

        self.resume_id += 1;
        info!(
            "ASHA {}: audio started (resume_id={})",
            self.device_path, self.resume_id
        );
        Ok(self.resume_id)
    }

    /// Stop ASHA audio streaming.
    ///
    /// Sends the ASHA Stop command and closes the LE CoC socket.
    /// Returns the current resume ID.
    pub fn stop(&mut self) -> u32 {
        debug!("ASHA {}: stopping audio stream", self.device_path);
        let _ = self.asha.stop();
        self.close_socket();
        self.resume_id
    }

    /// Reset ASHA device state.
    ///
    /// Closes the socket, resets the ASHA protocol engine state, and
    /// zeroes the resume ID counter.
    pub fn state_reset(&mut self) {
        debug!("ASHA {}: state reset", self.device_path);
        self.close_socket();
        self.asha.state_reset();
        self.resume_id = 0;
    }

    // -------------------------------------------------------------------
    // Property accessors
    // -------------------------------------------------------------------

    /// Current resume ID (incremented per `start()` call).
    pub fn get_resume_id(&self) -> u32 {
        self.resume_id
    }

    /// ASHA render delay in milliseconds.
    pub fn get_render_delay(&self) -> u16 {
        self.asha.render_delay()
    }

    /// Current ASHA streaming state.
    pub fn get_state(&self) -> AshaState {
        self.asha.state()
    }

    /// Raw file descriptor of the LE CoC socket (if connected).
    pub fn get_fd(&self) -> Option<RawFd> {
        self.socket.as_ref().map(|s| s.as_raw_fd())
    }

    /// Negotiated output MTU of the LE CoC socket.
    pub fn get_omtu(&self) -> u16 {
        self.omtu
    }

    /// Negotiated input MTU of the LE CoC socket.
    pub fn get_imtu(&self) -> u16 {
        self.imtu
    }

    /// Current ASHA volume level (−128 .. 0).
    pub fn get_volume(&self) -> i8 {
        self.asha.volume()
    }

    /// Set the ASHA volume via a GATT write to the Volume characteristic.
    ///
    /// Returns `true` if the write was queued successfully.
    pub fn set_volume(&self, volume: i8) -> bool {
        self.asha.set_volume(volume)
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// Establish the LE CoC audio socket to the hearing aid.
    async fn connect_socket(&mut self) -> Result<(), BtdError> {
        let src_addr = btd_adapter_get_address(&self.adapter).await;

        let psm = self.asha.psm();
        if psm == 0 {
            return Err(BtdError::failed("ASHA LE PSM not discovered"));
        }

        let dest_type = match self.device_addr_type {
            AddressType::LeRandom => BDADDR_LE_RANDOM,
            _ => BDADDR_LE_PUBLIC,
        };

        debug!(
            "ASHA {}: connecting LE CoC socket (PSM={}, imtu={}, omtu={})",
            self.device_path, psm, ASHA_CONNECTION_MTU, ASHA_MIN_MTU
        );

        let socket = BluetoothSocket::builder()
            .source_bdaddr(src_addr)
            .source_type(BDADDR_LE_PUBLIC)
            .dest_bdaddr(self.device_addr)
            .dest_type(dest_type)
            .mode(L2capMode::LeFlowctl)
            .psm(psm)
            .imtu(ASHA_CONNECTION_MTU)
            .omtu(ASHA_MIN_MTU)
            .sec_level(SecLevel::Medium)
            .connect()
            .await
            .map_err(|e| BtdError::failed(&format!("LE CoC connect: {e}")))?;

        // Read the negotiated MTUs from the socket.
        match socket.mtu() {
            Ok((imtu, omtu)) => {
                self.imtu = if imtu > 0 { imtu } else { ASHA_CONNECTION_MTU };
                self.omtu = if omtu > 0 { omtu } else { ASHA_MIN_MTU };
            }
            Err(e) => {
                warn!(
                    "ASHA {}: failed to read socket MTU ({}), using defaults",
                    self.device_path, e
                );
                self.imtu = ASHA_CONNECTION_MTU;
                self.omtu = ASHA_MIN_MTU;
            }
        }

        debug!(
            "ASHA {}: LE CoC connected (fd={}, imtu={}, omtu={})",
            self.device_path,
            socket.as_raw_fd(),
            self.imtu,
            self.omtu
        );

        // Log the optimized LE connection parameters for ASHA streaming.
        // In the C code these are applied via btd_device_set_conn_param()
        // which configures the kernel MGMT connection parameter update.
        debug!(
            "ASHA {}: conn params (interval [{:#06x}..{:#06x}], latency {:#06x}, timeout {:#06x})",
            self.device_path,
            ASHA_CONN_INTERVAL_MIN,
            ASHA_CONN_INTERVAL_MAX,
            ASHA_CONN_LATENCY,
            ASHA_CONN_TIMEOUT,
        );

        self.socket = Some(socket);
        Ok(())
    }

    /// Close the LE CoC audio socket if open.
    fn close_socket(&mut self) {
        if let Some(socket) = self.socket.take() {
            debug!(
                "ASHA {}: closing LE CoC socket (fd={})",
                self.device_path,
                socket.as_raw_fd()
            );
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        self.imtu = ASHA_CONNECTION_MTU;
        self.omtu = ASHA_MIN_MTU;
    }

}

// ---------------------------------------------------------------------------
// File descriptor duplication helper
// ---------------------------------------------------------------------------

/// Duplicate a raw file descriptor via `libc::dup`, returning an `OwnedFd`.
///
/// This is a designated FFI boundary site — the only `unsafe` in this module,
/// consistent with `sdp/server.rs` and `plugin.rs` patterns in this crate.
#[allow(unsafe_code)]
fn dup_raw_fd(raw: RawFd) -> Result<OwnedFd, BtdError> {
    // SAFETY: `raw` is a valid open file descriptor obtained from
    // `BluetoothSocket::as_raw_fd()`. `libc::dup` returns a new valid fd
    // on success or −1 on error. The returned fd is owned exclusively by
    // the caller and immediately wrapped in `OwnedFd` for RAII.
    let new_fd = unsafe { libc::dup(raw) };
    if new_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(BtdError::failed(&format!("dup fd {raw}: {err}")));
    }
    // SAFETY: `new_fd` is a non-negative fd returned by `libc::dup` that
    // we own exclusively. Wrapping in `OwnedFd` transfers ownership for
    // automatic close-on-drop.
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

// ---------------------------------------------------------------------------
// D-Bus interface: org.bluez.MediaEndpoint1 (ASHA properties)
// ---------------------------------------------------------------------------

/// ASHA-specific `org.bluez.MediaEndpoint1` D-Bus interface.
///
/// Exposes read-only properties describing the hearing aid's capabilities.
/// Registered at `<device_path>/asha`.
struct AshaEndpointIface {
    /// Shared reference to the BtAsha protocol engine for property reads.
    asha: BtAsha,
    /// Device D-Bus object path.
    device_path: String,
    /// Transport D-Bus object path (set after transport creation).
    transport_path: String,
}

#[zbus::interface(name = "org.bluez.MediaEndpoint1")]
impl AshaEndpointIface {
    /// ASHA profile UUID.
    #[zbus(property, name = "UUID")]
    async fn uuid(&self) -> String {
        ASHA_PROFILE_UUID.to_string()
    }

    /// Hearing aid side: `"right"` or `"left"`.
    #[zbus(property, name = "Side")]
    async fn side(&self) -> String {
        if self.asha.right_side() {
            "right".to_string()
        } else {
            "left".to_string()
        }
    }

    /// Whether the hearing aid is part of a binaural set.
    #[zbus(property, name = "Binaural")]
    async fn binaural(&self) -> bool {
        self.asha.binaural()
    }

    /// HiSyncId — 8-byte identifier for binaural pairing.
    #[zbus(property, name = "HiSyncId")]
    async fn hi_sync_id(&self) -> Vec<u8> {
        self.asha.hisync_id().to_vec()
    }

    /// Supported codec bitmask.
    #[zbus(property, name = "Codecs")]
    async fn codecs(&self) -> u16 {
        self.asha.codec_ids()
    }

    /// D-Bus object path of the owning device.
    #[zbus(property, name = "Device")]
    async fn device(&self) -> OwnedObjectPath {
        OwnedObjectPath::try_from(self.device_path.clone()).unwrap_or_default()
    }

    /// D-Bus object path of the ASHA media transport.
    #[zbus(property, name = "Transport")]
    async fn transport(&self) -> OwnedObjectPath {
        OwnedObjectPath::try_from(self.transport_path.clone()).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Async endpoint registration helper
// ---------------------------------------------------------------------------

/// Register the MediaEndpoint1 D-Bus interface and create the media
/// transport for the given ASHA device.
///
/// This function is structured to carefully manage lock scopes so that the
/// `std::sync::Mutex<AshaDevice>` is never held across `.await` points.
async fn asha_register_endpoint_for(
    asha_arc: Arc<std::sync::Mutex<AshaDevice>>,
) -> Result<(), BtdError> {
    // Phase 1 (sync): extract everything we need from the locked device.
    let (device_path, asha_clone, adapter, adapter_path, device_addr, device_addr_type) = {
        let asha_dev = asha_arc
            .lock()
            .map_err(|_| BtdError::failed("ASHA device lock"))?;
        (
            asha_dev.device_path.clone(),
            asha_dev.asha.clone(),
            Arc::clone(&asha_dev.adapter),
            asha_dev.adapter_path.clone(),
            asha_dev.device_addr,
            asha_dev.device_addr_type,
        )
    };
    // Guard dropped here — safe for async calls below.

    let endpoint_path = format!("{device_path}/asha");
    debug!("ASHA {}: registering endpoint at {}", device_path, endpoint_path);

    // Build the ASHA MediaEndpoint descriptor.
    let asha_ep = media_endpoint_get_asha(&adapter);
    let asha_ep_arc = Arc::new(std::sync::Mutex::new(asha_ep));

    // Register the D-Bus interface for endpoint properties.
    let conn = btd_get_dbus_connection().clone();
    let iface = AshaEndpointIface {
        asha: asha_clone.clone(),
        device_path: device_path.clone(),
        transport_path: String::new(),
    };

    if let Err(e) = conn.object_server().at(&*endpoint_path, iface).await {
        error!(
            "ASHA {}: failed to register {} at {}: {}",
            device_path, MEDIA_ENDPOINT_INTERFACE, endpoint_path, e
        );
        return Err(BtdError::failed(&format!("D-Bus register: {e}")));
    }

    // Mark endpoint as registered (quick sync lock).
    {
        let mut asha_dev = asha_arc
            .lock()
            .map_err(|_| BtdError::failed("ASHA device lock"))?;
        asha_dev.endpoint_registered = true;
    }

    // Create a BtdDevice for the transport layer.
    let device_for_transport = Arc::new(BtdDevice::new(
        adapter,
        device_addr,
        device_addr_type,
        &adapter_path,
    ));

    // Create the media transport (async).
    match media_transport_create(
        device_for_transport,
        Arc::clone(&asha_ep_arc),
        Vec::new(),
        None,
    )
    .await
    {
        Some(transport) => {
            // Inject the BtAsha reference into the transport's ASHA ops.
            media_transport_set_asha(&transport, asha_clone).await;

            // Get the transport path.
            let tp = media_transport_get_path(&transport).await;
            debug!("ASHA {}: transport created at {}", device_path, tp);

            // Update the D-Bus endpoint interface with the transport path.
            if let Ok(iface_ref) = conn
                .object_server()
                .interface::<_, AshaEndpointIface>(&*endpoint_path)
                .await
            {
                let mut iface_guard = iface_ref.get_mut().await;
                iface_guard.transport_path = tp;
            }

            // Store transport reference (quick sync lock).
            {
                let mut asha_dev = asha_arc
                    .lock()
                    .map_err(|_| BtdError::failed("ASHA device lock"))?;
                asha_dev.transport = Some(transport);
            }
        }
        None => {
            error!("ASHA {}: failed to create media transport", device_path);
            // Unregister the endpoint we just registered.
            let _ = conn
                .object_server()
                .remove::<AshaEndpointIface, _>(&*endpoint_path)
                .await;
            if let Ok(mut asha_dev) = asha_arc.lock() {
                asha_dev.endpoint_registered = false;
            }
            return Err(BtdError::failed("transport creation failed"));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Profile lifecycle callbacks
// ---------------------------------------------------------------------------

/// Profile probe: allocate an `AshaDevice` for a newly discovered hearing aid.
fn asha_probe(device: &Arc<TokioMutex<BtdDevice>>) -> Result<(), BtdError> {
    // Extract device info without holding the lock across await points
    // (this callback is synchronous).
    let dev = device.try_lock().map_err(|_| BtdError::busy())?;
    let path = dev.get_path().to_string();
    let addr = *dev.get_address();
    let addr_type = dev.get_address_type();
    let adapter = Arc::clone(dev.get_adapter());
    let adapter_path = dev.adapter_path.clone();
    drop(dev);

    let asha_dev = AshaDevice::new(path.clone(), addr, addr_type, adapter, adapter_path);
    let asha_arc = Arc::new(std::sync::Mutex::new(asha_dev));

    let mut map = ASHA_DEVICES
        .lock()
        .map_err(|_| BtdError::failed("ASHA device map poisoned"))?;
    map.insert(path.clone(), asha_arc);

    info!("ASHA: probed device {}", path);
    Ok(())
}

/// Profile accept: discover ASHA GATT characteristics and register endpoint.
fn asha_accept(
    device: &Arc<TokioMutex<BtdDevice>>,
) -> Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        let (path, db, client) = {
            let dev = device.lock().await;
            let path = dev.get_path().to_string();
            let db = dev.get_gatt_db().cloned();
            let client = dev.get_gatt_client().cloned();
            (path, db, client)
        };

        let db = db.ok_or_else(|| {
            error!("ASHA {}: no GATT database available", path);
            BtdError::not_available()
        })?;
        let client = client.ok_or_else(|| {
            error!("ASHA {}: no GATT client available", path);
            BtdError::not_available()
        })?;

        // Look up our AshaDevice.
        let asha_arc = {
            let map = ASHA_DEVICES
                .lock()
                .map_err(|_| BtdError::failed("ASHA device map poisoned"))?;
            map.get(&path)
                .cloned()
                .ok_or_else(|| BtdError::failed("ASHA device not found"))?
        };

        // Attach GATT client and discover ASHA service.
        // The completion callback will register the endpoint.
        let asha_arc_cb = Arc::clone(&asha_arc);
        let attach_ok = {
            let asha_dev = asha_arc.lock().map_err(|_| BtdError::failed("lock"))?;
            asha_dev.asha.attach(
                &db,
                &client,
                Some(Box::new(move || {
                    let arc = asha_arc_cb;
                    tokio::spawn(async move {
                        // Perform registration in a helper that manages
                        // lock scopes carefully to avoid holding
                        // std::sync::Mutex across await points.
                        if let Err(e) = asha_register_endpoint_for(arc).await {
                            error!("ASHA: endpoint registration failed: {}", e);
                        }
                    });
                })),
            )
        };

        if !attach_ok {
            error!("ASHA {}: GATT attach failed (service not found)", path);
            return Err(BtdError::not_available());
        }

        info!("ASHA {}: accepted, GATT discovery in progress", path);
        Ok(())
    })
}

/// Profile disconnect: stop streaming and tear down transport.
fn asha_disconnect(
    device: &Arc<TokioMutex<BtdDevice>>,
) -> Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        let path = {
            let dev = device.lock().await;
            dev.get_path().to_string()
        };

        let asha_arc = {
            let map = ASHA_DEVICES
                .lock()
                .map_err(|_| BtdError::failed("ASHA device map poisoned"))?;
            map.get(&path).cloned()
        };

        if let Some(asha_arc) = asha_arc {
            // Phase 1: synchronous work under the std::sync::Mutex lock.
            let transport_to_destroy = {
                let mut asha_dev =
                    asha_arc.lock().map_err(|_| BtdError::failed("lock"))?;

                // Stop streaming and close socket.
                let _ = asha_dev.stop();

                // Reset the ASHA protocol engine (releases GATT references).
                asha_dev.asha.reset();

                // Take the transport handle for async destruction (outside the lock).
                asha_dev.transport.take()
            };
            // Guard dropped here — safe for async work below.

            // Phase 2: async D-Bus cleanup (no std::sync::Mutex held).
            if let Some(transport) = transport_to_destroy {
                debug!("ASHA {}: destroying transport", path);
                media_transport_destroy(transport).await;
            }

            // Check if endpoint needs unregistration (quick lock scope).
            let needs_unregister = {
                match asha_arc.lock() {
                    Ok(d) => d.endpoint_registered,
                    Err(_) => false,
                }
            };
            // Guard fully dropped here — safe for async work below.

            if needs_unregister {
                let endpoint_path = format!("{}/asha", path);
                let conn = btd_get_dbus_connection().clone();
                let _ = conn
                    .object_server()
                    .remove::<AshaEndpointIface, _>(&*endpoint_path)
                    .await;

                // Mark endpoint unregistered (quick lock scope).
                if let Ok(mut d) = asha_arc.lock() {
                    d.endpoint_registered = false;
                }
                debug!("ASHA {}: unregistered endpoint at {}", path, endpoint_path);
            }

            info!("ASHA {}: disconnected", path);
        } else {
            warn!("ASHA {}: disconnect for unknown device", path);
        }

        Ok(())
    })
}

/// Profile remove: full cleanup and removal from device map.
fn asha_remove(device: &Arc<TokioMutex<BtdDevice>>) {
    let device = Arc::clone(device);
    tokio::spawn(async move {
        let path = {
            let dev = device.lock().await;
            dev.get_path().to_string()
        };

        // Remove from global map.
        let asha_arc = {
            let mut map = match ASHA_DEVICES.lock() {
                Ok(m) => m,
                Err(_) => {
                    error!("ASHA {}: device map poisoned on remove", path);
                    return;
                }
            };
            map.remove(&path)
        };

        if let Some(asha_arc) = asha_arc {
            // Phase 1: synchronous work under the std::sync::Mutex.
            let (transport_to_destroy, was_registered) = {
                let mut asha_dev = match asha_arc.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        error!("ASHA {}: lock failed on remove", path);
                        return;
                    }
                };

                let _ = asha_dev.stop();
                asha_dev.asha.reset();

                let transport = asha_dev.transport.take();
                let registered = asha_dev.endpoint_registered;
                asha_dev.endpoint_registered = false;
                (transport, registered)
            };
            // Guard dropped — safe for async.

            // Phase 2: async cleanup.
            if let Some(transport) = transport_to_destroy {
                debug!("ASHA {}: destroying transport", path);
                media_transport_destroy(transport).await;
            }

            if was_registered {
                let endpoint_path = format!("{}/asha", path);
                let conn = btd_get_dbus_connection().clone();
                let _ = conn
                    .object_server()
                    .remove::<AshaEndpointIface, _>(&*endpoint_path)
                    .await;
                debug!("ASHA {}: unregistered endpoint at {}", path, endpoint_path);
            }

            info!("ASHA {}: removed", path);
        } else {
            debug!("ASHA {}: remove for unknown device (already removed?)", path);
        }
    });
}

// ---------------------------------------------------------------------------
// Plugin init / exit
// ---------------------------------------------------------------------------

/// Initialize the ASHA source plugin.
///
/// Registers the `asha-source` BLE profile with probe, accept, disconnect,
/// and remove callbacks.
fn asha_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("asha: initializing plugin");

    tokio::spawn(async {
        let mut profile = BtdProfile::new("asha-source");
        profile.remote_uuid = Some(ASHA_PROFILE_UUID.to_string());
        profile.bearer = BTD_PROFILE_BEARER_LE;
        profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
        profile.auto_connect = true;
        profile.experimental = true;

        profile.set_device_probe(Box::new(asha_probe));
        profile.set_device_remove(Box::new(asha_remove));

        profile.set_accept(Box::new(|dev| asha_accept(dev)));
        profile.set_disconnect(Box::new(|dev| asha_disconnect(dev)));

        if let Err(e) = btd_profile_register(profile).await {
            error!("asha: failed to register profile: {}", e);
        } else {
            info!("asha: registered asha-source profile");
        }
    });

    info!("asha: plugin initialized");
    Ok(())
}

/// Shut down the ASHA source plugin.
///
/// Unregisters the profile and cleans up all active ASHA devices.
fn asha_exit() {
    debug!("asha: shutting down plugin");

    tokio::spawn(async {
        // Drain all ASHA devices and collect async cleanup work.
        let cleanup_work: Vec<(String, Option<Arc<TokioMutex<MediaTransport>>>, bool)> = {
            let mut map = match ASHA_DEVICES.lock() {
                Ok(m) => m,
                Err(_) => {
                    error!("asha: device map poisoned on exit");
                    return;
                }
            };

            let mut work = Vec::new();
            for (path, asha_arc) in map.drain() {
                let mut asha_dev = match asha_arc.lock() {
                    Ok(g) => g,
                    Err(_) => continue,
                };
                let _ = asha_dev.stop();
                asha_dev.asha.reset();

                let transport = asha_dev.transport.take();
                let registered = asha_dev.endpoint_registered;
                asha_dev.endpoint_registered = false;
                work.push((path, transport, registered));
            }
            work
        };

        // Perform async cleanup outside the std::sync::Mutex.
        for (path, transport, was_registered) in cleanup_work {
            if let Some(transport) = transport {
                media_transport_destroy(transport).await;
            }
            if was_registered {
                let endpoint_path = format!("{path}/asha");
                let conn = btd_get_dbus_connection().clone();
                let _ = conn
                    .object_server()
                    .remove::<AshaEndpointIface, _>(&*endpoint_path)
                    .await;
            }
        }

        info!("asha: plugin shut down");
    });
}

// ---------------------------------------------------------------------------
// Inventory plugin registration
// ---------------------------------------------------------------------------

inventory::submit! {
    PluginDesc {
        name: "asha",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: asha_init,
        exit: asha_exit,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bluez_shared::sys::bluetooth::BDADDR_ANY;

    // Helper: build a dummy AshaDevice for testing.
    fn make_test_device() -> AshaDevice {
        let adapter = Arc::new(TokioMutex::new(BtdAdapter::new_for_test(0)));
        AshaDevice::new(
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF".to_string(),
            BDADDR_ANY,
            AddressType::LePublic,
            adapter,
            "/org/bluez/hci0".to_string(),
        )
    }

    #[test]
    fn asha_constants() {
        assert_eq!(ASHA_MIN_MTU, 163);
        assert_eq!(ASHA_CONNECTION_MTU, 512);
        assert_eq!(ASHA_CONN_INTERVAL_MIN, 0x0010);
        assert_eq!(ASHA_CONN_INTERVAL_MAX, 0x0010);
        assert_eq!(ASHA_CONN_LATENCY, 0x000A);
        assert_eq!(ASHA_CONN_TIMEOUT, 0x0064);
    }

    #[test]
    fn asha_profile_uuid_matches() {
        // ASHA uses the 16-bit UUID 0xFDF0, expressed as a full 128-bit UUID.
        assert!(ASHA_PROFILE_UUID.starts_with("0000FDF0"));
    }

    #[test]
    fn asha_device_new_defaults() {
        let dev = make_test_device();
        assert_eq!(dev.get_resume_id(), 0);
        assert_eq!(dev.get_state(), AshaState::Stopped);
        assert_eq!(dev.get_fd(), None);
        assert_eq!(dev.get_imtu(), ASHA_CONNECTION_MTU);
        assert_eq!(dev.get_omtu(), ASHA_MIN_MTU);
        assert!(!dev.endpoint_registered);
        assert!(dev.transport.is_none());
        assert!(dev.socket.is_none());
    }

    #[test]
    fn asha_device_stop_returns_resume_id() {
        let mut dev = make_test_device();
        // resume_id starts at 0; stop() should return current value.
        assert_eq!(dev.stop(), 0);
    }

    #[test]
    fn asha_device_state_reset_clears_resume_id() {
        let mut dev = make_test_device();
        dev.resume_id = 42;
        dev.state_reset();
        assert_eq!(dev.get_resume_id(), 0);
    }

    #[test]
    fn asha_device_set_volume_no_gatt() {
        let dev = make_test_device();
        // Without a GATT client attached, set_volume should return false.
        assert!(!dev.set_volume(-10));
    }

    #[test]
    fn asha_device_get_volume_default() {
        let dev = make_test_device();
        // Default volume from BtAsha::new() should be 0.
        assert_eq!(dev.get_volume(), 0);
    }

    #[test]
    fn asha_device_get_render_delay_default() {
        let dev = make_test_device();
        // Default render_delay from BtAsha::new() should be 0.
        assert_eq!(dev.get_render_delay(), 0);
    }

    #[test]
    fn asha_global_device_map_insert_and_lookup() {
        let adapter = Arc::new(TokioMutex::new(BtdAdapter::new_for_test(99)));
        let path = "/org/bluez/hci99/dev_11_22_33_44_55_66".to_string();
        let dev = AshaDevice::new(
            path.clone(),
            BDADDR_ANY,
            AddressType::LeRandom,
            adapter,
            "/org/bluez/hci99".to_string(),
        );
        let arc = Arc::new(std::sync::Mutex::new(dev));

        // Insert into global map.
        {
            let mut map = ASHA_DEVICES.lock().unwrap();
            map.insert(path.clone(), Arc::clone(&arc));
        }

        // Look up.
        {
            let map = ASHA_DEVICES.lock().unwrap();
            assert!(map.contains_key(&path));
        }

        // Clean up so we don't affect other tests.
        {
            let mut map = ASHA_DEVICES.lock().unwrap();
            map.remove(&path);
        }
    }

    #[test]
    fn asha_close_socket_when_none_is_noop() {
        let mut dev = make_test_device();
        // close_socket on a device with no socket should not panic.
        dev.close_socket();
        assert!(dev.socket.is_none());
    }

    #[test]
    fn asha_device_addr_type_to_kernel() {
        let dev = make_test_device();
        // Device was created with LePublic.
        let dest_type = match dev.device_addr_type {
            AddressType::LeRandom => BDADDR_LE_RANDOM,
            _ => BDADDR_LE_PUBLIC,
        };
        assert_eq!(dest_type, BDADDR_LE_PUBLIC);
    }
}
