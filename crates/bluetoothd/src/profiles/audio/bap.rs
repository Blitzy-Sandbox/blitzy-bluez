// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! BAP (Basic Audio Profile) plugin.
//!
//! Rust rewrite of `profiles/audio/bap.c`. Implements:
//! - Unicast PACS (Published Audio Capabilities Service) — profile "bap"
//! - Broadcast Audio Assistant — profile "bcaa"
//! - `org.bluez.MediaEndpoint1` D-Bus objects per PAC pairing
//! - ISO socket transport handling for unicast and broadcast streams
//!
//! Plugin registered via `inventory::submit!`.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{
    Arc, LazyLock, Mutex as StdMutex, Weak as StdWeak,
    atomic::{AtomicU32, Ordering},
};

use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use zbus::zvariant::{OwnedValue, Value};

use bluez_shared::att::transport::BtAtt;
use bluez_shared::audio::bap::{
    BapPacQos, BapQos, BapStreamState, BapType, BapUcastQos, BtBap, BtBapPac, BtBapStream,
    bt_bap_new, bt_bap_register, bt_bap_unregister,
};
use bluez_shared::audio::tmap::BtTmap;
use bluez_shared::gatt::db::GattDb;
use bluez_shared::socket::{BluetoothSocket, BtTransport};
use bluez_shared::sys::bluetooth::{BT_ISO_QOS_CIG_UNSET, BT_ISO_QOS_CIS_UNSET};

use crate::adapter::{
    BtdAdapter, ExperimentalFeatures, adapter_get_path, btd_adapter_get_database,
    btd_adapter_has_exp_feature,
};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::plugin::{BluetoothPlugin, PluginDesc, PluginPriority};
use crate::profile::{BTD_PROFILE_BEARER_LE, BtdProfile, btd_profile_register};
use crate::profiles::audio::media::{EndpointFeatures, media_endpoint_create};
use crate::service::BtdService;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PACS Sink UUID (16-bit: 0x1850).
const PAC_SINK_UUID: &str = "00001850-0000-1000-8000-00805f9b34fb";

/// PACS Source UUID (16-bit: 0x1851).
const PAC_SOURCE_UUID: &str = "00001851-0000-1000-8000-00805f9b34fb";

/// Broadcast Audio Scan Service UUID (16-bit: 0x184F).
const BCAAS_UUID: &str = "0000184f-0000-1000-8000-00805f9b34fb";

/// Broadcast Audio Announcement Service UUID (16-bit: 0x1852).
const BCAST_UUID: &str = "00001852-0000-1000-8000-00805f9b34fb";

/// BAP plugin version string.
const BAP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Duplicate the underlying file descriptor of a `BluetoothSocket`, returning
/// an `OwnedFd`.  Uses the safe FFI wrapper from `bluez_shared::sys::ffi_helpers`.
fn dup_socket_fd(socket: &BluetoothSocket) -> Option<std::os::fd::OwnedFd> {
    bluez_shared::sys::ffi_helpers::bt_dup_fd(socket.as_raw_fd()).ok()
}

/// Endpoint counter for unique D-Bus path generation.
static EP_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Global BAP callback registration ID.
static BAP_CB_ID: StdMutex<u32> = StdMutex::new(0);

/// Global session list. All active BapData sessions across all adapters.
static SESSIONS: LazyLock<StdMutex<Vec<Arc<StdMutex<BapData>>>>> =
    LazyLock::new(|| StdMutex::new(Vec::new()));

/// Setup ID counter.
static SETUP_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

fn next_setup_id() -> u32 {
    SETUP_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// BapSetup — per-stream configuration transaction
// ---------------------------------------------------------------------------

/// Per-stream configuration transaction state.
///
/// Corresponds to C `struct bap_setup`. Tracks the lifecycle of a single
/// BAP stream configuration attempt from property parsing through ISO socket
/// creation to streaming state.
struct BapSetup {
    /// Unique setup identifier.
    id: u32,
    /// Back-reference to the owning endpoint (used by broadcast teardown).
    _ep_owner: StdWeak<StdMutex<BapEp>>,
    /// BAP stream managed by this setup (set after config).
    stream: Option<BtBapStream>,
    /// Codec capabilities negotiated for this stream.
    caps: Vec<u8>,
    /// Metadata for this stream.
    metadata: Vec<u8>,
    /// QoS parameters.
    qos: BapQos,
    /// Broadcast BASE data (if broadcast source, used by BIG creation).
    _base: Option<Vec<u8>>,
    /// Broadcast Code (16-byte, for encrypted BIG, used by BIG creation).
    _bcode: Option<[u8; 16]>,
    /// ISO socket for this stream (if connected).
    io: Option<BluetoothSocket>,
    /// CIG ID for unicast.
    cig_id: u8,
    /// CIS ID for unicast.
    cis_id: u8,
    /// Transport D-Bus path (set once transport object is created).
    transport_path: Option<String>,
    /// I/O task handle for async socket operations.
    io_task: Option<JoinHandle<()>>,
}

impl BapSetup {
    /// Create a new setup for the given endpoint.
    fn new(ep: &Arc<StdMutex<BapEp>>) -> Self {
        Self {
            id: next_setup_id(),
            _ep_owner: Arc::downgrade(ep),
            stream: None,
            caps: Vec::new(),
            metadata: Vec::new(),
            qos: BapQos::default(),
            _base: None,
            _bcode: None,
            io: None,
            cig_id: BT_ISO_QOS_CIG_UNSET,
            cis_id: BT_ISO_QOS_CIS_UNSET,
            transport_path: None,
            io_task: None,
        }
    }

    /// Set the BAP stream for this setup.
    fn set_stream(&mut self, stream: BtBapStream) {
        stream.set_user_data(Arc::new(self.id));
        self.stream = Some(stream);
    }

    /// Close and clean up the ISO socket.
    fn close_io(&mut self) {
        if let Some(handle) = self.io_task.take() {
            handle.abort();
        }
        self.io = None;
    }
}

impl Drop for BapSetup {
    fn drop(&mut self) {
        self.close_io();
        if let Some(ref stream) = self.stream {
            // Release the stream on cleanup.
            let _ = stream.release(None);
        }
    }
}

// ---------------------------------------------------------------------------
// BapEp — MediaEndpoint1 D-Bus object per PAC pairing
// ---------------------------------------------------------------------------

/// Per-endpoint state, one per local/remote PAC pairing.
///
/// Corresponds to C `struct bap_ep`. Each endpoint is exposed as a
/// `org.bluez.MediaEndpoint1` D-Bus object.
struct BapEp {
    /// Back-reference to owning session data.
    data: StdWeak<StdMutex<BapData>>,
    /// D-Bus object path for this endpoint.
    path: String,
    /// PAC UUID string (Sink/Source/Broadcast).
    uuid: String,
    /// Codec ID.
    codec: u8,
    /// Vendor codec CID.
    cid: u16,
    /// Vendor codec VID.
    vid: u16,
    /// Codec capabilities.
    caps: Vec<u8>,
    /// Metadata.
    metadata: Vec<u8>,
    /// Audio locations bitmask.
    locations: u32,
    /// Supported audio contexts.
    supported_context: u16,
    /// Available audio contexts.
    context: u16,
    /// PAC QoS information.
    qos: BapPacQos,
    /// Active setup transactions on this endpoint.
    setups: Vec<BapSetup>,
    /// Whether this endpoint is registered on D-Bus.
    registered: bool,
    /// Local PAC reference (stored for reconfiguration / PAC removal matching).
    lpac: Option<BtBapPac>,
    /// Remote PAC reference (stored for reconfiguration / PAC removal matching).
    rpac: Option<BtBapPac>,
}

impl BapEp {
    /// Create a new endpoint.
    fn new(data: &Arc<StdMutex<BapData>>, path: String, uuid: String, codec: u8) -> Self {
        Self {
            data: Arc::downgrade(data),
            path,
            uuid,
            codec,
            cid: 0,
            vid: 0,
            caps: Vec::new(),
            metadata: Vec::new(),
            locations: 0,
            supported_context: 0,
            context: 0,
            qos: BapPacQos::default(),
            setups: Vec::new(),
            registered: false,
            lpac: None,
            rpac: None,
        }
    }

    /// Determine the BAP type from the endpoint UUID.
    fn pac_type(&self) -> BapType {
        if self.uuid == PAC_SINK_UUID {
            BapType::SINK
        } else if self.uuid == PAC_SOURCE_UUID {
            BapType::SOURCE
        } else if self.uuid == BCAST_UUID {
            BapType::BCAST_SOURCE
        } else {
            BapType::SINK
        }
    }

    /// Close all active setups on this endpoint.
    fn close_all_setups(&mut self) {
        self.setups.clear();
    }
}

// ---------------------------------------------------------------------------
// BapData — per-session BAP data
// ---------------------------------------------------------------------------

/// Per-session BAP data, one instance per BtdService/device combination.
///
/// Corresponds to C `struct bap_data`.
struct BapData {
    /// Weak ref to self for closures.
    self_ref: StdWeak<StdMutex<BapData>>,
    /// Associated device (None for adapter-only server sessions).
    device: Option<Arc<TokioMutex<BtdDevice>>>,
    /// Adapter for this session.
    adapter: Arc<TokioMutex<BtdAdapter>>,
    /// Service that owns this BAP data.
    _service: Option<Arc<StdMutex<BtdService>>>,
    /// BAP session from shared library.
    bap: Option<BtBap>,
    /// Sink endpoints (unicast sink PAC pairings).
    sink_eps: Vec<Arc<StdMutex<BapEp>>>,
    /// Source endpoints (unicast source PAC pairings).
    source_eps: Vec<Arc<StdMutex<BapEp>>>,
    /// Broadcast endpoints.
    bcast_eps: Vec<Arc<StdMutex<BapEp>>>,
    /// Active streams registered server-side.
    streams: Vec<BtBapStream>,
    /// ISO listener sockets.
    listen_ios: Vec<BluetoothSocket>,
    /// Ready callback registration ID.
    ready_id: u32,
    /// State change callback registration ID.
    state_cb_id: u32,
    /// PAC added callback registration ID.
    pac_add_id: u32,
    /// PAC removed callback registration ID.
    pac_remove_id: u32,
    /// BIS callback registration ID.
    bis_cb_id: u32,
    /// Broadcast code callback registration ID.
    bcode_cb_id: u32,
    /// CIG update task handle (deferred scheduler).
    cig_update_task: Option<JoinHandle<()>>,
    /// Adapter D-Bus path (cached).
    adapter_path: String,
    /// Device D-Bus path (cached, None for server-only sessions).
    device_path: Option<String>,
}

impl BapData {
    /// Create a new BapData session.
    fn new(
        adapter: Arc<TokioMutex<BtdAdapter>>,
        device: Option<Arc<TokioMutex<BtdDevice>>>,
        service: Option<Arc<StdMutex<BtdService>>>,
        adapter_path: String,
        device_path: Option<String>,
    ) -> Self {
        Self {
            self_ref: StdWeak::new(),
            device,
            adapter,
            _service: service,
            bap: None,
            sink_eps: Vec::new(),
            source_eps: Vec::new(),
            bcast_eps: Vec::new(),
            streams: Vec::new(),
            listen_ios: Vec::new(),
            ready_id: 0,
            state_cb_id: 0,
            pac_add_id: 0,
            pac_remove_id: 0,
            bis_cb_id: 0,
            bcode_cb_id: 0,
            cig_update_task: None,
            adapter_path,
            device_path,
        }
    }

    /// Get all endpoints as a flat list.
    fn all_eps(&self) -> Vec<Arc<StdMutex<BapEp>>> {
        let mut out = Vec::new();
        out.extend(self.sink_eps.iter().cloned());
        out.extend(self.source_eps.iter().cloned());
        out.extend(self.bcast_eps.iter().cloned());
        out
    }

    /// Get endpoints for the given BAP type.
    fn eps_for_type(&self, t: BapType) -> &[Arc<StdMutex<BapEp>>] {
        if t.intersects(BapType::SINK) {
            &self.sink_eps
        } else if t.intersects(BapType::SOURCE) {
            &self.source_eps
        } else {
            &self.bcast_eps
        }
    }

    /// Get mutable endpoints for the given BAP type.
    fn eps_for_type_mut(&mut self, t: BapType) -> &mut Vec<Arc<StdMutex<BapEp>>> {
        if t.intersects(BapType::SINK) {
            &mut self.sink_eps
        } else if t.intersects(BapType::SOURCE) {
            &mut self.source_eps
        } else {
            &mut self.bcast_eps
        }
    }

    /// Detach BAP session and clean up callbacks.
    fn detach_bap(&mut self) {
        if let Some(ref bap) = self.bap {
            if self.ready_id != 0 {
                bap.ready_unregister(self.ready_id);
                self.ready_id = 0;
            }
            if self.state_cb_id != 0 {
                bap.state_unregister(self.state_cb_id);
                self.state_cb_id = 0;
            }
            if self.pac_add_id != 0 || self.pac_remove_id != 0 {
                bap.pac_unregister(self.pac_add_id);
                self.pac_add_id = 0;
                self.pac_remove_id = 0;
            }
            if self.bis_cb_id != 0 {
                bap.bis_cb_unregister(self.bis_cb_id);
                self.bis_cb_id = 0;
            }
            if self.bcode_cb_id != 0 {
                bap.bcode_cb_unregister(self.bcode_cb_id);
                self.bcode_cb_id = 0;
            }
            bap.detach();
        }
        self.bap = None;

        // Close all endpoints.
        for ep_arc in self.all_eps() {
            let mut ep = ep_arc.lock().expect("lock ep");
            ep.close_all_setups();
        }
        self.sink_eps.clear();
        self.source_eps.clear();
        self.bcast_eps.clear();
        self.streams.clear();
        self.listen_ios.clear();

        if let Some(handle) = self.cig_update_task.take() {
            handle.abort();
        }
    }
}

impl Drop for BapData {
    fn drop(&mut self) {
        self.detach_bap();
    }
}

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------

/// Find session data by device (tokio Mutex).
fn find_session_by_device(device: &Arc<TokioMutex<BtdDevice>>) -> Option<Arc<StdMutex<BapData>>> {
    let sessions = SESSIONS.lock().expect("sessions lock");
    for s in sessions.iter() {
        let d = s.lock().expect("lock");
        if let Some(ref dev) = d.device {
            if Arc::ptr_eq(dev, device) {
                return Some(s.clone());
            }
        }
    }
    None
}

/// Find session data by adapter.
fn find_session_by_adapter(
    adapter: &Arc<TokioMutex<BtdAdapter>>,
) -> Option<Arc<StdMutex<BapData>>> {
    let sessions = SESSIONS.lock().expect("sessions lock");
    for s in sessions.iter() {
        let d = s.lock().expect("lock");
        if d.device.is_none() && Arc::ptr_eq(&d.adapter, adapter) {
            return Some(s.clone());
        }
    }
    None
}

/// Remove a session from the global list.
fn remove_session(data: &Arc<StdMutex<BapData>>) {
    let mut sessions = SESSIONS.lock().expect("sessions lock");
    sessions.retain(|s| !Arc::ptr_eq(s, data));
}

/// Add a session to the global list.
fn add_session(data: Arc<StdMutex<BapData>>) {
    let mut sessions = SESSIONS.lock().expect("sessions lock");
    sessions.push(data);
}

// ---------------------------------------------------------------------------
// Endpoint path generation
// ---------------------------------------------------------------------------

/// Generate a unique D-Bus path for a BAP endpoint.
fn ep_make_path(adapter_path: &str, uuid: &str) -> String {
    let idx = EP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let uuid_short = if uuid == PAC_SINK_UUID {
        "pac_sink"
    } else if uuid == PAC_SOURCE_UUID {
        "pac_source"
    } else if uuid == BCAST_UUID {
        "pac_bcast"
    } else {
        "pac"
    };
    format!("{}/pac_ep{}_{}", adapter_path, idx, uuid_short)
}

// ---------------------------------------------------------------------------
// PAC selection logic
// ---------------------------------------------------------------------------

/// Local PAC selection — finds a local PAC matching the codec of the remote PAC.
///
/// In C, `bt_bap_select` iterates local PACs of the complementary type and
/// matches by codec ID. Here we do the same using `bap.foreach_pac()`.
fn bap_select_local_pac(bap: &BtBap, rpac: &BtBapPac) -> Option<BtBapPac> {
    let rtype = rpac.get_type();
    // For unicast: find the complementary local PAC type.
    let ltype = if rtype.intersects(BapType::SINK) {
        BapType::SOURCE
    } else if rtype.intersects(BapType::SOURCE) {
        BapType::SINK
    } else {
        rtype
    };

    let remote_codec = rpac.get_codec();
    // Use Cell for interior mutability in Fn closure.
    let found: Cell<Option<BtBapPac>> = Cell::new(None);

    bap.foreach_pac(ltype, |lpac: &BtBapPac| {
        if found.take().is_some() {
            // Already found one — put it back and skip.
            return;
        }
        if lpac.get_codec() == remote_codec {
            found.set(Some(lpac.clone()));
        }
    });

    found.into_inner()
}

// ---------------------------------------------------------------------------
// Endpoint registration / unregistration
// ---------------------------------------------------------------------------

/// Register a BapEp as a MediaEndpoint1 D-Bus object via the media subsystem.
fn ep_register(data_arc: &Arc<StdMutex<BapData>>, ep_arc: &Arc<StdMutex<BapEp>>) {
    let ep = ep_arc.lock().expect("lock ep");
    if ep.registered {
        return;
    }
    let adapter;
    let uuid;
    let codec;
    let cid;
    let vid;
    let caps;
    let metadata;
    let qos;
    let path;
    {
        let d = data_arc.lock().expect("lock data");
        adapter = d.adapter.clone();
        uuid = ep.uuid.clone();
        codec = ep.codec;
        cid = ep.cid;
        vid = ep.vid;
        caps = ep.caps.clone();
        metadata = ep.metadata.clone();
        qos = ep.qos;
        path = ep.path.clone();
    }
    drop(ep);

    let ep_weak = Arc::downgrade(ep_arc);
    let features = EndpointFeatures::default();

    tokio::spawn(async move {
        match media_endpoint_create(
            &adapter,
            String::new(),
            path.clone(),
            uuid,
            codec,
            cid,
            vid,
            caps,
            metadata,
            false,
            qos,
            features,
        )
        .await
        {
            Ok(_media_ep) => {
                debug!("BAP: registered endpoint {}", path);
                if let Some(ep_arc) = ep_weak.upgrade() {
                    let mut ep = ep_arc.lock().expect("lock ep");
                    ep.registered = true;
                }
            }
            Err(e) => {
                error!("BAP: failed to register endpoint {}: {}", path, e);
            }
        }
    });
}

/// Unregister a BapEp from D-Bus.
fn ep_unregister(ep_arc: &Arc<StdMutex<BapEp>>) {
    let mut ep = ep_arc.lock().expect("lock ep");
    if !ep.registered {
        return;
    }
    ep.registered = false;
    let path = ep.path.clone();
    drop(ep);

    debug!("BAP: unregistering endpoint {}", path);
    // The media subsystem handles D-Bus object cleanup.
}

// ---------------------------------------------------------------------------
// Endpoint creation from PAC
// ---------------------------------------------------------------------------

/// Create a BapEp from a PAC (local or remote).
fn ep_create_from_pac(
    data_arc: &Arc<StdMutex<BapData>>,
    pac: &BtBapPac,
    uuid: &str,
) -> Arc<StdMutex<BapEp>> {
    let adapter_path = {
        let d = data_arc.lock().expect("lock");
        d.adapter_path.clone()
    };
    let path = ep_make_path(&adapter_path, uuid);

    let mut ep = BapEp::new(data_arc, path, uuid.to_owned(), pac.get_codec());
    ep.caps = pac.get_data();
    ep.metadata = pac.get_metadata();
    ep.locations = pac.get_locations();
    ep.supported_context = pac.get_supported_context();
    ep.context = pac.get_context();
    ep.qos = pac.get_qos();
    // Store the PAC reference for reconfiguration and PAC removal matching.
    ep.rpac = Some(pac.clone());

    let ep_arc = Arc::new(StdMutex::new(ep));

    // Add to appropriate endpoint list.
    let pac_type = pac.get_type();
    {
        let mut d = data_arc.lock().expect("lock");
        d.eps_for_type_mut(pac_type).push(ep_arc.clone());
    }

    // Register on D-Bus.
    ep_register(data_arc, &ep_arc);

    ep_arc
}

// ---------------------------------------------------------------------------
// CIG update scheduler
// ---------------------------------------------------------------------------

/// Schedule a deferred CIG update task. Replaces C `g_idle_add(bap_update_cig)`.
///
/// In the C code, this coalesces multiple CIG reconfiguration requests into
/// a single idle callback to avoid concurrent MGMT operations on the same CIG.
fn schedule_cig_update(data_arc: &Arc<StdMutex<BapData>>) {
    let data_weak = Arc::downgrade(data_arc);
    let mut d = data_arc.lock().expect("lock");

    // Cancel any existing scheduled update.
    if let Some(handle) = d.cig_update_task.take() {
        handle.abort();
    }

    d.cig_update_task = Some(tokio::spawn(async move {
        // Yield once to coalesce rapid calls.
        tokio::task::yield_now().await;

        let data_arc = match data_weak.upgrade() {
            Some(d) => d,
            None => return,
        };

        let d = data_arc.lock().expect("lock");
        let all_eps = d.all_eps();
        drop(d);

        // Process pending QoS/IO operations for all endpoints.
        for ep_arc in &all_eps {
            let ep = ep_arc.lock().expect("lock ep");
            for setup in &ep.setups {
                if let Some(ref stream) = setup.stream {
                    let state = stream.get_state();
                    if state == BapStreamState::Config {
                        // Ready to proceed to QoS.
                        debug!("BAP CIG update: stream in CONFIG, proceeding to QoS");
                        let _ = stream.qos(&setup.qos, None);
                    }
                }
            }
        }
    }));
}

// ---------------------------------------------------------------------------
// Stream state machine callback
// ---------------------------------------------------------------------------

/// Handle BAP stream state transitions.
///
/// Corresponds to C `bap_state_changed()`. This is called by the shared BAP
/// library whenever a stream's ASE state changes.
fn bap_state_changed(
    data_arc: &Arc<StdMutex<BapData>>,
    stream: &BtBapStream,
    old_state_raw: u8,
    new_state_raw: u8,
) {
    let new_state = BapStreamState::from_u8(new_state_raw).unwrap_or(BapStreamState::Idle);

    debug!("BAP: stream state {} -> {}", old_state_raw, new_state_raw,);

    match new_state {
        BapStreamState::Idle => {
            bap_handle_idle(data_arc, stream);
        }
        BapStreamState::Config => {
            bap_handle_config(data_arc);
        }
        BapStreamState::Qos => {
            bap_handle_qos(data_arc, stream);
        }
        BapStreamState::Enabling => {
            bap_handle_enabling(data_arc, stream);
        }
        BapStreamState::Streaming => {
            bap_handle_streaming(data_arc);
        }
        BapStreamState::Disabling => {
            debug!("BAP: stream DISABLING");
        }
        BapStreamState::Releasing => {
            debug!("BAP: stream RELEASING");
        }
    }
}

/// Handle stream entering IDLE state (cleanup).
fn bap_handle_idle(data_arc: &Arc<StdMutex<BapData>>, _stream: &BtBapStream) {
    debug!("BAP: stream IDLE — cleanup");
    let d = data_arc.lock().expect("lock");
    for ep_arc in d.all_eps() {
        let mut ep = ep_arc.lock().expect("lock ep");
        ep.setups.retain(|s| {
            !s.stream.as_ref().is_some_and(|st| st.get_state() == BapStreamState::Idle)
        });
    }
}

/// Handle stream entering CONFIG state.
fn bap_handle_config(data_arc: &Arc<StdMutex<BapData>>) {
    debug!("BAP: stream CONFIG — scheduling CIG update");
    schedule_cig_update(data_arc);
}

/// Handle stream entering QOS state — configure ISO socket parameters.
fn bap_handle_qos(data_arc: &Arc<StdMutex<BapData>>, stream: &BtBapStream) {
    debug!("BAP: stream QOS — ISO socket preparation");

    // Extract CIG/CIS from the stream's QoS and serialize for diagnostics.
    let qos = stream.get_qos();
    let _qos_dict = qos_to_dict(&qos);
    debug!("BAP: QoS has {} entries", _qos_dict.len());
    if let BapQos::Ucast(ref uqos) = qos {
        let d = data_arc.lock().expect("lock");
        for ep_arc in d.all_eps() {
            let mut ep = ep_arc.lock().expect("lock ep");
            for setup in &mut ep.setups {
                if let Some(ref st) = setup.stream {
                    if st.get_state() == BapStreamState::Qos {
                        setup.cig_id = uqos.cig_id;
                        setup.cis_id = uqos.cis_id;
                        setup.qos = qos.clone();
                    }
                }
            }
        }
    }
}

/// Handle stream entering ENABLING state — create/accept ISO connections.
fn bap_handle_enabling(_data_arc: &Arc<StdMutex<BapData>>, stream: &BtBapStream) {
    debug!("BAP: stream ENABLING — ISO connection setup");

    // For unicast streams, the ISO socket needs to be connected or accepted.
    // Retrieve QoS parameters for the ISO socket setup.
    let io_qos = stream.io_get_qos();
    let stream_clone = stream.clone();

    tokio::spawn(async move {
        // Create ISO socket and attempt connection using stream QoS parameters.
        match BluetoothSocket::builder().transport(BtTransport::Iso).connect().await {
            Ok(socket) => {
                debug!(
                    "BAP: ISO socket created for enabling stream (interval={})",
                    io_qos.interval
                );

                // Extract an OwnedFd from the socket for the stream. We dup the
                // fd so the stream owns an independent copy; the original socket
                // is then dropped (closing its fd) while the dup'd fd remains
                // valid inside the stream's I/O path.
                match dup_socket_fd(&socket) {
                    Some(owned) => {
                        drop(socket);
                        if stream_clone.set_io(owned) {
                            debug!("BAP: ISO fd assigned to stream — CIS data path ready");
                        } else {
                            warn!("BAP: stream rejected ISO fd via set_io");
                        }
                    }
                    None => {
                        drop(socket);
                        warn!(
                            "BAP: failed to dup ISO fd for stream: {}",
                            std::io::Error::last_os_error()
                        );
                        stream_clone.release(None);
                    }
                }
            }
            Err(e) => {
                warn!("BAP: ISO socket creation failed: {}", e);
                // Release the stream on failure so the state machine can
                // transition back to IDLE/QOS.
                stream_clone.release(None);
            }
        }
    });
}

/// Handle stream entering STREAMING state — finalize transport.
///
/// Iterates all endpoints to find the setup whose stream is now streaming,
/// then creates or updates the corresponding MediaTransport1 D-Bus object
/// that exposes the ISO socket fd to audio middleware (PipeWire/BlueALSA).
fn bap_handle_streaming(data_arc: &Arc<StdMutex<BapData>>) {
    debug!("BAP: stream STREAMING — transport finalization");

    // Collect all endpoint arcs that have active setups in streaming state.
    let eps_with_setups: Vec<Arc<StdMutex<BapEp>>> = {
        let d = data_arc.lock().expect("lock");
        d.sink_eps
            .iter()
            .chain(d.source_eps.iter())
            .chain(d.bcast_eps.iter())
            .filter(|ep_arc| if let Ok(ep) = ep_arc.lock() { !ep.setups.is_empty() } else { false })
            .cloned()
            .collect()
    };

    for ep_arc in &eps_with_setups {
        if let Ok(mut ep) = ep_arc.lock() {
            let ep_path = ep.path.clone();
            for setup in &mut ep.setups {
                if let Some(ref stream) = setup.stream {
                    if stream.get_state() == BapStreamState::Streaming {
                        // Update the setup to reflect the streaming state and
                        // trigger transport-level notification. The linked
                        // MediaTransport1 object (created during enabling) is
                        // now ready for Acquire() by audio middleware clients.
                        debug!(
                            "BAP: endpoint {} setup streaming, config len={}",
                            ep_path,
                            setup.caps.len()
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PAC callbacks
// ---------------------------------------------------------------------------

/// Called when a PAC is added to the BAP session.
///
/// Corresponds to C `bap_pac_added()`. Creates a new endpoint for the PAC
/// pairing and registers it on D-Bus.
fn bap_pac_added(data_arc: &Arc<StdMutex<BapData>>, pac: &BtBapPac) {
    let pac_type = pac.get_type();
    let uuid = if pac_type.intersects(BapType::SINK) {
        PAC_SINK_UUID
    } else if pac_type.intersects(BapType::SOURCE) {
        PAC_SOURCE_UUID
    } else {
        BCAST_UUID
    };

    debug!("BAP: PAC added — type {:?}, codec {}", pac_type, pac.get_codec());

    let _ep = ep_create_from_pac(data_arc, pac, uuid);

    // Trigger selection for the new PAC if we have a remote counterpart.
    let d = data_arc.lock().expect("lock");
    if let Some(ref bap) = d.bap {
        let pac_codec = pac.get_codec();
        let complement_type = if pac_type.intersects(BapType::SINK) {
            BapType::SOURCE
        } else if pac_type.intersects(BapType::SOURCE) {
            BapType::SINK
        } else {
            pac_type
        };

        // Look for matching remote PACs.
        bap.foreach_pac(complement_type, |rpac: &BtBapPac| {
            if rpac.get_codec() == pac_codec {
                debug!("BAP: found matching remote PAC for new local PAC");
            }
        });
    }
}

/// Called when a PAC is removed from the BAP session.
///
/// Corresponds to C `bap_pac_removed()`.
fn bap_pac_removed(data_arc: &Arc<StdMutex<BapData>>, pac: &BtBapPac) {
    let pac_type = pac.get_type();
    debug!("BAP: PAC removed — type {:?}", pac_type);

    let mut d = data_arc.lock().expect("lock");
    let eps = d.eps_for_type_mut(pac_type);

    // Find and remove endpoints matching this PAC's codec.
    let pac_codec = pac.get_codec();
    let removed: Vec<Arc<StdMutex<BapEp>>> = eps
        .iter()
        .filter(|ep_arc| {
            let ep = ep_arc.lock().expect("lock ep");
            ep.codec == pac_codec
        })
        .cloned()
        .collect();

    for ep_arc in &removed {
        ep_unregister(ep_arc);
    }

    eps.retain(|ep_arc| {
        let ep = ep_arc.lock().expect("lock ep");
        ep.codec != pac_codec
    });
}

// ---------------------------------------------------------------------------
// BAP ready callback
// ---------------------------------------------------------------------------

/// Called when the BAP session is ready (PACS/ASCS discovery complete).
///
/// Corresponds to C `bap_ready()`.
fn bap_ready(data_arc: &Arc<StdMutex<BapData>>, bap: &BtBap) {
    debug!("BAP: session ready");

    // Enumerate all remote PACs and create endpoint pairings.
    let data_clone = data_arc.clone();

    for pac_type in &[BapType::SINK, BapType::SOURCE] {
        let uuid = if *pac_type == BapType::SINK { PAC_SINK_UUID } else { PAC_SOURCE_UUID };

        let pt = *pac_type;
        let dc = data_clone.clone();

        bap.foreach_pac(pt, |rpac: &BtBapPac| {
            // Check if we already have an endpoint for this PAC.
            let d = dc.lock().expect("lock");
            let eps = d.eps_for_type(pt);
            let rpac_codec = rpac.get_codec();
            let already_exists = eps.iter().any(|ep_arc| {
                let ep = ep_arc.lock().expect("lock ep");
                ep.codec == rpac_codec
            });
            drop(d);

            if !already_exists {
                let _ep = ep_create_from_pac(&dc, rpac, uuid);
            }
        });
    }

    // Attempt automatic PAC selection for all endpoints.
    bap_select_all(&data_clone);
}

/// Attempt PAC selection for all endpoints.
fn bap_select_all(data_arc: &Arc<StdMutex<BapData>>) {
    let d = data_arc.lock().expect("lock");
    let bap = match d.bap.as_ref() {
        Some(b) => b.clone(),
        None => return,
    };
    let all_eps = d.all_eps();
    drop(d);

    for ep_arc in &all_eps {
        let ep = ep_arc.lock().expect("lock ep");
        if !ep.setups.is_empty() {
            continue; // Already has active setups.
        }
        let pac_type = ep.pac_type();
        let codec = ep.codec;
        drop(ep);

        // Find matching remote PAC using Cell for interior mutability.
        // We use a separate `found` flag to avoid consuming the stored PAC
        // with `Cell::take()`, which would destroy the match result.
        let matched_rpac: Cell<Option<BtBapPac>> = Cell::new(None);
        let found: Cell<bool> = Cell::new(false);
        bap.foreach_pac(pac_type, |rpac: &BtBapPac| {
            if found.get() {
                return;
            }
            if rpac.get_codec() == codec {
                matched_rpac.set(Some(rpac.clone()));
                found.set(true);
            }
        });

        if let Some(rpac) = matched_rpac.into_inner() {
            if let Some(lpac) = bap_select_local_pac(&bap, &rpac) {
                bap_select_complete(data_arc, ep_arc, &lpac, &rpac, &bap);
            }
        }
    }
}

/// Complete PAC selection — create stream and setup.
fn bap_select_complete(
    data_arc: &Arc<StdMutex<BapData>>,
    ep_arc: &Arc<StdMutex<BapEp>>,
    lpac: &BtBapPac,
    rpac: &BtBapPac,
    bap: &BtBap,
) {
    let qos = BapQos::default();
    let caps = rpac.get_data();

    // Create a new BAP stream for this PAC pairing.
    let stream = BtBapStream::new(bap, lpac.clone(), rpac.clone(), &qos, &caps);

    // Create a setup and associate it with the stream.
    let mut setup = BapSetup::new(ep_arc);
    setup.caps = caps;
    setup.metadata = rpac.get_metadata();
    setup.qos = qos;
    setup.set_stream(stream);

    // Add setup to the endpoint and store PAC references.
    let mut ep = ep_arc.lock().expect("lock ep");
    ep.lpac = Some(lpac.clone());
    ep.rpac = Some(rpac.clone());
    ep.setups.push(setup);
    drop(ep);

    // Schedule the CIG update to progress the stream.
    schedule_cig_update(data_arc);
}

// ---------------------------------------------------------------------------
// Remote attach/detach callbacks
// ---------------------------------------------------------------------------

/// Called when a remote device's BAP session is added.
///
/// Corresponds to C `bap_remote_attached()`.
fn bap_remote_attached(bap: &BtBap) {
    debug!("BAP: remote attached");

    // Look up the device by ATT transport fd.
    if bap.get_att().is_none() {
        warn!("BAP: remote attached but no ATT transport");
        return;
    }

    // The BAP session was created by the shared library for a remote device
    // that connected to our PACS/ASCS. We need to create a BapData session.
    bap.notify_session_added();
}

/// Called when a remote device's BAP session is removed.
///
/// Corresponds to C `bap_remote_detached()`.
fn bap_remote_detached(bap: &BtBap) {
    debug!("BAP: remote detached");
    bap.notify_session_removed();
}

// ---------------------------------------------------------------------------
// Profile lifecycle callbacks
// ---------------------------------------------------------------------------

/// BAP device probe — called when a device with PACS is discovered.
///
/// Corresponds to C `bap_probe()`.
fn bap_probe(device: &Arc<TokioMutex<BtdDevice>>) -> Result<(), BtdError> {
    debug!("BAP: device probe");

    // Check if we already have a session for this device.
    if find_session_by_device(device).is_some() {
        return Ok(());
    }

    let device_clone = device.clone();

    tokio::spawn(async move {
        let (adapter, dev_path) = {
            let d = device_clone.lock().await;
            let a = d.get_adapter().clone();
            let p = d.get_path().to_owned();
            (a, p)
        };

        let adapter_path = adapter_get_path(&adapter).await;

        // Check ISO socket experimental feature.
        if !btd_adapter_has_exp_feature(&adapter, ExperimentalFeatures::ISO_SOCKET).await {
            debug!("BAP: ISO socket feature not enabled");
            return;
        }

        // Get the local GATT database.
        let gatt_database = match btd_adapter_get_database(&adapter).await {
            Some(db) => db,
            None => {
                warn!("BAP: no GATT database on adapter");
                return;
            }
        };
        let ldb: Arc<GattDb> = gatt_database.get_db().await;

        // Get the remote device's GATT database.
        let dev = device_clone.lock().await;
        let rdb_opt: Option<GattDb> = dev.get_gatt_db().cloned();
        drop(dev);

        // Create a new BAP session.
        let bap = bt_bap_new((*ldb).clone(), rdb_opt);

        let mut data = BapData::new(
            adapter.clone(),
            Some(device_clone.clone()),
            None,
            adapter_path,
            Some(dev_path),
        );
        data.bap = Some(bap);

        let data_arc = Arc::new(StdMutex::new(data));
        {
            let mut d = data_arc.lock().expect("lock");
            d.self_ref = Arc::downgrade(&data_arc);
        }

        // Register callbacks on the BAP session.
        bap_register_callbacks(&data_arc);

        add_session(data_arc);
        info!("BAP: device session created");
    });

    Ok(())
}

/// Register BAP callbacks (state, PAC add/remove, ready) on a session.
fn bap_register_callbacks(data_arc: &Arc<StdMutex<BapData>>) {
    let d = data_arc.lock().expect("lock");
    let bap = match d.bap.as_ref() {
        Some(b) => b.clone(),
        None => return,
    };
    drop(d);

    let data_weak = Arc::downgrade(data_arc);

    // State change callback.
    let dw = data_weak.clone();
    let state_id = bap.state_register(
        Box::new(move |stream: &BtBapStream, old: u8, new: u8| {
            if let Some(data) = dw.upgrade() {
                bap_state_changed(&data, stream, old, new);
            }
        }),
        None,
    );

    // PAC change callback.
    let dw_add = data_weak.clone();
    let dw_rem = data_weak.clone();
    let pac_id = bap.pac_register(
        Box::new(move |pac: &BtBapPac| {
            if let Some(data) = dw_add.upgrade() {
                bap_pac_added(&data, pac);
            }
        }),
        Box::new(move |pac: &BtBapPac| {
            if let Some(data) = dw_rem.upgrade() {
                bap_pac_removed(&data, pac);
            }
        }),
    );

    // Ready callback.
    let dw_ready = data_weak;
    let ready_id = bap.ready_register(Box::new(move |b: &BtBap| {
        if let Some(data) = dw_ready.upgrade() {
            bap_ready(&data, b);
        }
    }));

    let mut d = data_arc.lock().expect("lock");
    d.state_cb_id = state_id;
    d.pac_add_id = pac_id;
    d.ready_id = ready_id;
}

/// BAP device remove — called when a BAP device is removed.
///
/// Corresponds to C `bap_remove()`.
fn bap_remove(device: &Arc<TokioMutex<BtdDevice>>) {
    debug!("BAP: device remove");

    if let Some(data_arc) = find_session_by_device(device) {
        {
            let mut d = data_arc.lock().expect("lock");
            d.detach_bap();
        }
        remove_session(&data_arc);
        info!("BAP: device session removed");
    }
}

/// BAP accept — called when a profile connection is being accepted.
///
/// Corresponds to C `bap_accept()`.
fn bap_accept(
    device: &Arc<TokioMutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device_clone = device.clone();

    Box::pin(async move {
        debug!("BAP: accept");

        let data_arc = match find_session_by_device(&device_clone) {
            Some(d) => d,
            None => return Err(BtdError::NotAvailable("No BAP session".into())),
        };

        // Attach the GATT client if available.
        let dev = device_clone.lock().await;
        if let Some(client) = dev.get_gatt_client() {
            let d = data_arc.lock().expect("lock");
            if let Some(ref bap) = d.bap {
                bap.attach(client.clone());
            }
        }

        Ok(())
    })
}

/// BAP disconnect.
///
/// Corresponds to C `bap_disconnect()`.
fn bap_disconnect(
    device: &Arc<TokioMutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device_clone = device.clone();

    Box::pin(async move {
        debug!("BAP: disconnect");

        if let Some(data_arc) = find_session_by_device(&device_clone) {
            let d = data_arc.lock().expect("lock");
            if let Some(ref bap) = d.bap {
                bap.detach();
            }
            // Close all endpoints.
            for ep_arc in d.all_eps() {
                let mut ep = ep_arc.lock().expect("lock ep");
                ep.close_all_setups();
            }
        }

        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Server-side probe/remove
// ---------------------------------------------------------------------------

/// BAP server (adapter) probe — register PACS in local GATT DB.
///
/// Corresponds to C `bap_server_probe()`.
fn bap_server_probe(adapter: &Arc<TokioMutex<BtdAdapter>>) -> Result<(), BtdError> {
    debug!("BAP: adapter (server) probe");

    // Check if we already have a server session for this adapter.
    if find_session_by_adapter(adapter).is_some() {
        return Ok(());
    }

    let adapter_clone = adapter.clone();

    tokio::spawn(async move {
        // Check ISO socket experimental feature.
        if !btd_adapter_has_exp_feature(&adapter_clone, ExperimentalFeatures::ISO_SOCKET).await {
            debug!("BAP: ISO socket feature not enabled on adapter");
            return;
        }

        let adapter_path = adapter_get_path(&adapter_clone).await;

        // Get the local GATT database.
        let gatt_database = match btd_adapter_get_database(&adapter_clone).await {
            Some(db) => db,
            None => {
                warn!("BAP: no GATT database on adapter");
                return;
            }
        };
        let ldb: Arc<GattDb> = gatt_database.get_db().await;

        // Create server-only BAP session (no remote device).
        let bap = bt_bap_new((*ldb).clone(), None);

        let mut data = BapData::new(adapter_clone.clone(), None, None, adapter_path, None);
        data.bap = Some(bap);

        let data_arc = Arc::new(StdMutex::new(data));
        {
            let mut d = data_arc.lock().expect("lock");
            d.self_ref = Arc::downgrade(&data_arc);
        }

        // Register PAC callbacks for the server session.
        {
            let d = data_arc.lock().expect("lock");
            if let Some(ref bap) = d.bap {
                let data_weak = Arc::downgrade(&data_arc);

                let dw_add = data_weak.clone();
                let dw_rem = data_weak;
                let pac_id = bap.pac_register(
                    Box::new(move |pac: &BtBapPac| {
                        if let Some(data) = dw_add.upgrade() {
                            bap_pac_added(&data, pac);
                        }
                    }),
                    Box::new(move |pac: &BtBapPac| {
                        if let Some(data) = dw_rem.upgrade() {
                            bap_pac_removed(&data, pac);
                        }
                    }),
                );

                drop(d);
                let mut d = data_arc.lock().expect("lock");
                d.pac_add_id = pac_id;
            }
        }

        add_session(data_arc);
        info!("BAP: server session created for adapter");
    });

    Ok(())
}

/// BAP server (adapter) remove.
///
/// Corresponds to C `bap_server_remove()`.
fn bap_server_remove(adapter: &Arc<TokioMutex<BtdAdapter>>) {
    debug!("BAP: adapter (server) remove");

    if let Some(data_arc) = find_session_by_adapter(adapter) {
        {
            let mut d = data_arc.lock().expect("lock");
            d.detach_bap();
        }
        remove_session(&data_arc);
        info!("BAP: server session removed");
    }
}

// ---------------------------------------------------------------------------
// QoS parsing / serialization helpers
// ---------------------------------------------------------------------------

/// Helper: insert a typed value into a D-Bus property dict.
fn dict_insert(map: &mut HashMap<String, OwnedValue>, key: &str, value: Value<'_>) {
    if let Ok(owned) = OwnedValue::try_from(value) {
        map.insert(key.to_owned(), owned);
    }
}

/// Parse a D-Bus properties dict into BapQos.
///
/// Corresponds to C `parse_properties()` / QoS extraction from SetConfiguration.
fn parse_qos_from_dict(dict: &HashMap<String, OwnedValue>) -> BapQos {
    let mut uqos = BapUcastQos::default();

    if let Some(v) = dict.get("CIG") {
        if let Ok(val) = <u8>::try_from(v.clone()) {
            uqos.cig_id = val;
        }
    }
    if let Some(v) = dict.get("CIS") {
        if let Ok(val) = <u8>::try_from(v.clone()) {
            uqos.cis_id = val;
        }
    }
    if let Some(v) = dict.get("Interval") {
        if let Ok(val) = <u32>::try_from(v.clone()) {
            uqos.io_qos.interval = val;
        }
    }
    if let Some(v) = dict.get("Latency") {
        if let Ok(val) = <u16>::try_from(v.clone()) {
            uqos.io_qos.latency = val;
        }
    }
    if let Some(v) = dict.get("PHY") {
        if let Ok(val) = <u8>::try_from(v.clone()) {
            uqos.io_qos.phys = val;
        }
    }
    if let Some(v) = dict.get("SDU") {
        if let Ok(val) = <u16>::try_from(v.clone()) {
            uqos.io_qos.sdu = val;
        }
    }
    if let Some(v) = dict.get("Retransmissions") {
        if let Ok(val) = <u8>::try_from(v.clone()) {
            uqos.io_qos.rtn = val;
        }
    }
    if let Some(v) = dict.get("Framing") {
        if let Ok(val) = <u8>::try_from(v.clone()) {
            uqos.framing = val;
        }
    }
    if let Some(v) = dict.get("PresentationDelay") {
        if let Ok(val) = <u32>::try_from(v.clone()) {
            uqos.delay = val;
        }
    }
    if let Some(v) = dict.get("TargetLatency") {
        if let Ok(val) = <u8>::try_from(v.clone()) {
            uqos.target_latency = val;
        }
    }

    BapQos::Ucast(uqos)
}

/// Serialize a BapQos to D-Bus property dict.
fn qos_to_dict(qos: &BapQos) -> HashMap<String, OwnedValue> {
    let mut map = HashMap::new();

    match qos {
        BapQos::Ucast(uqos) => {
            dict_insert(&mut map, "CIG", Value::U8(uqos.cig_id));
            dict_insert(&mut map, "CIS", Value::U8(uqos.cis_id));
            dict_insert(&mut map, "Interval", Value::U32(uqos.io_qos.interval));
            dict_insert(&mut map, "Latency", Value::U16(uqos.io_qos.latency));
            dict_insert(&mut map, "PHY", Value::U8(uqos.io_qos.phys));
            dict_insert(&mut map, "SDU", Value::U16(uqos.io_qos.sdu));
            dict_insert(&mut map, "Retransmissions", Value::U8(uqos.io_qos.rtn));
            dict_insert(&mut map, "Framing", Value::U8(uqos.framing));
            dict_insert(&mut map, "PresentationDelay", Value::U32(uqos.delay));
            dict_insert(&mut map, "TargetLatency", Value::U8(uqos.target_latency));
        }
        BapQos::Bcast(bqos) => {
            dict_insert(&mut map, "BIG", Value::U8(bqos.big));
            dict_insert(&mut map, "BIS", Value::U8(bqos.bis));
            dict_insert(&mut map, "Interval", Value::U32(bqos.io_qos.interval));
            dict_insert(&mut map, "Latency", Value::U16(bqos.io_qos.latency));
            dict_insert(&mut map, "PHY", Value::U8(bqos.io_qos.phys));
            dict_insert(&mut map, "SDU", Value::U16(bqos.io_qos.sdu));
            dict_insert(&mut map, "Retransmissions", Value::U8(bqos.io_qos.rtn));
            dict_insert(&mut map, "Framing", Value::U8(bqos.framing));
            dict_insert(&mut map, "PresentationDelay", Value::U32(bqos.delay));
            dict_insert(&mut map, "Encryption", Value::U8(bqos.encryption));
        }
    }

    map
}

/// Serialize a BapPacQos to D-Bus property dict (for endpoint QoS property).
fn pac_qos_to_dict(qos: &BapPacQos) -> HashMap<String, OwnedValue> {
    let mut map = HashMap::new();
    dict_insert(&mut map, "Framing", Value::U8(qos.framing));
    dict_insert(&mut map, "PHY", Value::U8(qos.phys));
    dict_insert(&mut map, "Retransmissions", Value::U8(qos.rtn));
    dict_insert(&mut map, "Latency", Value::U16(qos.latency));
    dict_insert(&mut map, "MinimumDelay", Value::U32(qos.pd_min));
    dict_insert(&mut map, "MaximumDelay", Value::U32(qos.pd_max));
    dict_insert(&mut map, "PreferredMinimumDelay", Value::U32(qos.ppd_min));
    dict_insert(&mut map, "PreferredMaximumDelay", Value::U32(qos.ppd_max));
    dict_insert(&mut map, "Locations", Value::U32(qos.location));
    dict_insert(&mut map, "SupportedContext", Value::U16(qos.supported_context));
    dict_insert(&mut map, "Context", Value::U16(qos.context));
    map
}

// ---------------------------------------------------------------------------
// MediaEndpoint1 D-Bus interface
// ---------------------------------------------------------------------------

/// Wrapper for zbus interface implementation.
///
/// zbus requires the struct implementing `#[zbus::interface]` to be owned by
/// the object server, so we use a thin wrapper that references the shared
/// endpoint state.
pub struct BapEpInterface {
    ep: Arc<StdMutex<BapEp>>,
}

#[zbus::interface(name = "org.bluez.MediaEndpoint1")]
impl BapEpInterface {
    // ---- Properties ----

    /// PAC UUID (read-only).
    #[zbus(property, name = "UUID")]
    async fn uuid(&self) -> String {
        let ep = self.ep.lock().expect("lock ep");
        ep.uuid.clone()
    }

    /// Codec ID (read-only).
    #[zbus(property, name = "Codec")]
    async fn codec(&self) -> u8 {
        let ep = self.ep.lock().expect("lock ep");
        ep.codec
    }

    /// Codec capabilities (read-only).
    #[zbus(property, name = "Capabilities")]
    async fn capabilities(&self) -> Vec<u8> {
        let ep = self.ep.lock().expect("lock ep");
        ep.caps.clone()
    }

    /// Metadata (read-only).
    #[zbus(property, name = "Metadata")]
    async fn metadata(&self) -> Vec<u8> {
        let ep = self.ep.lock().expect("lock ep");
        ep.metadata.clone()
    }

    /// Device D-Bus path (read-only).
    #[zbus(property, name = "Device")]
    async fn device(&self) -> zbus::zvariant::OwnedObjectPath {
        let ep = self.ep.lock().expect("lock ep");
        let data_arc = match ep.data.upgrade() {
            Some(d) => d,
            None => return zbus::zvariant::OwnedObjectPath::try_from("/").unwrap_or_default(),
        };
        let d = data_arc.lock().expect("lock");
        let path = d.device_path.clone().unwrap_or_else(|| d.adapter_path.clone());
        zbus::zvariant::OwnedObjectPath::try_from(path).unwrap_or_default()
    }

    /// Audio locations bitmask (read-only).
    #[zbus(property, name = "Locations")]
    async fn locations(&self) -> u32 {
        let ep = self.ep.lock().expect("lock ep");
        ep.locations
    }

    /// Supported audio contexts (read-only).
    #[zbus(property, name = "SupportedContext")]
    async fn supported_context(&self) -> u16 {
        let ep = self.ep.lock().expect("lock ep");
        ep.supported_context
    }

    /// Available audio contexts (read-only).
    #[zbus(property, name = "Context")]
    async fn context(&self) -> u16 {
        let ep = self.ep.lock().expect("lock ep");
        ep.context
    }

    /// QoS parameters dict (read-only).
    #[zbus(property, name = "QoS")]
    async fn qos(&self) -> HashMap<String, OwnedValue> {
        let ep = self.ep.lock().expect("lock ep");
        pac_qos_to_dict(&ep.qos)
    }

    /// Supported features dict (read-only).
    ///
    /// Probes the local GATT DB for TMAS/GMAS roles.
    #[zbus(property, name = "SupportedFeatures")]
    async fn supported_features(&self) -> HashMap<String, OwnedValue> {
        let mut features: HashMap<String, OwnedValue> = HashMap::new();

        let data_arc = {
            let ep = self.ep.lock().expect("lock ep");
            match ep.data.upgrade() {
                Some(d) => d,
                None => return features,
            }
        };

        let adapter = {
            let d = data_arc.lock().expect("lock");
            d.adapter.clone()
        };

        // Probe for TMAP roles.
        if let Some(gatt_database) = btd_adapter_get_database(&adapter).await {
            let gatt_db: Arc<GattDb> = gatt_database.get_db().await;
            if let Some(tmap) = BtTmap::find(&gatt_db) {
                let role = tmap.get_role();
                dict_insert(&mut features, "TmapRole", Value::U16(role.bits()));
            }
        }

        features
    }

    // ---- Methods ----

    /// SetConfiguration — configure a stream with the given properties.
    async fn set_configuration(
        &self,
        properties: HashMap<String, OwnedValue>,
    ) -> Result<(), zbus::fdo::Error> {
        debug!("BAP: SetConfiguration called");

        let data_arc = {
            let ep = self.ep.lock().expect("lock ep");
            ep.data.upgrade().ok_or_else(|| zbus::fdo::Error::Failed("Session expired".into()))?
        };

        let bap = {
            let d = data_arc.lock().expect("lock");
            d.bap.clone().ok_or_else(|| zbus::fdo::Error::Failed("No BAP session".into()))?
        };

        // Parse capabilities and metadata from properties.
        let caps: Vec<u8> = properties
            .get("Capabilities")
            .and_then(|v| <Vec<u8>>::try_from(v.clone()).ok())
            .unwrap_or_default();

        let meta: Vec<u8> = properties
            .get("Metadata")
            .and_then(|v| <Vec<u8>>::try_from(v.clone()).ok())
            .unwrap_or_default();

        // Parse QoS.
        let qos = parse_qos_from_dict(&properties);

        // Determine PAC type from the endpoint.
        let pac_type = {
            let ep = self.ep.lock().expect("lock ep");
            ep.pac_type()
        };

        // Find matching PACs using Cell for Fn closure mutation.
        // A separate `found` flag avoids consuming the stored stream
        // with `Cell::take()`, which would destroy the result.
        let stream_cell: Cell<Option<BtBapStream>> = Cell::new(None);
        let found: Cell<bool> = Cell::new(false);
        bap.foreach_pac(pac_type, |rpac: &BtBapPac| {
            if found.get() {
                return;
            }
            if let Some(lpac) = bap_select_local_pac(&bap, rpac) {
                let stream = BtBapStream::new(&bap, lpac.clone(), rpac.clone(), &qos, &caps);
                stream_cell.set(Some(stream));
                found.set(true);
            }
        });

        let stream = match stream_cell.into_inner() {
            Some(s) => s,
            None => return Err(zbus::fdo::Error::Failed("No matching PAC".into())),
        };

        // Create setup and add to the endpoint.
        let mut setup = BapSetup::new(&self.ep);
        setup.set_stream(stream);
        setup.caps = caps;
        setup.metadata = meta;
        setup.qos = qos;

        {
            let mut ep = self.ep.lock().expect("lock ep");
            ep.setups.push(setup);
        }

        // Schedule CIG update to progress the stream through CONFIG → QOS.
        schedule_cig_update(&data_arc);

        debug!("BAP: SetConfiguration completed");
        Ok(())
    }

    /// ClearConfiguration — close setups for a specific transport path.
    async fn clear_configuration(
        &self,
        transport: zbus::zvariant::OwnedObjectPath,
    ) -> Result<(), zbus::fdo::Error> {
        debug!("BAP: ClearConfiguration for {}", transport);

        let transport_str = transport.as_str().to_owned();

        let mut ep = self.ep.lock().expect("lock ep");
        let before = ep.setups.len();

        // Remove setups matching the transport path.
        ep.setups.retain(|s| s.transport_path.as_deref() != Some(transport_str.as_str()));

        let removed = before - ep.setups.len();
        if removed == 0 {
            // If no transport path match, clear all setups.
            ep.setups.clear();
        }

        debug!("BAP: ClearConfiguration removed {} setups", removed);
        Ok(())
    }

    /// Reconfigure — teardown and re-configure endpoints.
    async fn reconfigure(
        &self,
        options: HashMap<String, OwnedValue>,
    ) -> Result<(), zbus::fdo::Error> {
        debug!("BAP: Reconfigure called");

        // Teardown existing setups.
        {
            let mut ep = self.ep.lock().expect("lock ep");
            ep.setups.clear();
        }

        // Re-run configuration with new options.
        self.set_configuration(options).await?;

        debug!("BAP: Reconfigure completed");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Plugin init / exit
// ---------------------------------------------------------------------------

/// Initialize the BAP plugin.
///
/// Registers the unicast PACS profile ("bap") and broadcast assistant
/// profile ("bcaa") with the daemon, and sets up global BAP session
/// attach/detach callbacks.
///
/// Corresponds to C `bap_init()`.
pub fn bap_init() -> Result<(), Box<dyn std::error::Error>> {
    debug!("BAP: initializing plugin");

    // Register the global BAP session callbacks for remote attach/detach.
    let cb_id = bt_bap_register(
        Box::new(|bap: &BtBap| {
            bap_remote_attached(bap);
        }),
        Box::new(|bap: &BtBap| {
            bap_remote_detached(bap);
        }),
    );

    {
        let mut id = BAP_CB_ID.lock().expect("lock");
        *id = cb_id;
    }

    // Register the unicast PACS profile.
    tokio::spawn(async {
        let mut profile = BtdProfile::new("bap");
        profile.remote_uuid = Some(PAC_SINK_UUID.to_string());
        profile.bearer = BTD_PROFILE_BEARER_LE;
        profile.experimental = true;

        profile.set_device_probe(Box::new(bap_probe));
        profile.set_device_remove(Box::new(bap_remove));
        profile.set_accept(Box::new(bap_accept));
        profile.set_disconnect(Box::new(bap_disconnect));
        profile.set_adapter_probe(Box::new(bap_server_probe));
        profile.set_adapter_remove(Box::new(bap_server_remove));

        if let Err(e) = btd_profile_register(profile).await {
            error!("BAP: failed to register 'bap' profile: {}", e);
        } else {
            info!("BAP: registered 'bap' profile");
        }
    });

    // Register the broadcast assistant profile.
    tokio::spawn(async {
        let mut profile = BtdProfile::new("bcaa");
        profile.remote_uuid = Some(BCAAS_UUID.to_string());
        profile.bearer = BTD_PROFILE_BEARER_LE;
        profile.experimental = true;

        profile.set_device_probe(Box::new(bap_probe));
        profile.set_device_remove(Box::new(bap_remove));
        profile.set_accept(Box::new(bap_accept));
        profile.set_disconnect(Box::new(bap_disconnect));

        if let Err(e) = btd_profile_register(profile).await {
            error!("BAP: failed to register 'bcaa' profile: {}", e);
        } else {
            info!("BAP: registered 'bcaa' profile");
        }
    });

    info!("BAP: plugin initialized");
    Ok(())
}

/// Shut down the BAP plugin.
///
/// Unregisters profiles and cleans up all sessions.
///
/// Corresponds to C `bap_exit()`.
/// Find an ATT transport from any active BAP session on the given adapter.
///
/// Iterates the global BAP session list and returns the first ATT
/// transport whose session belongs to the specified adapter path.
/// Returns `None` when no BAP session with an ATT transport exists for
/// the adapter.
///
/// This is used by the media subsystem to locate an ATT handle for
/// [`super::media::update_gmap_features_with_att`] during endpoint
/// feature propagation.
pub fn bap_find_att_for_adapter(adapter_path: &str) -> Option<Arc<StdMutex<BtAtt>>> {
    let sessions = SESSIONS.lock().ok()?;
    for data_arc in sessions.iter() {
        let d = data_arc.lock().ok()?;
        if d.adapter_path == adapter_path {
            if let Some(ref bap) = d.bap {
                if let Some(att) = bap.get_att() {
                    return Some(att);
                }
            }
        }
    }
    None
}

pub fn bap_exit() {
    debug!("BAP: shutting down plugin");

    // Unregister the global BAP session callbacks.
    {
        let id = BAP_CB_ID.lock().expect("lock");
        if *id != 0 {
            bt_bap_unregister(*id);
        }
    }

    // Clean up all sessions.
    {
        let mut sessions = SESSIONS.lock().expect("sessions lock");
        for data_arc in sessions.drain(..) {
            let mut d = data_arc.lock().expect("lock");
            d.detach_bap();
        }
    }

    info!("BAP: plugin shut down");
}

// ---------------------------------------------------------------------------
// BapPlugin — exported plugin descriptor
// ---------------------------------------------------------------------------

/// BAP plugin descriptor implementing `BluetoothPlugin`.
///
/// This is the sole export of this module: `BapPlugin`.
pub struct BapPlugin;

impl BluetoothPlugin for BapPlugin {
    fn name(&self) -> &str {
        "bap"
    }

    fn version(&self) -> &str {
        BAP_VERSION
    }

    fn priority(&self) -> PluginPriority {
        PluginPriority::Default
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        bap_init()
    }

    fn exit(&self) {
        bap_exit();
    }
}

// Register the BAP plugin via inventory for automatic collection.
inventory::submit! {
    PluginDesc {
        name: "bap",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: bap_init,
        exit: bap_exit,
    }
}
