// Bluetooth Mesh I/O subsystem — trait, broker, and shared types.
//
// Rewrite of mesh/mesh-io.c + mesh/mesh-io.h + mesh/mesh-io-api.h from BlueZ v5.86.
// This module defines:
//   1. The `MeshIoBackend` trait replacing the C vtable `struct mesh_io_api`
//   2. All shared types (enums, structs, type aliases) used across backends
//   3. The singleton I/O broker managing backend selection, RX filter dispatch,
//      and the unprovisioned-beacon loopback timer
//   4. Public sub-module declarations for generic, mgmt, and unit backends

pub mod generic;
pub mod mgmt;
pub mod unit;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use bluez_shared::sys::mgmt::MGMT_INDEX_NONE;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Unlimited TX count sentinel (from mesh-io.h `MESH_IO_TX_COUNT_UNLIMITED`).
pub const MESH_IO_TX_COUNT_UNLIMITED: u8 = 0;

/// BLE AD type for Mesh Provisioning PDUs.
pub const BT_AD_MESH_PROV: u8 = 0x29;

/// BLE AD type for Mesh Network Data PDUs.
pub const BT_AD_MESH_DATA: u8 = 0x2A;

/// BLE AD type for Mesh Beacon frames.
pub const BT_AD_MESH_BEACON: u8 = 0x2B;

/// Standard BLE advertising data maximum length.
pub const MESH_AD_MAX_LEN: usize = 31;

/// Filter pattern matching unprovisioned beacons (AD type + zero byte).
const UNPRV_FILTER: [u8; 2] = [BT_AD_MESH_BEACON, 0x00];

/// Loopback timer interval in milliseconds.
const LOOPBACK_INTERVAL_MS: u64 = 500;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// I/O backend type selector (replaces C `enum mesh_io_type`).
///
/// Discriminant values must match the C original exactly because `main.rs`
/// maps CLI arguments to these values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MeshIoType {
    /// No backend selected.
    None = 0,
    /// Unit-test backend using Unix datagram sockets.
    UnitTest = 1,
    /// Automatic backend selection via MGMT controller enumeration.
    Auto = 2,
    /// Kernel MGMT mesh extensions backend.
    Mgmt = 3,
    /// Raw HCI user-channel backend (generic LE scanning/advertising).
    Generic = 4,
}

/// Timing type for mesh TX scheduling (replaces C `enum mesh_io_timing_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MeshIoTimingType {
    /// Standard periodic advertising.
    General = 1,
    /// Friend Poll request.
    Poll = 2,
    /// Friend Poll response with timed instant.
    PollRsp = 3,
}

/// TX send information combining timing type with associated parameters.
///
/// Replaces the C `struct mesh_io_send_info` which used a tagged union.
/// Converting the C union to a Rust enum with associated data is more
/// idiomatic and type-safe.
#[derive(Debug, Clone)]
pub enum MeshIoSendInfo {
    /// Standard periodic advertising parameters.
    General {
        /// Advertising interval in milliseconds.
        interval: u16,
        /// Number of transmissions (0 = unlimited via `MESH_IO_TX_COUNT_UNLIMITED`).
        cnt: u8,
        /// Minimum random delay before first TX (milliseconds).
        min_delay: u8,
        /// Maximum random delay before first TX (milliseconds).
        max_delay: u8,
    },
    /// Friend Poll request parameters.
    Poll {
        /// Scan duration in milliseconds.
        scan_duration: u16,
        /// Delay after scan before poll TX.
        scan_delay: u8,
        /// Up to two filter IDs for the poll.
        filter_ids: [u8; 2],
        /// Minimum delay.
        min_delay: u8,
        /// Maximum delay.
        max_delay: u8,
    },
    /// Friend Poll response parameters with absolute instant.
    PollRsp {
        /// Target instant (millisecond timestamp).
        instant: u32,
        /// Delay from instant in milliseconds.
        delay: u8,
    },
}

impl MeshIoSendInfo {
    /// Return the timing type classification for this send info.
    ///
    /// Backends use this to determine scheduling strategy.
    pub fn timing_type(&self) -> MeshIoTimingType {
        match self {
            MeshIoSendInfo::General { .. } => MeshIoTimingType::General,
            MeshIoSendInfo::Poll { .. } => MeshIoTimingType::Poll,
            MeshIoSendInfo::PollRsp { .. } => MeshIoTimingType::PollRsp,
        }
    }
}

// ---------------------------------------------------------------------------
// Core Structs
// ---------------------------------------------------------------------------

/// Received packet metadata (replaces C `struct mesh_io_recv_info`).
#[derive(Debug, Clone)]
pub struct MeshIoRecvInfo {
    /// Sender Bluetooth address (6 bytes).
    pub addr: [u8; 6],
    /// Reception timestamp in milliseconds.
    pub instant: u32,
    /// Advertising channel index.
    pub chan: u8,
    /// Received signal strength indicator.
    pub rssi: i8,
}

/// Backend capability report (replaces C `struct mesh_io_caps`).
#[derive(Debug, Clone)]
pub struct MeshIoCaps {
    /// Maximum number of simultaneous RX filters the backend supports.
    pub max_num_filters: u8,
    /// Scan window timing accuracy in percent.
    pub window_accuracy: u8,
}

/// Initialization options passed to backend `init()` (replaces C `void *opts`).
#[derive(Debug, Clone)]
pub struct MeshIoOpts {
    /// Bluetooth controller HCI index.
    pub index: u16,
}

/// Registered RX filter with associated callback (replaces C `struct mesh_io_reg`).
pub struct MeshIoReg {
    /// Callback invoked when a packet matching this filter is received.
    pub cb: MeshIoRecvFn,
    /// Length of the filter pattern in bytes.
    pub len: u8,
    /// Filter pattern bytes — incoming data prefix must match.
    pub filter: Vec<u8>,
}

impl std::fmt::Debug for MeshIoReg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshIoReg").field("len", &self.len).field("filter", &self.filter).finish()
    }
}

/// Internal I/O state shared between the broker and backend implementations.
///
/// Replaces C `struct mesh_io` from `mesh-io-api.h`. The `pvt` (private backend
/// data) and `api` (vtable pointer) fields are absorbed into the `MeshIoBackend`
/// trait object held by `MeshIoBroker`.
pub struct MeshIoState {
    /// Currently active HCI controller index (`MGMT_INDEX_NONE` if none).
    pub index: i32,
    /// Preferred controller index (`MGMT_INDEX_NONE` for auto-selection).
    pub favored_index: i32,
    /// One-shot callback invoked when the backend becomes ready.
    pub ready: Option<MeshIoReadyFn>,
    /// Registered RX filter list (replaces `l_queue *rx_regs`).
    pub rx_regs: Vec<MeshIoReg>,
    /// Opaque user context carried through the broker lifecycle.
    pub user_data: (),
}

impl MeshIoState {
    /// Create a new state with both indices set to `MGMT_INDEX_NONE`.
    fn new() -> Self {
        Self {
            index: MGMT_INDEX_NONE as i32,
            favored_index: MGMT_INDEX_NONE as i32,
            ready: None,
            rx_regs: Vec::new(),
            user_data: (),
        }
    }
}

impl std::fmt::Debug for MeshIoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshIoState")
            .field("index", &self.index)
            .field("favored_index", &self.favored_index)
            .field("rx_regs_count", &self.rx_regs.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Callback Type Definitions
// ---------------------------------------------------------------------------

/// RX packet delivery callback (replaces C `mesh_io_recv_func_t`).
///
/// Receives the packet metadata and raw advertising data slice.
pub type MeshIoRecvFn = Arc<dyn Fn(&MeshIoRecvInfo, &[u8]) + Send + Sync>;

/// Backend ready notification callback (replaces C `mesh_io_ready_func_t`).
///
/// Called once when the backend finishes initialization. The boolean
/// parameter indicates success (`true`) or failure (`false`).
pub type MeshIoReadyFn = Box<dyn FnOnce(bool) + Send>;

// ---------------------------------------------------------------------------
// MeshIoBackend Trait
// ---------------------------------------------------------------------------

/// Backend I/O interface (replaces C `struct mesh_io_api` vtable).
///
/// Each backend (generic, mgmt, unit) implements this trait to provide
/// hardware-specific advertising, scanning, and filter management.
pub trait MeshIoBackend: Send + Sync {
    /// Initialize the backend with the given controller options.
    ///
    /// Returns `true` on success. The backend should call the ready callback
    /// stored in `io.ready` once hardware setup is complete.
    fn init(&mut self, io: &mut MeshIoState, opts: &MeshIoOpts) -> bool;

    /// Tear down the backend and release hardware resources.
    fn destroy(&mut self, io: &mut MeshIoState) -> bool;

    /// Query backend capabilities.
    fn caps(&self, io: &MeshIoState) -> Option<MeshIoCaps>;

    /// Transmit mesh advertising data with the specified timing.
    fn send(&mut self, io: &mut MeshIoState, info: &MeshIoSendInfo, data: &[u8]) -> bool;

    /// Register an RX filter and associated callback on the backend.
    fn register_recv(&mut self, io: &mut MeshIoState, filter: &[u8], cb: MeshIoRecvFn) -> bool;

    /// Remove an RX filter from the backend.
    fn deregister_recv(&mut self, io: &mut MeshIoState, filter: &[u8]) -> bool;

    /// Cancel an in-progress or queued TX matching the given pattern.
    fn cancel(&mut self, io: &mut MeshIoState, data: &[u8]) -> bool;
}

// ---------------------------------------------------------------------------
// Backend Dispatch
// ---------------------------------------------------------------------------

/// Create a boxed backend instance for the requested type.
///
/// Replaces the C `mesh_io_table[]` static dispatch array. Returns `None`
/// for `MeshIoType::None` and `MeshIoType::Auto` (auto-selection is handled
/// by the broker in `mesh_io_new`).
pub fn create_backend(io_type: MeshIoType) -> Option<Box<dyn MeshIoBackend>> {
    match io_type {
        MeshIoType::Mgmt => Some(Box::new(mgmt::MgmtBackend::new())),
        MeshIoType::Generic => Some(Box::new(generic::GenericBackend::new())),
        MeshIoType::UnitTest => Some(Box::new(unit::UnitBackend::new())),
        MeshIoType::None | MeshIoType::Auto => None,
    }
}

// ---------------------------------------------------------------------------
// Singleton Broker
// ---------------------------------------------------------------------------

/// I/O broker managing the active backend, RX filter registry, and the
/// unprovisioned-beacon loopback timer.
///
/// Replaces the C `static struct mesh_io *default_io` singleton together
/// with the `loop_adv_to` timer and `loop_pkts` queue.
pub struct MeshIoBroker {
    /// Shared I/O state visible to backends and filter dispatch.
    pub state: MeshIoState,
    /// Currently active backend (trait object replacing the C vtable).
    pub backend: Option<Box<dyn MeshIoBackend>>,
    /// Handle for the 500 ms unprovisioned-beacon loopback timer task.
    loop_adv_to: Option<JoinHandle<()>>,
    /// Packets queued for loopback delivery.
    loop_pkts: Vec<Vec<u8>>,
    /// The selected `MeshIoType` of the current backend.
    backend_type: MeshIoType,
}

/// Global singleton broker protected by a mutex.
static DEFAULT_IO: OnceLock<Mutex<MeshIoBroker>> = OnceLock::new();

impl MeshIoBroker {
    /// Create a new broker with no backend and empty registrations.
    fn new() -> Self {
        Self {
            state: MeshIoState::new(),
            backend: None,
            loop_adv_to: None,
            loop_pkts: Vec::new(),
            backend_type: MeshIoType::None,
        }
    }
}

// ---------------------------------------------------------------------------
// Private Helpers
// ---------------------------------------------------------------------------

/// Obtain a millisecond-precision monotonic-ish timestamp.
///
/// Replaces `get_instant()` in the C loopback system. Uses system time
/// truncated to `u32` which wraps every ~49 days — identical to the C
/// `gettimeofday` based implementation.
fn get_instant() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u32
}

/// Re-register all existing RX filters on the current backend.
///
/// Called after a backend switch so that the new backend receives all
/// previously registered filters. Replaces C `refresh_rx()`.
fn refresh_rx(broker: &mut MeshIoBroker) {
    if let Some(mut backend) = broker.backend.take() {
        // Collect filter+cb pairs first to avoid borrow conflicts.
        let filters: Vec<(Vec<u8>, MeshIoRecvFn)> = broker
            .state
            .rx_regs
            .iter()
            .map(|reg| (reg.filter.clone(), Arc::clone(&reg.cb)))
            .collect();

        for (filter, cb) in filters {
            backend.register_recv(&mut broker.state, &filter, cb);
        }
        broker.backend = Some(backend);
    }
}

/// Controller-alert callback for automatic backend selection.
///
/// Replaces C `ctl_alert()`. Called by `mesh_mgmt_list` (in the `mgmt`
/// submodule) when controllers are enumerated. Decides which backend to
/// activate based on controller capabilities.
///
/// # Arguments
/// * `index` — HCI controller index
/// * `up` — `true` if the controller was added/found, `false` if removed
/// * `pwr` — `true` if the controller is currently powered on
/// * `mesh` — `true` if the controller supports kernel mesh extensions
pub(crate) fn ctl_alert(index: i32, up: bool, pwr: bool, mesh: bool) {
    warn!("ctl_alert(index={}, up={}, pwr={}, mesh={})", index, up, pwr, mesh);

    let guard = match DEFAULT_IO.get() {
        Some(mtx) => match mtx.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        },
        None => return,
    };

    let mut broker = guard;

    // If a specific adapter was requested, ignore other adapters.
    if broker.state.favored_index != MGMT_INDEX_NONE as i32 && index != broker.state.favored_index {
        return;
    }

    if !up {
        // Controller removed or powered down — force re-open.
        if index == broker.state.index {
            broker.state.index = MGMT_INDEX_NONE as i32;
            if let Some(mut backend) = broker.backend.take() {
                backend.destroy(&mut broker.state);
            }
            broker.backend_type = MeshIoType::None;
            // Trigger re-enumeration via mgmt.
            debug!("Controller {} removed, re-enumerating", index);
            // Note: In the C code this calls mesh_mgmt_list(ctl_alert, io).
            // In async Rust the re-enumeration is handled by the mgmt module
            // event loop which will call ctl_alert again when new controllers
            // appear.
        }
        return;
    }

    // If we already have a backend, do nothing.
    if broker.backend.is_some() {
        return;
    }

    // Select backend based on controller capabilities.
    let io_type = if mesh {
        broker.state.favored_index = index;
        MeshIoType::Mgmt
    } else {
        MeshIoType::Generic
    };

    info!("Selecting {:?} backend for controller {}", io_type, index);

    if let Some(mut backend) = create_backend(io_type) {
        let opts = MeshIoOpts { index: index as u16 };
        broker.state.index = index;
        if backend.init(&mut broker.state, &opts) {
            broker.backend = Some(backend);
            broker.backend_type = io_type;
            refresh_rx(&mut broker);
        } else {
            error!("Backend {:?} init failed for index {}", io_type, index);
            broker.state.index = MGMT_INDEX_NONE as i32;
        }
    }
}

/// Find the index of an existing RX registration whose filter matches
/// the given pattern.
///
/// Replaces C `find_by_filter()`. Compares stored filter bytes directly
/// against the provided `filter` slice.
fn find_by_filter(rx_regs: &[MeshIoReg], filter: &[u8]) -> Option<usize> {
    rx_regs.iter().position(|reg| reg.filter.as_slice() == filter)
}

/// Deliver a loopback packet to all RX registrations matching the
/// unprovisioned beacon filter.
///
/// Replaces C `loop_foreach()` + `loop_rx()`. For each registered RX
/// callback whose filter is a prefix of `data`, invokes the callback with
/// a synthetic `MeshIoRecvInfo`.
fn deliver_loopback(rx_regs: &[MeshIoReg], data: &[u8]) {
    if data.is_empty() {
        return;
    }

    // Only deliver if the AD type matches the unprovisioned beacon.
    if data[0] != BT_AD_MESH_BEACON {
        return;
    }

    let info = MeshIoRecvInfo { addr: [0u8; 6], instant: get_instant(), chan: 0, rssi: 0 };

    for reg in rx_regs {
        if reg.filter.is_empty() || data.starts_with(&reg.filter) {
            (reg.cb)(&info, data);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API Functions
// ---------------------------------------------------------------------------

/// Create a new mesh I/O broker, selecting or auto-detecting the backend.
///
/// Replaces C `mesh_io_new()`. Only one broker may exist at a time.
///
/// # Arguments
/// * `io_type` — Backend type (or `Auto` for automatic selection).
/// * `opts` — Controller options (HCI index).
/// * `cb` — Ready callback invoked once the backend is initialised.
///
/// Returns `true` if the broker was successfully created.
pub fn mesh_io_new(io_type: MeshIoType, opts: MeshIoOpts, cb: Option<MeshIoReadyFn>) -> bool {
    // Only allow one broker instance (singleton).
    if DEFAULT_IO.get().is_some() {
        error!("mesh_io_new: broker already exists");
        return false;
    }

    let mut broker = MeshIoBroker::new();
    broker.state.ready = cb;
    broker.state.favored_index = MGMT_INDEX_NONE as i32;
    broker.state.index = MGMT_INDEX_NONE as i32;

    if io_type == MeshIoType::Auto {
        // Store the preferred index from opts for auto-selection filtering.
        if opts.index != MGMT_INDEX_NONE {
            broker.state.favored_index = opts.index as i32;
        }

        // Install the broker before triggering enumeration so that
        // ctl_alert() can find it.
        if DEFAULT_IO.set(Mutex::new(broker)).is_err() {
            error!("mesh_io_new: failed to set singleton");
            return false;
        }

        info!("mesh_io_new: auto-selecting backend via MGMT enumeration");
        // In the C code, mesh_mgmt_list(ctl_alert, io) triggers enumeration
        // and ctl_alert selects the best backend. In the async Rust
        // architecture this is driven by the mgmt module's event loop
        // which calls ctl_alert for each discovered controller.
        //
        // Establish the callback reference so the mgmt module can invoke
        // the controller alert handler. This also ensures the compiler
        // sees ctl_alert as reachable from mesh_io_new.
        mgmt::register_ctl_alert(ctl_alert);
        return true;
    }

    // Explicit backend type — create and initialise directly.
    let mut backend = match create_backend(io_type) {
        Some(b) => b,
        None => {
            error!("mesh_io_new: no backend for type {:?}", io_type);
            return false;
        }
    };

    broker.state.index = opts.index as i32;

    if !backend.init(&mut broker.state, &opts) {
        error!("mesh_io_new: backend init failed for {:?}", io_type);
        return false;
    }

    broker.backend = Some(backend);
    broker.backend_type = io_type;

    if DEFAULT_IO.set(Mutex::new(broker)).is_err() {
        error!("mesh_io_new: failed to set singleton");
        return false;
    }

    info!("mesh_io_new: backend {:?} initialised", io_type);
    true
}

/// Destroy the mesh I/O broker and release all resources.
///
/// Replaces C `mesh_io_destroy()`. In the original C code this was a no-op;
/// lifecycle is managed by controller events. This implementation cleans up
/// the loopback timer and backend if present.
pub fn mesh_io_destroy() {
    if let Some(mtx) = DEFAULT_IO.get() {
        let mut broker = match mtx.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Cancel loopback timer.
        if let Some(handle) = broker.loop_adv_to.take() {
            handle.abort();
        }

        // Destroy backend.
        if let Some(mut backend) = broker.backend.take() {
            backend.destroy(&mut broker.state);
        }
        broker.backend_type = MeshIoType::None;
        broker.loop_pkts.clear();
        broker.state.rx_regs.clear();

        debug!("mesh_io_destroy: broker cleaned up");
    }
}

/// Query the active backend's capabilities.
///
/// Replaces C `mesh_io_get_caps()`. Returns `None` if no backend is active.
pub fn mesh_io_get_caps() -> Option<MeshIoCaps> {
    let mtx = DEFAULT_IO.get()?;
    let broker = match mtx.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    broker.backend.as_ref().and_then(|b| b.caps(&broker.state))
}

/// Register (or update) an RX filter callback.
///
/// Replaces C `mesh_io_register_recv_cb()`. If a filter with the same
/// byte pattern already exists, its callback is updated in place.
/// Otherwise a new registration is created and pushed to the head of
/// the list.
///
/// The filter is also forwarded to the active backend via
/// `backend.register_recv()`.
pub fn mesh_io_register_recv_cb(filter: &[u8], cb: MeshIoRecvFn) -> bool {
    let mtx = match DEFAULT_IO.get() {
        Some(m) => m,
        None => {
            error!("mesh_io_register_recv_cb: no broker");
            return false;
        }
    };

    let mut broker = match mtx.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    if filter.is_empty() {
        return false;
    }

    // Check for an existing registration with the same filter.
    if let Some(pos) = find_by_filter(&broker.state.rx_regs, filter) {
        // Update the callback on the existing registration.
        broker.state.rx_regs[pos].cb = Arc::clone(&cb);
    } else {
        // Create a new registration.
        let reg =
            MeshIoReg { cb: Arc::clone(&cb), len: filter.len() as u8, filter: filter.to_vec() };
        // Push to head (replaces l_queue_push_head).
        broker.state.rx_regs.insert(0, reg);
    }

    // Forward to the active backend.
    if let Some(mut backend) = broker.backend.take() {
        backend.register_recv(&mut broker.state, filter, cb);
        broker.backend = Some(backend);
    }

    true
}

/// Remove an RX filter registration.
///
/// Replaces C `mesh_io_deregister_recv_cb()`. Removes the registration
/// whose filter matches `filter` and notifies the backend.
pub fn mesh_io_deregister_recv_cb(filter: &[u8]) -> bool {
    let mtx = match DEFAULT_IO.get() {
        Some(m) => m,
        None => return false,
    };

    let mut broker = match mtx.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let pos = match find_by_filter(&broker.state.rx_regs, filter) {
        Some(p) => p,
        None => return false,
    };

    broker.state.rx_regs.remove(pos);

    // Notify the backend.
    if let Some(mut backend) = broker.backend.take() {
        backend.deregister_recv(&mut broker.state, filter);
        broker.backend = Some(backend);
    }

    true
}

/// Transmit mesh advertising data.
///
/// Replaces C `mesh_io_send()`. If the data begins with `BT_AD_MESH_BEACON`
/// the unprovisioned-beacon loopback timer is started so that the daemon
/// can receive its own beacon advertisements.
pub fn mesh_io_send(info: &MeshIoSendInfo, data: &[u8]) -> bool {
    let mtx = match DEFAULT_IO.get() {
        Some(m) => m,
        None => {
            error!("mesh_io_send: no broker");
            return false;
        }
    };

    let mut broker = match mtx.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    // If this is an unprovisioned beacon, start the loopback timer.
    if !data.is_empty() && data[0] == BT_AD_MESH_BEACON {
        start_loopback(&mut broker, data);
    }

    // Delegate to the backend.
    if let Some(mut backend) = broker.backend.take() {
        let result = backend.send(&mut broker.state, info, data);
        broker.backend = Some(backend);
        result
    } else {
        error!("mesh_io_send: no backend");
        false
    }
}

/// Cancel a queued or in-progress TX matching the given pattern.
///
/// Replaces C `mesh_io_send_cancel()`. If the pattern matches the
/// unprovisioned beacon filter the loopback timer is cancelled.
pub fn mesh_io_send_cancel(pattern: &[u8]) -> bool {
    let mtx = match DEFAULT_IO.get() {
        Some(m) => m,
        None => return false,
    };

    let mut broker = match mtx.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    // Cancel loopback if pattern matches unprovisioned beacon.
    if !pattern.is_empty() && pattern[0] == UNPRV_FILTER[0] {
        cancel_loopback(&mut broker);
    }

    if let Some(mut backend) = broker.backend.take() {
        let result = backend.cancel(&mut broker.state, pattern);
        broker.backend = Some(backend);
        result
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Unprovisioned Beacon Loopback System
// ---------------------------------------------------------------------------

/// Start (or restart) the 500 ms unprovisioned-beacon loopback timer.
///
/// Stores a copy of the TX data and spawns a tokio task that periodically
/// delivers the beacon to matching RX registrations. Replaces the C
/// `loop_unprv_beacon()` + `loop_rx()` + `loop_foreach()` functions.
fn start_loopback(broker: &mut MeshIoBroker, data: &[u8]) {
    // Cancel any existing loopback timer.
    if let Some(handle) = broker.loop_adv_to.take() {
        handle.abort();
    }

    // Store a copy of the packet for loopback delivery.
    let pkt = data.to_vec();

    // Check if there is already a packet with the same AD type in the
    // loopback queue. Replace it if so, otherwise add.
    let ad_type = pkt[0];
    let mut found = false;
    for existing in &mut broker.loop_pkts {
        if !existing.is_empty() && existing[0] == ad_type {
            *existing = pkt.clone();
            found = true;
            break;
        }
    }
    if !found {
        broker.loop_pkts.push(pkt);
    }

    // We cannot hold the broker lock inside the spawned task because
    // `MutexGuard` is not `Send`. Instead, the task accesses the global
    // singleton each iteration.
    let handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(LOOPBACK_INTERVAL_MS)).await;

            let mtx = match DEFAULT_IO.get() {
                Some(m) => m,
                None => break,
            };

            let broker = match mtx.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };

            // Deliver each stored loopback packet to matching RX
            // registrations.
            for pkt in &broker.loop_pkts {
                deliver_loopback(&broker.state.rx_regs, pkt);
            }

            // The task continues looping; it will be aborted when the
            // loopback is cancelled or the broker is destroyed.
        }
    });

    broker.loop_adv_to = Some(handle);
    debug!("Loopback timer started for unprovisioned beacon");
}

/// Cancel the unprovisioned-beacon loopback timer and clear queued packets.
///
/// Replaces C `loop_destroy()`.
fn cancel_loopback(broker: &mut MeshIoBroker) {
    if let Some(handle) = broker.loop_adv_to.take() {
        handle.abort();
        debug!("Loopback timer cancelled");
    }
    broker.loop_pkts.clear();
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // -- Constants -----------------------------------------------------------

    #[test]
    fn constants_match_spec() {
        assert_eq!(MESH_IO_TX_COUNT_UNLIMITED, 0u8);
        assert_eq!(BT_AD_MESH_PROV, 0x29);
        assert_eq!(BT_AD_MESH_DATA, 0x2A);
        assert_eq!(BT_AD_MESH_BEACON, 0x2B);
        assert_eq!(MESH_AD_MAX_LEN, 31);
    }

    // -- Enum discriminants --------------------------------------------------

    #[test]
    fn mesh_io_type_discriminants() {
        assert_eq!(MeshIoType::None as u8, 0);
        assert_eq!(MeshIoType::UnitTest as u8, 1);
        assert_eq!(MeshIoType::Auto as u8, 2);
        assert_eq!(MeshIoType::Mgmt as u8, 3);
        assert_eq!(MeshIoType::Generic as u8, 4);
    }

    #[test]
    fn mesh_io_type_equality() {
        assert_eq!(MeshIoType::Mgmt, MeshIoType::Mgmt);
        assert_ne!(MeshIoType::Mgmt, MeshIoType::Generic);
    }

    #[test]
    fn mesh_io_timing_type_discriminants() {
        assert_eq!(MeshIoTimingType::General as u8, 1);
        assert_eq!(MeshIoTimingType::Poll as u8, 2);
        assert_eq!(MeshIoTimingType::PollRsp as u8, 3);
    }

    // -- MeshIoSendInfo ------------------------------------------------------

    #[test]
    fn send_info_general_timing() {
        let info = MeshIoSendInfo::General { interval: 100, cnt: 5, min_delay: 10, max_delay: 20 };
        assert_eq!(info.timing_type(), MeshIoTimingType::General);
    }

    #[test]
    fn send_info_poll_timing() {
        let info = MeshIoSendInfo::Poll {
            scan_duration: 200,
            scan_delay: 5,
            filter_ids: [1, 2],
            min_delay: 10,
            max_delay: 30,
        };
        assert_eq!(info.timing_type(), MeshIoTimingType::Poll);
    }

    #[test]
    fn send_info_poll_rsp_timing() {
        let info = MeshIoSendInfo::PollRsp { instant: 12345678, delay: 50 };
        assert_eq!(info.timing_type(), MeshIoTimingType::PollRsp);
    }

    // -- Core struct construction --------------------------------------------

    #[test]
    fn recv_info_fields() {
        let info = MeshIoRecvInfo {
            addr: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            instant: 999,
            chan: 37,
            rssi: -42,
        };
        assert_eq!(info.addr, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(info.instant, 999);
        assert_eq!(info.chan, 37);
        assert_eq!(info.rssi, -42);
    }

    #[test]
    fn caps_fields() {
        let caps = MeshIoCaps { max_num_filters: 128, window_accuracy: 10 };
        assert_eq!(caps.max_num_filters, 128);
        assert_eq!(caps.window_accuracy, 10);
    }

    #[test]
    fn opts_index() {
        let opts = MeshIoOpts { index: 42 };
        assert_eq!(opts.index, 42);
    }

    #[test]
    fn reg_creation_and_debug() {
        let cb: MeshIoRecvFn = Arc::new(|_info, _data| {});
        let reg = MeshIoReg { cb, len: 2, filter: vec![0x2B, 0x00] };
        assert_eq!(reg.len, 2);
        assert_eq!(reg.filter, vec![0x2B, 0x00]);
        let s = format!("{:?}", reg);
        assert!(s.contains("MeshIoReg"));
    }

    #[test]
    fn state_debug() {
        let state = MeshIoState {
            index: 0,
            favored_index: -1,
            ready: None,
            rx_regs: Vec::new(),
            user_data: (),
        };
        let s = format!("{:?}", state);
        assert!(s.contains("MeshIoState"));
    }

    // -- Backend dispatch ----------------------------------------------------

    #[test]
    fn create_backend_returns_some_for_valid_types() {
        assert!(create_backend(MeshIoType::Mgmt).is_some());
        assert!(create_backend(MeshIoType::Generic).is_some());
        assert!(create_backend(MeshIoType::UnitTest).is_some());
    }

    #[test]
    fn create_backend_returns_none_for_none_and_auto() {
        assert!(create_backend(MeshIoType::None).is_none());
        assert!(create_backend(MeshIoType::Auto).is_none());
    }

    // -- Backend trait methods -----------------------------------------------

    #[test]
    fn backend_caps_returns_valid() {
        let backend = create_backend(MeshIoType::Generic).unwrap();
        let state = MeshIoState::new();
        let caps = backend.caps(&state);
        assert!(caps.is_some());
        assert!(caps.unwrap().max_num_filters > 0);
    }

    #[test]
    fn backend_destroy_succeeds() {
        let mut backend = create_backend(MeshIoType::UnitTest).unwrap();
        let mut state = MeshIoState::new();
        assert!(backend.destroy(&mut state));
    }

    // -- Callback types ------------------------------------------------------

    #[test]
    fn recv_fn_invocation() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();
        let cb: MeshIoRecvFn = Arc::new(move |_info, _data| {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        });
        let info = MeshIoRecvInfo { addr: [0; 6], instant: 0, chan: 0, rssi: 0 };
        cb(&info, &[0x2B, 0x01]);
        cb(&info, &[0x2B, 0x02]);
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    // -- find_by_filter ------------------------------------------------------

    #[test]
    fn find_by_filter_found() {
        let cb: MeshIoRecvFn = Arc::new(|_, _| {});
        let regs = vec![
            MeshIoReg { cb: cb.clone(), len: 1, filter: vec![0x29] },
            MeshIoReg { cb, len: 2, filter: vec![0x2B, 0x00] },
        ];
        assert_eq!(find_by_filter(&regs, &[0x2B, 0x00]), Some(1));
    }

    #[test]
    fn find_by_filter_not_found() {
        let cb: MeshIoRecvFn = Arc::new(|_, _| {});
        let regs = vec![MeshIoReg { cb, len: 1, filter: vec![0x29] }];
        assert_eq!(find_by_filter(&regs, &[0xFF]), None);
    }

    #[test]
    fn find_by_filter_empty_regs() {
        let regs: Vec<MeshIoReg> = Vec::new();
        assert_eq!(find_by_filter(&regs, &[0x2B]), None);
    }

    // -- deliver_loopback ----------------------------------------------------

    #[test]
    fn deliver_loopback_matching_filter() {
        let counter = Arc::new(AtomicU32::new(0));
        let cc = counter.clone();
        let cb: MeshIoRecvFn = Arc::new(move |info, data| {
            assert_eq!(info.chan, 0);
            assert_eq!(data[0], BT_AD_MESH_BEACON);
            cc.fetch_add(1, Ordering::Relaxed);
        });
        let regs = vec![MeshIoReg { cb, len: 2, filter: vec![BT_AD_MESH_BEACON, 0x00] }];
        deliver_loopback(&regs, &[BT_AD_MESH_BEACON, 0x00, 0x01, 0x02]);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn deliver_loopback_non_beacon_ignored() {
        let counter = Arc::new(AtomicU32::new(0));
        let cc = counter.clone();
        let cb: MeshIoRecvFn = Arc::new(move |_, _| {
            cc.fetch_add(1, Ordering::Relaxed);
        });
        let regs = vec![MeshIoReg { cb, len: 1, filter: vec![BT_AD_MESH_DATA] }];
        deliver_loopback(&regs, &[BT_AD_MESH_DATA, 0x01]);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn deliver_loopback_empty_data() {
        let cb: MeshIoRecvFn = Arc::new(|_, _| {
            panic!("should not be called");
        });
        let regs = vec![MeshIoReg { cb, len: 1, filter: vec![BT_AD_MESH_BEACON] }];
        deliver_loopback(&regs, &[]);
    }

    // -- get_instant ---------------------------------------------------------

    #[test]
    fn get_instant_returns_non_zero() {
        assert!(get_instant() > 0);
    }
}
