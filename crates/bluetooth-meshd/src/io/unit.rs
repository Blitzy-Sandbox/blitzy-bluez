// Bluetooth Mesh I/O — Unit-test backend using Unix datagram sockets.
//
// Rewrite of mesh/mesh-io-unit.c (512 lines) + mesh/mesh-io-unit.h (12 lines)
// from BlueZ v5.86.  This backend communicates via a Unix datagram socket bound
// to `/tmp/mesh-io-unit-<index>`, implementing a simple GetId handshake so that
// mesh integration tests can run without real Bluetooth hardware.

use std::collections::VecDeque;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::sys::socket::{self as sock, AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr};
use rand::Rng;
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, error};

use super::{
    MESH_AD_MAX_LEN, MESH_IO_TX_COUNT_UNLIMITED, MeshIoBackend, MeshIoCaps, MeshIoOpts,
    MeshIoRecvFn, MeshIoRecvInfo, MeshIoSendInfo, MeshIoState,
};

// ---------------------------------------------------------------------------
// Internal Data Structures
// ---------------------------------------------------------------------------

/// Transmit packet entry in the TX queue (replaces C `struct tx_pkt`).
struct TxPkt {
    /// Timing and scheduling information.
    info: MeshIoSendInfo,
    /// Whether the packet should be removed from the queue after sending.
    delete: bool,
    /// Length of valid data in `pkt`.
    len: u16,
    /// Packet data buffer (max BLE advertising data size).
    pkt: [u8; MESH_AD_MAX_LEN],
}

/// Mutable inner state shared between trait methods and spawned async tasks.
///
/// Replaces C `struct mesh_io_private` from mesh-io-unit.c lines 33-44.
struct UnitInner {
    /// D-Bus unique name retrieved via the GetId handshake
    /// (replaces `char *unique_name`).
    unique_name: Option<String>,
    /// Handle for the active TX timeout/worker task
    /// (replaces `struct l_timeout *tx_timeout`).
    tx_timeout: Option<JoinHandle<()>>,
    /// Transmit packet queue (replaces `struct l_queue *tx_pkts`).
    tx_pkts: VecDeque<TxPkt>,
    /// Local address bytes (replaces `uint8_t addr[6]`).
    addr: [u8; 6],
    /// Filesystem path of the bound Unix socket (for cleanup on destroy).
    socket_path: String,
    /// Owned file descriptor for the Unix datagram socket
    /// (replaces `int fd`).
    fd: Option<OwnedFd>,
}

// ---------------------------------------------------------------------------
// Timestamp Utilities
// ---------------------------------------------------------------------------

/// Obtain a millisecond-precision timestamp (replaces C `get_instant()`).
///
/// Uses system time truncated to `u32` which wraps every ~49 days, matching
/// the C `gettimeofday`-based implementation.
fn get_instant() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u32
}

/// Calculate remaining milliseconds until a target instant
/// (replaces C `instant_remaining_ms()`).
///
/// Uses wrapping arithmetic so that a target in the past produces a large
/// value (matching the C unsigned subtraction semantics).
fn instant_remaining_ms(target: u32) -> u32 {
    target.wrapping_sub(get_instant())
}

// ---------------------------------------------------------------------------
// RX Processing (included for structural parity with C original)
// ---------------------------------------------------------------------------

/// Construct a `MeshIoRecvInfo` and dispatch to RX filter callbacks
/// (replaces C `process_rx()` + `process_rx_callbacks()` — lines 90-114).
///
/// In the unit backend the private rx_regs list is always empty because
/// `register_recv` is a no-op, so this function effectively does nothing.
/// It is retained for structural parity with the C implementation.
fn process_rx(addr: &[u8; 6], rssi: i8, instant: u32, _data: &[u8]) {
    let _info = MeshIoRecvInfo { addr: *addr, instant, chan: 7, rssi };
    // Unit backend: private rx_regs always empty — no callbacks to invoke.
}

// ---------------------------------------------------------------------------
// TX Engine
// ---------------------------------------------------------------------------

/// Send a single packet on the Unix datagram socket
/// (replaces C `send_pkt()` — lines 307-317).
fn send_pkt_on_fd(raw_fd: i32, tx: &TxPkt) {
    let data = &tx.pkt[..tx.len as usize];
    if let Err(e) = sock::send(raw_fd, data, MsgFlags::MSG_DONTWAIT) {
        error!("Failed to send packet: {}", e);
    }
}

/// TX timeout handler — pops the head of the TX queue, transmits it, and
/// reschedules itself (replaces C `tx_to()` — lines 319-366).
fn tx_to(inner: &Arc<Mutex<UnitInner>>) {
    let reschedule_ms = {
        let mut guard = match inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        // Pop head of queue.
        let Some(mut tx) = guard.tx_pkts.pop_front() else {
            // Queue empty — cancel timeout.
            if let Some(h) = guard.tx_timeout.take() {
                h.abort();
            }
            return;
        };

        // Determine interval and remaining count based on timing type.
        let (ms, count) = match &tx.info {
            MeshIoSendInfo::General { interval, cnt, .. } => (*interval, *cnt),
            _ => (25, 1),
        };

        // Decrement the repetition counter for General timing.
        if let MeshIoSendInfo::General { cnt, .. } = &mut tx.info {
            if *cnt != MESH_IO_TX_COUNT_UNLIMITED {
                *cnt = cnt.saturating_sub(1);
            }
        }

        tx.delete = count == 1;

        // Transmit the packet.
        if let Some(ref fd) = guard.fd {
            send_pkt_on_fd(fd.as_raw_fd(), &tx);
        }

        let mut next_ms = ms;

        if tx.delete {
            // Packet consumed — check whether the next queued packet is a
            // POLL_RSP so we can recalculate the wakeup delay.
            if let Some(next) = guard.tx_pkts.front() {
                if let MeshIoSendInfo::PollRsp { instant, delay } = &next.info {
                    let remaining = instant_remaining_ms(instant.wrapping_add(u32::from(*delay)));
                    next_ms = remaining as u16;
                }
            }
            // tx is dropped — not pushed back.
        } else {
            // Re-enqueue at the tail for repeated transmission.
            guard.tx_pkts.push_back(tx);
        }

        next_ms
    };

    // Schedule the next tx_to invocation after the computed delay.
    schedule_tx_timeout(inner, u64::from(reschedule_ms));
}

/// TX worker — computes the initial randomised delay before the first
/// transmission and schedules `tx_to` (replaces C `tx_worker()` —
/// lines 368-419).
fn tx_worker(inner: &Arc<Mutex<UnitInner>>) {
    let delay = {
        let guard = match inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        let Some(tx) = guard.tx_pkts.front() else {
            return;
        };

        match &tx.info {
            MeshIoSendInfo::General { min_delay, max_delay, .. } => {
                random_delay(u32::from(*min_delay), u32::from(*max_delay))
            }

            MeshIoSendInfo::Poll { min_delay, max_delay, .. } => {
                random_delay(u32::from(*min_delay), u32::from(*max_delay))
            }

            MeshIoSendInfo::PollRsp { instant, delay } => {
                let remaining = instant_remaining_ms(instant.wrapping_add(u32::from(*delay)));
                if remaining > 255 { 0 } else { remaining }
            }
        }
    };

    if delay == 0 {
        tx_to(inner);
    } else {
        schedule_tx_timeout(inner, u64::from(delay));
    }
}

/// Compute a random delay in the range `[min, max)`.
///
/// If `min == max` the value is deterministic.  Replaces the
/// `l_getrandom(&delay, sizeof(delay))` pattern in the C TX worker.
fn random_delay(min: u32, max: u32) -> u32 {
    if min >= max {
        return min;
    }
    let range = max.saturating_sub(min);
    if range == 0 {
        return min;
    }
    let offset: u32 = rand::thread_rng().gen_range(0..range);
    min + offset
}

/// Schedule (or reschedule) the TX timeout task.
///
/// Cancels any existing timeout task before spawning a new one.
fn schedule_tx_timeout(inner: &Arc<Mutex<UnitInner>>, delay_ms: u64) {
    let inner_clone = Arc::clone(inner);
    let handle = tokio::spawn(async move {
        sleep(Duration::from_millis(delay_ms)).await;
        tx_to(&inner_clone);
    });

    let mut guard = match inner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    if let Some(old) = guard.tx_timeout.take() {
        old.abort();
    }
    guard.tx_timeout = Some(handle);
}

// ---------------------------------------------------------------------------
// Socket I/O and D-Bus Handshake
// ---------------------------------------------------------------------------

/// Async loop processing incoming data on the Unix datagram socket
/// (replaces C `incoming()` — lines 116-144).
///
/// Two message types are handled:
/// - **Mesh data** (`size > 9 && buf[0] != 0`): dispatched through
///   `process_rx` with RSSI −20 and channel 7.
/// - **GetId request** (`size == 1 && buf[0] == 0`): the daemon responds
///   with its D-Bus unique name so that test harnesses can correlate the
///   Unix socket endpoint to a specific D-Bus service.
async fn incoming_loop(inner: Arc<Mutex<UnitInner>>, async_fd: AsyncFd<OwnedFd>) {
    loop {
        // Wait for the socket to become readable.
        let mut ready = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                error!("AsyncFd readable error: {}", e);
                break;
            }
        };

        let raw_fd = async_fd.get_ref().as_raw_fd();
        let mut buf = [0u8; MESH_AD_MAX_LEN];
        let result = sock::recv(raw_fd, &mut buf, MsgFlags::MSG_DONTWAIT);

        match result {
            Ok(size) if size > 9 && buf[0] != 0 => {
                // Mesh advertising data — dispatch through RX callbacks.
                let instant = get_instant();
                let guard = match inner.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                process_rx(&guard.addr, -20, instant, &buf[1..size]);
            }
            Ok(size) if size == 1 && buf[0] == 0 => {
                // GetId request — respond with the D-Bus unique name.
                let guard = match inner.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                if let Some(ref name) = guard.unique_name {
                    let name_bytes = name.as_bytes();
                    // Format: [0x00] [name bytes...] [0x00 null terminator]
                    let total_len = name_bytes.len() + 2;
                    if total_len <= MESH_AD_MAX_LEN {
                        let mut resp = vec![0u8; total_len];
                        resp[1..1 + name_bytes.len()].copy_from_slice(name_bytes);
                        // resp[0] and resp[total_len-1] are already 0.
                        if let Err(e) = sock::send(raw_fd, &resp, MsgFlags::MSG_DONTWAIT) {
                            error!("Failed to send GetId response: {}", e);
                        }
                    }
                }
            }
            Ok(_) => {
                // Zero-length or unrecognised — ignore.
            }
            Err(nix::errno::Errno::EAGAIN) => {
                // Spurious wake-up — not actually ready; re-arm.
                ready.clear_ready();
                continue;
            }
            Err(e) => {
                error!("Socket recv error: {}", e);
                break;
            }
        }

        ready.clear_ready();
    }
}

/// Retrieve the daemon's D-Bus unique name and store it in the inner state
/// (replaces C `get_name()` + `hello_callback()` — lines 172-201).
///
/// Uses `zbus::Connection::system()` to connect to the system bus and
/// obtain the connection's unique name (e.g. `:1.42`).
async fn get_dbus_unique_name(inner: Arc<Mutex<UnitInner>>) {
    match zbus::Connection::system().await {
        Ok(conn) => {
            if let Some(name) = conn.unique_name() {
                let name_str = name.to_string();
                debug!("User-Daemon unique name: {}", name_str);
                let mut guard = match inner.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                guard.unique_name = Some(name_str);
            } else {
                debug!("D-Bus connected but unique name not yet available");
            }
        }
        Err(e) => {
            error!("Failed to connect to system D-Bus: {}", e);
        }
    }
}

/// Deferred startup callback — fires the ready notification and kicks off
/// D-Bus name retrieval (replaces C `unit_up()` — lines 203-213).
async fn unit_up(inner: Arc<Mutex<UnitInner>>, ready_cb: Option<Box<dyn FnOnce(bool) + Send>>) {
    debug!("Started io-unit");

    // Notify the broker that the backend is ready.
    if let Some(cb) = ready_cb {
        cb(true);
    }

    // Retrieve the D-Bus unique name (replaces l_timeout_create_ms(1, get_name, ...)).
    get_dbus_unique_name(inner).await;
}

// ---------------------------------------------------------------------------
// UnitBackend — Public API
// ---------------------------------------------------------------------------

/// Unit-test I/O backend using Unix datagram sockets.
///
/// Replaces the C `const struct mesh_io_api mesh_io_unit` vtable and the
/// associated `struct mesh_io_private`.  Communicates with test harnesses
/// via a Unix datagram socket bound to `/tmp/mesh-io-unit-<index>`,
/// supporting a simple GetId handshake for D-Bus identity exchange.
pub struct UnitBackend {
    /// Shared mutable state accessed by both trait methods and async tasks.
    inner: Arc<Mutex<UnitInner>>,
    /// Handle for the async socket read loop task.
    read_task: Option<JoinHandle<()>>,
    /// Handle for the deferred startup / D-Bus name retrieval task.
    startup_task: Option<JoinHandle<()>>,
}

impl Default for UnitBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl UnitBackend {
    /// Create a new uninitialised unit-test backend instance.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(UnitInner {
                unique_name: None,
                tx_timeout: None,
                tx_pkts: VecDeque::new(),
                addr: [0u8; 6],
                socket_path: String::new(),
                fd: None,
            })),
            read_task: None,
            startup_task: None,
        }
    }
}

impl MeshIoBackend for UnitBackend {
    /// Initialise the unit-test backend (replaces C `unit_init()` —
    /// lines 215-267).
    ///
    /// Creates a Unix datagram socket, binds it, spawns the async read loop,
    /// and defers D-Bus name retrieval.
    fn init(&mut self, io: &mut MeshIoState, opts: &MeshIoOpts) -> bool {
        debug!("Starting Unit test IO");

        // Derive socket path from the controller index.
        let socket_path = format!("/tmp/mesh-io-unit-{}", opts.index);

        // Remove any stale socket file (mirrors C `unlink(pvt->addr.sun_path)`).
        let _ = std::fs::remove_file(&socket_path);

        // Create the Unix datagram socket (AF_LOCAL, SOCK_DGRAM).
        let fd = match sock::socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                error!("Failed to create unit socket: {}", e);
                return false;
            }
        };

        // Construct the Unix socket address and bind.
        let addr = match UnixAddr::new(socket_path.as_str()) {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to create UnixAddr for '{}': {}", socket_path, e);
                return false;
            }
        };

        if let Err(e) = sock::bind(fd.as_raw_fd(), &addr) {
            error!("Failed to bind Unit Test socket '{}': {}", socket_path, e);
            return false;
        }

        // Duplicate the fd for the async read loop.  The original is kept in
        // UnitInner for synchronous send operations; the clone is moved into
        // the AsyncFd owned by the read task.
        let reader_fd = match fd.try_clone() {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to dup socket fd: {}", e);
                return false;
            }
        };

        let async_fd = match AsyncFd::new(reader_fd) {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to create AsyncFd: {}", e);
                return false;
            }
        };

        // Store inner state.
        {
            let mut guard = match self.inner.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            guard.socket_path = socket_path;
            guard.fd = Some(fd);
        }

        // Spawn the incoming packet handler (replaces l_io_new + l_io_set_read_handler).
        let inner_read = Arc::clone(&self.inner);
        self.read_task = Some(tokio::spawn(incoming_loop(inner_read, async_fd)));

        // Defer the startup / ready notification (replaces l_idle_oneshot(unit_up, ...)).
        let inner_startup = Arc::clone(&self.inner);
        let ready_cb = io.ready.take();
        self.startup_task = Some(tokio::spawn(unit_up(inner_startup, ready_cb)));

        true
    }

    /// Tear down the backend and release all resources
    /// (replaces C `unit_destroy()` — lines 269-287).
    fn destroy(&mut self, _io: &mut MeshIoState) -> bool {
        debug!("Destroying unit test IO");

        // Abort all spawned async tasks.
        if let Some(h) = self.read_task.take() {
            h.abort();
        }
        if let Some(h) = self.startup_task.take() {
            h.abort();
        }

        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        // Cancel any pending TX timeout.
        if let Some(h) = guard.tx_timeout.take() {
            h.abort();
        }

        // Clear all queues and state.
        guard.unique_name = None;
        guard.tx_pkts.clear();

        // Close socket and clean up path.
        let path = guard.socket_path.clone();
        guard.fd = None; // OwnedFd closes on drop.
        if !path.is_empty() {
            let _ = std::fs::remove_file(&path);
        }
        guard.socket_path.clear();

        true
    }

    /// Query backend capabilities (replaces C `unit_caps()` — lines 289-300).
    ///
    /// Returns `max_num_filters = 255` and `window_accuracy = 50`, matching
    /// the C original exactly.
    fn caps(&self, _io: &MeshIoState) -> Option<MeshIoCaps> {
        Some(MeshIoCaps { max_num_filters: 255, window_accuracy: 50 })
    }

    /// Transmit mesh advertising data (replaces C `send_tx()` —
    /// lines 421-452).
    ///
    /// Creates a `TxPkt`, inserts it into the queue (head for POLL_RSP,
    /// tail otherwise), and schedules the TX worker if not already sending.
    fn send(&mut self, _io: &mut MeshIoState, info: &MeshIoSendInfo, data: &[u8]) -> bool {
        if data.is_empty() || data.len() > MESH_AD_MAX_LEN {
            return false;
        }

        let mut pkt_buf = [0u8; MESH_AD_MAX_LEN];
        pkt_buf[..data.len()].copy_from_slice(data);

        let tx = TxPkt { info: info.clone(), delete: false, len: data.len() as u16, pkt: pkt_buf };

        let needs_worker = {
            let mut guard = match self.inner.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };

            if matches!(info, MeshIoSendInfo::PollRsp { .. }) {
                // POLL_RSP always goes to head and always triggers worker.
                guard.tx_pkts.push_front(tx);
                true
            } else {
                // Other types go to tail; only schedule worker if queue was empty.
                let was_empty = guard.tx_pkts.is_empty();
                guard.tx_pkts.push_back(tx);
                was_empty
            }
        };

        if needs_worker {
            // Cancel existing timeout and schedule the TX worker.
            {
                let mut guard = match self.inner.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                if let Some(h) = guard.tx_timeout.take() {
                    h.abort();
                }
            }
            let inner_clone = Arc::clone(&self.inner);
            tokio::spawn(async move {
                tx_worker(&inner_clone);
            });
        }

        true
    }

    /// Register an RX filter — no-op for the unit backend
    /// (replaces C `recv_register()` — lines 491-495).
    fn register_recv(&mut self, _io: &mut MeshIoState, _filter: &[u8], _cb: MeshIoRecvFn) -> bool {
        true
    }

    /// Deregister an RX filter — no-op for the unit backend
    /// (replaces C `recv_deregister()` — lines 497-501).
    fn deregister_recv(&mut self, _io: &mut MeshIoState, _filter: &[u8]) -> bool {
        true
    }

    /// Cancel queued TX packets matching the given pattern
    /// (replaces C `tx_cancel()` — lines 454-489).
    ///
    /// When `data.len() == 1`, removes all packets whose first byte (AD type)
    /// matches `data[0]` (or all packets if `data[0] == 0`).  Otherwise
    /// removes all packets whose prefix matches the full `data` slice.
    fn cancel(&mut self, _io: &mut MeshIoState, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        if data.len() == 1 {
            // Remove by AD type (replaces find_by_ad_type).
            let ad_type = data[0];
            guard.tx_pkts.retain(|tx| {
                // C semantics: match if `!ad_type || ad_type == tx->pkt[0]`
                // We KEEP (retain) when the condition is NOT met.
                ad_type != 0 && tx.pkt[0] != ad_type
            });
        } else {
            // Remove by pattern prefix (replaces find_by_pattern).
            let pattern = data;
            guard.tx_pkts.retain(|tx| {
                if (tx.len as usize) < pattern.len() {
                    true // Too short to match — keep.
                } else {
                    tx.pkt[..pattern.len()] != *pattern
                }
            });
        }

        // If the queue is now empty, cancel any pending timeout.
        if guard.tx_pkts.is_empty() {
            if let Some(h) = guard.tx_timeout.take() {
                h.abort();
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a default `MeshIoState` for testing.
    fn test_state() -> MeshIoState {
        MeshIoState {
            index: -1,
            favored_index: -1,
            ready: None,
            rx_regs: Vec::new(),
            user_data: (),
        }
    }

    #[test]
    fn unit_backend_new_creates_instance() {
        let _b = UnitBackend::new();
    }

    #[test]
    fn unit_backend_default_creates_instance() {
        let _b = UnitBackend::default();
    }

    #[test]
    fn caps_returns_correct_values() {
        let backend = UnitBackend::new();
        let state = test_state();
        let caps = backend.caps(&state).expect("caps should return Some");
        assert_eq!(caps.max_num_filters, 255);
        assert_eq!(caps.window_accuracy, 50);
    }

    #[test]
    fn register_recv_is_noop_returns_true() {
        let mut backend = UnitBackend::new();
        let mut state = test_state();
        let cb: super::MeshIoRecvFn = Arc::new(|_info: &MeshIoRecvInfo, _data: &[u8]| {});
        assert!(backend.register_recv(&mut state, &[0x29], cb));
    }

    #[test]
    fn deregister_recv_is_noop_returns_true() {
        let mut backend = UnitBackend::new();
        let mut state = test_state();
        assert!(backend.deregister_recv(&mut state, &[0x29]));
    }

    #[test]
    fn cancel_empty_data_returns_false() {
        let mut backend = UnitBackend::new();
        let mut state = test_state();
        assert!(!backend.cancel(&mut state, &[]));
    }

    #[test]
    fn cancel_with_data_returns_true_empty_queue() {
        let mut backend = UnitBackend::new();
        let mut state = test_state();
        assert!(backend.cancel(&mut state, &[0x29]));
    }

    #[test]
    fn destroy_without_init_succeeds() {
        let mut backend = UnitBackend::new();
        let mut state = test_state();
        assert!(backend.destroy(&mut state));
    }

    #[test]
    fn send_empty_data_returns_false() {
        let mut backend = UnitBackend::new();
        let mut state = test_state();
        let info = MeshIoSendInfo::General { interval: 100, cnt: 5, min_delay: 10, max_delay: 20 };
        assert!(!backend.send(&mut state, &info, &[]));
    }

    #[test]
    fn send_oversized_data_returns_false() {
        let mut backend = UnitBackend::new();
        let mut state = test_state();
        let info = MeshIoSendInfo::General { interval: 100, cnt: 5, min_delay: 10, max_delay: 20 };
        let big = [0u8; MESH_AD_MAX_LEN + 1];
        assert!(!backend.send(&mut state, &info, &big));
    }

    #[test]
    fn get_instant_returns_nonzero() {
        assert!(get_instant() > 0);
    }

    #[test]
    fn instant_remaining_ms_past_target_wraps() {
        let past = get_instant().wrapping_sub(1000);
        let remaining = instant_remaining_ms(past);
        // Wrapping subtraction produces a very large u32.
        assert!(remaining > u32::MAX / 2);
    }

    #[test]
    fn random_delay_min_equals_max() {
        assert_eq!(random_delay(42, 42), 42);
    }

    #[test]
    fn random_delay_min_greater_than_max() {
        assert_eq!(random_delay(100, 50), 100);
    }

    #[test]
    fn random_delay_in_range() {
        for _ in 0..100 {
            let d = random_delay(10, 20);
            assert!((10..20).contains(&d), "delay {} out of range [10, 20)", d);
        }
    }
}
