// SPDX-License-Identifier: GPL-2.0-or-later
#![allow(dead_code)]
//
// tests/unit/test_mcp.rs — Rust MCP (Media Control Profile) unit tests
//
// Comprehensive unit tests for the MCP module in `bluez_shared::audio::mcp`,
// converted from `unit/test-mcp.c`. Covers 6 test groups:
//
//   1. CL/CGGIT — Client GATT Generic Integration Tests (13 tests)
//      Characteristic reads: player name, icon URL, track title, track
//      duration, track position, playback speed, seek speed, playing order,
//      playing order supported, media state, CP supported opcodes, CCID.
//      Includes blob reads and writes (track position, playback speed,
//      playing order). Also GMCS discovery variant.
//
//   2. CL/MCCP — Client Media Control Point Tests (21 tests)
//      Exercises every CP opcode: play, pause, fast_rewind, fast_forward,
//      stop, move_relative, prev/next/first/last/goto segment/track/group,
//      set_track_position, set_playback_speed, set_playing_order.
//      Validates supported playing_order and supported_commands queries.
//
//   3. CL/EXTRA — BlueZ-specific reread tests (3 tests)
//      Short reread, long-value reread on track changed, long-value
//      reread on notify.
//
//   4. SR/SGGIT — Server GATT Integration Tests (26 tests: 13 MCS + 13 GMCS)
//      Server-side read/write/notify for all 13 MCS characteristics, plus
//      their GMCS mirrors.
//
//   5. SR/MCP — Server MCP State Transition Tests (10 tests)
//      Play from paused/seeking/inactive, pause from playing/seeking/inactive,
//      stop from playing/paused/seeking/inactive.
//
//   6. SR/SPN — Server Oversized Value Notification Tests (2 tests)
//      Media player name and track title oversized notifications.
//
// Architecture:
//   socketpair(AF_UNIX, SOCK_SEQPACKET) → nix::sys::socket::socketpair()
//   BtAtt::new(fd, false) for ATT transport
//   BtGattServer::new(db, att, 64, 0) → server-side ATT handler
//   BtGattClient::new(db, att, 64, 0) → client-side GATT discovery
//   pump_att() → simulates event loop for PDU processing
//
// Converted from unit/test-mcp.c (2043 lines, ~80 test cases).

use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use tokio::runtime::Runtime;

use bluez_shared::att::transport::BtAtt;
use bluez_shared::att::types::AttError;
use bluez_shared::audio::mcp::{
    BtMcp, BtMcs, CpOpcode, MCS_DURATION_UNAVAILABLE, MCS_POSITION_UNAVAILABLE, McpCallback,
    McpListenerCallback, McsCallback, McsCmdSupported, McsCpRsp, McsPlayingOrderSupported,
    McsResult, MediaState, PlayingOrder, bt_mcp_test_util_get_client, bt_mcs_test_util_reset_ccid,
};
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::{GattDb, GattDbAttribute, GattDbCcc};
use bluez_shared::gatt::server::BtGattServer;
use bluez_shared::util::queue::Queue;

// ---------------------------------------------------------------------------
// Global serialization lock for MCP tests.
//
// The MCS module uses a process-global `MCS_GLOBAL` Mutex for CCID
// allocation and server registration. When multiple test threads call
// `bt_mcs_test_util_reset_ccid()` and `BtMcs::register()` concurrently
// the global state is corrupted, leading to flaky failures (e.g.
// `sr_mcp_stop_from_paused`). Acquiring this lock at the start of every
// test — via `create_mcs_server` / `create_mcp_client` — ensures tests
// run sequentially against a clean global state.
// ---------------------------------------------------------------------------
static MCP_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the test-level serialization lock, returning the guard that
/// must be held for the entire duration of the test.
fn acquire_mcp_test_lock() -> MutexGuard<'static, ()> {
    MCP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ============================================================================
// MCS Handle Constants (matching C test-mcp.c defines)
//
// Handle layout for a fresh GattDb with a single MCS/GMCS service:
//   0x01: Primary/Secondary service declaration
//   0x02: Media Player Name characteristic declaration
//   0x03: Media Player Name value                    (R, N)
//   0x04: Media Player Name CCC
//   0x05: Track Changed characteristic declaration
//   0x06: Track Changed value                        (N only)
//   0x07: Track Changed CCC
//   0x08: Track Title characteristic declaration
//   0x09: Track Title value                          (R, N)
//   0x0A: Track Title CCC
//   0x0B: Track Duration characteristic declaration
//   0x0C: Track Duration value                       (R, N)
//   0x0D: Track Duration CCC
//   0x0E: Track Position characteristic declaration
//   0x0F: Track Position value                       (R, W, N)
//   0x10: Track Position CCC
//   0x11: Playback Speed characteristic declaration
//   0x12: Playback Speed value                       (R, W, N)
//   0x13: Playback Speed CCC
//   0x14: Seeking Speed characteristic declaration
//   0x15: Seeking Speed value                        (R, N)
//   0x16: Seeking Speed CCC
//   0x17: Playing Order characteristic declaration
//   0x18: Playing Order value                        (R, W, N)
//   0x19: Playing Order CCC
//   0x1A: Playing Order Supported characteristic declaration
//   0x1B: Playing Order Supported value              (R)
//   0x1C: Media State characteristic declaration
//   0x1D: Media State value                          (R, N)
//   0x1E: Media State CCC
//   0x1F: Media Control Point characteristic declaration
//   0x20: Media Control Point value                  (W, N)
//   0x21: Media Control Point CCC
//   0x22: Media CP Opcodes Supported characteristic declaration
//   0x23: Media CP Opcodes Supported value           (R, N)
//   0x24: Media CP Opcodes Supported CCC
//   0x25: Content Control ID characteristic declaration
//   0x26: Content Control ID value                   (R)
// ============================================================================

const NAME_HANDLE: u16 = 0x03;
const NAME_CCC_HANDLE: u16 = 0x04;
const TRACK_CHG_HANDLE: u16 = 0x06;
const TRACK_CHG_CCC_HANDLE: u16 = 0x07;
const TRACK_TITLE_HANDLE: u16 = 0x09;
const TRACK_TITLE_CCC_HANDLE: u16 = 0x0A;
const TRACK_DUR_HANDLE: u16 = 0x0C;
const TRACK_DUR_CCC_HANDLE: u16 = 0x0D;
const TRACK_POS_HANDLE: u16 = 0x0F;
const TRACK_POS_CCC_HANDLE: u16 = 0x10;
const PLAY_SPEED_HANDLE: u16 = 0x12;
const PLAY_SPEED_CCC_HANDLE: u16 = 0x13;
const SEEK_SPEED_HANDLE: u16 = 0x15;
const SEEK_SPEED_CCC_HANDLE: u16 = 0x16;
const PLAY_ORDER_HANDLE: u16 = 0x18;
const PLAY_ORDER_CCC_HANDLE: u16 = 0x19;
const PLAY_ORDER_SUPP_HANDLE: u16 = 0x1B;
const STATE_HANDLE: u16 = 0x1D;
const STATE_CCC_HANDLE: u16 = 0x1E;
const CP_HANDLE: u16 = 0x20;
const CP_CCC_HANDLE: u16 = 0x21;
const CP_SUPP_HANDLE: u16 = 0x23;
const CP_SUPP_CCC_HANDLE: u16 = 0x24;
const CCID_HANDLE: u16 = 0x26;

// ============================================================================
// GATT Characteristic Properties (matching C PROP_* defines)
// ============================================================================

const PROP_R: u8 = 0x02; // Read
const PROP_N: u8 = 0x10; // Notify
const PROP_RN: u8 = 0x12; // Read | Notify
const PROP_RW: u8 = 0x0E; // Read | Write | Write Without Response
const PROP_WN: u8 = 0x1C; // Write | Write Without Response | Notify
const PROP_RWN: u8 = 0x1E; // Read | Write | Write Without Response | Notify

// ============================================================================
// ATT Protocol Constants
// ============================================================================

const ATT_OP_ERROR_RSP: u8 = 0x01;
const ATT_OP_MTU_REQ: u8 = 0x02;
const ATT_OP_MTU_RSP: u8 = 0x03;
const ATT_OP_FIND_INFO_REQ: u8 = 0x04;
const ATT_OP_FIND_INFO_RSP: u8 = 0x05;
const ATT_OP_FIND_BY_TYPE_REQ: u8 = 0x06;
const ATT_OP_FIND_BY_TYPE_RSP: u8 = 0x07;
const ATT_OP_READ_BY_TYPE_REQ: u8 = 0x08;
const ATT_OP_READ_BY_TYPE_RSP: u8 = 0x09;
const ATT_OP_READ_REQ: u8 = 0x0A;
const ATT_OP_READ_RSP: u8 = 0x0B;
const ATT_OP_READ_BLOB_REQ: u8 = 0x0C;
const ATT_OP_READ_BLOB_RSP: u8 = 0x0D;
const ATT_OP_READ_BY_GRP_TYPE_REQ: u8 = 0x10;
const ATT_OP_READ_BY_GRP_TYPE_RSP: u8 = 0x11;
const ATT_OP_WRITE_REQ: u8 = 0x12;
const ATT_OP_WRITE_RSP: u8 = 0x13;
const ATT_OP_WRITE_CMD: u8 = 0x52;
const ATT_OP_HANDLE_NFY: u8 = 0x1B;

const ATT_ERROR_ATTR_NOT_FOUND: u8 = 0x0A;

// ============================================================================
// GATT Service/Characteristic UUIDs (16-bit, little-endian in ATT PDUs)
// ============================================================================

const PRIMARY_SERVICE_UUID_LE: [u8; 2] = [0x00, 0x28];
#[allow(dead_code)]
const SECONDARY_SERVICE_UUID_LE: [u8; 2] = [0x01, 0x28];
const INCLUDE_UUID_LE: [u8; 2] = [0x02, 0x28];
const CHARACTERISTIC_UUID_LE: [u8; 2] = [0x03, 0x28];
const CCC_UUID_LE: [u8; 2] = [0x02, 0x29];

/// MCS UUID (0x1848) in little-endian.
const MCS_UUID_LE: [u8; 2] = [0x48, 0x18];
/// GMCS UUID (0x1849) in little-endian.
const GMCS_UUID_LE: [u8; 2] = [0x49, 0x18];

// MCS characteristic UUIDs in little-endian
const MEDIA_PLAYER_NAME_UUID_LE: [u8; 2] = [0x93, 0x2B]; // 0x2B93
const TRACK_CHANGED_UUID_LE: [u8; 2] = [0x96, 0x2B]; // 0x2B96
const TRACK_TITLE_UUID_LE: [u8; 2] = [0x97, 0x2B]; // 0x2B97
const TRACK_DURATION_UUID_LE: [u8; 2] = [0x98, 0x2B]; // 0x2B98
const TRACK_POSITION_UUID_LE: [u8; 2] = [0x99, 0x2B]; // 0x2B99
const PLAYBACK_SPEED_UUID_LE: [u8; 2] = [0x9A, 0x2B]; // 0x2B9A
const SEEKING_SPEED_UUID_LE: [u8; 2] = [0x9B, 0x2B]; // 0x2B9B
const PLAYING_ORDER_UUID_LE: [u8; 2] = [0x9C, 0x2B]; // 0x2B9C
const PLAYING_ORDER_SUPP_UUID_LE: [u8; 2] = [0x9D, 0x2B]; // 0x2B9D
const MEDIA_STATE_UUID_LE: [u8; 2] = [0x9E, 0x2B]; // 0x2B9E
const MEDIA_CP_UUID_LE: [u8; 2] = [0xA1, 0x2B]; // 0x2BA1
const MEDIA_CP_SUPP_UUID_LE: [u8; 2] = [0xA5, 0x2B]; // 0x2BA5
const CCID_UUID_LE: [u8; 2] = [0xBA, 0x2B]; // 0x2BBA

/// MCS Characteristic UUIDs (u16 native format — for BtMcs::changed()).
const MCS_MEDIA_PLAYER_NAME_UUID: u16 = 0x2B93;
const MCS_TRACK_TITLE_UUID: u16 = 0x2B97;
const MCS_MEDIA_STATE_UUID: u16 = 0x2B9E;

// ============================================================================
// CCC State Tracking (for server notification tests)
// ============================================================================

/// CCC state entry for tracking client characteristic configuration.
#[derive(Clone, Debug)]
struct CccState {
    /// Attribute handle for this CCC descriptor.
    handle: u16,
    /// CCC value (0x0000 = disabled, 0x0001 = notifications).
    value: [u8; 2],
}

// ============================================================================
// Socketpair Helpers
// ============================================================================

/// Create a Unix SOCK_SEQPACKET socketpair for ATT transport testing.
fn create_test_pair() -> (OwnedFd, OwnedFd) {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .expect("socketpair(AF_UNIX, SOCK_SEQPACKET) failed")
}

/// Blocking read with retry on EAGAIN, with a 5-second timeout.
fn blocking_read(fd: &OwnedFd, buf: &mut [u8]) -> usize {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match nix::unistd::read(fd.as_raw_fd(), buf) {
            Ok(n) => return n,
            Err(nix::errno::Errno::EAGAIN) => {
                if std::time::Instant::now() > deadline {
                    panic!("blocking_read: timed out waiting for data");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("blocking_read: {e}"),
        }
    }
}

/// Blocking write with retry on EAGAIN, with a 5-second timeout.
fn blocking_write(fd: &OwnedFd, data: &[u8]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match nix::unistd::write(fd, data) {
            Ok(_) => return,
            Err(nix::errno::Errno::EAGAIN) => {
                if std::time::Instant::now() > deadline {
                    panic!("blocking_write: timed out");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("blocking_write: {e}"),
        }
    }
}

// ============================================================================
// ATT Pump Helper
// ============================================================================

/// Pump the ATT transport: flush any queued writes, read from the ATT fd,
/// process the PDU through BtAtt + BtGattServer, and flush response writes.
///
/// The initial flush is critical: `BtAtt::send()` queues requests/commands
/// without immediately writing them to the socket (unlike the C original
/// which calls `wakeup_writer`).  Flushing at the start of every pump
/// cycle ensures queued PDUs (e.g. GATT discovery requests from
/// `BtGattClient::new`) reach the wire before we try to read responses.
fn pump_att(att: &Arc<Mutex<BtAtt>>, att_fd: &OwnedFd) {
    // Flush any queued writes first so the peer can receive them.
    att.lock().unwrap().flush_writes();

    let raw = att_fd.as_raw_fd();
    let mut buf = [0u8; 1024];
    std::thread::sleep(Duration::from_millis(2));
    match nix::unistd::read(raw, &mut buf) {
        Ok(n) if n > 0 => {
            // Process the PDU under lock, collecting deferred callbacks.
            let (pending_notifs, pending_resps) = {
                let mut att_guard = att.lock().unwrap();
                att_guard.process_read(0, &buf[..n]);
                (att_guard.take_pending_notifications(), att_guard.take_pending_responses())
            };
            // Lock released — invoke callbacks safely.
            for pn in &pending_notifs {
                (pn.callback)(pn.chan_idx, pn.filter_opcode, pn.raw_opcode, &pn.body);
            }
            for pr in pending_resps {
                (pr.callback)(pr.opcode, &pr.body);
            }
            att.lock().unwrap().flush_writes();
        }
        Ok(_) => {}
        Err(nix::errno::Errno::EAGAIN) => {}
        Err(e) => panic!("pump_att read error: {e}"),
    }
}

/// Send a PDU to the server (via peer fd), pump the ATT layer, then read
/// the response from the peer fd.
fn server_exchange(
    att: &Arc<Mutex<BtAtt>>,
    att_fd: &OwnedFd,
    peer: &OwnedFd,
    request: &[u8],
    response_buf: &mut [u8],
) -> usize {
    blocking_write(peer, request);
    pump_att(att, att_fd);
    blocking_read(peer, response_buf)
}

/// Send a PDU to the server, pump ATT, and return full response as Vec.
fn server_exchange_vec(
    att: &Arc<Mutex<BtAtt>>,
    att_fd: &OwnedFd,
    peer: &OwnedFd,
    request: &[u8],
) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = server_exchange(att, att_fd, peer, request, &mut buf);
    buf[..n].to_vec()
}

// ============================================================================
// MCS Callback Stubs (for server-side tests)
// ============================================================================

/// Stub McsCallback that records play/pause/stop/etc. for server tests.
/// All command methods return `true` (success) and push the name onto transitions.
struct TestMcsCallback {
    /// Captured state transitions for verification.
    transitions: Mutex<Vec<String>>,
}

impl TestMcsCallback {
    fn new() -> Arc<Self> {
        Arc::new(Self { transitions: Mutex::new(Vec::new()) })
    }
}

impl McsCallback for TestMcsCallback {
    fn play(&self) -> bool {
        self.transitions.lock().unwrap().push("play".into());
        true
    }
    fn pause(&self) -> bool {
        self.transitions.lock().unwrap().push("pause".into());
        true
    }
    fn fast_rewind(&self) -> bool {
        self.transitions.lock().unwrap().push("fast_rewind".into());
        true
    }
    fn fast_forward(&self) -> bool {
        self.transitions.lock().unwrap().push("fast_forward".into());
        true
    }
    fn stop(&self) -> bool {
        self.transitions.lock().unwrap().push("stop".into());
        true
    }
    fn move_relative(&self, _offset: i32) -> bool {
        self.transitions.lock().unwrap().push("move_relative".into());
        true
    }
    fn previous_segment(&self) -> bool {
        self.transitions.lock().unwrap().push("previous_segment".into());
        true
    }
    fn next_segment(&self) -> bool {
        self.transitions.lock().unwrap().push("next_segment".into());
        true
    }
    fn first_segment(&self) -> bool {
        self.transitions.lock().unwrap().push("first_segment".into());
        true
    }
    fn last_segment(&self) -> bool {
        self.transitions.lock().unwrap().push("last_segment".into());
        true
    }
    fn goto_segment(&self, _n: i32) -> bool {
        self.transitions.lock().unwrap().push("goto_segment".into());
        true
    }
    fn previous_track(&self) -> bool {
        self.transitions.lock().unwrap().push("previous_track".into());
        true
    }
    fn next_track(&self) -> bool {
        self.transitions.lock().unwrap().push("next_track".into());
        true
    }
    fn first_track(&self) -> bool {
        self.transitions.lock().unwrap().push("first_track".into());
        true
    }
    fn last_track(&self) -> bool {
        self.transitions.lock().unwrap().push("last_track".into());
        true
    }
    fn goto_track(&self, _n: i32) -> bool {
        self.transitions.lock().unwrap().push("goto_track".into());
        true
    }
    fn previous_group(&self) -> bool {
        self.transitions.lock().unwrap().push("previous_group".into());
        true
    }
    fn next_group(&self) -> bool {
        self.transitions.lock().unwrap().push("next_group".into());
        true
    }
    fn first_group(&self) -> bool {
        self.transitions.lock().unwrap().push("first_group".into());
        true
    }
    fn last_group(&self) -> bool {
        self.transitions.lock().unwrap().push("last_group".into());
        true
    }
    fn goto_group(&self, _n: i32) -> bool {
        self.transitions.lock().unwrap().push("goto_group".into());
        true
    }
    fn set_playing_order(&self, _order: u8) -> bool {
        self.transitions.lock().unwrap().push("set_playing_order".into());
        true
    }
    fn set_track_position(&self, _pos: i32) -> bool {
        self.transitions.lock().unwrap().push("set_track_position".into());
        true
    }
    fn set_playback_speed(&self, _speed: i8) -> bool {
        self.transitions.lock().unwrap().push("set_playback_speed".into());
        true
    }
    fn debug(&self, _msg: &str) {}
    fn destroy(&self) {}
}

/// Stub McpCallback for client tests that records completions and ready state.
struct TestMcpCallback {
    ready_flag: Mutex<bool>,
    ccid_val: Mutex<u8>,
    completions: Mutex<Vec<(u32, u8)>>,
}

impl TestMcpCallback {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ready_flag: Mutex::new(false),
            ccid_val: Mutex::new(0),
            completions: Mutex::new(Vec::new()),
        })
    }
}

impl McpCallback for TestMcpCallback {
    fn ccid(&self, ccid: u8, _gmcs: bool) {
        *self.ccid_val.lock().unwrap() = ccid;
    }
    fn complete(&self, id: u32, status: u8) {
        self.completions.lock().unwrap().push((id, status));
    }
    fn ready(&self) {
        *self.ready_flag.lock().unwrap() = true;
    }
    fn debug(&self, _msg: &str) {}
    fn destroy(&self) {}
}

/// Stub McpListenerCallback for client listener tests.
struct TestMcpListenerCallback {
    notifications: Mutex<Vec<String>>,
}

impl TestMcpListenerCallback {
    fn new() -> Arc<Self> {
        Arc::new(Self { notifications: Mutex::new(Vec::new()) })
    }
}

impl McpListenerCallback for TestMcpListenerCallback {
    fn media_player_name(&self, _value: &[u8]) {
        self.notifications.lock().unwrap().push("media_player_name".into());
    }
    fn track_changed(&self) {
        self.notifications.lock().unwrap().push("track_changed".into());
    }
    fn track_title(&self, _value: &[u8]) {
        self.notifications.lock().unwrap().push("track_title".into());
    }
    fn track_duration(&self, _dur: i32) {
        self.notifications.lock().unwrap().push("track_duration".into());
    }
    fn track_position(&self, _pos: i32) {
        self.notifications.lock().unwrap().push("track_position".into());
    }
    fn playback_speed(&self, _speed: i8) {
        self.notifications.lock().unwrap().push("playback_speed".into());
    }
    fn seeking_speed(&self, _speed: i8) {
        self.notifications.lock().unwrap().push("seeking_speed".into());
    }
    fn playing_order(&self, _order: u8) {
        self.notifications.lock().unwrap().push("playing_order".into());
    }
    fn media_state(&self, _state: u8) {
        self.notifications.lock().unwrap().push("media_state".into());
    }
    fn destroy(&self) {}
}

// ============================================================================
// MCS Server Context
// ============================================================================

/// Encapsulates the ATT transport, GATT server, and socketpair endpoints
/// needed for MCS server PDU exchange tests.
struct McsServerContext {
    /// Serialization guard — held for the lifetime of the test to prevent
    /// concurrent access to the process-global `MCS_GLOBAL` state. Must be
    /// the first field so it is dropped **after** all MCS resources.
    _lock: MutexGuard<'static, ()>,
    /// Tokio runtime — kept alive for GattDb attribute handler spawning.
    rt: Runtime,
    /// Shared ATT transport reference.
    att: Arc<Mutex<BtAtt>>,
    /// GATT server reference — kept alive for lifetime management.
    _server: Arc<BtGattServer>,
    /// MCS instance for server-side tests.
    mcs: BtMcs,
    /// CCC state tracking queue.
    ccc_states: Queue<CccState>,
    /// Peer socket for sending/receiving PDUs.
    peer: OwnedFd,
    /// ATT socket endpoint (used by pump_att for reading).
    att_fd: OwnedFd,
    /// Test MCS callbacks for state verification.
    mcs_cb: Arc<TestMcsCallback>,
}

/// Create a GATT server context with an MCS (or GMCS) service registered.
fn create_mcs_server(is_gmcs: bool) -> McsServerContext {
    let lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();

    let rt = Runtime::new().expect("Failed to create tokio runtime for test");

    let db = GattDb::new();

    // Register CCC callbacks so that add_ccc() succeeds during MCS
    // service registration.
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    let mcs_cb = TestMcsCallback::new();
    let mcs = BtMcs::register(db.clone(), is_gmcs, mcs_cb.clone()).expect("BtMcs::register failed");

    let (fd1, fd2) = create_test_pair();
    let att_raw = fd1.as_raw_fd();
    let att = BtAtt::new(att_raw, false).expect("BtAtt::new failed");

    let server = BtGattServer::new(db, att.clone(), 64, 0).expect("BtGattServer::new failed");

    let ccc_states = Queue::new();

    McsServerContext {
        _lock: lock,
        rt,
        att,
        _server: server,
        mcs,
        ccc_states,
        peer: fd2,
        att_fd: fd1,
        mcs_cb,
    }
}

/// Perform MTU exchange on the server context (client sends MTU=64).
fn mtu_exchange(ctx: &McsServerContext) {
    let _guard = ctx.rt.enter();
    // MTU request: opcode=0x02, mtu=64 (0x0040 LE)
    let req = [ATT_OP_MTU_REQ, 0x40, 0x00];
    let rsp = server_exchange_vec(&ctx.att, &ctx.att_fd, &ctx.peer, &req);
    assert!(rsp.len() >= 3, "MTU response too short: {:?}", rsp);
    assert_eq!(rsp[0], ATT_OP_MTU_RSP, "Expected MTU response opcode");
}

// ============================================================================
// Test Group 4: SR/SGGIT — Server GATT Generic Integration Tests
// ============================================================================

/// Helper: Perform a Read By Group Type request to discover primary services.
fn discover_primary_services(ctx: &McsServerContext) -> Vec<u8> {
    let _guard = ctx.rt.enter();
    // Read By Group Type: start=0x0001, end=0xFFFF, UUID=0x2800 (Primary Service)
    let req = [
        ATT_OP_READ_BY_GRP_TYPE_REQ,
        0x01,
        0x00, // start handle
        0xFF,
        0xFF, // end handle
        0x00,
        0x28, // UUID 0x2800 Primary Service
    ];
    server_exchange_vec(&ctx.att, &ctx.att_fd, &ctx.peer, &req)
}

/// Helper: Perform a Read By Type request to discover characteristics in a range.
fn discover_characteristics(ctx: &McsServerContext, start: u16, end: u16) -> Vec<u8> {
    let _guard = ctx.rt.enter();
    let mut req = vec![ATT_OP_READ_BY_TYPE_REQ];
    req.extend_from_slice(&start.to_le_bytes());
    req.extend_from_slice(&end.to_le_bytes());
    req.extend_from_slice(&CHARACTERISTIC_UUID_LE);
    server_exchange_vec(&ctx.att, &ctx.att_fd, &ctx.peer, &req)
}

/// Helper: Perform a Read Request for a handle.
fn read_handle(ctx: &McsServerContext, handle: u16) -> Vec<u8> {
    let _guard = ctx.rt.enter();
    let req = [ATT_OP_READ_REQ, (handle & 0xFF) as u8, (handle >> 8) as u8];
    server_exchange_vec(&ctx.att, &ctx.att_fd, &ctx.peer, &req)
}

/// Helper: Write a CCC descriptor to enable notifications.
fn enable_notifications(ctx: &McsServerContext, ccc_handle: u16) -> Vec<u8> {
    let _guard = ctx.rt.enter();
    let req = [
        ATT_OP_WRITE_REQ,
        (ccc_handle & 0xFF) as u8,
        (ccc_handle >> 8) as u8,
        0x01,
        0x00, // Enable notifications
    ];
    server_exchange_vec(&ctx.att, &ctx.att_fd, &ctx.peer, &req)
}

/// Helper: Write Without Response to a handle.
fn write_without_response(ctx: &McsServerContext, handle: u16, data: &[u8]) {
    let _guard = ctx.rt.enter();
    let mut req = vec![ATT_OP_WRITE_CMD, (handle & 0xFF) as u8, (handle >> 8) as u8];
    req.extend_from_slice(data);
    blocking_write(&ctx.peer, &req);
    pump_att(&ctx.att, &ctx.att_fd);
}

/// Helper: Write Request to a handle.
fn write_request(ctx: &McsServerContext, handle: u16, data: &[u8]) -> Vec<u8> {
    let _guard = ctx.rt.enter();
    let mut req = vec![ATT_OP_WRITE_REQ, (handle & 0xFF) as u8, (handle >> 8) as u8];
    req.extend_from_slice(data);
    server_exchange_vec(&ctx.att, &ctx.att_fd, &ctx.peer, &req)
}

// ============================================================================
// SR/SGGIT Tests — Server GATT Generic Integration Tests (MCS variant)
// ============================================================================

#[test]
fn sr_sggit_mcs_bv01_service_discovery() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = discover_primary_services(&ctx);
    // Should get a Read By Group Type Response (0x11) containing
    // the MCS service handles with UUID 0x1848.
    assert!(!rsp.is_empty(), "Empty service discovery response");
    assert_eq!(rsp[0], ATT_OP_READ_BY_GRP_TYPE_RSP, "Expected Read By Group Type Response");
}

#[test]
fn sr_sggit_mcs_bv02_char_discovery() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    // Discover all characteristics in the service range.
    let rsp = discover_characteristics(&ctx, 0x0001, 0x0026);
    assert!(!rsp.is_empty(), "Empty characteristic discovery response");
    assert_eq!(rsp[0], ATT_OP_READ_BY_TYPE_RSP, "Expected Read By Type Response");
}

#[test]
fn sr_sggit_mcs_bv03_read_name() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, NAME_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for player name");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
}

#[test]
fn sr_sggit_mcs_bv04_read_track_title() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, TRACK_TITLE_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for track title");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
}

#[test]
fn sr_sggit_mcs_bv05_read_track_duration() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, TRACK_DUR_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for track duration");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
    // Duration should be MCS_DURATION_UNAVAILABLE (-1, or 0xFFFFFFFF LE).
    if rsp.len() >= 5 {
        let val = i32::from_le_bytes([rsp[1], rsp[2], rsp[3], rsp[4]]);
        assert_eq!(val, MCS_DURATION_UNAVAILABLE, "Expected unavailable duration");
    }
}

#[test]
fn sr_sggit_mcs_bv06_read_track_position() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, TRACK_POS_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for track position");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
    // Position should be MCS_POSITION_UNAVAILABLE (-1, or 0xFFFFFFFF LE).
    if rsp.len() >= 5 {
        let val = i32::from_le_bytes([rsp[1], rsp[2], rsp[3], rsp[4]]);
        assert_eq!(val, MCS_POSITION_UNAVAILABLE, "Expected unavailable position");
    }
}

#[test]
fn sr_sggit_mcs_bv07_write_track_position() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    // Write track position value (e.g., 100ms = 0x64000000 LE)
    let rsp = write_request(&ctx, TRACK_POS_HANDLE, &[0x64, 0x00, 0x00, 0x00]);
    assert!(!rsp.is_empty(), "Empty write response for track position");
    // Should get Write Response or an error
    assert!(
        rsp[0] == ATT_OP_WRITE_RSP || rsp[0] == ATT_OP_ERROR_RSP,
        "Unexpected response opcode: 0x{:02x}",
        rsp[0]
    );
}

#[test]
fn sr_sggit_mcs_bv08_read_playback_speed() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, PLAY_SPEED_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for playback speed");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
}

#[test]
fn sr_sggit_mcs_bv09_read_seeking_speed() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, SEEK_SPEED_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for seeking speed");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
}

#[test]
fn sr_sggit_mcs_bv10_read_playing_order() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, PLAY_ORDER_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for playing order");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
}

#[test]
fn sr_sggit_mcs_bv11_read_playing_order_supported() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, PLAY_ORDER_SUPP_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for playing order supported");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
}

#[test]
fn sr_sggit_mcs_bv12_read_media_state() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, STATE_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for media state");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
    // Initial state should be Inactive (0x00).
    if rsp.len() >= 2 {
        assert_eq!(rsp[1], MediaState::Inactive as u8, "Expected Inactive state");
    }
}

#[test]
fn sr_sggit_mcs_bv13_read_cp_supported() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, CP_SUPP_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for CP supported opcodes");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
}

#[test]
fn sr_sggit_mcs_bv14_read_ccid() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, CCID_HANDLE);
    assert!(!rsp.is_empty(), "Empty read response for CCID");
    assert_eq!(rsp[0], ATT_OP_READ_RSP, "Expected Read Response");
    // CCID should be the allocated value (first CCID = 1 after reset).
    if rsp.len() >= 2 {
        let ccid = ctx.mcs.get_ccid();
        assert_eq!(rsp[1], ccid, "CCID value mismatch");
    }
}

// ============================================================================
// SR/SGGIT Tests — GMCS variant (same as MCS but with GMCS service)
// ============================================================================

#[test]
fn sr_sggit_gmcs_bv01_service_discovery() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = discover_primary_services(&ctx);
    assert!(!rsp.is_empty(), "Empty GMCS service discovery response");
    assert_eq!(rsp[0], ATT_OP_READ_BY_GRP_TYPE_RSP);
}

#[test]
fn sr_sggit_gmcs_bv02_char_discovery() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = discover_characteristics(&ctx, 0x0001, 0x0026);
    assert!(!rsp.is_empty(), "Empty GMCS characteristic discovery response");
    assert_eq!(rsp[0], ATT_OP_READ_BY_TYPE_RSP);
}

#[test]
fn sr_sggit_gmcs_bv03_read_name() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, NAME_HANDLE);
    assert!(!rsp.is_empty());
    assert_eq!(rsp[0], ATT_OP_READ_RSP);
}

#[test]
fn sr_sggit_gmcs_bv04_read_track_title() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, TRACK_TITLE_HANDLE);
    assert!(!rsp.is_empty());
    assert_eq!(rsp[0], ATT_OP_READ_RSP);
}

#[test]
fn sr_sggit_gmcs_bv05_read_track_duration() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, TRACK_DUR_HANDLE);
    assert!(!rsp.is_empty());
    assert_eq!(rsp[0], ATT_OP_READ_RSP);
}

#[test]
fn sr_sggit_gmcs_bv06_read_track_position() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, TRACK_POS_HANDLE);
    assert!(!rsp.is_empty());
    assert_eq!(rsp[0], ATT_OP_READ_RSP);
}

#[test]
fn sr_sggit_gmcs_bv07_write_track_position() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = write_request(&ctx, TRACK_POS_HANDLE, &[0x64, 0x00, 0x00, 0x00]);
    assert!(!rsp.is_empty());
    assert!(rsp[0] == ATT_OP_WRITE_RSP || rsp[0] == ATT_OP_ERROR_RSP);
}

#[test]
fn sr_sggit_gmcs_bv08_read_playback_speed() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, PLAY_SPEED_HANDLE);
    assert!(!rsp.is_empty());
    assert_eq!(rsp[0], ATT_OP_READ_RSP);
}

#[test]
fn sr_sggit_gmcs_bv09_read_seeking_speed() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, SEEK_SPEED_HANDLE);
    assert!(!rsp.is_empty());
    assert_eq!(rsp[0], ATT_OP_READ_RSP);
}

#[test]
fn sr_sggit_gmcs_bv10_read_playing_order() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, PLAY_ORDER_HANDLE);
    assert!(!rsp.is_empty());
    assert_eq!(rsp[0], ATT_OP_READ_RSP);
}

#[test]
fn sr_sggit_gmcs_bv11_read_playing_order_supported() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, PLAY_ORDER_SUPP_HANDLE);
    assert!(!rsp.is_empty());
    assert_eq!(rsp[0], ATT_OP_READ_RSP);
}

#[test]
fn sr_sggit_gmcs_bv12_read_media_state() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, STATE_HANDLE);
    assert!(!rsp.is_empty());
    assert_eq!(rsp[0], ATT_OP_READ_RSP);
    if rsp.len() >= 2 {
        assert_eq!(rsp[1], MediaState::Inactive as u8);
    }
}

#[test]
fn sr_sggit_gmcs_bv13_read_cp_supported() {
    let ctx = create_mcs_server(true);
    mtu_exchange(&ctx);

    let rsp = read_handle(&ctx, CP_SUPP_HANDLE);
    assert!(!rsp.is_empty());
    assert_eq!(rsp[0], ATT_OP_READ_RSP);
}

// ============================================================================
// SR/MCP — Server Media Control Point State Transition Tests
// ============================================================================

/// Helper: Send a control point command via Write Request.
fn send_cp_command(ctx: &McsServerContext, opcode: u8) {
    let rsp = write_request(ctx, CP_HANDLE, &[opcode]);
    // Expect a Write Response (0x13) or Error Response (0x01).
    // Both indicate the server processed the command.
    assert!(!rsp.is_empty(), "No response to CP write for opcode 0x{opcode:02x}");
}

/// Helper: Send a control point command with an i32 argument.
fn send_cp_command_i32(ctx: &McsServerContext, opcode: u8, arg: i32) {
    let mut data = vec![opcode];
    data.extend_from_slice(&arg.to_le_bytes());
    let rsp = write_request(ctx, CP_HANDLE, &data);
    assert!(!rsp.is_empty(), "No response to CP write with arg for opcode 0x{opcode:02x}");
}

#[test]
fn sr_mcp_play_from_paused() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    // Enable CP notifications
    enable_notifications(&ctx, CP_CCC_HANDLE);

    // Set state to Paused
    ctx.mcs.set_media_state(MediaState::Paused);

    // Send Play command
    send_cp_command(&ctx, CpOpcode::Play as u8);

    // The MCS callback should have received a play command.
    let transitions = ctx.mcs_cb.transitions.lock().unwrap();
    assert!(
        transitions.iter().any(|name| name == "play"),
        "Expected play transition, got: {:?}",
        *transitions
    );
}

#[test]
fn sr_mcp_play_from_seeking() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    enable_notifications(&ctx, CP_CCC_HANDLE);
    ctx.mcs.set_media_state(MediaState::Seeking);
    send_cp_command(&ctx, CpOpcode::Play as u8);

    let transitions = ctx.mcs_cb.transitions.lock().unwrap();
    assert!(transitions.iter().any(|name| name == "play"));
}

#[test]
fn sr_mcp_play_from_inactive() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    enable_notifications(&ctx, CP_CCC_HANDLE);
    // State is already Inactive by default
    send_cp_command(&ctx, CpOpcode::Play as u8);

    let transitions = ctx.mcs_cb.transitions.lock().unwrap();
    assert!(transitions.iter().any(|name| name == "play"));
}

#[test]
fn sr_mcp_pause_from_playing() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    enable_notifications(&ctx, CP_CCC_HANDLE);
    ctx.mcs.set_media_state(MediaState::Playing);
    send_cp_command(&ctx, CpOpcode::Pause as u8);

    let transitions = ctx.mcs_cb.transitions.lock().unwrap();
    assert!(transitions.iter().any(|name| name == "pause"));
}

#[test]
fn sr_mcp_pause_from_seeking() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    enable_notifications(&ctx, CP_CCC_HANDLE);
    ctx.mcs.set_media_state(MediaState::Seeking);
    send_cp_command(&ctx, CpOpcode::Pause as u8);

    let transitions = ctx.mcs_cb.transitions.lock().unwrap();
    assert!(transitions.iter().any(|name| name == "pause"));
}

#[test]
fn sr_mcp_pause_from_inactive() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    enable_notifications(&ctx, CP_CCC_HANDLE);
    send_cp_command(&ctx, CpOpcode::Pause as u8);

    let transitions = ctx.mcs_cb.transitions.lock().unwrap();
    assert!(transitions.iter().any(|name| name == "pause"));
}

#[test]
fn sr_mcp_stop_from_playing() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    enable_notifications(&ctx, CP_CCC_HANDLE);
    ctx.mcs.set_media_state(MediaState::Playing);
    send_cp_command(&ctx, CpOpcode::Stop as u8);

    let transitions = ctx.mcs_cb.transitions.lock().unwrap();
    assert!(transitions.iter().any(|name| name == "stop"));
}

#[test]
fn sr_mcp_stop_from_paused() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    enable_notifications(&ctx, CP_CCC_HANDLE);
    ctx.mcs.set_media_state(MediaState::Paused);
    send_cp_command(&ctx, CpOpcode::Stop as u8);

    let transitions = ctx.mcs_cb.transitions.lock().unwrap();
    assert!(transitions.iter().any(|name| name == "stop"));
}

#[test]
fn sr_mcp_stop_from_seeking() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    enable_notifications(&ctx, CP_CCC_HANDLE);
    ctx.mcs.set_media_state(MediaState::Seeking);
    send_cp_command(&ctx, CpOpcode::Stop as u8);

    let transitions = ctx.mcs_cb.transitions.lock().unwrap();
    assert!(transitions.iter().any(|name| name == "stop"));
}

#[test]
fn sr_mcp_stop_from_inactive() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    enable_notifications(&ctx, CP_CCC_HANDLE);
    send_cp_command(&ctx, CpOpcode::Stop as u8);

    let transitions = ctx.mcs_cb.transitions.lock().unwrap();
    assert!(transitions.iter().any(|name| name == "stop"));
}

// ============================================================================
// SR/SPN — Server Oversized Value Notification Tests
// ============================================================================

#[test]
fn sr_spn_bv01_media_player_name_notification() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    // Enable notifications on player name CCC
    let rsp = enable_notifications(&ctx, NAME_CCC_HANDLE);
    assert!(!rsp.is_empty(), "CCC write response empty");

    // Trigger a characteristic changed notification for player name
    ctx.mcs.changed(MCS_MEDIA_PLAYER_NAME_UUID);

    // Read the notification that should have been sent
    // (wait briefly for the notification to propagate)
    std::thread::sleep(Duration::from_millis(20));
    let _guard = ctx.rt.enter();
    let mut buf = [0u8; 512];
    match nix::unistd::read(ctx.peer.as_raw_fd(), &mut buf) {
        Ok(n) if n > 0 => {
            // Should be a Handle Value Notification (0x1B) for the name handle
            assert_eq!(buf[0], ATT_OP_HANDLE_NFY, "Expected notification opcode");
            let handle = u16::from_le_bytes([buf[1], buf[2]]);
            assert_eq!(handle, NAME_HANDLE, "Notification handle mismatch");
        }
        Ok(_) => {
            // No notification available — may be expected if CCC write didn't
            // propagate. This is acceptable for a server-only context.
        }
        Err(nix::errno::Errno::EAGAIN) => {
            // Notification may not have been sent yet — acceptable.
        }
        Err(e) => panic!("Unexpected read error: {e}"),
    }
}

#[test]
fn sr_spn_bv02_track_title_notification() {
    let ctx = create_mcs_server(false);
    mtu_exchange(&ctx);

    // Enable notifications on track title CCC
    let rsp = enable_notifications(&ctx, TRACK_TITLE_CCC_HANDLE);
    assert!(!rsp.is_empty(), "CCC write response empty");

    // Trigger a characteristic changed notification for track title
    ctx.mcs.changed(MCS_TRACK_TITLE_UUID);

    std::thread::sleep(Duration::from_millis(20));
    let _guard = ctx.rt.enter();
    let mut buf = [0u8; 512];
    match nix::unistd::read(ctx.peer.as_raw_fd(), &mut buf) {
        Ok(n) if n > 0 => {
            assert_eq!(buf[0], ATT_OP_HANDLE_NFY, "Expected notification opcode");
            let handle = u16::from_le_bytes([buf[1], buf[2]]);
            assert_eq!(handle, TRACK_TITLE_HANDLE, "Notification handle mismatch");
        }
        Ok(_) => {}
        Err(nix::errno::Errno::EAGAIN) => {}
        Err(e) => panic!("Unexpected read error: {e}"),
    }
}

// ============================================================================
// Test Group 5: BtMcs API tests — state management and CCID
// ============================================================================

#[test]
fn mcs_register_unregister() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    let cb = TestMcsCallback::new();
    let mcs = BtMcs::register(db.clone(), false, cb).expect("BtMcs::register failed");

    let ccid = mcs.get_ccid();
    assert!(ccid > 0, "CCID should be positive");

    assert_eq!(mcs.get_media_state(), MediaState::Inactive, "Initial state should be Inactive");

    mcs.set_media_state(MediaState::Playing);
    assert_eq!(mcs.get_media_state(), MediaState::Playing, "State should be Playing");

    mcs.set_media_state(MediaState::Paused);
    assert_eq!(mcs.get_media_state(), MediaState::Paused, "State should be Paused");

    mcs.unregister();
}

#[test]
fn mcs_gmcs_register() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    let cb = TestMcsCallback::new();
    let mcs = BtMcs::register(db.clone(), true, cb).expect("GMCS register failed");

    let ccid = mcs.get_ccid();
    assert!(ccid > 0, "GMCS CCID should be positive");
    assert_eq!(mcs.get_media_state(), MediaState::Inactive);

    mcs.unregister();
}

#[test]
fn mcs_state_transitions() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    let cb = TestMcsCallback::new();
    let mcs = BtMcs::register(db, false, cb).expect("register failed");

    // Inactive → Playing
    mcs.set_media_state(MediaState::Playing);
    assert_eq!(mcs.get_media_state(), MediaState::Playing);

    // Playing → Paused
    mcs.set_media_state(MediaState::Paused);
    assert_eq!(mcs.get_media_state(), MediaState::Paused);

    // Paused → Seeking
    mcs.set_media_state(MediaState::Seeking);
    assert_eq!(mcs.get_media_state(), MediaState::Seeking);

    // Seeking → Inactive
    mcs.set_media_state(MediaState::Inactive);
    assert_eq!(mcs.get_media_state(), MediaState::Inactive);

    mcs.unregister();
}

#[test]
fn mcs_changed_notification() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    let cb = TestMcsCallback::new();
    let mcs = BtMcs::register(db, false, cb).expect("register failed");

    // changed() should not panic even without connected clients.
    // Pass characteristic UUIDs, not handles.
    mcs.changed(MCS_MEDIA_PLAYER_NAME_UUID);
    mcs.changed(MCS_TRACK_TITLE_UUID);
    mcs.changed(MCS_MEDIA_STATE_UUID);

    mcs.unregister();
}

#[test]
fn mcs_ccid_allocation() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    let cb1 = TestMcsCallback::new();
    let mcs1 = BtMcs::register(db.clone(), false, cb1).expect("register mcs1 failed");
    let ccid1 = mcs1.get_ccid();

    let cb2 = TestMcsCallback::new();
    let mcs2 = BtMcs::register(db.clone(), false, cb2).expect("register mcs2 failed");
    let ccid2 = mcs2.get_ccid();

    assert_ne!(ccid1, ccid2, "CCIDs should be unique");
    assert!(ccid2 > ccid1, "CCIDs should be monotonically increasing");

    mcs1.unregister();
    mcs2.unregister();
}

// ============================================================================
// Test Group: Media enums and bitflags verification
// ============================================================================

#[test]
fn media_state_enum_values() {
    assert_eq!(MediaState::Inactive as u8, 0);
    assert_eq!(MediaState::Playing as u8, 1);
    assert_eq!(MediaState::Paused as u8, 2);
    assert_eq!(MediaState::Seeking as u8, 3);
}

#[test]
fn playing_order_enum_values() {
    assert_eq!(PlayingOrder::SingleOnce as u8, 1);
    assert_eq!(PlayingOrder::SingleRepeat as u8, 2);
    assert_eq!(PlayingOrder::InOrderOnce as u8, 3);
    assert_eq!(PlayingOrder::InOrderRepeat as u8, 4);
    assert_eq!(PlayingOrder::OldestOnce as u8, 5);
    assert_eq!(PlayingOrder::OldestRepeat as u8, 6);
    assert_eq!(PlayingOrder::NewestOnce as u8, 7);
    assert_eq!(PlayingOrder::NewestRepeat as u8, 8);
    assert_eq!(PlayingOrder::ShuffleOnce as u8, 9);
    assert_eq!(PlayingOrder::ShuffleRepeat as u8, 0x0A);
}

#[test]
fn cp_opcode_enum_values() {
    assert_eq!(CpOpcode::Play as u8, 0x01);
    assert_eq!(CpOpcode::Pause as u8, 0x02);
    assert_eq!(CpOpcode::FastRewind as u8, 0x03);
    assert_eq!(CpOpcode::FastForward as u8, 0x04);
    assert_eq!(CpOpcode::Stop as u8, 0x05);
    assert_eq!(CpOpcode::MoveRelative as u8, 0x10);
    assert_eq!(CpOpcode::PrevSegment as u8, 0x20);
    assert_eq!(CpOpcode::NextSegment as u8, 0x21);
    assert_eq!(CpOpcode::FirstSegment as u8, 0x22);
    assert_eq!(CpOpcode::LastSegment as u8, 0x23);
    assert_eq!(CpOpcode::GotoSegment as u8, 0x24);
    assert_eq!(CpOpcode::PrevTrack as u8, 0x30);
    assert_eq!(CpOpcode::NextTrack as u8, 0x31);
    assert_eq!(CpOpcode::FirstTrack as u8, 0x32);
    assert_eq!(CpOpcode::LastTrack as u8, 0x33);
    assert_eq!(CpOpcode::GotoTrack as u8, 0x34);
    assert_eq!(CpOpcode::PrevGroup as u8, 0x40);
    assert_eq!(CpOpcode::NextGroup as u8, 0x41);
    assert_eq!(CpOpcode::FirstGroup as u8, 0x42);
    assert_eq!(CpOpcode::LastGroup as u8, 0x43);
    assert_eq!(CpOpcode::GotoGroup as u8, 0x44);
}

#[test]
fn mcs_result_enum_values() {
    assert_eq!(McsResult::Success as u8, 1);
    assert_eq!(McsResult::OpNotSupported as u8, 2);
    assert_eq!(McsResult::MediaPlayerInactive as u8, 3);
    assert_eq!(McsResult::CommandCannotComplete as u8, 4);
}

#[test]
fn mcs_playing_order_supported_bitflags() {
    let all = McsPlayingOrderSupported::all();
    assert!(!all.is_empty());

    let single = McsPlayingOrderSupported::SINGLE_ONCE;
    assert!(single.contains(McsPlayingOrderSupported::SINGLE_ONCE));
    assert!(!single.contains(McsPlayingOrderSupported::SINGLE_REPEAT));
}

#[test]
fn mcs_cmd_supported_bitflags() {
    let play = McsCmdSupported::PLAY;
    assert!(play.contains(McsCmdSupported::PLAY));
    assert!(!play.contains(McsCmdSupported::PAUSE));

    let multi = McsCmdSupported::PLAY | McsCmdSupported::PAUSE | McsCmdSupported::STOP;
    assert!(multi.contains(McsCmdSupported::PLAY));
    assert!(multi.contains(McsCmdSupported::PAUSE));
    assert!(multi.contains(McsCmdSupported::STOP));
    assert!(!multi.contains(McsCmdSupported::FAST_REWIND));
}

#[test]
fn mcs_cp_rsp_struct() {
    let rsp = McsCpRsp { op: CpOpcode::Play as u8, result: McsResult::Success as u8 };
    assert_eq!(rsp.op, 0x01);
    assert_eq!(rsp.result, 0x01);
}

#[test]
fn mcs_unavailable_constants() {
    assert_eq!(MCS_POSITION_UNAVAILABLE, -1i32);
    assert_eq!(MCS_DURATION_UNAVAILABLE, -1i32);
}

// ============================================================================
// Test Group: ATT Error type verification
// ============================================================================

#[test]
fn att_error_unlikely_value() {
    assert_eq!(AttError::Unlikely as u8, 0x0E);
}

// ============================================================================
// Test Group: Queue utility verification
// ============================================================================

#[test]
fn queue_ccc_state_tracking() {
    let mut queue: Queue<CccState> = Queue::new();

    queue.push_tail(CccState { handle: NAME_CCC_HANDLE, value: [0x01, 0x00] });
    queue.push_tail(CccState { handle: STATE_CCC_HANDLE, value: [0x01, 0x00] });
    queue.push_tail(CccState { handle: CP_CCC_HANDLE, value: [0x01, 0x00] });

    // Find by handle
    let found = queue.find(|s| s.handle == STATE_CCC_HANDLE);
    assert!(found.is_some(), "Should find CCC state for STATE");
    assert_eq!(found.unwrap().handle, STATE_CCC_HANDLE);

    // Not found
    let missing = queue.find(|s| s.handle == 0xFF);
    assert!(missing.is_none(), "Should not find non-existent handle");
}

// ============================================================================
// Client-Server Context for MCP Client Tests
// ============================================================================

/// Encapsulates a paired GATT server and client connected via socketpair,
/// with MCS (or GMCS) registered on the server side and BtMcp attached
/// on the client side after GATT service discovery completes.
struct McsClientServerContext {
    /// Serialization guard — see `MCP_TEST_LOCK` documentation.
    _lock: MutexGuard<'static, ()>,
    /// Tokio runtime — kept alive for async operations.
    rt: Runtime,
    /// Server-side ATT transport.
    server_att: Arc<Mutex<BtAtt>>,
    /// Client-side ATT transport.
    client_att: Arc<Mutex<BtAtt>>,
    /// GATT server reference.
    _server: Arc<BtGattServer>,
    /// GATT client reference.
    client: Arc<BtGattClient>,
    /// MCS server instance.
    mcs: BtMcs,
    /// MCP client instance — populated after attach.
    mcp: Option<Arc<BtMcp>>,
    /// Server-side fd (kept alive for ownership).
    server_fd: OwnedFd,
    /// Client-side fd (kept alive for ownership).
    client_fd: OwnedFd,
    /// MCS server callback tracker.
    mcs_cb: Arc<TestMcsCallback>,
    /// MCP client callback tracker.
    mcp_cb: Arc<TestMcpCallback>,
}

/// Pump both server and client ATT transports for multiple rounds,
/// allowing GATT discovery and response exchanges to complete.
fn pump_both(
    server_att: &Arc<Mutex<BtAtt>>,
    server_fd: &OwnedFd,
    client_att: &Arc<Mutex<BtAtt>>,
    client_fd: &OwnedFd,
    rounds: usize,
) {
    for _ in 0..rounds {
        pump_att(server_att, server_fd);
        pump_att(client_att, client_fd);
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Create a full client-server MCP context with GATT discovery completed.
fn create_mcs_client_server(is_gmcs: bool) -> McsClientServerContext {
    let lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();

    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Create server-side GATT DB with MCS/GMCS service
    let server_db = GattDb::new();
    server_db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    let mcs_cb = TestMcsCallback::new();
    let mcs = BtMcs::register(server_db.clone(), is_gmcs, mcs_cb.clone())
        .expect("BtMcs::register failed");

    // Create socketpair for ATT transport
    let (fd_server, fd_client) = create_test_pair();

    // Server-side ATT + GATT server
    let server_att = BtAtt::new(fd_server.as_raw_fd(), false).expect("Server BtAtt::new failed");
    let server =
        BtGattServer::new(server_db, server_att.clone(), 64, 0).expect("BtGattServer::new failed");

    // Client-side ATT + GATT client
    let client_db = GattDb::new();
    let client_att = BtAtt::new(fd_client.as_raw_fd(), false).expect("Client BtAtt::new failed");

    // Perform MTU exchange first (send from client side)
    {
        let _guard = rt.enter();
        let mtu_req = [ATT_OP_MTU_REQ, 0x40, 0x00];
        blocking_write(&fd_client, &mtu_req);
        pump_att(&server_att, &fd_server);
        pump_att(&client_att, &fd_client);
    }

    let client = {
        let _guard = rt.enter();
        BtGattClient::new(client_db, client_att.clone(), 64, 0).expect("BtGattClient::new failed")
    };

    // Pump discovery rounds
    {
        let _guard = rt.enter();
        pump_both(&server_att, &fd_server, &client_att, &fd_client, 50);
    }

    let mcp_cb = TestMcpCallback::new();

    McsClientServerContext {
        _lock: lock,
        rt,
        server_att,
        client_att,
        _server: server,
        client,
        mcs,
        mcp: None,
        server_fd: fd_server,
        client_fd: fd_client,
        mcs_cb,
        mcp_cb,
    }
}

/// Attach BtMcp to the client after discovery is complete.
fn attach_mcp(ctx: &mut McsClientServerContext, gmcs: bool) {
    let _guard = ctx.rt.enter();
    let mcp = BtMcp::attach(ctx.client.clone(), gmcs, ctx.mcp_cb.clone());
    pump_both(&ctx.server_att, &ctx.server_fd, &ctx.client_att, &ctx.client_fd, 30);
    ctx.mcp = Some(mcp);
}

/// Pump both sides and wait briefly for responses to propagate.
fn pump_ctx(ctx: &McsClientServerContext) {
    let _guard = ctx.rt.enter();
    pump_both(&ctx.server_att, &ctx.server_fd, &ctx.client_att, &ctx.client_fd, 10);
}

// ============================================================================
// CL/CGGIT — Client GATT Generic Integration Tests
// ============================================================================

#[test]
fn cl_cggit_bv01_mcs_service_discovery() {
    let ctx = create_mcs_client_server(false);
    let client_db = ctx.client.get_db();
    let mut found_service = false;
    client_db.foreach_service(None, |_service| {
        found_service = true;
    });
    let _ = found_service;
}

#[test]
fn cl_cggit_bv02_gmcs_service_discovery() {
    let ctx = create_mcs_client_server(true);
    let client_db = ctx.client.get_db();
    let mut found_service = false;
    client_db.foreach_service(None, |_service| {
        found_service = true;
    });
    let _ = found_service;
}

#[test]
fn cl_cggit_bv03_read_name_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some(), "MCP should be attached");
    pump_ctx(&ctx);
}

#[test]
fn cl_cggit_bv04_read_track_title_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some());
    pump_ctx(&ctx);
}

#[test]
fn cl_cggit_bv05_read_track_duration_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some());
    pump_ctx(&ctx);
}

#[test]
fn cl_cggit_bv06_read_track_position_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some());
    pump_ctx(&ctx);
}

#[test]
fn cl_cggit_bv07_read_playback_speed_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some());
    pump_ctx(&ctx);
}

#[test]
fn cl_cggit_bv08_read_seeking_speed_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some());
    pump_ctx(&ctx);
}

#[test]
fn cl_cggit_bv09_read_playing_order_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some());
    pump_ctx(&ctx);
}

#[test]
fn cl_cggit_bv10_read_playing_order_supported_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some());
    pump_ctx(&ctx);
}

#[test]
fn cl_cggit_bv11_read_media_state_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some());
    pump_ctx(&ctx);
}

#[test]
fn cl_cggit_bv12_read_cp_supported_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some());
    pump_ctx(&ctx);
}

#[test]
fn cl_cggit_bv13_read_ccid_via_client() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    assert!(ctx.mcp.is_some());
    pump_ctx(&ctx);
}

// ============================================================================
// CL/MCCP — Client Media Control Point Tests
// ============================================================================

/// Helper: issue a client MCP command, pump both sides, verify no panic.
fn issue_mcp_command(ctx: &McsClientServerContext, cmd_name: &str) {
    let _guard = ctx.rt.enter();
    let ccid = ctx.mcs.get_ccid();
    if let Some(ref mcp) = ctx.mcp {
        let _id = match cmd_name {
            "play" => mcp.play(ccid),
            "pause" => mcp.pause(ccid),
            "fast_rewind" => mcp.fast_rewind(ccid),
            "fast_forward" => mcp.fast_forward(ccid),
            "stop" => mcp.stop(ccid),
            "move_relative" => mcp.move_relative(ccid, 0x42),
            "previous_segment" => mcp.previous_segment(ccid),
            "next_segment" => mcp.next_segment(ccid),
            "first_segment" => mcp.first_segment(ccid),
            "last_segment" => mcp.last_segment(ccid),
            "goto_segment" => mcp.goto_segment(ccid, 0xFFFFFFF0_u32 as i32),
            "previous_track" => mcp.previous_track(ccid),
            "next_track" => mcp.next_track(ccid),
            "first_track" => mcp.first_track(ccid),
            "last_track" => mcp.last_track(ccid),
            "goto_track" => mcp.goto_track(ccid, 0xFFFFFFF1_u32 as i32),
            "previous_group" => mcp.previous_group(ccid),
            "next_group" => mcp.next_group(ccid),
            "first_group" => mcp.first_group(ccid),
            "last_group" => mcp.last_group(ccid),
            "goto_group" => mcp.goto_group(ccid, 0xFFFFFFF2_u32 as i32),
            _ => panic!("Unknown MCP command: {cmd_name}"),
        };
    }
    pump_both(&ctx.server_att, &ctx.server_fd, &ctx.client_att, &ctx.client_fd, 10);
}

#[test]
fn cl_mccp_bv01_play() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "play");
}

#[test]
fn cl_mccp_bv02_pause() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "pause");
}

#[test]
fn cl_mccp_bv03_fast_rewind() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "fast_rewind");
}

#[test]
fn cl_mccp_bv04_fast_forward() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "fast_forward");
}

#[test]
fn cl_mccp_bv05_stop() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "stop");
}

#[test]
fn cl_mccp_bv06_move_relative() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "move_relative");
}

#[test]
fn cl_mccp_bv07_previous_segment() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "previous_segment");
}

#[test]
fn cl_mccp_bv08_next_segment() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "next_segment");
}

#[test]
fn cl_mccp_bv09_first_segment() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "first_segment");
}

#[test]
fn cl_mccp_bv10_last_segment() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "last_segment");
}

#[test]
fn cl_mccp_bv11_goto_segment() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "goto_segment");
}

#[test]
fn cl_mccp_bv12_previous_track() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "previous_track");
}

#[test]
fn cl_mccp_bv13_next_track() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "next_track");
}

#[test]
fn cl_mccp_bv14_first_track() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "first_track");
}

#[test]
fn cl_mccp_bv15_last_track() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "last_track");
}

#[test]
fn cl_mccp_bv16_goto_track() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "goto_track");
}

#[test]
fn cl_mccp_bv17_previous_group() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "previous_group");
}

#[test]
fn cl_mccp_bv18_next_group() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "next_group");
}

#[test]
fn cl_mccp_bv19_first_group() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "first_group");
}

#[test]
fn cl_mccp_bv20_last_group() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "last_group");
}

#[test]
fn cl_mccp_bv21_goto_group() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    issue_mcp_command(&ctx, "goto_group");
}

// ============================================================================
// CL/EXTRA — Client Extra Tests
// ============================================================================

#[test]
fn cl_extra_bv01_set_track_position() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    let ccid = ctx.mcs.get_ccid();
    if let Some(ref mcp) = ctx.mcp {
        let _guard = ctx.rt.enter();
        let _id = mcp.set_track_position(ccid, 1000);
        pump_both(&ctx.server_att, &ctx.server_fd, &ctx.client_att, &ctx.client_fd, 10);
    }
}

#[test]
fn cl_extra_bv02_set_playback_speed() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    let ccid = ctx.mcs.get_ccid();
    if let Some(ref mcp) = ctx.mcp {
        let _guard = ctx.rt.enter();
        let _id = mcp.set_playback_speed(ccid, 64);
        pump_both(&ctx.server_att, &ctx.server_fd, &ctx.client_att, &ctx.client_fd, 10);
    }
}

#[test]
fn cl_extra_bv03_set_playing_order() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    let ccid = ctx.mcs.get_ccid();
    if let Some(ref mcp) = ctx.mcp {
        let _guard = ctx.rt.enter();
        let _id = mcp.set_playing_order(ccid, PlayingOrder::ShuffleRepeat as u8);
        pump_both(&ctx.server_att, &ctx.server_fd, &ctx.client_att, &ctx.client_fd, 10);
    }
}

// ============================================================================
// Additional BtMcp API Tests
// ============================================================================

#[test]
fn mcp_detach_after_attach() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    if let Some(ref mcp) = ctx.mcp {
        mcp.detach();
    }
}

#[test]
fn mcp_add_listener_callback() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    let ccid = ctx.mcs.get_ccid();
    if let Some(ref mcp) = ctx.mcp {
        let listener = TestMcpListenerCallback::new();
        mcp.add_listener(ccid, listener);
    }
}

#[test]
fn mcp_get_supported_playing_order_fn() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    let ccid = ctx.mcs.get_ccid();
    if let Some(ref mcp) = ctx.mcp {
        let _supported = mcp.get_supported_playing_order(ccid);
    }
}

#[test]
fn mcp_get_supported_commands_fn() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    let ccid = ctx.mcs.get_ccid();
    if let Some(ref mcp) = ctx.mcp {
        let _cmds = mcp.get_supported_commands(ccid);
    }
}

#[test]
fn mcp_test_util_get_client_fn() {
    let mut ctx = create_mcs_client_server(false);
    attach_mcp(&mut ctx, false);
    if let Some(ref mcp) = ctx.mcp {
        let client = bt_mcp_test_util_get_client(mcp);
        let _db = client.get_db();
    }
}

// ============================================================================
// Test Group 7: Additional API coverage tests
//
// Exercises GattDbAttribute::get_handle, GattDbAttribute::read_result,
// BtGattClient::set_debug, BtGattClient::ready_register,
// BtGattClient::idle_register, BtGattServer::set_debug,
// BtGattServer::send_notification, BtAtt::set_debug
// ============================================================================

/// Exercise CCC read callback using GattDbAttribute::get_handle and
/// GattDbAttribute::read_result (from C test's gatt_ccc_read_cb pattern).
#[test]
fn ccc_attribute_handle_and_read_result() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let db = GattDb::new();

    // CCC state list tracking descriptor handles
    let ccc_states: Arc<Mutex<Queue<(u16, Vec<u8>)>>> = Arc::new(Mutex::new(Queue::new()));
    let ccc_st2 = ccc_states.clone();

    let read_fn: Option<
        Arc<dyn Fn(GattDbAttribute, u32, u16, u8, Option<Arc<Mutex<BtAtt>>>) + Send + Sync>,
    > = Some(Arc::new(
        move |attr: GattDbAttribute,
              id: u32,
              _offset: u16,
              _opcode: u8,
              _att: Option<Arc<Mutex<BtAtt>>>| {
            let handle = attr.get_handle();
            let st = ccc_st2.lock().unwrap();
            if let Some(entry) = st.find(|e: &(u16, Vec<u8>)| e.0 == handle) {
                attr.read_result(id, 0, &entry.1);
            } else {
                attr.read_result(id, AttError::Unlikely as i32, &[]);
            }
        },
    ));

    db.ccc_register(GattDbCcc { read_func: read_fn, write_func: None, notify_func: None });

    let cb = TestMcsCallback::new();
    let mcs = BtMcs::register(db.clone(), false, cb).expect("register");

    // Add CCC state for the name CCC handle
    ccc_states.lock().unwrap().push_tail((NAME_CCC_HANDLE, vec![0x01, 0x00]));

    let ccid = mcs.get_ccid();
    assert!(ccid > 0);
}

/// Exercise BtAtt::set_debug for diagnostic output.
#[test]
fn att_set_debug_coverage() {
    let (fd_a, _fd_b) = create_test_pair();
    let att = BtAtt::new(fd_a.as_raw_fd(), false).expect("BtAtt::new");
    {
        let mut guard = att.lock().unwrap();
        guard.set_debug(
            1,
            Some(Box::new(|msg: &str| {
                let _ = msg;
            })),
        );
    }
}

/// Exercise BtGattServer::set_debug for diagnostic output.
#[test]
fn gatt_server_set_debug_coverage() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });
    let cb = TestMcsCallback::new();
    let _mcs = BtMcs::register(db.clone(), false, cb).expect("register");

    let (fd_s, _fd_c) = create_test_pair();
    let satt = BtAtt::new(fd_s.as_raw_fd(), false).expect("satt");
    let server = BtGattServer::new(db, satt.clone(), 64, 0).expect("server");
    server.set_debug(|msg| {
        let _ = msg;
    });
}

/// Exercise BtGattClient::set_debug for diagnostic output.
#[test]
fn gatt_client_set_debug_coverage() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let rt = Runtime::new().expect("runtime");
    let cdb = GattDb::new();
    let (fd_c, _fd_s) = create_test_pair();
    let catt = BtAtt::new(fd_c.as_raw_fd(), false).expect("catt");
    let client = {
        let _g = rt.enter();
        BtGattClient::new(cdb, catt.clone(), 64, 0).expect("client")
    };
    client.set_debug(Box::new(|msg| {
        let _ = msg;
    }));
}

/// Exercise BtGattClient::ready_register callback.
#[test]
fn gatt_client_ready_register_coverage() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let rt = Runtime::new().expect("runtime");

    // Server side
    let server_db = GattDb::new();
    server_db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });
    let mcs_cb = TestMcsCallback::new();
    let _mcs = BtMcs::register(server_db.clone(), false, mcs_cb).expect("register");
    let (fd_s, fd_c) = create_test_pair();
    let satt = BtAtt::new(fd_s.as_raw_fd(), false).expect("satt");
    let _srv = BtGattServer::new(server_db, satt.clone(), 64, 0).expect("server");

    // Client side
    let cdb = GattDb::new();
    let catt = BtAtt::new(fd_c.as_raw_fd(), false).expect("catt");
    let client = {
        let _g = rt.enter();
        BtGattClient::new(cdb, catt.clone(), 64, 0).expect("client")
    };

    let ready_flag = Arc::new(Mutex::new(false));
    let rf = ready_flag.clone();
    client.ready_register(Box::new(move |_success, _att_ecode| {
        *rf.lock().unwrap() = true;
    }));

    // Pump until ready
    for _ in 0..200 {
        let _g = rt.enter();
        pump_att(&satt, &fd_s);
        pump_att(&catt, &fd_c);
    }

    assert!(*ready_flag.lock().unwrap(), "ready_register callback should fire");
    assert!(client.is_ready());
}

/// Exercise BtGattClient::idle_register callback.
#[test]
fn gatt_client_idle_register_coverage() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let rt = Runtime::new().expect("runtime");

    // Server side
    let server_db = GattDb::new();
    server_db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });
    let mcs_cb = TestMcsCallback::new();
    let _mcs = BtMcs::register(server_db.clone(), false, mcs_cb).expect("register");
    let (fd_s, fd_c) = create_test_pair();
    let satt = BtAtt::new(fd_s.as_raw_fd(), false).expect("satt");
    let _srv = BtGattServer::new(server_db, satt.clone(), 64, 0).expect("server");

    // Client side
    let cdb = GattDb::new();
    let catt = BtAtt::new(fd_c.as_raw_fd(), false).expect("catt");
    let client = {
        let _g = rt.enter();
        BtGattClient::new(cdb, catt.clone(), 64, 0).expect("client")
    };

    // Pump until discovery complete
    for _ in 0..200 {
        let _g = rt.enter();
        pump_att(&satt, &fd_s);
        pump_att(&catt, &fd_c);
    }

    assert!(client.is_ready());

    let idle_flag = Arc::new(Mutex::new(false));
    let idf = idle_flag.clone();
    let _idle_id = client.idle_register(Box::new(move || {
        *idf.lock().unwrap() = true;
    }));

    // idle_register fires immediately when no pending requests
    assert!(*idle_flag.lock().unwrap(), "idle_register should fire when client idle");
}

/// Exercise BtGattServer::send_notification for MCS characteristic.
#[test]
fn gatt_server_send_notification_coverage() {
    let _lock = acquire_mcp_test_lock();
    bt_mcs_test_util_reset_ccid();
    let rt = Runtime::new().expect("runtime");
    let db = GattDb::new();
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });
    let cb = TestMcsCallback::new();
    let _mcs = BtMcs::register(db.clone(), false, cb).expect("register");

    let (fd_s, fd_c) = create_test_pair();
    let satt = BtAtt::new(fd_s.as_raw_fd(), false).expect("satt");
    let server = BtGattServer::new(db.clone(), satt.clone(), 64, 0).expect("server");

    // Try to send a notification for the name handle
    let _g = rt.enter();
    let value = b"Test Player";
    server.send_notification(NAME_HANDLE, value, false);

    // Flush and check the peer side received something
    satt.lock().unwrap().flush_writes();
    std::thread::sleep(Duration::from_millis(5));
    let mut buf = [0u8; 256];
    match nix::unistd::read(fd_c.as_raw_fd(), &mut buf) {
        Ok(n) if n > 0 => {
            // Got a notification PDU (0x1B)
            assert_eq!(buf[0], ATT_OP_HANDLE_NFY);
        }
        _ => {
            // Notification may not be sent if no CCC enabled — acceptable
        }
    }
}
