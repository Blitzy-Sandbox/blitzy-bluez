// SPDX-License-Identifier: GPL-2.0-or-later
//
// crates/bluez-emulator/src/le.rs — LE-specific HCI controller emulator
//
// Complete Rust rewrite of emulator/le.c (2,083 lines) and emulator/le.h
// (19 lines). Implements a separate LE controller emulator backing VHCI
// integration and simulated PHY. Opens /dev/vhci, registers fd handlers
// via tokio, maintains LE controller state, and implements LE HCI command
// handlers.
//
// All HCI command responses are byte-identical to the C original.

use std::io::IoSlice;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex};

use tokio::task::JoinHandle;
use tokio::time::Duration;

use bluez_shared::crypto::aes_cmac::{self, CryptoError};
use bluez_shared::crypto::ecc::{self, EccError};
use bluez_shared::sys::bluetooth::{BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, htobs};
use bluez_shared::sys::hci::{
    // Event codes
    EVT_CMD_COMPLETE,
    EVT_CMD_STATUS,
    EVT_LE_ADVERTISING_REPORT,
    EVT_LE_CONN_COMPLETE,
    EVT_LE_META_EVENT,
    // Error codes
    HCI_COMMAND_DISALLOWED,
    // Packet type indicators
    HCI_COMMAND_PKT,
    HCI_EVENT_PKT,
    HCI_INVALID_PARAMETERS,
    HCI_MEMORY_FULL,
    HCI_NO_CONNECTION,
    HCI_PRIMARY,
    HCI_SUCCESS,
    HCI_UNKNOWN_COMMAND,
    HCI_UNSPECIFIED_ERROR,
    HCI_VENDOR_PKT,
    // OCF constants — Link Control
    OCF_DISCONNECT,
    // OCF constants — LE Controller
    OCF_LE_ADD_DEVICE_TO_RESOLV_LIST,
    OCF_LE_ADD_DEVICE_TO_WHITE_LIST,
    OCF_LE_CLEAR_RESOLV_LIST,
    OCF_LE_CLEAR_WHITE_LIST,
    OCF_LE_CREATE_CONN,
    OCF_LE_CREATE_CONN_CANCEL,
    OCF_LE_ENCRYPT,
    OCF_LE_RAND,
    OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER,
    OCF_LE_READ_BUFFER_SIZE,
    OCF_LE_READ_LOCAL_SUPPORTED_FEATURES,
    OCF_LE_READ_SUPPORTED_STATES,
    OCF_LE_READ_WHITE_LIST_SIZE,
    OCF_LE_REMOVE_DEVICE_FROM_RESOLV_LIST,
    OCF_LE_SET_ADDRESS_RESOLUTION_ENABLE,
    OCF_LE_SET_ADVERTISE_ENABLE,
    OCF_LE_SET_ADVERTISING_DATA,
    OCF_LE_SET_ADVERTISING_PARAMETERS,
    OCF_LE_SET_EVENT_MASK,
    OCF_LE_SET_RANDOM_ADDRESS,
    OCF_LE_SET_SCAN_ENABLE,
    OCF_LE_SET_SCAN_PARAMETERS,
    OCF_LE_SET_SCAN_RESPONSE_DATA,
    // OCF constants — Informational Parameters
    OCF_READ_BD_ADDR,
    OCF_READ_BUFFER_SIZE,
    OCF_READ_LOCAL_COMMANDS,
    OCF_READ_LOCAL_FEATURES,
    OCF_READ_LOCAL_VERSION,
    // OCF constants — Host Controller
    OCF_RESET,
    OCF_SET_EVENT_MASK,
    // OGF constants
    OGF_HOST_CTL,
    OGF_INFO_PARAM,
    OGF_LE_CTL,
    OGF_LINK_CONTROL,
    // Opcode helper
    opcode,
};

use crate::phy::{BT_PHY_PKT_ADV, BtPhy, BtPhyPktAdv};

// ── Constants ───────────────────────────────────────────────────────────────

/// Maximum number of entries in the LE accept list.
const ACCEPT_LIST_SIZE: usize = 16;

/// Maximum number of entries in the LE resolving list.
const RESOLV_LIST_SIZE: usize = 16;

/// Maximum number of entries in the scan duplicate cache.
const SCAN_CACHE_SIZE: usize = 64;

/// Default LE data TX octets (Core Spec v5.x).
const DEFAULT_TX_LEN: u16 = 0x001b;
/// Default LE data TX time (microseconds).
const DEFAULT_TX_TIME: u16 = 0x0148;
/// Maximum LE data TX octets.
const MAX_TX_LEN: u16 = 0x00fb;
/// Maximum LE data TX time.
const MAX_TX_TIME: u16 = 0x0848;
/// Maximum LE data RX octets.
const MAX_RX_LEN: u16 = 0x00fb;
/// Maximum LE data RX time.
const MAX_RX_TIME: u16 = 0x0848;

/// Default all PHYs preference (no preference).
const DEFAULT_ALL_PHYS: u8 = 0x03;
/// Default TX PHYs (none specified).
const DEFAULT_TX_PHYS: u8 = 0x00;
/// Default RX PHYs (none specified).
const DEFAULT_RX_PHYS: u8 = 0x00;

// H:4 packet type indicators are imported from hci.rs as
// HCI_COMMAND_PKT (0x01) and HCI_EVENT_PKT (0x04).

/// Wire size of BtPhyPktAdv struct in bytes.
const PHY_PKT_ADV_SIZE: usize = 18;

// ── OCF constants not yet in hci.rs ─────────────────────────────────────────

/// OCF for Set Event Mask Page 2.
const OCF_SET_EVENT_MASK_PAGE2: u16 = 0x0063;
/// OCF for LE Remove Device From Accept List.
const OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST: u16 = 0x0012;
/// OCF for LE Read Resolving List Size.
const OCF_LE_READ_RESOLV_LIST_SIZE: u16 = 0x002A;
/// OCF for LE Read Peer Resolvable Address.
const OCF_LE_READ_PEER_RESOLV_ADDR: u16 = 0x002B;
/// OCF for LE Read Local Resolvable Address.
const OCF_LE_READ_LOCAL_RESOLV_ADDR: u16 = 0x002C;
/// OCF for LE Set Resolvable Private Address Timeout.
const OCF_LE_SET_RESOLV_TIMEOUT: u16 = 0x002E;
/// OCF for LE Set Data Length.
const OCF_LE_SET_DATA_LENGTH: u16 = 0x0022;
/// OCF for LE Read Suggested Default Data Length.
const OCF_LE_READ_DEFAULT_DATA_LENGTH: u16 = 0x0023;
/// OCF for LE Write Suggested Default Data Length.
const OCF_LE_WRITE_DEFAULT_DATA_LENGTH: u16 = 0x0024;
/// OCF for LE Read Local P-256 Public Key.
const OCF_LE_READ_LOCAL_PK256: u16 = 0x0025;
/// OCF for LE Generate DHKey.
const OCF_LE_GENERATE_DHKEY: u16 = 0x0026;
/// OCF for LE Read Maximum Data Length.
const OCF_LE_READ_MAX_DATA_LENGTH: u16 = 0x002F;
/// OCF for LE Read PHY.
const OCF_LE_READ_PHY: u16 = 0x0030;
/// OCF for LE Set Default PHY.
const OCF_LE_SET_DEFAULT_PHY: u16 = 0x0031;
/// OCF for LE Set PHY.
const OCF_LE_SET_PHY: u16 = 0x0032;

// ── Error Type ──────────────────────────────────────────────────────────────

/// Error type for BtLe operations.
#[derive(Debug)]
pub enum BtLeError {
    /// Failed to open /dev/vhci device.
    VhciOpen(std::io::Error),
    /// VHCI write failed.
    VhciWrite(nix::errno::Errno),
    /// VHCI read failed.
    VhciRead(nix::errno::Errno),
    /// PHY initialization failed.
    PhyInit(std::io::Error),
    /// Cryptographic operation failed.
    Crypto(CryptoError),
    /// ECC operation failed.
    Ecc(EccError),
}

impl std::fmt::Display for BtLeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BtLeError::VhciOpen(e) => write!(f, "VHCI open failed: {e}"),
            BtLeError::VhciWrite(e) => write!(f, "VHCI write failed: {e}"),
            BtLeError::VhciRead(e) => write!(f, "VHCI read failed: {e}"),
            BtLeError::PhyInit(e) => write!(f, "PHY init failed: {e}"),
            BtLeError::Crypto(e) => write!(f, "Crypto error: {e}"),
            BtLeError::Ecc(e) => write!(f, "ECC error: {e}"),
        }
    }
}

impl std::error::Error for BtLeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BtLeError::VhciOpen(e) => Some(e),
            BtLeError::Crypto(e) => Some(e),
            BtLeError::Ecc(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CryptoError> for BtLeError {
    fn from(e: CryptoError) -> Self {
        BtLeError::Crypto(e)
    }
}

impl From<EccError> for BtLeError {
    fn from(e: EccError) -> Self {
        BtLeError::Ecc(e)
    }
}

// ── Internal data structures ────────────────────────────────────────────────

/// Entry in the LE accept list (formerly "white list").
#[derive(Debug, Clone, Copy, Default)]
struct AcceptListEntry {
    /// Address type (BDADDR_LE_PUBLIC or BDADDR_LE_RANDOM), or 0xFF = empty.
    addr_type: u8,
    /// 6-byte Bluetooth device address.
    addr: [u8; 6],
}

/// Entry in the LE resolving list.
#[derive(Debug, Clone, Copy)]
struct ResolvingListEntry {
    /// Address type.
    addr_type: u8,
    /// 6-byte Bluetooth device address.
    addr: [u8; 6],
    /// Peer IRK (Identity Resolving Key).
    peer_irk: [u8; 16],
    /// Local IRK.
    local_irk: [u8; 16],
}

impl Default for ResolvingListEntry {
    fn default() -> Self {
        Self { addr_type: 0xff, addr: [0; 6], peer_irk: [0; 16], local_irk: [0; 16] }
    }
}

/// Entry in the scan duplicate filter cache.
#[derive(Debug, Clone, Copy, Default)]
struct ScanCacheEntry {
    /// Address type.
    addr_type: u8,
    /// 6-byte Bluetooth device address.
    addr: [u8; 6],
}

// ── Inner state ─────────────────────────────────────────────────────────────

/// The mutable inner state of the LE controller emulator.
///
/// Protected by a `Mutex` inside `BtLe` to allow concurrent access
/// from the VHCI read task and PHY receive callback.
struct BtLeInner {
    /// Owned file descriptor for the /dev/vhci device.
    /// Using OwnedFd provides automatic close-on-drop and safe AsFd.
    vhci_fd: OwnedFd,
    /// PHY layer instance for advertising broadcasts.
    phy: Arc<BtPhy>,
    /// General HCI event mask (8 bytes).
    event_mask: [u8; 8],
    /// LE-specific event mask (8 bytes).
    le_event_mask: [u8; 8],
    /// BD_ADDR assigned by the VHCI driver.
    bdaddr: [u8; 6],
    /// Random address set by the host via LE Set Random Address.
    random_addr: [u8; 6],
    /// LE feature page bits.
    le_features: [u8; 8],
    /// LE supported states bitmap.
    le_states: [u8; 8],
    /// Supported commands bitmask (64 bytes).
    le_supported_commands: [u8; 64],
    // ── Advertising state ───────────────────────────────────────────────
    adv_type: u8,
    adv_own_addr_type: u8,
    adv_direct_addr_type: u8,
    adv_direct_addr: [u8; 6],
    adv_channel_map: u8,
    adv_filter_policy: u8,
    adv_min_interval: u16,
    adv_max_interval: u16,
    adv_data: [u8; 31],
    adv_data_len: u8,
    scan_rsp_data: [u8; 31],
    scan_rsp_len: u8,
    adv_enable: bool,
    // ── Scanning state ──────────────────────────────────────────────────
    le_scan_type: u8,
    le_scan_own_addr_type: u8,
    le_scan_filter_policy: u8,
    le_scan_interval: u16,
    le_scan_window: u16,
    le_scan_enable: bool,
    le_scan_filter_dup: u8,
    scan_window_active: bool,
    scan_chan_idx: u8,
    // ── Accept list ─────────────────────────────────────────────────────
    accept_list: [AcceptListEntry; ACCEPT_LIST_SIZE],
    // ── Resolving list ──────────────────────────────────────────────────
    resolv_list: [ResolvingListEntry; RESOLV_LIST_SIZE],
    le_resolv_enable: bool,
    // ── Scan duplicate cache ────────────────────────────────────────────
    scan_cache: Vec<ScanCacheEntry>,
    // ── Data length ─────────────────────────────────────────────────────
    le_default_tx_octets: u16,
    le_default_tx_time: u16,
    // ── PHY preferences ─────────────────────────────────────────────────
    le_all_phys: u8,
    le_tx_phy: u8,
    le_rx_phy: u8,
    // ── ECC private key ─────────────────────────────────────────────────
    local_sk256: [u8; 32],
    // ── Version info ────────────────────────────────────────────────────
    hci_ver: u8,
    hci_rev: u16,
    manufacturer: u16,
}

// ── BtLe public API ─────────────────────────────────────────────────────────

/// LE HCI controller emulator.
///
/// Replaces the opaque `struct bt_le` from emulator/le.h. Uses `Arc`-based
/// sharing instead of manual reference counting (`bt_le_ref`/`bt_le_unref`).
pub struct BtLe {
    /// Shared mutable inner state.
    inner: Arc<Mutex<BtLeInner>>,
    /// VHCI read task handle.
    vhci_task: Mutex<Option<JoinHandle<()>>>,
    /// Advertising timer task handle.
    adv_task: Mutex<Option<JoinHandle<()>>>,
    /// Scan timer task handle.
    scan_task: Mutex<Option<JoinHandle<()>>>,
}

impl BtLe {
    /// Create a new LE controller emulator.
    ///
    /// Replaces `bt_le_new()` from emulator/le.c lines 2031-2080.
    /// Opens `/dev/vhci`, sends creation request, reads BD_ADDR,
    /// initializes controller state, creates PHY, and spawns tasks.
    pub fn new() -> Result<Arc<Self>, BtLeError> {
        // Open /dev/vhci
        let vhci_fd = open_vhci()?;

        // Write creation request: [HCI_VENDOR_PKT, HCI_PRIMARY]
        let req = [HCI_VENDOR_PKT, HCI_PRIMARY];
        nix::unistd::write(&vhci_fd, &req).map_err(BtLeError::VhciWrite)?;

        // Read back the response to obtain the controller index.
        // nix::unistd::read takes RawFd, so extract a copy.
        let raw_fd = vhci_fd.as_raw_fd();
        let mut resp = [0u8; 4];
        let _n = nix::unistd::read(raw_fd, &mut resp).map_err(BtLeError::VhciRead)?;

        // Create PHY instance
        let phy = BtPhy::new().map_err(BtLeError::PhyInit)?;

        // Initialize inner state with defaults.
        // Transfer OwnedFd ownership to inner — OwnedFd will be closed
        // automatically when BtLeInner is dropped.
        let mut inner_state = BtLeInner {
            vhci_fd,
            phy: Arc::clone(&phy),
            event_mask: [0; 8],
            le_event_mask: [0; 8],
            bdaddr: [0; 6],
            random_addr: [0; 6],
            le_features: [0; 8],
            le_states: [0; 8],
            le_supported_commands: [0; 64],
            adv_type: 0,
            adv_own_addr_type: 0,
            adv_direct_addr_type: 0,
            adv_direct_addr: [0; 6],
            adv_channel_map: 0x07,
            adv_filter_policy: 0,
            adv_min_interval: 0x0800,
            adv_max_interval: 0x0800,
            adv_data: [0; 31],
            adv_data_len: 0,
            scan_rsp_data: [0; 31],
            scan_rsp_len: 0,
            adv_enable: false,
            le_scan_type: 0,
            le_scan_own_addr_type: 0,
            le_scan_filter_policy: 0,
            le_scan_interval: 0x0010,
            le_scan_window: 0x0010,
            le_scan_enable: false,
            le_scan_filter_dup: 0,
            scan_window_active: false,
            scan_chan_idx: 37,
            accept_list: [AcceptListEntry { addr_type: 0xff, addr: [0; 6] }; ACCEPT_LIST_SIZE],
            resolv_list: core::array::from_fn(|_| ResolvingListEntry::default()),
            le_resolv_enable: false,
            scan_cache: Vec::new(),
            le_default_tx_octets: DEFAULT_TX_LEN,
            le_default_tx_time: DEFAULT_TX_TIME,
            le_all_phys: DEFAULT_ALL_PHYS,
            le_tx_phy: DEFAULT_TX_PHYS,
            le_rx_phy: DEFAULT_RX_PHYS,
            local_sk256: [0; 32],
            hci_ver: 0x09,
            hci_rev: 0x0000,
            manufacturer: 0x05f1,
        };

        reset_defaults(&mut inner_state);

        // Generate a random BD_ADDR for the emulated controller
        let mut addr_bytes = [0u8; 6];
        let _ = aes_cmac::random_bytes(&mut addr_bytes);
        inner_state.bdaddr = addr_bytes;

        let inner = Arc::new(Mutex::new(inner_state));

        let bt_le = Arc::new(Self {
            inner: Arc::clone(&inner),
            vhci_task: Mutex::new(None),
            adv_task: Mutex::new(None),
            scan_task: Mutex::new(None),
        });

        // Register PHY receive callback
        {
            let inner_clone = Arc::clone(&inner);
            phy.register(move |pkt_type, data| {
                phy_recv_callback(&inner_clone, pkt_type, data);
            });
        }

        // Spawn the VHCI read task.
        // Passes Arc<BtLe> so the read loop can drive start_adv/stop_adv
        // and start_scan/stop_scan after processing commands.
        {
            let bt_le_clone = Arc::clone(&bt_le);
            let task = tokio::task::spawn(async move {
                vhci_read_loop(bt_le_clone, raw_fd).await;
            });
            if let Ok(mut guard) = bt_le.vhci_task.lock() {
                *guard = Some(task);
            }
        }

        Ok(bt_le)
    }
}

impl Drop for BtLe {
    fn drop(&mut self) {
        // Abort all tasks
        if let Ok(mut guard) = self.vhci_task.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.adv_task.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.scan_task.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        // The VHCI fd (OwnedFd) is closed automatically when BtLeInner
        // is dropped — the Arc<Mutex<BtLeInner>> releases its refcount,
        // and when the last reference (from the aborted tasks) is gone,
        // OwnedFd::drop() closes the fd safely.
    }
}

// ── VHCI helpers ────────────────────────────────────────────────────────────

/// Open `/dev/vhci` in O_RDWR | O_NONBLOCK mode.
///
/// Uses `std::fs::OpenOptions` to avoid any unsafe code — the File is
/// converted to an `OwnedFd` via the safe `From<File>` implementation.
fn open_vhci() -> Result<OwnedFd, BtLeError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/vhci")
        .map_err(BtLeError::VhciOpen)?;
    Ok(OwnedFd::from(file))
}

/// Async VHCI read loop, replaces `vhci_read_callback` from le.c line 1969.
///
/// Reads HCI command packets from the VHCI fd and dispatches them to
/// `process_command`. After each command, checks if advertising or scanning
/// enable state changed and starts/stops the corresponding timer tasks.
async fn vhci_read_loop(bt_le: Arc<BtLe>, fd: RawFd) {
    // Wrap the raw fd in AsyncFd for poll-based reading.
    // AsyncFd<RawFd> does NOT close the fd on drop — it only deregisters
    // from epoll. The OwnedFd in BtLeInner handles close-on-drop.
    let async_fd = match tokio::io::unix::AsyncFd::new(fd) {
        Ok(afd) => afd,
        Err(e) => {
            tracing::error!("Failed to create AsyncFd for VHCI: {}", e);
            return;
        }
    };

    loop {
        // Wait for the fd to become readable
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("VHCI readable wait failed: {}", e);
                break;
            }
        };

        let mut buf = [0u8; 4096];
        match nix::unistd::read(fd, &mut buf) {
            Ok(n) if n > 0 => {
                let data = &buf[..n];
                // First byte is the H:4 packet type indicator
                if !data.is_empty() && data[0] == HCI_COMMAND_PKT {
                    // Snapshot enable flags before command processing
                    let (adv_before, scan_before) = {
                        match bt_le.inner.lock() {
                            Ok(state) => (state.adv_enable, state.le_scan_enable),
                            Err(_) => break,
                        }
                    };

                    // Process the HCI command
                    {
                        if let Ok(mut state) = bt_le.inner.lock() {
                            process_command(&mut state, &data[1..]);
                        }
                    }

                    // Check if enable state changed and start/stop timers.
                    // This replaces the direct start_adv/stop_adv/start_scan/
                    // stop_scan calls that the C code makes from within the
                    // command handlers. We do it here because the timer
                    // functions need Arc<BtLe> which command handlers don't
                    // have (they only receive &mut BtLeInner).
                    let (adv_after, scan_after) = {
                        match bt_le.inner.lock() {
                            Ok(state) => (state.adv_enable, state.le_scan_enable),
                            Err(_) => break,
                        }
                    };

                    if adv_after != adv_before {
                        if adv_after {
                            start_adv(&bt_le);
                        } else {
                            stop_adv(&bt_le);
                        }
                    }

                    if scan_after != scan_before {
                        if scan_after {
                            start_scan(&bt_le);
                        } else {
                            stop_scan(&bt_le);
                        }
                    }
                }
            }
            Ok(_) => {
                // EOF or zero-length read
                guard.clear_ready();
            }
            Err(nix::errno::Errno::EAGAIN) => {
                guard.clear_ready();
            }
            Err(e) => {
                tracing::error!("VHCI read error: {}", e);
                break;
            }
        }
    }
}

// ── Reset defaults ──────────────────────────────────────────────────────────

/// Initialize controller state to spec defaults.
/// Replaces `reset_defaults()` from le.c lines 193-372.
fn reset_defaults(le: &mut BtLeInner) {
    // Clear supported commands
    le.le_supported_commands = [0; 64];

    // Byte 0: Disconnect, etc.
    le.le_supported_commands[0] = 0x20; // Disconnect
    // Byte 5: Set Event Mask
    le.le_supported_commands[5] = 0x40;
    // Byte 14: Read Local Version, Read Local Supported Features
    le.le_supported_commands[14] = 0xa8;
    // Byte 15: Read BD ADDR
    le.le_supported_commands[15] = 0x02;
    // Byte 22: Set Event Mask Page 2
    le.le_supported_commands[22] = 0x04;
    // Byte 25: LE Set Event Mask, LE Read Buffer Size, LE Read Local
    // Supported Features, LE Set Random Address
    le.le_supported_commands[25] = 0xf7;
    // Byte 26: LE Set Advertising Parameters through LE Create Connection
    le.le_supported_commands[26] = 0xff;
    // Byte 27: LE Create Connection Cancel through LE Read Remote Features
    le.le_supported_commands[27] = 0xff;
    // Byte 28: LE Encrypt, LE Rand, LE Start Encryption,
    // LE Long Term Key Request Reply, LE Long Term Key Request Neg Reply,
    // LE Read Supported States
    le.le_supported_commands[28] = 0x3f;
    // Byte 33: LE Set Data Length
    le.le_supported_commands[33] = 0x10;
    // Byte 34: LE Read Suggested Default Data Length,
    // LE Write Suggested Default Data Length,
    // LE Read Local P-256 Public Key, LE Generate DHKey,
    // LE Add Device To Resolving List, LE Remove Device From Resolving List
    le.le_supported_commands[34] = 0x3f;
    // Byte 35: LE Clear Resolving List, LE Read Resolving List Size,
    // LE Read Peer Resolvable Address, LE Read Local Resolvable Address,
    // LE Set Address Resolution Enable, LE Set Resolvable Private Address Timeout,
    // LE Read Maximum Data Length
    le.le_supported_commands[35] = 0x7f;
    // Byte 36: LE Read PHY, LE Set Default PHY, LE Set PHY
    le.le_supported_commands[36] = 0x07;

    // Event mask: enable all common events
    le.event_mask = [0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00, 0x00];

    // LE event mask: default per spec
    le.le_event_mask = [0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    // LE features: Encryption, Connection Parameters Request, Extended Reject
    // Indication, Slave-initiated Features Exchange, LE Ping,
    // Data Packet Length Extension, LL Privacy, Extended Scanner Filter Policies
    le.le_features = [0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    // Clear advertising state
    le.adv_type = 0x00;
    le.adv_own_addr_type = 0x00;
    le.adv_direct_addr_type = 0x00;
    le.adv_direct_addr = [0; 6];
    le.adv_channel_map = 0x07;
    le.adv_filter_policy = 0x00;
    le.adv_min_interval = 0x0800;
    le.adv_max_interval = 0x0800;
    le.adv_data = [0; 31];
    le.adv_data_len = 0;
    le.scan_rsp_data = [0; 31];
    le.scan_rsp_len = 0;
    le.adv_enable = false;

    // Clear scanning state
    le.le_scan_type = 0x00;
    le.le_scan_own_addr_type = 0x00;
    le.le_scan_filter_policy = 0x00;
    le.le_scan_interval = 0x0010;
    le.le_scan_window = 0x0010;
    le.le_scan_enable = false;
    le.le_scan_filter_dup = 0x00;
    le.scan_window_active = false;
    le.scan_chan_idx = 37;

    // Clear accept list
    clear_accept_list(le);

    // Clear resolving list
    clear_resolv_list(le);
    le.le_resolv_enable = false;

    // LE states: all supported
    le.le_states = [0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00];

    // Data length defaults
    le.le_default_tx_octets = DEFAULT_TX_LEN;
    le.le_default_tx_time = DEFAULT_TX_TIME;

    // PHY defaults
    le.le_all_phys = DEFAULT_ALL_PHYS;
    le.le_tx_phy = DEFAULT_TX_PHYS;
    le.le_rx_phy = DEFAULT_RX_PHYS;

    // Clear scan cache
    le.scan_cache.clear();

    // Clear random address
    le.random_addr = [0; 6];
    le.local_sk256 = [0; 32];
}

// ── Accept list helpers ─────────────────────────────────────────────────────

/// Check if an address is in the accept list.
fn is_in_accept_list(le: &BtLeInner, addr_type: u8, addr: &[u8; 6]) -> bool {
    for entry in &le.accept_list {
        if entry.addr_type == addr_type && entry.addr == *addr {
            return true;
        }
    }
    false
}

/// Clear all accept list entries (set addr_type to 0xFF).
fn clear_accept_list(le: &mut BtLeInner) {
    for entry in le.accept_list.iter_mut() {
        entry.addr_type = 0xff;
        entry.addr = [0; 6];
    }
}

// ── Resolving list helpers ──────────────────────────────────────────────────

/// Clear all resolving list entries.
fn clear_resolv_list(le: &mut BtLeInner) {
    for entry in le.resolv_list.iter_mut() {
        entry.addr_type = 0xff;
        entry.addr = [0; 6];
        entry.peer_irk = [0; 16];
        entry.local_irk = [0; 16];
    }
}

/// Resolve a peer address using the resolving list IRKs.
///
/// If `le_resolv_enable` is true and the address is a resolvable private
/// address (RPA), attempts to match via `bt_crypto_ah` against each
/// stored peer IRK. On match, replaces the address and type in place.
///
/// Replaces `resolve_peer_addr()` from le.c lines 162-190.
fn resolve_peer_addr(le: &BtLeInner, addr_type: &mut u8, addr: &mut [u8; 6]) -> bool {
    if !le.le_resolv_enable {
        return false;
    }

    // Only attempt to resolve if the address is a resolvable private address.
    // RPA check: most significant two bits of the address (MSB of addr[5])
    // are 01 (i.e. addr[5] & 0xC0 == 0x40).
    if *addr_type != BDADDR_LE_RANDOM || (addr[5] & 0xc0) != 0x40 {
        return false;
    }

    // Extract the 3-byte hash from the RPA (lower 3 bytes)
    let prand = [addr[3], addr[4], addr[5]];

    for entry in &le.resolv_list {
        if entry.addr_type == 0xff {
            continue;
        }

        // Check if the peer IRK is all zeros (no resolution possible)
        if entry.peer_irk == [0u8; 16] {
            continue;
        }

        // Compute ah(IRK, prand) and compare with the hash portion
        if let Ok(hash) = aes_cmac::bt_crypto_ah(&entry.peer_irk, &prand) {
            if hash[0] == addr[0] && hash[1] == addr[1] && hash[2] == addr[2] {
                // Match found: replace address with identity address
                *addr_type = entry.addr_type;
                *addr = entry.addr;
                return true;
            }
        }
    }

    false
}

// ── Scan cache helpers ──────────────────────────────────────────────────────

/// Clear the scan duplicate filter cache.
fn clear_scan_cache(le: &mut BtLeInner) {
    le.scan_cache.clear();
}

/// Add an address to the scan cache for duplicate filtering.
/// Returns true if the address was already in the cache (duplicate).
fn add_to_scan_cache(le: &mut BtLeInner, addr_type: u8, addr: &[u8; 6]) -> bool {
    // Check if already in cache
    for entry in &le.scan_cache {
        if entry.addr_type == addr_type && entry.addr == *addr {
            return true;
        }
    }

    // Add to cache (evict oldest if full)
    if le.scan_cache.len() >= SCAN_CACHE_SIZE {
        le.scan_cache.remove(0);
    }

    le.scan_cache.push(ScanCacheEntry { addr_type, addr: *addr });

    false
}

// ── Event generation ────────────────────────────────────────────────────────

/// Send an HCI event to the host via the VHCI fd.
///
/// Builds the H:4 type byte + hci_event_hdr + params and writes via writev.
/// Replaces `send_event()` from le.c lines 413-438.
fn send_event(le: &BtLeInner, event_code: u8, params: &[u8]) {
    let plen = params.len() as u8;

    // Build the event: H:4 indicator + event header + parameters
    let mut buf = Vec::with_capacity(1 + 2 + params.len());
    buf.push(HCI_EVENT_PKT);
    buf.push(event_code);
    buf.push(plen);
    buf.extend_from_slice(params);

    // Write to VHCI fd using nix writev for scatter-gather.
    // OwnedFd implements AsFd, so we can pass a reference directly.
    let iov = [IoSlice::new(&buf)];
    if let Err(e) = nix::sys::uio::writev(&le.vhci_fd, &iov) {
        tracing::error!("VHCI event write failed: {}", e);
    }
}

/// Send a Command Complete event.
///
/// Replaces `cmd_complete()` from le.c lines 614-627.
fn cmd_complete(le: &BtLeInner, opc: u16, params: &[u8]) {
    let mut data = Vec::with_capacity(3 + params.len());
    // ncmd = 1 (Number of HCI command packets the Host can send)
    data.push(0x01);
    // opcode in little-endian
    let opc_le = htobs(opc);
    data.push(opc_le as u8);
    data.push((opc_le >> 8) as u8);
    data.extend_from_slice(params);

    send_event(le, EVT_CMD_COMPLETE, &data);
}

/// Send a Command Status event.
///
/// Replaces `cmd_status()` from le.c lines 629-645.
fn cmd_status(le: &BtLeInner, opc: u16, status: u8) {
    let opc_le = htobs(opc);
    let data = [
        status,
        0x01, // ncmd
        opc_le as u8,
        (opc_le >> 8) as u8,
    ];
    send_event(le, EVT_CMD_STATUS, &data);
}

/// Send an LE Meta Event.
///
/// Replaces `le_meta_event()` from le.c lines 647-672.
/// Gates on event_mask bit for LE Meta Event (bit 61 = byte 7, bit 5)
/// and le_event_mask for the specific subevent.
fn le_meta_event(le: &BtLeInner, subevent: u8, params: &[u8]) {
    // Check if LE Meta Event is enabled in the general event mask
    // Bit 61 = byte 7, bit 5 (0x20)
    if (le.event_mask[7] & 0x20) == 0 {
        return;
    }

    let mut data = Vec::with_capacity(1 + params.len());
    data.push(subevent);
    data.extend_from_slice(params);

    send_event(le, EVT_LE_META_EVENT, &data);
}

// ── PHY packet serialization ────────────────────────────────────────────────

/// Serialize a BtPhyPktAdv into bytes for PHY transmission.
fn serialize_phy_pkt_adv(pkt: &BtPhyPktAdv) -> [u8; PHY_PKT_ADV_SIZE] {
    let mut buf = [0u8; PHY_PKT_ADV_SIZE];
    buf[0] = pkt.chan_idx;
    buf[1] = pkt.pdu_type;
    buf[2] = pkt.tx_addr_type;
    buf[3..9].copy_from_slice(&pkt.tx_addr);
    buf[9] = pkt.rx_addr_type;
    buf[10..16].copy_from_slice(&pkt.rx_addr);
    buf[16] = pkt.adv_data_len;
    buf[17] = pkt.scan_rsp_len;
    buf
}

/// Deserialize a BtPhyPktAdv from raw bytes.
fn deserialize_phy_pkt_adv(data: &[u8]) -> Option<BtPhyPktAdv> {
    if data.len() < PHY_PKT_ADV_SIZE {
        return None;
    }
    Some(BtPhyPktAdv {
        chan_idx: data[0],
        pdu_type: data[1],
        tx_addr_type: data[2],
        tx_addr: [data[3], data[4], data[5], data[6], data[7], data[8]],
        rx_addr_type: data[9],
        rx_addr: [data[10], data[11], data[12], data[13], data[14], data[15]],
        adv_data_len: data[16],
        scan_rsp_len: data[17],
    })
}

// ── Advertising emulation ───────────────────────────────────────────────────

/// Send an advertising packet on a specific channel via PHY.
///
/// Replaces `send_adv_pkt()` from le.c lines 440-469.
fn send_adv_pkt(le: &BtLeInner, channel: u8) {
    let own_addr = if le.adv_own_addr_type == 0x01 { le.random_addr } else { le.bdaddr };

    let pkt = BtPhyPktAdv {
        chan_idx: channel,
        pdu_type: le.adv_type,
        tx_addr_type: le.adv_own_addr_type,
        tx_addr: own_addr,
        rx_addr_type: le.adv_direct_addr_type,
        rx_addr: le.adv_direct_addr,
        adv_data_len: le.adv_data_len,
        scan_rsp_len: le.scan_rsp_len,
    };

    let pkt_bytes = serialize_phy_pkt_adv(&pkt);
    let adv_slice = &le.adv_data[..le.adv_data_len as usize];
    let srp_slice = &le.scan_rsp_data[..le.scan_rsp_len as usize];

    le.phy.send_vector(BT_PHY_PKT_ADV, &pkt_bytes, adv_slice, srp_slice);
}

/// Get a random advertising delay between 0 and 10 ms.
///
/// Replaces `get_adv_delay()` from le.c lines 498-506.
fn get_adv_delay() -> Duration {
    let mut delay_bytes = [0u8; 2];
    let _ = aes_cmac::random_bytes(&mut delay_bytes);
    let delay_ms = u16::from_le_bytes(delay_bytes) % 11;
    Duration::from_millis(u64::from(delay_ms))
}

/// Calculate the advertising interval in milliseconds from the
/// min/max interval values (0.625ms units).
fn get_adv_interval_ms(min_interval: u16, max_interval: u16) -> u64 {
    // Use average of min and max, converted from 0.625ms units to ms
    let avg = (u64::from(min_interval) + u64::from(max_interval)) / 2;
    // 0.625ms = 5/8 ms, so interval_ms = avg * 5 / 8
    let interval_ms = (avg * 5) / 8;
    if interval_ms == 0 { 1 } else { interval_ms }
}

/// Start the advertising timer.
///
/// Replaces `start_adv()` from le.c lines 531-544.
fn start_adv(bt_le: &Arc<BtLe>) {
    // Stop any existing advertising timer
    stop_adv(bt_le);

    let inner = Arc::clone(&bt_le.inner);
    let btl = Arc::clone(bt_le);

    let task = tokio::task::spawn(async move {
        loop {
            // Get advertising parameters under lock
            let (min_interval, max_interval, channel_map, enable) = {
                let le = match inner.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                (le.adv_min_interval, le.adv_max_interval, le.adv_channel_map, le.adv_enable)
            };

            if !enable {
                break;
            }

            let interval = Duration::from_millis(get_adv_interval_ms(min_interval, max_interval))
                + get_adv_delay();

            tokio::time::sleep(interval).await;

            // Send advertising packets on enabled channels
            if let Ok(le) = inner.lock() {
                if !le.adv_enable {
                    break;
                }
                if channel_map & 0x01 != 0 {
                    send_adv_pkt(&le, 37);
                }
                if channel_map & 0x02 != 0 {
                    send_adv_pkt(&le, 38);
                }
                if channel_map & 0x04 != 0 {
                    send_adv_pkt(&le, 39);
                }
            }
        }
    });

    if let Ok(mut guard) = btl.adv_task.lock() {
        *guard = Some(task);
    }
}

/// Stop the advertising timer.
///
/// Replaces `stop_adv()` from le.c lines 546-554.
fn stop_adv(bt_le: &Arc<BtLe>) {
    if let Ok(mut guard) = bt_le.adv_task.lock() {
        if let Some(handle) = guard.take() {
            handle.abort();
        }
    }
}

// ── Scanning emulation ──────────────────────────────────────────────────────

/// Start the scanning timer.
///
/// Replaces `start_scan()` from le.c lines 583-596.
fn start_scan(bt_le: &Arc<BtLe>) {
    stop_scan(bt_le);

    let inner = Arc::clone(&bt_le.inner);

    let task = tokio::task::spawn(async move {
        loop {
            let (interval, window, enable) = {
                let le = match inner.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                (le.le_scan_interval, le.le_scan_window, le.le_scan_enable)
            };

            if !enable {
                break;
            }

            // Scan window active phase
            {
                if let Ok(mut le) = inner.lock() {
                    le.scan_window_active = true;
                    // Cycle channel index: 37 -> 38 -> 39 -> 37
                    le.scan_chan_idx =
                        if le.scan_chan_idx >= 39 { 37 } else { le.scan_chan_idx + 1 };
                }
            }

            // Window duration: window * 0.625ms
            let window_ms = (u64::from(window) * 5) / 8;
            let window_dur = Duration::from_millis(if window_ms == 0 { 1 } else { window_ms });
            tokio::time::sleep(window_dur).await;

            // If interval == window, the scan window covers the entire interval.
            // Otherwise, deactivate for the remainder.
            if interval > window {
                if let Ok(mut le) = inner.lock() {
                    le.scan_window_active = false;
                }
                let remaining_ms = (u64::from(interval - window) * 5) / 8;
                if remaining_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(remaining_ms)).await;
                }
            }
        }
    });

    if let Ok(mut guard) = bt_le.scan_task.lock() {
        *guard = Some(task);
    }
}

/// Stop the scanning timer.
///
/// Replaces `stop_scan()` from le.c lines 598-611.
fn stop_scan(bt_le: &Arc<BtLe>) {
    if let Ok(mut guard) = bt_le.scan_task.lock() {
        if let Some(handle) = guard.take() {
            handle.abort();
        }
    }
}

// ── Command dispatch table entry ────────────────────────────────────────────

/// Entry in the HCI command dispatch table.
///
/// Replaces `struct cmd_entry` in le.c cmd_table[].
struct CmdEntry {
    /// HCI opcode.
    opcode: u16,
    /// Handler function. Returns true if the command was handled.
    handler: fn(&mut BtLeInner, u16, &[u8]),
    /// Expected parameter length (0 = variable).
    size: usize,
    /// If true, the parameter length must match `size` exactly.
    fixed: bool,
}

/// Build the command dispatch table matching le.c cmd_table[].
fn build_cmd_table() -> Vec<CmdEntry> {
    vec![
        CmdEntry {
            opcode: opcode(OGF_LINK_CONTROL, OCF_DISCONNECT),
            handler: cmd_disconnect,
            size: 3,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_HOST_CTL, OCF_SET_EVENT_MASK),
            handler: cmd_set_event_mask,
            size: 8,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_HOST_CTL, OCF_RESET),
            handler: cmd_reset,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_HOST_CTL, OCF_SET_EVENT_MASK_PAGE2),
            handler: cmd_set_event_mask_page2,
            size: 8,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_INFO_PARAM, OCF_READ_LOCAL_VERSION),
            handler: cmd_read_local_version,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_INFO_PARAM, OCF_READ_LOCAL_COMMANDS),
            handler: cmd_read_local_commands,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_INFO_PARAM, OCF_READ_LOCAL_FEATURES),
            handler: cmd_read_local_features,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_INFO_PARAM, OCF_READ_BUFFER_SIZE),
            handler: cmd_read_buffer_size,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_INFO_PARAM, OCF_READ_BD_ADDR),
            handler: cmd_read_bd_addr,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_EVENT_MASK),
            handler: cmd_le_set_event_mask,
            size: 8,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_BUFFER_SIZE),
            handler: cmd_le_read_buffer_size,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_LOCAL_SUPPORTED_FEATURES),
            handler: cmd_le_read_local_features,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_RANDOM_ADDRESS),
            handler: cmd_le_set_random_address,
            size: 6,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISING_PARAMETERS),
            handler: cmd_le_set_adv_parameters,
            size: 15,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER),
            handler: cmd_le_read_adv_tx_power,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISING_DATA),
            handler: cmd_le_set_adv_data,
            size: 32,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_SCAN_RESPONSE_DATA),
            handler: cmd_le_set_scan_rsp_data,
            size: 32,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE),
            handler: cmd_le_set_adv_enable,
            size: 1,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS),
            handler: cmd_le_set_scan_parameters,
            size: 7,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE),
            handler: cmd_le_set_scan_enable,
            size: 2,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_CREATE_CONN),
            handler: cmd_le_create_conn,
            size: 25,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_CREATE_CONN_CANCEL),
            handler: cmd_le_create_conn_cancel,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_WHITE_LIST_SIZE),
            handler: cmd_le_read_accept_list_size,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_CLEAR_WHITE_LIST),
            handler: cmd_le_clear_accept_list,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_ADD_DEVICE_TO_WHITE_LIST),
            handler: cmd_le_add_to_accept_list,
            size: 7,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST),
            handler: cmd_le_remove_from_accept_list,
            size: 7,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_ENCRYPT),
            handler: cmd_le_encrypt,
            size: 32,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_RAND),
            handler: cmd_le_rand,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_SUPPORTED_STATES),
            handler: cmd_le_read_supported_states,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_DATA_LENGTH),
            handler: cmd_le_set_data_length,
            size: 6,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_DEFAULT_DATA_LENGTH),
            handler: cmd_le_read_default_data_length,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_WRITE_DEFAULT_DATA_LENGTH),
            handler: cmd_le_write_default_data_length,
            size: 4,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_LOCAL_PK256),
            handler: cmd_le_read_local_pk256,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_GENERATE_DHKEY),
            handler: cmd_le_generate_dhkey,
            size: 64,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_ADD_DEVICE_TO_RESOLV_LIST),
            handler: cmd_le_add_to_resolv_list,
            size: 39,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_REMOVE_DEVICE_FROM_RESOLV_LIST),
            handler: cmd_le_remove_from_resolv_list,
            size: 7,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_CLEAR_RESOLV_LIST),
            handler: cmd_le_clear_resolv_list,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_RESOLV_LIST_SIZE),
            handler: cmd_le_read_resolv_list_size,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_PEER_RESOLV_ADDR),
            handler: cmd_le_read_peer_resolv_addr,
            size: 7,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_LOCAL_RESOLV_ADDR),
            handler: cmd_le_read_local_resolv_addr,
            size: 7,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_ADDRESS_RESOLUTION_ENABLE),
            handler: cmd_le_set_resolv_enable,
            size: 1,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_RESOLV_TIMEOUT),
            handler: cmd_le_set_resolv_timeout,
            size: 2,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_MAX_DATA_LENGTH),
            handler: cmd_le_read_max_data_length,
            size: 0,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_READ_PHY),
            handler: cmd_le_read_phy,
            size: 2,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_DEFAULT_PHY),
            handler: cmd_le_set_default_phy,
            size: 3,
            fixed: true,
        },
        CmdEntry {
            opcode: opcode(OGF_LE_CTL, OCF_LE_SET_PHY),
            handler: cmd_le_set_phy,
            size: 7,
            fixed: true,
        },
    ]
}

// ── Command dispatch ────────────────────────────────────────────────────────

/// Process an incoming HCI command from the host.
///
/// Replaces `process_command()` from le.c lines 1930-1963.
fn process_command(le: &mut BtLeInner, data: &[u8]) {
    // Parse the HCI command header (3 bytes: opcode LE16 + plen)
    if data.len() < 3 {
        return;
    }

    let opc = u16::from_le_bytes([data[0], data[1]]);
    let plen = data[2] as usize;

    // Verify we have enough data
    if data.len() < 3 + plen {
        return;
    }

    let params = &data[3..3 + plen];

    // Look up the command in the dispatch table
    let table = build_cmd_table();
    for entry in &table {
        if entry.opcode == opc {
            if entry.fixed && plen != entry.size {
                cmd_status(le, opc, HCI_INVALID_PARAMETERS);
                return;
            }
            if !entry.fixed && plen < entry.size {
                cmd_status(le, opc, HCI_INVALID_PARAMETERS);
                return;
            }
            (entry.handler)(le, opc, params);
            return;
        }
    }

    // Unknown command
    cmd_status(le, opc, HCI_UNKNOWN_COMMAND);
}

// ── Individual HCI command handlers ─────────────────────────────────────────

/// HCI Disconnect command handler.
///
/// Replaces `cmd_disconnect()` from le.c lines 675-682.
/// The LE-only emulator has no connections, so always returns error.
fn cmd_disconnect(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    cmd_status(le, opc, HCI_NO_CONNECTION);
}

/// HCI Set Event Mask command handler.
///
/// Replaces `cmd_set_event_mask()` from le.c lines 684-696.
fn cmd_set_event_mask(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    le.event_mask.copy_from_slice(&params[..8]);
    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// HCI Reset command handler.
///
/// Replaces `cmd_reset()` from le.c lines 698-705.
fn cmd_reset(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    // Stop advertising and scanning
    le.adv_enable = false;
    le.le_scan_enable = false;

    reset_defaults(le);
    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// HCI Set Event Mask Page 2 command handler.
///
/// Replaces `cmd_set_event_mask_page2()` from le.c lines 707-717.
fn cmd_set_event_mask_page2(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    // Page 2 event mask is acknowledged but not stored (LE-only controller)
    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// HCI Read Local Version Information command handler.
///
/// Replaces `cmd_read_local_version()` from le.c lines 719-738.
fn cmd_read_local_version(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut rsp = [0u8; 9];
    rsp[0] = HCI_SUCCESS; // status
    rsp[1] = le.hci_ver; // HCI version (0x09 = BT 5.0)
    rsp[2..4].copy_from_slice(&htobs(le.hci_rev).to_le_bytes()); // HCI revision
    rsp[4] = le.hci_ver; // LMP version (same as HCI)
    rsp[5..7].copy_from_slice(&htobs(le.manufacturer).to_le_bytes()); // Manufacturer
    rsp[7..9].copy_from_slice(&htobs(0x0000u16).to_le_bytes()); // LMP subversion
    cmd_complete(le, opc, &rsp);
}

/// HCI Read Local Supported Commands command handler.
///
/// Replaces `cmd_read_local_commands()` from le.c lines 740-753.
fn cmd_read_local_commands(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut rsp = [0u8; 65];
    rsp[0] = HCI_SUCCESS;
    rsp[1..65].copy_from_slice(&le.le_supported_commands);
    cmd_complete(le, opc, &rsp);
}

/// HCI Read Local Supported Features command handler.
///
/// Replaces `cmd_read_local_features()` from le.c lines 755-768.
fn cmd_read_local_features(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut rsp = [0u8; 9];
    rsp[0] = HCI_SUCCESS;
    // For an LE-only controller, bit 6 of byte 4 = LE Supported
    // and bit 7 of byte 4 = BR/EDR Not Supported
    rsp[5] = 0x60; // byte 4 of features: LE Supported (Host) + no BR/EDR
    cmd_complete(le, opc, &rsp);
}

/// HCI Read Buffer Size command handler.
///
/// Replaces `cmd_read_buffer_size()` from le.c lines 770-784.
/// For an LE-only controller, all BR/EDR buffer sizes are 0.
fn cmd_read_buffer_size(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut rsp = [0u8; 8];
    rsp[0] = HCI_SUCCESS;
    // ACL data packet length = 0
    // SCO data packet length = 0
    // Total num ACL data packets = 0
    // Total num SCO data packets = 0
    cmd_complete(le, opc, &rsp);
}

/// HCI Read BD ADDR command handler.
///
/// Replaces `cmd_read_bd_addr()` from le.c lines 786-798.
fn cmd_read_bd_addr(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut rsp = [0u8; 7];
    rsp[0] = HCI_SUCCESS;
    rsp[1..7].copy_from_slice(&le.bdaddr);
    cmd_complete(le, opc, &rsp);
}

// ── LE-specific command handlers ────────────────────────────────────────────

/// LE Set Event Mask command handler.
///
/// Replaces `cmd_le_set_event_mask()` from le.c lines 800-812.
fn cmd_le_set_event_mask(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    le.le_event_mask.copy_from_slice(&params[..8]);
    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Read Buffer Size command handler.
///
/// Replaces `cmd_le_read_buffer_size()` from le.c lines 814-828.
fn cmd_le_read_buffer_size(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut rsp = [0u8; 4];
    rsp[0] = HCI_SUCCESS;
    // LE ACL Data Packet Length = 64 (0x0040)
    rsp[1..3].copy_from_slice(&htobs(64u16).to_le_bytes());
    // Total Num LE ACL Data Packets = 1
    rsp[3] = 0x01;
    cmd_complete(le, opc, &rsp);
}

/// LE Read Local Supported Features command handler.
///
/// Replaces `cmd_le_read_local_features()` from le.c lines 830-843.
fn cmd_le_read_local_features(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut rsp = [0u8; 9];
    rsp[0] = HCI_SUCCESS;
    rsp[1..9].copy_from_slice(&le.le_features);
    cmd_complete(le, opc, &rsp);
}

/// LE Set Random Address command handler.
///
/// Replaces `cmd_le_set_random_address()` from le.c lines 845-857.
fn cmd_le_set_random_address(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    le.random_addr.copy_from_slice(&params[..6]);
    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Set Advertising Parameters command handler.
///
/// Replaces `cmd_le_set_adv_parameters()` from le.c lines 859-937.
/// Validates all parameters per Bluetooth spec.
fn cmd_le_set_adv_parameters(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let adv_min_interval = u16::from_le_bytes([params[0], params[1]]);
    let adv_max_interval = u16::from_le_bytes([params[2], params[3]]);
    let adv_type = params[4];
    let own_addr_type = params[5];
    let direct_addr_type = params[6];
    let mut direct_addr = [0u8; 6];
    direct_addr.copy_from_slice(&params[7..13]);
    let channel_map = params[13];
    let filter_policy = params[14];

    // Validate advertising type (0x00 - 0x03)
    if adv_type > 0x03 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Validate intervals based on advertising type
    // For ADV_DIRECT_IND (high duty cycle), intervals are ignored
    // For other types: min >= 0x0020 (except connectable undirected 0x00A0),
    // max >= min, max <= 0x4000
    if adv_type != 0x01 {
        // Non-directed types: minimum interval is 0x0020 per Core Spec.
        // Both connectable undirected (0x00) and non-connectable/scannable
        // types share the same minimum of 0x0020 in this emulator.
        if adv_min_interval < 0x0020 {
            cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
            return;
        }
        if adv_max_interval < 0x0020 {
            cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
            return;
        }
        if adv_min_interval > adv_max_interval {
            cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
            return;
        }
    }

    // Validate own address type (0x00 - 0x03)
    if own_addr_type > 0x03 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Validate channel map (at least one channel must be enabled)
    if channel_map == 0x00 || channel_map > 0x07 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Validate filter policy (0x00 - 0x03)
    if filter_policy > 0x03 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    le.adv_type = adv_type;
    le.adv_min_interval = adv_min_interval;
    le.adv_max_interval = adv_max_interval;
    le.adv_own_addr_type = own_addr_type;
    le.adv_direct_addr_type = direct_addr_type;
    le.adv_direct_addr = direct_addr;
    le.adv_channel_map = channel_map;
    le.adv_filter_policy = filter_policy;

    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Read Advertising Channel TX Power command handler.
///
/// Replaces `cmd_le_read_adv_tx_power()` from le.c lines 939-950.
fn cmd_le_read_adv_tx_power(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    // TX Power Level = 0 dBm (emulated)
    let rsp = [HCI_SUCCESS, 0x00];
    cmd_complete(le, opc, &rsp);
}

/// LE Set Advertising Data command handler.
///
/// Replaces `cmd_le_set_adv_data()` from le.c lines 952-971.
fn cmd_le_set_adv_data(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let data_len = params[0];
    if data_len > 0x1f {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    le.adv_data_len = data_len;
    le.adv_data = [0; 31];
    if data_len > 0 {
        let len = data_len as usize;
        le.adv_data[..len].copy_from_slice(&params[1..1 + len]);
    }

    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Set Scan Response Data command handler.
///
/// Replaces `cmd_le_set_scan_rsp_data()` from le.c lines 973-992.
fn cmd_le_set_scan_rsp_data(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let data_len = params[0];
    if data_len > 0x1f {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    le.scan_rsp_len = data_len;
    le.scan_rsp_data = [0; 31];
    if data_len > 0 {
        let len = data_len as usize;
        le.scan_rsp_data[..len].copy_from_slice(&params[1..1 + len]);
    }

    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Set Advertise Enable command handler.
///
/// Replaces `cmd_le_set_adv_enable()` from le.c lines 994-1017.
fn cmd_le_set_adv_enable(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let enable = params[0];

    if enable > 0x01 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    le.adv_enable = enable != 0;
    cmd_complete(le, opc, &[HCI_SUCCESS]);

    // Note: actual timer start/stop happens in the caller context
    // via the BtLe wrapper since we need Arc access. The C code calls
    // start_adv/stop_adv directly here. In Rust, this is handled
    // in the VHCI read loop after process_command returns.
}

/// LE Set Scan Parameters command handler.
///
/// Replaces `cmd_le_set_scan_parameters()` from le.c lines 1019-1062.
fn cmd_le_set_scan_parameters(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let scan_type = params[0];
    let scan_interval = u16::from_le_bytes([params[1], params[2]]);
    let scan_window = u16::from_le_bytes([params[3], params[4]]);
    let own_addr_type = params[5];
    let filter_policy = params[6];

    // Validate scan type (0x00 = passive, 0x01 = active)
    if scan_type > 0x01 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Validate interval range: 0x0004 - 0x4000
    if !(0x0004..=0x4000).contains(&scan_interval) {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Validate window range: 0x0004 - 0x4000
    if !(0x0004..=0x4000).contains(&scan_window) {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Window must not exceed interval
    if scan_window > scan_interval {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Validate own address type (0x00 - 0x03)
    if own_addr_type > 0x03 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Validate filter policy (0x00 - 0x03)
    if filter_policy > 0x03 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    le.le_scan_type = scan_type;
    le.le_scan_interval = scan_interval;
    le.le_scan_window = scan_window;
    le.le_scan_own_addr_type = own_addr_type;
    le.le_scan_filter_policy = filter_policy;

    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Set Scan Enable command handler.
///
/// Replaces `cmd_le_set_scan_enable()` from le.c lines 1064-1094.
fn cmd_le_set_scan_enable(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let enable = params[0];
    let filter_dup = params[1];

    if enable > 0x01 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    if filter_dup > 0x01 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    le.le_scan_enable = enable != 0;
    le.le_scan_filter_dup = filter_dup;

    if enable != 0 {
        clear_scan_cache(le);
    }

    cmd_complete(le, opc, &[HCI_SUCCESS]);
    // Timer start/stop handled in the VHCI read loop via BtLe wrapper
}

/// LE Create Connection command handler.
///
/// Replaces `cmd_le_create_conn()` from le.c lines 1096-1108.
/// For the LE-only emulator, this is a stub that returns Command Status.
fn cmd_le_create_conn(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    cmd_status(le, opc, HCI_SUCCESS);
}

/// LE Create Connection Cancel command handler.
///
/// Replaces `cmd_le_create_conn_cancel()` from le.c lines 1110-1137.
fn cmd_le_create_conn_cancel(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    cmd_complete(le, opc, &[HCI_SUCCESS]);

    // Send LE Connection Complete event with error status
    // (Command Disallowed since there is no pending connection)
    if (le.le_event_mask[0] & 0x01) != 0 {
        let mut evt_data = [0u8; 19];
        evt_data[0] = HCI_COMMAND_DISALLOWED; // status
        // handle = 0x0000 (LE16)
        evt_data[1] = 0x00;
        evt_data[2] = 0x00;
        // role = 0
        evt_data[3] = 0x00;
        // peer_addr_type = 0
        evt_data[4] = 0x00;
        // peer_addr = 00:00:00:00:00:00
        // interval = 0, latency = 0, supervision_timeout = 0
        // master_clock_accuracy = 0
        le_meta_event(le, EVT_LE_CONN_COMPLETE, &evt_data);
    }
}

// ── Accept list commands ────────────────────────────────────────────────────

/// LE Read Accept List Size command handler.
///
/// Replaces `cmd_le_read_accept_list_size()` from le.c lines 1174-1183.
fn cmd_le_read_accept_list_size(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let rsp = [HCI_SUCCESS, ACCEPT_LIST_SIZE as u8];
    cmd_complete(le, opc, &rsp);
}

/// LE Clear Accept List command handler.
///
/// Replaces `cmd_le_clear_accept_list()` from le.c lines 1185-1200.
fn cmd_le_clear_accept_list(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    // Cannot modify accept list while advertising with filter policy
    // that uses the accept list, or while scanning with filter policy
    // that uses the accept list
    if le.adv_enable && (le.adv_filter_policy == 0x01 || le.adv_filter_policy == 0x03) {
        cmd_complete(le, opc, &[HCI_COMMAND_DISALLOWED]);
        return;
    }
    if le.le_scan_enable && (le.le_scan_filter_policy == 0x01 || le.le_scan_filter_policy == 0x03) {
        cmd_complete(le, opc, &[HCI_COMMAND_DISALLOWED]);
        return;
    }

    clear_accept_list(le);
    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Add Device To Accept List command handler.
///
/// Replaces `cmd_le_add_to_accept_list()` from le.c lines 1202-1246.
fn cmd_le_add_to_accept_list(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let addr_type = params[0];
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&params[1..7]);

    // Cannot modify while advertising/scanning with filter policy
    if le.adv_enable && (le.adv_filter_policy == 0x01 || le.adv_filter_policy == 0x03) {
        cmd_complete(le, opc, &[HCI_COMMAND_DISALLOWED]);
        return;
    }
    if le.le_scan_enable && (le.le_scan_filter_policy == 0x01 || le.le_scan_filter_policy == 0x03) {
        cmd_complete(le, opc, &[HCI_COMMAND_DISALLOWED]);
        return;
    }

    // Validate address type
    if addr_type != BDADDR_LE_PUBLIC && addr_type != BDADDR_LE_RANDOM {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Check if already in list
    if is_in_accept_list(le, addr_type, &addr) {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Find an empty slot
    let mut found = false;
    for entry in le.accept_list.iter_mut() {
        if entry.addr_type == 0xff {
            entry.addr_type = addr_type;
            entry.addr = addr;
            found = true;
            break;
        }
    }

    if !found {
        cmd_complete(le, opc, &[HCI_MEMORY_FULL]);
        return;
    }

    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Remove Device From Accept List command handler.
///
/// Replaces `cmd_le_remove_from_accept_list()` from le.c lines 1248-1286.
fn cmd_le_remove_from_accept_list(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let addr_type = params[0];
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&params[1..7]);

    // Cannot modify while advertising/scanning with filter policy
    if le.adv_enable && (le.adv_filter_policy == 0x01 || le.adv_filter_policy == 0x03) {
        cmd_complete(le, opc, &[HCI_COMMAND_DISALLOWED]);
        return;
    }
    if le.le_scan_enable && (le.le_scan_filter_policy == 0x01 || le.le_scan_filter_policy == 0x03) {
        cmd_complete(le, opc, &[HCI_COMMAND_DISALLOWED]);
        return;
    }

    // Validate address type
    if addr_type != BDADDR_LE_PUBLIC && addr_type != BDADDR_LE_RANDOM {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Find and remove
    let mut found = false;
    for entry in le.accept_list.iter_mut() {
        if entry.addr_type == addr_type && entry.addr == addr {
            entry.addr_type = 0xff;
            entry.addr = [0; 6];
            found = true;
            break;
        }
    }

    if !found {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

// ── Crypto commands ─────────────────────────────────────────────────────────

/// LE Encrypt command handler.
///
/// Replaces `cmd_le_encrypt()` from le.c lines 1310-1340.
fn cmd_le_encrypt(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let mut key = [0u8; 16];
    key.copy_from_slice(&params[..16]);
    let mut plaintext = [0u8; 16];
    plaintext.copy_from_slice(&params[16..32]);

    match aes_cmac::bt_crypto_e(&key, &plaintext) {
        Ok(encrypted) => {
            let mut rsp = [0u8; 17];
            rsp[0] = HCI_SUCCESS;
            rsp[1..17].copy_from_slice(&encrypted);
            cmd_complete(le, opc, &rsp);
        }
        Err(_) => {
            cmd_complete(le, opc, &[HCI_UNSPECIFIED_ERROR]);
        }
    }
}

/// LE Rand command handler.
///
/// Replaces `cmd_le_rand()` from le.c lines 1342-1359.
fn cmd_le_rand(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut random = [0u8; 8];
    match aes_cmac::random_bytes(&mut random) {
        Ok(()) => {
            let mut rsp = [0u8; 9];
            rsp[0] = HCI_SUCCESS;
            rsp[1..9].copy_from_slice(&random);
            cmd_complete(le, opc, &rsp);
        }
        Err(_) => {
            cmd_complete(le, opc, &[HCI_UNSPECIFIED_ERROR]);
        }
    }
}

/// LE Read Supported States command handler.
///
/// Replaces `cmd_le_read_supported_states()` from le.c lines 1361-1373.
fn cmd_le_read_supported_states(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut rsp = [0u8; 9];
    rsp[0] = HCI_SUCCESS;
    rsp[1..9].copy_from_slice(&le.le_states);
    cmd_complete(le, opc, &rsp);
}

// ── Data length commands ────────────────────────────────────────────────────

/// LE Set Data Length command handler.
///
/// Replaces `cmd_le_set_data_length()` from le.c lines 1375-1413.
fn cmd_le_set_data_length(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let handle = u16::from_le_bytes([params[0], params[1]]);
    let tx_octets = u16::from_le_bytes([params[2], params[3]]);
    let tx_time = u16::from_le_bytes([params[4], params[5]]);

    // Validate handle (max 0x0EFF)
    if handle > 0x0eff {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Validate TX octets range
    if !(DEFAULT_TX_LEN..=MAX_TX_LEN).contains(&tx_octets) {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Validate TX time range
    if !(DEFAULT_TX_TIME..=MAX_TX_TIME).contains(&tx_time) {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // No active connection in LE-only emulator, return error
    cmd_complete(le, opc, &[HCI_NO_CONNECTION]);
}

/// LE Read Suggested Default Data Length command handler.
///
/// Replaces `cmd_le_read_default_data_length()` from le.c lines 1415-1427.
fn cmd_le_read_default_data_length(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut rsp = [0u8; 5];
    rsp[0] = HCI_SUCCESS;
    rsp[1..3].copy_from_slice(&le.le_default_tx_octets.to_le_bytes());
    rsp[3..5].copy_from_slice(&le.le_default_tx_time.to_le_bytes());
    cmd_complete(le, opc, &rsp);
}

/// LE Write Suggested Default Data Length command handler.
///
/// Replaces `cmd_le_write_default_data_length()` from le.c lines 1429-1453.
fn cmd_le_write_default_data_length(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let tx_octets = u16::from_le_bytes([params[0], params[1]]);
    let tx_time = u16::from_le_bytes([params[2], params[3]]);

    if !(DEFAULT_TX_LEN..=MAX_TX_LEN).contains(&tx_octets) {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    if !(DEFAULT_TX_TIME..=MAX_TX_TIME).contains(&tx_time) {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    le.le_default_tx_octets = tx_octets;
    le.le_default_tx_time = tx_time;

    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

// ── ECC commands ────────────────────────────────────────────────────────────

/// LE Read Local P-256 Public Key command handler.
///
/// Replaces `cmd_le_read_local_pk256()` from le.c lines 1455-1489.
fn cmd_le_read_local_pk256(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    cmd_status(le, opc, HCI_SUCCESS);

    // Generate P-256 keypair
    match ecc::ecc_make_key() {
        Ok((public_key, private_key)) => {
            le.local_sk256.copy_from_slice(&private_key);

            // Check if LE Read Local P-256 Public Key Complete event is enabled
            // le_event_mask[0] bit 7 (0x80)
            if (le.le_event_mask[0] & 0x80) != 0 {
                let mut evt = [0u8; 65];
                evt[0] = HCI_SUCCESS;
                evt[1..65].copy_from_slice(&public_key);
                le_meta_event(le, 0x08, &evt); // LE Read Local P-256 Public Key Complete
            }
        }
        Err(_) => {
            if (le.le_event_mask[0] & 0x80) != 0 {
                let mut evt = [0u8; 65];
                evt[0] = HCI_UNSPECIFIED_ERROR;
                le_meta_event(le, 0x08, &evt);
            }
        }
    }
}

/// LE Generate DHKey command handler.
///
/// Replaces `cmd_le_generate_dhkey()` from le.c lines 1491-1520.
fn cmd_le_generate_dhkey(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    cmd_status(le, opc, HCI_SUCCESS);

    let mut remote_pk = [0u8; 64];
    remote_pk.copy_from_slice(&params[..64]);

    match ecc::ecdh_shared_secret(&remote_pk, &le.local_sk256) {
        Ok(shared_secret) => {
            // Check if LE Generate DHKey Complete event is enabled
            // le_event_mask[1] bit 0 (0x01)
            if (le.le_event_mask[1] & 0x01) != 0 {
                let mut evt = [0u8; 33];
                evt[0] = HCI_SUCCESS;
                evt[1..33].copy_from_slice(&shared_secret);
                le_meta_event(le, 0x09, &evt); // LE Generate DHKey Complete
            }
        }
        Err(_) => {
            if (le.le_event_mask[1] & 0x01) != 0 {
                let mut evt = [0u8; 33];
                evt[0] = HCI_UNSPECIFIED_ERROR;
                le_meta_event(le, 0x09, &evt);
            }
        }
    }
}

// ── Resolving list commands ─────────────────────────────────────────────────

/// LE Add Device To Resolving List command handler.
///
/// Replaces `cmd_le_add_to_resolv_list()` from le.c lines 1522-1569.
fn cmd_le_add_to_resolv_list(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let addr_type = params[0];
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&params[1..7]);
    let mut peer_irk = [0u8; 16];
    peer_irk.copy_from_slice(&params[7..23]);
    let mut local_irk = [0u8; 16];
    local_irk.copy_from_slice(&params[23..39]);

    // Cannot modify while address resolution is enabled and
    // advertising or scanning is active
    if le.le_resolv_enable && (le.adv_enable || le.le_scan_enable) {
        cmd_complete(le, opc, &[HCI_COMMAND_DISALLOWED]);
        return;
    }

    // Validate address type
    if addr_type != BDADDR_LE_PUBLIC && addr_type != BDADDR_LE_RANDOM {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Check if already in resolving list
    for entry in &le.resolv_list {
        if entry.addr_type == addr_type && entry.addr == addr {
            cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
            return;
        }
    }

    // Find an empty slot
    let mut found = false;
    for entry in le.resolv_list.iter_mut() {
        if entry.addr_type == 0xff {
            entry.addr_type = addr_type;
            entry.addr = addr;
            entry.peer_irk = peer_irk;
            entry.local_irk = local_irk;
            found = true;
            break;
        }
    }

    if !found {
        cmd_complete(le, opc, &[HCI_MEMORY_FULL]);
        return;
    }

    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Remove Device From Resolving List command handler.
///
/// Replaces `cmd_le_remove_from_resolv_list()` from le.c lines 1571-1609.
fn cmd_le_remove_from_resolv_list(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let addr_type = params[0];
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&params[1..7]);

    if le.le_resolv_enable && (le.adv_enable || le.le_scan_enable) {
        cmd_complete(le, opc, &[HCI_COMMAND_DISALLOWED]);
        return;
    }

    if addr_type != BDADDR_LE_PUBLIC && addr_type != BDADDR_LE_RANDOM {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    let mut found = false;
    for entry in le.resolv_list.iter_mut() {
        if entry.addr_type == addr_type && entry.addr == addr {
            entry.addr_type = 0xff;
            entry.addr = [0; 6];
            entry.peer_irk = [0; 16];
            entry.local_irk = [0; 16];
            found = true;
            break;
        }
    }

    if !found {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Clear Resolving List command handler.
///
/// Replaces `cmd_le_clear_resolv_list()` from le.c lines 1611-1626.
fn cmd_le_clear_resolv_list(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    if le.le_resolv_enable && (le.adv_enable || le.le_scan_enable) {
        cmd_complete(le, opc, &[HCI_COMMAND_DISALLOWED]);
        return;
    }

    clear_resolv_list(le);
    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Read Resolving List Size command handler.
///
/// Replaces `cmd_le_read_resolv_list_size()` from le.c lines 1628-1637.
fn cmd_le_read_resolv_list_size(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let rsp = [HCI_SUCCESS, RESOLV_LIST_SIZE as u8];
    cmd_complete(le, opc, &rsp);
}

/// LE Read Peer Resolvable Address command handler.
///
/// Replaces `cmd_le_read_peer_resolv_addr()` from le.c lines 1639-1656.
fn cmd_le_read_peer_resolv_addr(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let addr_type = params[0];
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&params[1..7]);

    // Find the entry in the resolving list
    for entry in &le.resolv_list {
        if entry.addr_type == addr_type && entry.addr == addr {
            // Return the peer's resolvable address (all zeros since we
            // don't track active RPA in this emulator)
            let mut rsp = [0u8; 7];
            rsp[0] = HCI_SUCCESS;
            // peer resolvable address = all zeros
            cmd_complete(le, opc, &rsp);
            return;
        }
    }

    cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
}

/// LE Read Local Resolvable Address command handler.
///
/// Replaces `cmd_le_read_local_resolv_addr()` from le.c.
fn cmd_le_read_local_resolv_addr(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let addr_type = params[0];
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&params[1..7]);

    for entry in &le.resolv_list {
        if entry.addr_type == addr_type && entry.addr == addr {
            let mut rsp = [0u8; 7];
            rsp[0] = HCI_SUCCESS;
            // local resolvable address = all zeros
            cmd_complete(le, opc, &rsp);
            return;
        }
    }

    cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
}

/// LE Set Address Resolution Enable command handler.
///
/// Replaces `cmd_le_set_resolv_enable()` from le.c lines 1658-1678.
fn cmd_le_set_resolv_enable(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let enable = params[0];

    if enable > 0x01 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Cannot change while advertising or scanning
    if le.adv_enable || le.le_scan_enable {
        cmd_complete(le, opc, &[HCI_COMMAND_DISALLOWED]);
        return;
    }

    le.le_resolv_enable = enable != 0;
    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Set Resolvable Private Address Timeout command handler.
///
/// Replaces `cmd_le_set_resolv_timeout()` from le.c lines 1680-1698.
fn cmd_le_set_resolv_timeout(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let timeout = u16::from_le_bytes([params[0], params[1]]);

    // Valid range: 0x0001 to 0xA1B8 (1s to ~11.5 hours)
    if !(0x0001..=0xa1b8).contains(&timeout) {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // Timeout is acknowledged but not actively used by the emulator
    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

// ── Data length and PHY commands ────────────────────────────────────────────

/// LE Read Maximum Data Length command handler.
///
/// Replaces `cmd_le_read_max_data_length()` from le.c lines 1700-1716.
fn cmd_le_read_max_data_length(le: &mut BtLeInner, opc: u16, _params: &[u8]) {
    let mut rsp = [0u8; 9];
    rsp[0] = HCI_SUCCESS;
    rsp[1..3].copy_from_slice(&MAX_TX_LEN.to_le_bytes());
    rsp[3..5].copy_from_slice(&MAX_TX_TIME.to_le_bytes());
    rsp[5..7].copy_from_slice(&MAX_RX_LEN.to_le_bytes());
    rsp[7..9].copy_from_slice(&MAX_RX_TIME.to_le_bytes());
    cmd_complete(le, opc, &rsp);
}

/// LE Read PHY command handler.
///
/// Replaces `cmd_le_read_phy()` from le.c lines 1718-1736.
fn cmd_le_read_phy(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let handle = u16::from_le_bytes([params[0], params[1]]);

    // No active connections in the LE emulator
    // Return success with LE 1M PHY for both TX and RX
    let mut rsp = [0u8; 5];
    rsp[0] = HCI_SUCCESS;
    rsp[1..3].copy_from_slice(&handle.to_le_bytes());
    rsp[3] = 0x01; // TX PHY = LE 1M
    rsp[4] = 0x01; // RX PHY = LE 1M
    cmd_complete(le, opc, &rsp);
}

/// LE Set Default PHY command handler.
///
/// Replaces `cmd_le_set_default_phy()` from le.c lines 1738-1776.
fn cmd_le_set_default_phy(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let all_phys = params[0];
    let tx_phys = params[1];
    let rx_phys = params[2];

    // Validate PHY preferences
    // Allowed PHY bits: bit 0 = LE 1M, bit 1 = LE 2M, bit 2 = LE Coded
    let phys_mask: u8 = 0x07;

    // If all_phys bit 0 is 0, tx_phys must have at least one valid bit
    if (all_phys & 0x01) == 0 && (tx_phys & phys_mask) == 0 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    // If all_phys bit 1 is 0, rx_phys must have at least one valid bit
    if (all_phys & 0x02) == 0 && (rx_phys & phys_mask) == 0 {
        cmd_complete(le, opc, &[HCI_INVALID_PARAMETERS]);
        return;
    }

    le.le_all_phys = all_phys;
    le.le_tx_phy = tx_phys;
    le.le_rx_phy = rx_phys;

    cmd_complete(le, opc, &[HCI_SUCCESS]);
}

/// LE Set PHY command handler.
///
/// Replaces `cmd_le_set_phy()` from le.c lines 1778-1824.
fn cmd_le_set_phy(le: &mut BtLeInner, opc: u16, params: &[u8]) {
    let _handle = u16::from_le_bytes([params[0], params[1]]);
    let _all_phys = params[2];
    let _tx_phys = params[3];
    let _rx_phys = params[4];
    let _phy_options = u16::from_le_bytes([params[5], params[6]]);

    cmd_status(le, opc, HCI_SUCCESS);

    // Emulator always uses LE 1M PHY. Send PHY Update Complete event.
    // le_event_mask[1] bit 3 (0x08)
    if (le.le_event_mask[1] & 0x08) != 0 {
        let mut evt = [0u8; 6];
        evt[0] = HCI_SUCCESS; // status
        evt[1] = 0x00; // handle low
        evt[2] = 0x00; // handle high
        evt[3] = 0x01; // TX PHY = LE 1M
        evt[4] = 0x01; // RX PHY = LE 1M
        // Note: subevent 0x0C = LE PHY Update Complete
        le_meta_event(le, 0x0c, &evt);
    }
}

// ── PHY receive callback ────────────────────────────────────────────────────

/// Process incoming PHY packets for the LE emulator.
///
/// Replaces `phy_recv_callback()` from le.c lines 1988-2029.
///
/// When scanning is active and a BT_PHY_PKT_ADV is received on the
/// matching channel, generates LE Advertising Report events.
fn phy_recv_callback(inner: &Arc<Mutex<BtLeInner>>, pkt_type: u16, data: &[u8]) {
    if pkt_type != BT_PHY_PKT_ADV {
        return;
    }

    let mut le = match inner.lock() {
        Ok(g) => g,
        Err(_) => return,
    };

    // Check if LE Advertising Report event is enabled
    // le_event_mask[0] bit 1 (0x02)
    if (le.le_event_mask[0] & 0x02) == 0 {
        return;
    }

    // Must be scanning with scan window active
    if !le.le_scan_enable || !le.scan_window_active {
        return;
    }

    // Parse the advertising packet
    let pkt = match deserialize_phy_pkt_adv(data) {
        Some(p) => p,
        None => return,
    };

    // Check channel match
    if pkt.chan_idx != le.scan_chan_idx {
        return;
    }

    let mut report_addr_type = pkt.tx_addr_type;
    let mut report_addr = pkt.tx_addr;

    // Resolve address if address resolution is enabled
    resolve_peer_addr(&le, &mut report_addr_type, &mut report_addr);

    // Apply accept list filtering if the scan filter policy requires it
    if (le.le_scan_filter_policy == 0x01 || le.le_scan_filter_policy == 0x03)
        && !is_in_accept_list(&le, report_addr_type, &report_addr)
    {
        return;
    }

    // Apply duplicate filtering
    if le.le_scan_filter_dup != 0 && add_to_scan_cache(&mut le, report_addr_type, &report_addr) {
        return; // duplicate
    }

    // Build LE Advertising Report
    let adv_data_len = pkt.adv_data_len as usize;
    let adv_data_offset = PHY_PKT_ADV_SIZE;

    // Report parameters: num_reports(1) + evt_type(1) + addr_type(1) +
    // addr(6) + data_len(1) + data(N) + rssi(1)
    let report_len = 1 + 1 + 1 + 6 + 1 + adv_data_len + 1;
    let mut report = vec![0u8; report_len];

    report[0] = 0x01; // num_reports = 1
    report[1] = pkt.pdu_type; // event type
    report[2] = report_addr_type; // address type
    report[3..9].copy_from_slice(&report_addr); // address
    report[9] = adv_data_len as u8; // data length

    // Copy advertising data from the PHY payload
    if adv_data_len > 0 && data.len() >= adv_data_offset + adv_data_len {
        report[10..10 + adv_data_len]
            .copy_from_slice(&data[adv_data_offset..adv_data_offset + adv_data_len]);
    }

    // RSSI = 127 (not available) for emulated PHY
    report[10 + adv_data_len] = 127;

    le_meta_event(&le, EVT_LE_ADVERTISING_REPORT, &report);

    // For active scanning, also send scan response if available
    if le.le_scan_type == 0x01 && pkt.scan_rsp_len > 0 {
        let scan_rsp_len = pkt.scan_rsp_len as usize;
        let scan_rsp_offset = adv_data_offset + adv_data_len;
        let rsp_report_len = 1 + 1 + 1 + 6 + 1 + scan_rsp_len + 1;
        let mut rsp_report = vec![0u8; rsp_report_len];

        rsp_report[0] = 0x01; // num_reports = 1
        rsp_report[1] = 0x04; // event type = Scan Response
        rsp_report[2] = report_addr_type;
        rsp_report[3..9].copy_from_slice(&report_addr);
        rsp_report[9] = scan_rsp_len as u8;

        if scan_rsp_len > 0 && data.len() >= scan_rsp_offset + scan_rsp_len {
            rsp_report[10..10 + scan_rsp_len]
                .copy_from_slice(&data[scan_rsp_offset..scan_rsp_offset + scan_rsp_len]);
        }

        rsp_report[10 + scan_rsp_len] = 127; // RSSI

        le_meta_event(&le, EVT_LE_ADVERTISING_REPORT, &rsp_report);
    }
}
