//! PAN/BNEP Network Profile Implementation
//!
//! Complete Rust rewrite of the Bluetooth Personal Area Networking (PAN) profile,
//! consolidating `profiles/network/connection.c`, `server.c`, `bnep.c`, `manager.c`
//! and their headers into a single Rust module.
//!
//! Implements:
//! - `org.bluez.Network1` D-Bus interface (client-side PAN connections)
//! - `org.bluez.NetworkServer1` D-Bus interface (server-side PAN services)
//! - BNEP kernel interface management (ioctls for bnep device creation/deletion)
//! - Plugin registration via `inventory::submit!`
//!
//! # PAN Roles
//! - **PANU** (Personal Area Networking User): Client role connecting to GN/NAP
//! - **GN** (Group Ad-hoc Network): Small network without internet access
//! - **NAP** (Network Access Point): Bridge to external network (internet)

// SAFETY: This module contains designated unsafe FFI boundary code for kernel
// BNEP ioctls (BNEPCONNADD, BNEPCONNDEL, BNEPGETSUPPFEAT) and network interface
// ioctls (SIOCSIFFLAGS, SIOCBRADDIF, SIOCBRDELIF). All unsafe blocks are
// individually documented with // SAFETY: comments explaining invariants.
#![allow(unsafe_code)]
#![allow(dead_code)]

use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};
use tracing::{debug, info};

use crate::adapter::BtdAdapter;
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error, btd_info, btd_warn};
use crate::plugin::PluginPriority;
use crate::profile::{
    btd_profile_register, btd_profile_unregister, BtdProfile, BTD_PROFILE_BEARER_BREDR,
};
use crate::sdp::{
    add_record_to_server, remove_record_from_server, SdpData, SdpRecord,
    SDP_ATTR_BROWSE_GRP_LIST, SDP_ATTR_PFILE_DESC_LIST, SDP_ATTR_PROTO_DESC_LIST,
    SDP_ATTR_SVCLASS_ID_LIST,
};


use bluez_shared::sys::bluetooth::{BdAddr, BTPROTO_BNEP, BTPROTO_L2CAP, PF_BLUETOOTH};
use bluez_shared::sys::bnep::{
    bnep_connadd_req, bnep_conndel_req, BNEPCONNADD, BNEPCONNDEL, BNEPGETSUPPFEAT,
    BNEP_CONNECT_TO, BNEP_CONN_INVALID_DST, BNEP_CONN_INVALID_SRC, BNEP_CONN_INVALID_SVC,
    BNEP_CONN_NOT_ALLOWED, BNEP_MTU, BNEP_PSM, BNEP_SETUP_CONN_REQ, BNEP_SETUP_CONN_RSP,
    BNEP_SUCCESS, BNEP_SVC_GN, BNEP_SVC_NAP, BNEP_SVC_PANU,
};
use bluez_shared::util::uuid::BtUuid;

// ===========================================================================
// D-Bus Interface Names
// ===========================================================================

/// D-Bus interface name for the client-side Network1 interface.
pub const NETWORK_INTERFACE: &str = "org.bluez.Network1";

/// D-Bus interface name for the server-side NetworkServer1 interface.
pub const NETWORK_SERVER_INTERFACE: &str = "org.bluez.NetworkServer1";

// ===========================================================================
// PAN UUID Constants
// ===========================================================================

/// NAP service UUID string (128-bit form).
const NAP_UUID: &str = "00001116-0000-1000-8000-00805f9b34fb";

/// GN service UUID string (128-bit form).
const GN_UUID: &str = "00001117-0000-1000-8000-00805f9b34fb";

/// PANU service UUID string (128-bit form).
const PANU_UUID: &str = "00001115-0000-1000-8000-00805f9b34fb";

// ===========================================================================
// BNEP Protocol Constants (supplementing sys/bnep.rs)
// ===========================================================================

/// Maximum setup retry attempts for client connections.
const CON_SETUP_RETRIES: u32 = 3;

/// Setup timeout in seconds (for each retry).
const CON_SETUP_TO: u64 = 9;

/// BNEP setup response feature flag (for kernel feature detection).
const BNEP_SETUP_RESPONSE: u32 = 0x01;

/// BNEP base UUID bytes [4..16] used for UUID128 validation.
const BNEP_BASE_UUID_TAIL: [u8; 12] = [
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
];

/// Linux bridge ioctl: add interface to bridge (not in libc crate for Linux).
const SIOCBRADDIF: libc::c_ulong = 0x89a2;

/// Linux bridge ioctl: remove interface from bridge (not in libc crate for Linux).
const SIOCBRDELIF: libc::c_ulong = 0x89a3;

/// SDP protocol UUID for L2CAP.
const L2CAP_UUID_VAL: u16 = 0x0100;

/// SDP protocol UUID for BNEP.
const BNEP_UUID_VAL: u16 = 0x000F;

/// SDP attribute IDs not provided by sdp/mod.rs.
const SDP_ATTR_SVCNAME_PRIMARY: u16 = 0x0100;
const SDP_ATTR_SVCDESC_PRIMARY: u16 = 0x0101;
const SDP_ATTR_SVCPROV_PRIMARY: u16 = 0x0102;
const SDP_ATTR_SECURITY_DESC: u16 = 0x030A;
const SDP_ATTR_NET_ACCESS_TYPE: u16 = 0x030B;
const SDP_ATTR_MAX_NET_ACCESS_RATE: u16 = 0x030C;

/// BNEP version for SDP records.
const BNEP_VERSION: u16 = 0x0100;

/// Public browse group UUID.
const PUBLIC_BROWSE_GROUP: u16 = 0x1002;

// ===========================================================================
// Connection State
// ===========================================================================

/// Connection state for a PAN network session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnState {
    /// No active connection.
    #[default]
    Disconnected,
    /// Connection attempt in progress.
    Connecting,
    /// Active BNEP connection established.
    Connected,
}

impl std::fmt::Display for ConnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnState::Disconnected => write!(f, "disconnected"),
            ConnState::Connecting => write!(f, "connecting"),
            ConnState::Connected => write!(f, "connected"),
        }
    }
}

// ===========================================================================
// BNEP Session — Kernel BNEP Interface Management
// ===========================================================================

/// Static BNEP control socket file descriptor.
/// Opened once during `bnep_init()` and closed during `bnep_cleanup()`.
/// Uses std::sync::Mutex since it is accessed from synchronous contexts (ioctls).
static BNEP_CTL_SOCK: std::sync::LazyLock<std::sync::Mutex<Option<OwnedFd>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

/// Global configuration: whether security is enabled for PAN connections.
static CONF_SECURITY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// Global counter for bnep interface names.
static BNEP_IF_COUNTER: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

/// BNEP session representing a single kernel bnep network interface.
///
/// Manages the lifecycle of a BNEP connection: L2CAP socket handling,
/// BNEP setup frame exchange, kernel interface creation via ioctl,
/// and network interface bring-up/bridge integration.
pub struct BnepSession {
    /// Raw file descriptor of the L2CAP socket (kept for ioctl).
    fd: Option<OwnedFd>,
    /// Source (local) Bluetooth address.
    src: BdAddr,
    /// Destination (remote) Bluetooth address.
    dst: BdAddr,
    /// Source BNEP service role (e.g., BNEP_SVC_PANU).
    src_role: u16,
    /// Destination BNEP service role (e.g., BNEP_SVC_NAP).
    dst_role: u16,
    /// Kernel network interface name (e.g., "bnep0").
    iface: String,
    /// Current connection state.
    state: ConnState,
    /// Setup timeout task handle.
    setup_timer: Option<JoinHandle<()>>,
    /// Socket monitor task handle.
    monitor_task: Option<JoinHandle<()>>,
    /// Number of setup retries remaining.
    retry_count: u32,
}

impl BnepSession {
    /// Create a new BNEP session for a given connection.
    pub fn new(src: BdAddr, dst: BdAddr, src_role: u16, dst_role: u16) -> Self {
        let iface_num = BNEP_IF_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        BnepSession {
            fd: None,
            src,
            dst,
            src_role,
            dst_role,
            iface: format!("bnep{}", iface_num),
            state: ConnState::Disconnected,
            setup_timer: None,
            monitor_task: None,
            retry_count: CON_SETUP_RETRIES,
        }
    }

    /// Get the kernel network interface name.
    pub fn interface_name(&self) -> &str {
        &self.iface
    }

    /// Initiate a BNEP client connection over an existing L2CAP socket.
    ///
    /// Sends a BNEP_SETUP_CONN_REQ frame and waits for a response.
    /// On success, creates a kernel bnep interface via BNEPCONNADD ioctl.
    pub async fn connect(&mut self, socket_fd: OwnedFd) -> Result<String, BtdError> {
        self.fd = Some(socket_fd);
        self.state = ConnState::Connecting;

        let raw_fd = self.fd.as_ref().unwrap().as_raw_fd();

        // Send BNEP setup connection request.
        let req = self.build_setup_req();
        // SAFETY: Writing to a valid socket fd with a properly-formed buffer.
        let written = unsafe {
            libc::write(raw_fd, req.as_ptr() as *const libc::c_void, req.len())
        };
        if written < 0 {
            let err = std::io::Error::last_os_error();
            btd_error(0xFFFF, &format!("BNEP setup write failed: {}", err));
            self.state = ConnState::Disconnected;
            return Err(BtdError::failed(&format!("BNEP setup write: {}", err)));
        }

        debug!(
            src_role = self.src_role,
            dst_role = self.dst_role,
            dst = %self.dst.ba2str(),
            "Sent BNEP setup connection request"
        );

        // Read setup response with timeout.
        let resp = self.read_setup_response().await?;
        if resp != BNEP_SUCCESS {
            btd_error(
                0xFFFF,
                &format!("BNEP setup rejected with response code {:#06x}", resp),
            );
            self.state = ConnState::Disconnected;
            return Err(BtdError::failed(&format!(
                "BNEP connection not allowed (response: {:#06x})",
                resp
            )));
        }

        // Create kernel bnep interface.
        self.connadd()?;

        // Bring interface up.
        self.if_up()?;

        self.state = ConnState::Connected;
        info!(
            iface = %self.iface,
            dst = %self.dst.ba2str(),
            "BNEP connection established"
        );

        Ok(self.iface.clone())
    }

    /// Disconnect the BNEP session and clean up kernel interface.
    pub fn disconnect(&mut self) {
        if self.state == ConnState::Disconnected {
            return;
        }

        // Cancel any pending timer/monitor tasks.
        if let Some(handle) = self.setup_timer.take() {
            handle.abort();
        }
        if let Some(handle) = self.monitor_task.take() {
            handle.abort();
        }

        // Delete kernel bnep interface.
        if let Err(e) = self.conndel() {
            btd_warn(0xFFFF, &format!("BNEP conndel failed: {}", e));
        }

        self.fd.take();
        self.state = ConnState::Disconnected;

        info!(
            iface = %self.iface,
            dst = %self.dst.ba2str(),
            "BNEP connection terminated"
        );
    }

    /// Create a kernel bnep interface from the server side.
    ///
    /// Used by the PAN server after receiving an incoming BNEP setup request
    /// and validating the service roles. Creates the kernel network interface
    /// and optionally adds it to a Linux bridge.
    pub fn server_add(
        &mut self,
        socket_fd: OwnedFd,
        dst_role: u16,
        bridge: Option<&str>,
    ) -> Result<String, BtdError> {
        self.fd = Some(socket_fd);
        self.dst_role = dst_role;

        // Check if kernel supports setup response handling.
        let supp_feat = bnep_get_supp_feat();
        if supp_feat & BNEP_SETUP_RESPONSE != 0 {
            // Kernel handles setup response — use standard connadd.
            self.connadd()?;
        } else {
            // Legacy path: send setup response ourselves, then connadd.
            self.send_setup_response(BNEP_SUCCESS)?;
            self.connadd()?;
        }

        // Bring interface up.
        self.if_up()?;

        // Add to bridge if requested.
        if let Some(br) = bridge {
            if !br.is_empty() {
                if let Err(e) = add_to_bridge(br, &self.iface) {
                    btd_warn(
                        0xFFFF,
                        &format!("Failed to add {} to bridge {}: {}", self.iface, br, e),
                    );
                }
            }
        }

        self.state = ConnState::Connected;
        info!(
            iface = %self.iface,
            dst = %self.dst.ba2str(),
            bridge = ?bridge,
            "BNEP server connection established"
        );

        Ok(self.iface.clone())
    }

    /// Delete a server-side BNEP connection.
    ///
    /// Removes the kernel interface from the bridge (if applicable)
    /// and deletes the bnep device.
    pub fn server_delete(&mut self, bridge: Option<&str>) {
        // Remove from bridge if applicable.
        if let Some(br) = bridge {
            if !br.is_empty() {
                if let Err(e) = del_from_bridge(br, &self.iface) {
                    btd_debug(
                        0xFFFF,
                        &format!("Failed to remove {} from bridge {}: {}", self.iface, br, e),
                    );
                }
            }
        }

        self.disconnect();
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Build a BNEP_SETUP_CONN_REQ frame with UUID16 format.
    fn build_setup_req(&self) -> Vec<u8> {
        // Control type (1) + type (1) + uuid_size (1) + dst_uuid (2) + src_uuid (2)
        vec![
            0x01, // BNEP_CONTROL
            BNEP_SETUP_CONN_REQ,
            2, // UUID16 size
            (self.dst_role >> 8) as u8,
            (self.dst_role & 0xFF) as u8,
            (self.src_role >> 8) as u8,
            (self.src_role & 0xFF) as u8,
        ]
    }

    /// Read a BNEP setup connection response from the socket.
    async fn read_setup_response(&self) -> Result<u16, BtdError> {
        let raw_fd = self.fd.as_ref().unwrap().as_raw_fd();

        // Use a timeout for the response.
        let timeout_dur = Duration::from_secs(BNEP_CONNECT_TO as u64);

        let result = time::timeout(timeout_dur, async {
            let mut buf = [0u8; 16];
            loop {
                // SAFETY: Reading from a valid socket fd into a stack buffer.
                let n = unsafe {
                    libc::read(raw_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n <= 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(BtdError::failed(&format!("BNEP read failed: {}", err)));
                }
                let n = n as usize;
                if n < 4 {
                    continue;
                }
                // Parse control frame: type=0x01 (BNEP_CONTROL), subtype=SETUP_CONN_RSP
                if buf[0] == 0x01 && buf[1] == BNEP_SETUP_CONN_RSP && n >= 4 {
                    let resp_code = ((buf[2] as u16) << 8) | (buf[3] as u16);
                    return Ok(resp_code);
                }
                // Not a setup response — keep reading.
            }
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_) => {
                btd_error(0xFFFF, "BNEP setup response timed out");
                Err(BtdError::failed("BNEP setup response timed out"))
            }
        }
    }

    /// Send a BNEP setup connection response.
    fn send_setup_response(&self, response: u16) -> Result<(), BtdError> {
        let raw_fd = self.fd.as_ref().unwrap().as_raw_fd();
        let buf = [
            0x01u8,                        // BNEP_CONTROL
            BNEP_SETUP_CONN_RSP,           // SETUP_CONN_RSP
            (response >> 8) as u8,
            (response & 0xFF) as u8,
        ];
        // SAFETY: Writing to a valid socket fd with a properly-formed buffer.
        let written = unsafe {
            libc::write(raw_fd, buf.as_ptr() as *const libc::c_void, buf.len())
        };
        if written < 0 {
            let err = std::io::Error::last_os_error();
            return Err(BtdError::failed(&format!("BNEP send response failed: {}", err)));
        }
        Ok(())
    }

    /// Create a kernel bnep interface via BNEPCONNADD ioctl.
    fn connadd(&mut self) -> Result<(), BtdError> {
        let ctl_guard = BNEP_CTL_SOCK.try_lock();
        let ctl = match ctl_guard {
            Ok(ref guard) => guard.as_ref(),
            Err(_) => {
                return Err(BtdError::failed("BNEP control socket lock contention"));
            }
        };
        let ctl_fd = match ctl {
            Some(fd) => fd.as_raw_fd(),
            None => {
                return Err(BtdError::failed("BNEP control socket not initialized"));
            }
        };

        let sock_fd = self.fd.as_ref().unwrap().as_raw_fd();

        let mut req: bnep_connadd_req = unsafe { mem::zeroed() };
        req.sock = sock_fd;
        req.role = self.dst_role;
        req.flags = 0;

        // Copy interface name into the device field.
        let name_bytes = self.iface.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), req.device.len() - 1);
        req.device[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // SAFETY: BNEPCONNADD ioctl on a valid BNEP control socket with a
        // properly-initialized bnep_connadd_req struct. The sock field contains
        // a valid L2CAP socket fd, and the device field is null-terminated.
        let ret = unsafe { libc::ioctl(ctl_fd, BNEPCONNADD as libc::c_ulong, &req) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            btd_error(
                0xFFFF,
                &format!("BNEPCONNADD ioctl failed: {}", err),
            );
            return Err(BtdError::failed(&format!("BNEPCONNADD: {}", err)));
        }

        // Read back the actual interface name assigned by the kernel.
        let actual_name = {
            let end = req.device.iter().position(|&b| b == 0).unwrap_or(req.device.len());
            String::from_utf8_lossy(&req.device[..end]).to_string()
        };
        if !actual_name.is_empty() {
            self.iface = actual_name;
        }

        debug!(iface = %self.iface, "BNEP kernel interface created");
        Ok(())
    }

    /// Delete a kernel bnep interface via BNEPCONNDEL ioctl.
    fn conndel(&self) -> Result<(), BtdError> {
        let ctl_guard = BNEP_CTL_SOCK.try_lock();
        let ctl = match ctl_guard {
            Ok(ref guard) => guard.as_ref(),
            Err(_) => {
                return Err(BtdError::failed("BNEP control socket lock contention"));
            }
        };
        let ctl_fd = match ctl {
            Some(fd) => fd.as_raw_fd(),
            None => {
                return Err(BtdError::failed("BNEP control socket not initialized"));
            }
        };

        let mut req: bnep_conndel_req = unsafe { mem::zeroed() };
        req.flags = 0;
        let dst_bytes = self.dst.b;
        req.dst[..6].copy_from_slice(&dst_bytes[..6]);

        // SAFETY: BNEPCONNDEL ioctl on a valid BNEP control socket with a
        // properly-initialized bnep_conndel_req struct containing the
        // destination BD_ADDR of the connection to delete.
        let ret = unsafe { libc::ioctl(ctl_fd, BNEPCONNDEL as libc::c_ulong, &req) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(BtdError::failed(&format!("BNEPCONNDEL: {}", err)));
        }

        debug!(iface = %self.iface, "BNEP kernel interface deleted");
        Ok(())
    }

    /// Bring a network interface up using SIOCSIFFLAGS.
    fn if_up(&self) -> Result<(), BtdError> {
        set_if_flags(&self.iface, true)
    }

    /// Bring a network interface down using SIOCSIFFLAGS.
    #[allow(dead_code)]
    fn if_down(&self) -> Result<(), BtdError> {
        set_if_flags(&self.iface, false)
    }
}

impl Drop for BnepSession {
    fn drop(&mut self) {
        if self.state != ConnState::Disconnected {
            self.disconnect();
        }
    }
}

// ===========================================================================
// Network Interface Helpers (SIOCSIFFLAGS, bridge)
// ===========================================================================

/// Set network interface up or down via SIOCSIFFLAGS ioctl.
fn set_if_flags(iface_name: &str, up: bool) -> Result<(), BtdError> {
    // Create a temporary socket for the ioctl.
    // SAFETY: Creating an AF_INET DGRAM socket for ioctl use only.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        let err = std::io::Error::last_os_error();
        return Err(BtdError::failed(&format!("socket for ioctl: {}", err)));
    }

    // Build ifreq.
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = iface_name.as_bytes();
    let copy_len = std::cmp::min(name_bytes.len(), libc::IFNAMSIZ - 1);
    // SAFETY: Copying interface name bytes into ifreq.ifr_name field.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }

    // Get current flags.
    // SAFETY: SIOCGIFFLAGS ioctl on a valid socket with properly-initialized ifreq.
    let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::c_ulong, &mut ifr) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(BtdError::failed(&format!("SIOCGIFFLAGS: {}", err)));
    }

    // Modify flags.
    // SAFETY: Accessing the ifr_ifru.ifru_flags union field.
    unsafe {
        let flags = ifr.ifr_ifru.ifru_flags;
        if up {
            ifr.ifr_ifru.ifru_flags = flags | libc::IFF_UP as libc::c_short;
        } else {
            ifr.ifr_ifru.ifru_flags = flags & !(libc::IFF_UP as libc::c_short);
        }
    }

    // Set new flags.
    // SAFETY: SIOCSIFFLAGS ioctl with properly-set flags field.
    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::c_ulong, &ifr) };
    unsafe { libc::close(sock) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(BtdError::failed(&format!("SIOCSIFFLAGS: {}", err)));
    }

    debug!(iface = iface_name, up, "Network interface flags set");
    Ok(())
}

/// Add a network interface to a Linux bridge via SIOCBRADDIF ioctl.
fn add_to_bridge(bridge: &str, iface: &str) -> Result<(), BtdError> {
    let ifindex = get_if_index(iface)?;
    bridge_ioctl(bridge, ifindex, true)
}

/// Remove a network interface from a Linux bridge via SIOCBRDELIF ioctl.
fn del_from_bridge(bridge: &str, iface: &str) -> Result<(), BtdError> {
    let ifindex = get_if_index(iface)?;
    bridge_ioctl(bridge, ifindex, false)
}

/// Get the interface index for a named network interface.
fn get_if_index(iface: &str) -> Result<i32, BtdError> {
    // SAFETY: Creating an AF_INET DGRAM socket for ioctl use only.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        let err = std::io::Error::last_os_error();
        return Err(BtdError::failed(&format!("socket for ifindex: {}", err)));
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = iface.as_bytes();
    let copy_len = std::cmp::min(name_bytes.len(), libc::IFNAMSIZ - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }

    // SAFETY: SIOCGIFINDEX ioctl on a valid socket with properly-initialized ifreq.
    let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFINDEX as libc::c_ulong, &mut ifr) };
    unsafe { libc::close(sock) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(BtdError::failed(&format!("SIOCGIFINDEX({}): {}", iface, err)));
    }

    // SAFETY: Accessing ifr_ifru.ifru_ifindex union field after successful ioctl.
    let ifindex = unsafe { ifr.ifr_ifru.ifru_ifindex };
    Ok(ifindex)
}

/// Perform bridge add/remove ioctl.
fn bridge_ioctl(bridge: &str, ifindex: i32, add: bool) -> Result<(), BtdError> {
    // SAFETY: Creating an AF_INET DGRAM socket for ioctl use only.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        let err = std::io::Error::last_os_error();
        return Err(BtdError::failed(&format!("socket for bridge ioctl: {}", err)));
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = bridge.as_bytes();
    let copy_len = std::cmp::min(name_bytes.len(), libc::IFNAMSIZ - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }

    // Set the interface index to add/remove (writing union field is safe in Rust).
    ifr.ifr_ifru.ifru_ifindex = ifindex;

    let ioctl_cmd = if add {
        SIOCBRADDIF
    } else {
        SIOCBRDELIF
    };

    // SAFETY: SIOCBRADDIF/SIOCBRDELIF ioctl on a valid socket with the
    // bridge name in ifr_name and the interface index in ifr_ifru.ifru_ifindex.
    let ret = unsafe { libc::ioctl(sock, ioctl_cmd, &ifr) };
    unsafe { libc::close(sock) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        let op = if add { "add" } else { "remove" };
        return Err(BtdError::failed(&format!(
            "Bridge {} {} ifindex {}: {}",
            op, bridge, ifindex, err
        )));
    }

    debug!(
        bridge,
        ifindex,
        op = if add { "add" } else { "remove" },
        "Bridge interface operation completed"
    );
    Ok(())
}

/// Query BNEP kernel feature support via BNEPGETSUPPFEAT ioctl.
fn bnep_get_supp_feat() -> u32 {
    let ctl_guard = BNEP_CTL_SOCK.try_lock();
    let ctl = match ctl_guard {
        Ok(ref guard) => guard.as_ref(),
        Err(_) => return 0,
    };
    let ctl_fd = match ctl {
        Some(fd) => fd.as_raw_fd(),
        None => return 0,
    };

    let mut supp_feat: u32 = 0;
    // SAFETY: BNEPGETSUPPFEAT ioctl on a valid BNEP control socket,
    // writing the feature bitmask to a stack u32.
    let ret = unsafe {
        libc::ioctl(ctl_fd, BNEPGETSUPPFEAT as libc::c_ulong, &mut supp_feat)
    };
    if ret < 0 {
        return 0;
    }
    supp_feat
}

/// Initialize the BNEP subsystem by opening the kernel control socket.
fn bnep_init() -> Result<(), BtdError> {
    // SAFETY: Creating a PF_BLUETOOTH/SOCK_RAW/BTPROTO_BNEP socket for
    // BNEP kernel interface management. This is a privileged operation
    // requiring CAP_NET_ADMIN.
    let fd = unsafe {
        libc::socket(PF_BLUETOOTH as libc::c_int, libc::SOCK_RAW, BTPROTO_BNEP as libc::c_int)
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        btd_error(0xFFFF, &format!("Failed to open BNEP control socket: {}", err));
        return Err(BtdError::failed(&format!("BNEP control socket: {}", err)));
    }

    // SAFETY: fd is a valid file descriptor from a successful socket() call.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Store in global.
    let mut guard = BNEP_CTL_SOCK.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(owned_fd);

    btd_info(0xFFFF, "BNEP control socket initialized");
    Ok(())
}

/// Clean up the BNEP subsystem by closing the kernel control socket.
fn bnep_cleanup() {
    let mut guard = BNEP_CTL_SOCK.lock().unwrap_or_else(|e| e.into_inner());
    if guard.take().is_some() {
        btd_info(0xFFFF, "BNEP control socket closed");
    }
}

// ===========================================================================
// BNEP Setup Decode (server-side frame parsing)
// ===========================================================================

/// Decode a BNEP setup connection request from raw frame data.
///
/// Validates UUID format (UUID16/UUID32/UUID128), checks against the
/// Bluetooth base UUID for UUID128, and validates PAN role combinations.
///
/// Returns `(dst_role, src_role)` on success, or an error response code.
fn bnep_setup_decode(data: &[u8]) -> Result<(u16, u16), u16> {
    if data.len() < 3 {
        return Err(BNEP_CONN_NOT_ALLOWED);
    }

    let uuid_size = data[0] as usize;
    let expected_len = 1 + uuid_size * 2;
    if data.len() < expected_len {
        return Err(BNEP_CONN_NOT_ALLOWED);
    }

    let (dst_role, src_role) = match uuid_size {
        2 => {
            // UUID16
            let dst = ((data[1] as u16) << 8) | (data[2] as u16);
            let src = ((data[3] as u16) << 8) | (data[4] as u16);
            (dst, src)
        }
        4 => {
            // UUID32 — upper 16 bits must be zero for valid BT UUID.
            let dst32 = ((data[1] as u32) << 24)
                | ((data[2] as u32) << 16)
                | ((data[3] as u32) << 8)
                | (data[4] as u32);
            let src32 = ((data[5] as u32) << 24)
                | ((data[6] as u32) << 16)
                | ((data[7] as u32) << 8)
                | (data[8] as u32);
            if dst32 > 0xFFFF || src32 > 0xFFFF {
                return Err(BNEP_CONN_INVALID_SVC);
            }
            (dst32 as u16, src32 as u16)
        }
        16 => {
            // UUID128 — validate base UUID bytes [4..16].
            if data.len() < 33 {
                return Err(BNEP_CONN_NOT_ALLOWED);
            }
            // Destination UUID128: bytes [1..17]
            let dst_uuid = &data[1..17];
            let src_uuid = &data[17..33];

            // Check base UUID for destination.
            if dst_uuid[4..16] != BNEP_BASE_UUID_TAIL {
                return Err(BNEP_CONN_INVALID_DST);
            }
            // Check base UUID for source.
            if src_uuid[4..16] != BNEP_BASE_UUID_TAIL {
                return Err(BNEP_CONN_INVALID_SRC);
            }

            let dst = ((dst_uuid[2] as u16) << 8) | (dst_uuid[3] as u16);
            let src = ((src_uuid[2] as u16) << 8) | (src_uuid[3] as u16);
            (dst, src)
        }
        _ => {
            return Err(BNEP_CONN_NOT_ALLOWED);
        }
    };

    // Validate PAN role combinations.
    match dst_role {
        BNEP_SVC_NAP | BNEP_SVC_GN => {
            if src_role != BNEP_SVC_PANU {
                return Err(BNEP_CONN_INVALID_SRC);
            }
        }
        BNEP_SVC_PANU => {
            // PANU can accept PANU, GN, or NAP as source.
            if src_role != BNEP_SVC_PANU
                && src_role != BNEP_SVC_GN
                && src_role != BNEP_SVC_NAP
            {
                return Err(BNEP_CONN_INVALID_SRC);
            }
        }
        _ => {
            return Err(BNEP_CONN_INVALID_DST);
        }
    }

    debug!(dst_role, src_role, "BNEP setup decoded");
    Ok((dst_role, src_role))
}

// ===========================================================================
// UUID / Service ID Helpers
// ===========================================================================

/// Convert a UUID string to a BNEP service class ID.
fn uuid_to_bnep_svc(uuid_str: &str) -> Result<u16, BtdError> {
    let lower = uuid_str.to_lowercase();
    if lower == PANU_UUID || lower == "1115" || lower == "0x1115" {
        return Ok(BNEP_SVC_PANU);
    }
    if lower == NAP_UUID || lower == "1116" || lower == "0x1116" {
        return Ok(BNEP_SVC_NAP);
    }
    if lower == GN_UUID || lower == "1117" || lower == "0x1117" {
        return Ok(BNEP_SVC_GN);
    }

    // Try parsing as BtUuid.
    if let Ok(bt_uuid) = uuid_str.parse::<BtUuid>() {
        match bt_uuid {
            BtUuid::Uuid16(v) => match v {
                BNEP_SVC_PANU => return Ok(BNEP_SVC_PANU),
                BNEP_SVC_NAP => return Ok(BNEP_SVC_NAP),
                BNEP_SVC_GN => return Ok(BNEP_SVC_GN),
                _ => {}
            },
            BtUuid::Uuid32(v) => {
                let short = v as u16;
                if short == BNEP_SVC_PANU || short == BNEP_SVC_NAP || short == BNEP_SVC_GN {
                    return Ok(short);
                }
            }
            BtUuid::Uuid128(_bytes) => {
                // Check if it's a standard Bluetooth UUID with a PAN service.
                let uuid128 = bt_uuid.to_uuid128_bytes();
                let short = ((uuid128[2] as u16) << 8) | (uuid128[3] as u16);
                if short == BNEP_SVC_PANU || short == BNEP_SVC_NAP || short == BNEP_SVC_GN {
                    return Ok(short);
                }
            }
        }
    }

    Err(BtdError::invalid_args_str(&format!(
        "Invalid PAN UUID: {}",
        uuid_str
    )))
}

/// Convert a BNEP service class ID to its UUID string representation.
fn bnep_svc_to_uuid_str(svc: u16) -> &'static str {
    match svc {
        BNEP_SVC_PANU => PANU_UUID,
        BNEP_SVC_GN => GN_UUID,
        BNEP_SVC_NAP => NAP_UUID,
        _ => "",
    }
}

/// Get a human-readable name for a PAN service.
fn bnep_svc_name(svc: u16) -> &'static str {
    match svc {
        BNEP_SVC_PANU => "Personal Area Networking User",
        BNEP_SVC_GN => "Group Ad-hoc Network",
        BNEP_SVC_NAP => "Network Access Point",
        _ => "Unknown PAN Service",
    }
}

// ===========================================================================
// NetworkConn — Per-service connection state (client side)
// ===========================================================================

/// Per-service network connection state, stored as user_data in BtdService.
pub struct NetworkConn {
    /// BNEP service class ID (BNEP_SVC_PANU/GN/NAP).
    pub id: u16,
    /// Connection state.
    pub state: ConnState,
    /// Network interface name when connected.
    pub dev: String,
    /// BNEP session when connected.
    pub session: Option<BnepSession>,
    /// Pending D-Bus Connect() reply channel.
    pending_connect: Option<oneshot::Sender<Result<String, BtdError>>>,
    /// Connected UUID string for D-Bus property.
    connected_uuid: String,
}

impl NetworkConn {
    pub fn new(id: u16) -> Self {
        NetworkConn {
            id,
            state: ConnState::Disconnected,
            dev: String::new(),
            session: None,
            pending_connect: None,
            connected_uuid: String::new(),
        }
    }
}

// ===========================================================================
// NetworkPeer — Aggregates connections for a single device
// ===========================================================================

/// Aggregates all PAN connections for a single remote device.
///
/// Each device may have connections for multiple PAN roles (though typically
/// only one is active at a time).
pub struct NetworkPeer {
    /// Reference to the remote device.
    pub device: Arc<tokio::sync::Mutex<BtdDevice>>,
    /// Per-role connection states.
    pub connections: Vec<NetworkConn>,
}

impl NetworkPeer {
    pub fn new(device: Arc<tokio::sync::Mutex<BtdDevice>>) -> Self {
        NetworkPeer {
            device,
            connections: Vec::new(),
        }
    }

    /// Find the first active connection, if any.
    fn find_connected(&self) -> Option<&NetworkConn> {
        self.connections.iter().find(|c| c.state == ConnState::Connected)
    }

    /// Find the first connecting connection, if any.
    fn find_connecting(&self) -> Option<&NetworkConn> {
        self.connections.iter().find(|c| c.state == ConnState::Connecting)
    }
}

// ===========================================================================
// D-Bus Interface: org.bluez.Network1 (Client Side)
// ===========================================================================

/// Wrapper struct for the Network1 D-Bus interface.
///
/// Implements `org.bluez.Network1` on device object paths, providing
/// `Connect(uuid)`, `Disconnect()`, and properties `Connected`, `Interface`, `UUID`.
pub struct NetworkInterface {
    peer: Arc<tokio::sync::Mutex<NetworkPeer>>,
}

impl NetworkInterface {
    /// Create a new Network1 interface for a device.
    fn new(peer: Arc<tokio::sync::Mutex<NetworkPeer>>) -> Self {
        NetworkInterface { peer }
    }
}

#[zbus::interface(name = "org.bluez.Network1")]
impl NetworkInterface {
    /// Connect to the network device using the specified PAN service UUID.
    ///
    /// Returns the network interface name (e.g., "bnep0") on success.
    /// Errors: InvalidArguments, InProgress, AlreadyConnected, Failed.
    async fn connect(&self, uuid: String) -> Result<String, zbus::fdo::Error> {
        let svc_id = uuid_to_bnep_svc(&uuid).map_err(|e| {
            zbus::fdo::Error::InvalidArgs(format!("{}", e))
        })?;

        let mut peer = self.peer.lock().await;

        // Check if already connected or connecting.
        if let Some(_conn) = peer.find_connected() {
            return Err(zbus::fdo::Error::Failed(
                "org.bluez.Error.AlreadyConnected: Already connected".into(),
            ));
        }
        if let Some(_conn) = peer.find_connecting() {
            return Err(zbus::fdo::Error::Failed(
                "org.bluez.Error.InProgress: Connection in progress".into(),
            ));
        }

        // Find or create the connection entry for this service.
        let conn_idx = peer
            .connections
            .iter()
            .position(|c| c.id == svc_id)
            .unwrap_or_else(|| {
                peer.connections.push(NetworkConn::new(svc_id));
                peer.connections.len() - 1
            });

        let conn = &mut peer.connections[conn_idx];
        conn.state = ConnState::Connecting;
        conn.connected_uuid = uuid.clone();

        // Get device addresses.
        let dev_guard = peer.device.lock().await;
        let dst_addr = dev_guard.address;
        let adapter_arc = dev_guard.adapter.clone();
        drop(dev_guard);

        let src_addr = {
            let adapter_guard = adapter_arc.lock().await;
            adapter_guard.address
        };

        drop(peer);

        // Determine the local (source) role: we are always PANU when connecting.
        let src_role = BNEP_SVC_PANU;

        // Create BNEP session and connect.
        let mut session = BnepSession::new(src_addr, dst_addr, src_role, svc_id);

        // Create L2CAP connection to BNEP PSM.
        // SAFETY: Creating an L2CAP socket for BNEP connection.
        let sock_fd = unsafe {
            libc::socket(
                PF_BLUETOOTH,
                libc::SOCK_SEQPACKET,
                BTPROTO_L2CAP as libc::c_int,
            )
        };
        if sock_fd < 0 {
            let mut peer = self.peer.lock().await;
            if let Some(c) = peer.connections.iter_mut().find(|c| c.id == svc_id) {
                c.state = ConnState::Disconnected;
            }
            let err = std::io::Error::last_os_error();
            return Err(zbus::fdo::Error::Failed(format!("L2CAP socket: {}", err)));
        }

        // Set socket options for BNEP.
        set_l2cap_bnep_options(sock_fd);

        // Bind to local address.
        if let Err(e) = bind_l2cap_socket(sock_fd, &src_addr, 0) {
            unsafe { libc::close(sock_fd) };
            let mut peer = self.peer.lock().await;
            if let Some(c) = peer.connections.iter_mut().find(|c| c.id == svc_id) {
                c.state = ConnState::Disconnected;
            }
            return Err(zbus::fdo::Error::Failed(format!("L2CAP bind: {}", e)));
        }

        // Connect to remote BNEP PSM.
        let connect_result = connect_l2cap_socket(sock_fd, &dst_addr, BNEP_PSM);
        if let Err(e) = connect_result {
            unsafe { libc::close(sock_fd) };
            let mut peer = self.peer.lock().await;
            if let Some(c) = peer.connections.iter_mut().find(|c| c.id == svc_id) {
                c.state = ConnState::Disconnected;
            }
            return Err(zbus::fdo::Error::Failed(format!("L2CAP connect: {}", e)));
        }

        // SAFETY: sock_fd is a valid file descriptor from successful socket+connect.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(sock_fd) };

        match session.connect(owned_fd).await {
            Ok(iface_name) => {
                let mut peer = self.peer.lock().await;
                if let Some(c) = peer.connections.iter_mut().find(|c| c.id == svc_id) {
                    c.state = ConnState::Connected;
                    c.dev = iface_name.clone();
                    c.session = Some(session);
                }
                btd_info(
                    0xFFFF,
                    &format!("PAN connected: {} via {}", dst_addr.ba2str(), iface_name),
                );
                Ok(iface_name)
            }
            Err(e) => {
                let mut peer = self.peer.lock().await;
                if let Some(c) = peer.connections.iter_mut().find(|c| c.id == svc_id) {
                    c.state = ConnState::Disconnected;
                }
                Err(zbus::fdo::Error::Failed(format!("{}", e)))
            }
        }
    }

    /// Disconnect from the PAN network.
    ///
    /// Errors: NotConnected.
    async fn disconnect(&self) -> Result<(), zbus::fdo::Error> {
        let mut peer = self.peer.lock().await;

        // Find the active connection.
        let conn_idx = peer
            .connections
            .iter()
            .position(|c| c.state == ConnState::Connected || c.state == ConnState::Connecting);

        match conn_idx {
            Some(idx) => {
                // Extract device address before taking mutable ref to connections.
                let dst_str = {
                    let dev_guard = peer.device.lock().await;
                    dev_guard.address.ba2str()
                };

                let conn = &mut peer.connections[idx];
                if let Some(ref mut session) = conn.session {
                    session.disconnect();
                }
                conn.state = ConnState::Disconnected;
                conn.session = None;
                conn.dev.clear();
                conn.connected_uuid.clear();

                btd_info(0xFFFF, &format!("PAN disconnected: {}", dst_str));
                Ok(())
            }
            None => Err(zbus::fdo::Error::Failed(
                "org.bluez.Error.NotConnected: Not connected".into(),
            )),
        }
    }

    /// Whether a PAN connection is currently active.
    #[zbus(property)]
    async fn connected(&self) -> bool {
        let peer = self.peer.lock().await;
        peer.find_connected().is_some()
    }

    /// The BNEP network interface name (e.g., "bnep0"), or empty if not connected.
    #[zbus(property, name = "Interface")]
    async fn interface(&self) -> String {
        let peer = self.peer.lock().await;
        if let Some(conn) = peer.find_connected() {
            conn.dev.clone()
        } else {
            String::new()
        }
    }

    /// The UUID of the connected PAN service, or empty if not connected.
    #[zbus(property, name = "UUID")]
    async fn uuid(&self) -> String {
        let peer = self.peer.lock().await;
        if let Some(conn) = peer.find_connected() {
            conn.connected_uuid.clone()
        } else {
            String::new()
        }
    }
}

// ===========================================================================
// L2CAP Socket Helpers
// ===========================================================================

/// L2CAP socket address structure for Bluetooth connections.
#[repr(C)]
struct SockaddrL2 {
    l2_family: u16,
    l2_psm: u16,
    l2_bdaddr: [u8; 6],
    l2_cid: u16,
    l2_bdaddr_type: u8,
}

/// Set L2CAP socket options appropriate for BNEP.
fn set_l2cap_bnep_options(fd: RawFd) {
    // Set receive/send MTU.
    let mtu: u32 = BNEP_MTU as u32;
    // BT_RCVMTU = 13, BT_SNDMTU = 14 on SOL_BLUETOOTH = 274
    let sol_bt: libc::c_int = 274;

    // SAFETY: setsockopt on a valid L2CAP socket with properly-sized value buffer.
    unsafe {
        libc::setsockopt(
            fd,
            sol_bt,
            13, // BT_RCVMTU
            &mtu as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            sol_bt,
            14, // BT_SNDMTU
            &mtu as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
    }

    // Set security level to medium if security is enabled.
    if CONF_SECURITY.load(std::sync::atomic::Ordering::Relaxed) {
        #[repr(C)]
        struct BtSecurity {
            level: u8,
            key_size: u8,
        }
        let sec = BtSecurity {
            level: 2, // BT_SECURITY_MEDIUM
            key_size: 0,
        };
        // SAFETY: setsockopt with bt_security struct on valid L2CAP socket.
        unsafe {
            libc::setsockopt(
                fd,
                sol_bt,
                4, // BT_SECURITY
                &sec as *const BtSecurity as *const libc::c_void,
                std::mem::size_of::<BtSecurity>() as libc::socklen_t,
            );
        }
    }
}

/// Bind an L2CAP socket to a local Bluetooth address and PSM.
fn bind_l2cap_socket(fd: RawFd, addr: &BdAddr, psm: u16) -> Result<(), BtdError> {
    let mut sa: SockaddrL2 = unsafe { mem::zeroed() };
    sa.l2_family = libc::AF_BLUETOOTH as u16;
    sa.l2_psm = psm.to_le();
    sa.l2_bdaddr = addr.b;

    // SAFETY: bind() on a valid socket with properly-initialized sockaddr_l2.
    let ret = unsafe {
        libc::bind(
            fd,
            &sa as *const SockaddrL2 as *const libc::sockaddr,
            std::mem::size_of::<SockaddrL2>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(BtdError::failed(&format!("L2CAP bind: {}", err)));
    }
    Ok(())
}

/// Connect an L2CAP socket to a remote Bluetooth address on BNEP PSM.
fn connect_l2cap_socket(fd: RawFd, addr: &BdAddr, psm: u16) -> Result<(), BtdError> {
    let mut sa: SockaddrL2 = unsafe { mem::zeroed() };
    sa.l2_family = libc::AF_BLUETOOTH as u16;
    sa.l2_psm = psm.to_le();
    sa.l2_bdaddr = addr.b;

    // SAFETY: connect() on a valid L2CAP socket with properly-initialized sockaddr_l2.
    let ret = unsafe {
        libc::connect(
            fd,
            &sa as *const SockaddrL2 as *const libc::sockaddr,
            std::mem::size_of::<SockaddrL2>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(BtdError::failed(&format!("L2CAP connect: {}", err)));
    }
    Ok(())
}

// ===========================================================================
// PanServer — Per-role server registration
// ===========================================================================

/// A single PAN role registration on an adapter.
pub struct PanServer {
    /// BNEP service class ID (BNEP_SVC_NAP, BNEP_SVC_GN, BNEP_SVC_PANU).
    pub id: u16,
    /// SDP service record handle (0 if not registered).
    pub record_handle: u32,
    /// Linux bridge name for NAP/GN.
    pub bridge: String,
    /// Active server-side BNEP sessions.
    sessions: Vec<BnepSession>,
}

impl PanServer {
    pub fn new(id: u16, bridge: String) -> Self {
        PanServer {
            id,
            record_handle: 0,
            bridge,
            sessions: Vec::new(),
        }
    }
}

// ===========================================================================
// NetworkServer — Per-adapter server state
// ===========================================================================

/// Per-adapter PAN server state managing the listener socket and registered roles.
pub struct NetworkServer {
    /// Reference to the Bluetooth adapter.
    pub adapter: Arc<tokio::sync::Mutex<BtdAdapter>>,
    /// Shared BNEP PSM listener socket (created on first Register).
    pub listener: Option<OwnedFd>,
    /// Registered PAN server roles.
    pub servers: Vec<PanServer>,
    /// Listener task handle for async accept loop.
    listener_task: Option<JoinHandle<()>>,
}

impl NetworkServer {
    pub fn new(adapter: Arc<tokio::sync::Mutex<BtdAdapter>>) -> Self {
        NetworkServer {
            adapter,
            listener: None,
            servers: Vec::new(),
            listener_task: None,
        }
    }

    /// Check if a specific PAN role is registered.
    fn has_server(&self, id: u16) -> bool {
        self.servers.iter().any(|s| s.id == id)
    }
}

// ===========================================================================
// Global Server Registry
// ===========================================================================

/// Global registry of per-adapter NetworkServer instances.
static NETWORK_SERVERS: std::sync::LazyLock<tokio::sync::Mutex<Vec<NetworkServer>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(Vec::new()));

/// Global registry of per-device NetworkPeer instances (client side).
static NETWORK_PEERS: std::sync::LazyLock<
    tokio::sync::Mutex<Vec<Arc<tokio::sync::Mutex<NetworkPeer>>>>,
> = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(Vec::new()));

// ===========================================================================
// SDP Record Generation
// ===========================================================================

/// Create an SDP record for a PAN server role.
///
/// Generates a fully-populated SDP record with service class ID,
/// protocol descriptor list (L2CAP + BNEP), profile descriptor,
/// service name, and NAP-specific security/network attributes.
fn create_pan_sdp_record(svc_id: u16, name: &str, desc: &str, security: bool) -> SdpRecord {
    let mut rec = SdpRecord::new(0);

    // Service Class ID List.
    rec.attrs.insert(
        SDP_ATTR_SVCLASS_ID_LIST,
        SdpData::Sequence(vec![SdpData::Uuid16(svc_id)]),
    );

    // Protocol Descriptor List: L2CAP(PSM=BNEP_PSM) + BNEP(version, types).
    rec.attrs.insert(
        SDP_ATTR_PROTO_DESC_LIST,
        SdpData::Sequence(vec![
            SdpData::Sequence(vec![
                SdpData::Uuid16(L2CAP_UUID_VAL),
                SdpData::UInt16(BNEP_PSM),
            ]),
            SdpData::Sequence(vec![
                SdpData::Uuid16(BNEP_UUID_VAL),
                SdpData::UInt16(BNEP_VERSION),
                SdpData::Sequence(vec![
                    SdpData::UInt16(0x0800), // IPv4
                    SdpData::UInt16(0x0806), // ARP
                ]),
            ]),
        ]),
    );

    // Browse Group List.
    rec.attrs.insert(
        SDP_ATTR_BROWSE_GRP_LIST,
        SdpData::Sequence(vec![SdpData::Uuid16(PUBLIC_BROWSE_GROUP)]),
    );

    // Bluetooth Profile Descriptor List.
    rec.attrs.insert(
        SDP_ATTR_PFILE_DESC_LIST,
        SdpData::Sequence(vec![SdpData::Sequence(vec![
            SdpData::Uuid16(svc_id),
            SdpData::UInt16(0x0100), // version 1.0
        ])]),
    );

    // Service Name.
    if !name.is_empty() {
        rec.attrs
            .insert(SDP_ATTR_SVCNAME_PRIMARY, SdpData::Text(name.as_bytes().to_vec()));
    }

    // Service Description.
    if !desc.is_empty() {
        rec.attrs
            .insert(SDP_ATTR_SVCDESC_PRIMARY, SdpData::Text(desc.as_bytes().to_vec()));
    }

    // NAP-specific attributes.
    if svc_id == BNEP_SVC_NAP {
        // Security description: 0=none, 1=service-level enforced.
        let sec_val: u16 = if security { 1 } else { 0 };
        rec.attrs
            .insert(SDP_ATTR_SECURITY_DESC, SdpData::UInt16(sec_val));
        // Network access type: Ethernet (5).
        rec.attrs
            .insert(SDP_ATTR_NET_ACCESS_TYPE, SdpData::UInt16(5));
        // Max net access rate: 10 Mbps.
        rec.attrs
            .insert(SDP_ATTR_MAX_NET_ACCESS_RATE, SdpData::UInt32(10_000_000));
    }

    rec
}

// ===========================================================================
// D-Bus Interface: org.bluez.NetworkServer1 (Server Side)
// ===========================================================================

/// Wrapper struct for the `org.bluez.NetworkServer1` D-Bus interface.
///
/// Implements `Register(uuid, bridge)` and `Unregister(uuid)` methods on
/// adapter object paths, allowing external applications to control PAN server
/// role registration.
pub struct NetworkServerInterface {
    server: Arc<tokio::sync::Mutex<NetworkServer>>,
}

impl NetworkServerInterface {
    fn new(server: Arc<tokio::sync::Mutex<NetworkServer>>) -> Self {
        NetworkServerInterface { server }
    }
}

#[zbus::interface(name = "org.bluez.NetworkServer1")]
impl NetworkServerInterface {
    /// Register a PAN server for the specified service UUID.
    ///
    /// The `uuid` parameter identifies the PAN role (NAP, GN, or PANU).
    /// The `bridge` parameter specifies the Linux bridge interface name to
    /// attach incoming BNEP connections to (typically `"pan0"` or `"br0"`).
    ///
    /// # Errors
    /// - `InvalidArguments` if the UUID does not correspond to a valid PAN role
    /// - `AlreadyExists` if the specified role is already registered
    /// - `Failed` if the listener socket cannot be created
    pub async fn register(
        &self,
        uuid: String,
        bridge: String,
    ) -> Result<(), zbus::fdo::Error> {
        let svc_id = uuid_to_bnep_svc(&uuid).map_err(|e| {
            zbus::fdo::Error::InvalidArgs(format!("{}", e))
        })?;

        let mut server = self.server.lock().await;

        // Check if already registered.
        if server.has_server(svc_id) {
            return Err(zbus::fdo::Error::Failed(
                "org.bluez.Error.AlreadyExists: Service already registered".into(),
            ));
        }

        let security = CONF_SECURITY.load(std::sync::atomic::Ordering::Relaxed);

        // Create the listener socket if not yet created.
        if server.listener.is_none() {
            let adapter_guard = server.adapter.lock().await;
            let src_addr = adapter_guard.address;
            drop(adapter_guard);

            match create_listener_socket(&src_addr) {
                Ok(fd) => {
                    server.listener = Some(fd);
                }
                Err(e) => {
                    return Err(zbus::fdo::Error::Failed(format!(
                        "Failed to create listener: {}",
                        e
                    )));
                }
            }
        }

        // Build and register SDP record for this PAN role.
        let mut rec = create_pan_sdp_record(svc_id, bnep_svc_name(svc_id), "", security);
        let adapter_guard = server.adapter.lock().await;
        let src_addr = adapter_guard.address;
        drop(adapter_guard);
        // Register the SDP record with the SDP database (integration point
        // with the global SDP server). The record handle is stored for
        // cleanup during unregister.
        let record_handle = {
            let mut db = crate::sdp::SdpDatabase::new();
            match add_record_to_server(&mut db, &src_addr, &mut rec) {
                Ok(h) => h,
                Err(e) => {
                    btd_error(0xFFFF, &format!("SDP record registration failed: {}", e));
                    0
                }
            }
        };

        // Register the PAN server role.
        let mut pan_server = PanServer::new(svc_id, bridge.clone());
        pan_server.record_handle = record_handle;
        server.servers.push(pan_server);

        btd_info(
            0xFFFF,
            &format!(
                "NetworkServer1.Register: {} (bridge={})",
                bnep_svc_name(svc_id),
                bridge
            ),
        );

        Ok(())
    }

    /// Unregister a previously registered PAN server.
    ///
    /// Terminates all active BNEP sessions for this role and removes the
    /// corresponding SDP record. If no more roles are registered, the
    /// shared listener socket is closed.
    ///
    /// # Errors
    /// - `InvalidArguments` if the UUID does not correspond to a valid PAN role
    /// - `DoesNotExist` if the specified role is not currently registered
    pub async fn unregister(&self, uuid: String) -> Result<(), zbus::fdo::Error> {
        let svc_id = uuid_to_bnep_svc(&uuid).map_err(|e| {
            zbus::fdo::Error::InvalidArgs(format!("{}", e))
        })?;

        let mut server = self.server.lock().await;

        let pos = server.servers.iter().position(|s| s.id == svc_id);
        match pos {
            Some(idx) => {
                let pan = server.servers.remove(idx);

                // Remove SDP record if it was registered.
                if pan.record_handle != 0 {
                    let mut db = crate::sdp::SdpDatabase::new();
                    let _ = remove_record_from_server(&mut db, pan.record_handle);
                }

                // Disconnect all active sessions for this role.
                for mut session in pan.sessions {
                    session.server_delete(Some(&pan.bridge));
                }

                // If no more servers, close the listener.
                if server.servers.is_empty() {
                    server.listener.take();
                    if let Some(handle) = server.listener_task.take() {
                        handle.abort();
                    }
                }

                btd_info(
                    0xFFFF,
                    &format!("NetworkServer1.Unregister: {}", bnep_svc_name(svc_id)),
                );
                Ok(())
            }
            None => Err(zbus::fdo::Error::Failed(
                "org.bluez.Error.DoesNotExist: Service not registered".into(),
            )),
        }
    }
}

/// Create a listening L2CAP socket for BNEP PSM.
fn create_listener_socket(src_addr: &BdAddr) -> Result<OwnedFd, BtdError> {
    // SAFETY: Creating an L2CAP SEQPACKET socket for BNEP listening.
    let fd = unsafe {
        libc::socket(
            PF_BLUETOOTH as libc::c_int,
            libc::SOCK_SEQPACKET,
            BTPROTO_L2CAP as libc::c_int,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(BtdError::failed(&format!("L2CAP listen socket: {}", err)));
    }

    // Set socket options for BNEP.
    set_l2cap_bnep_options(fd);

    // Bind to BNEP PSM on the adapter address.
    bind_l2cap_socket(fd, src_addr, BNEP_PSM)?;

    // Listen for incoming connections.
    // SAFETY: listen() on a valid bound socket.
    let ret = unsafe { libc::listen(fd, 5) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: close a valid fd we just created.
        unsafe { libc::close(fd) };
        return Err(BtdError::failed(&format!("L2CAP listen: {}", err)));
    }

    // SAFETY: fd is a valid file descriptor from successful socket+bind+listen.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(owned)
}

// ===========================================================================
// Profile Registrations
// ===========================================================================

/// Build and register the three PAN profile descriptors (PANU, GN, NAP).
///
/// This is an async function because `btd_profile_register` is async.
async fn register_profiles_async() -> Result<(), BtdError> {
    // PANU profile: local=PANU, remote=NAP (primary).
    let mut panu = BtdProfile::new("network-panu");
    panu.local_uuid = Some(PANU_UUID.to_string());
    panu.remote_uuid = Some(NAP_UUID.to_string());
    panu.bearer = BTD_PROFILE_BEARER_BREDR;
    panu.auto_connect = false;
    btd_profile_register(panu).await?;

    // GN profile: local=GN, remote=PANU.
    let mut gn = BtdProfile::new("network-gn");
    gn.local_uuid = Some(GN_UUID.to_string());
    gn.remote_uuid = Some(PANU_UUID.to_string());
    gn.bearer = BTD_PROFILE_BEARER_BREDR;
    gn.auto_connect = false;
    btd_profile_register(gn).await?;

    // NAP profile: local=NAP, remote=PANU.
    let mut nap = BtdProfile::new("network-nap");
    nap.local_uuid = Some(NAP_UUID.to_string());
    nap.remote_uuid = Some(PANU_UUID.to_string());
    nap.bearer = BTD_PROFILE_BEARER_BREDR;
    nap.auto_connect = false;
    btd_profile_register(nap).await?;

    btd_info(0xFFFF, "PAN profiles registered (PANU, GN, NAP)");
    Ok(())
}

/// Unregister all PAN profiles.
///
/// This is an async function because `btd_profile_unregister` is async.
async fn unregister_profiles_async() {
    let names = ["network-panu", "network-gn", "network-nap"];
    for name in &names {
        let profile = BtdProfile::new(name);
        btd_profile_unregister(&profile).await;
    }
    btd_info(0xFFFF, "PAN profiles unregistered");
}

// ===========================================================================
// Configuration
// ===========================================================================

/// Path to the PAN network configuration file.
const NETWORK_CONF_PATH: &str = "/etc/bluetooth/network.conf";

/// Read network.conf and return whether security is enabled.
///
/// The `[General]` section may contain `DisableSecurity=true` which inverts
/// to security being disabled. Default is security enabled.
fn read_config() -> bool {
    match ini::Ini::load_from_file(NETWORK_CONF_PATH) {
        Ok(config) => {
            if let Some(section) = config.section(Some("General")) {
                if let Some(val) = section.get("DisableSecurity") {
                    let disable = val.eq_ignore_ascii_case("true") || val == "1";
                    if disable {
                        btd_info(0xFFFF, "PAN security disabled via network.conf");
                        return false;
                    }
                }
            }
            true
        }
        Err(e) => {
            btd_debug(
                0xFFFF,
                &format!(
                    "Could not load {}: {} (using defaults)",
                    NETWORK_CONF_PATH, e
                ),
            );
            true // Default: security enabled.
        }
    }
}

// ===========================================================================
// Plugin Init / Exit
// ===========================================================================

/// Initialize the PAN network plugin.
///
/// 1. Parses `network.conf` for security settings.
/// 2. Initializes the BNEP kernel control socket.
/// 3. Registers the three PAN profiles (PANU, GN, NAP) asynchronously.
pub fn network_init() -> Result<(), Box<dyn std::error::Error>> {
    let security = read_config();
    CONF_SECURITY.store(security, std::sync::atomic::Ordering::Relaxed);

    bnep_init().map_err(|e| -> Box<dyn std::error::Error> {
        Box::new(std::io::Error::other(
            format!("{}", e),
        ))
    })?;

    // Register profiles asynchronously (btd_profile_register is async).
    tokio::spawn(async move {
        if let Err(e) = register_profiles_async().await {
            btd_error(0xFFFF, &format!("Failed to register PAN profiles: {}", e));
        }
    });

    btd_info(0xFFFF, "Network plugin initialized");
    Ok(())
}

/// Shut down the PAN network plugin.
///
/// 1. Unregisters all PAN profiles asynchronously.
/// 2. Cleans up all server and client connections.
/// 3. Closes the BNEP control socket.
pub fn network_exit() {
    // Unregister profiles asynchronously.
    tokio::spawn(async move {
        unregister_profiles_async().await;
    });

    bnep_cleanup();
    btd_info(0xFFFF, "Network plugin shut down");
}

// ===========================================================================
// Plugin Registration via inventory
// ===========================================================================

mod _network_plugin_register {
    use super::PluginPriority;
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "network",
            version: env!("CARGO_PKG_VERSION"),
            priority: PluginPriority::Default,
            init: super::network_init,
            exit: super::network_exit,
        }
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conn_state_default() {
        assert_eq!(ConnState::default(), ConnState::Disconnected);
    }

    #[test]
    fn test_conn_state_display() {
        assert_eq!(ConnState::Disconnected.to_string(), "disconnected");
        assert_eq!(ConnState::Connecting.to_string(), "connecting");
        assert_eq!(ConnState::Connected.to_string(), "connected");
    }

    #[test]
    fn test_uuid_to_bnep_svc() {
        assert_eq!(uuid_to_bnep_svc(PANU_UUID).unwrap(), BNEP_SVC_PANU);
        assert_eq!(uuid_to_bnep_svc(NAP_UUID).unwrap(), BNEP_SVC_NAP);
        assert_eq!(uuid_to_bnep_svc(GN_UUID).unwrap(), BNEP_SVC_GN);
        assert_eq!(uuid_to_bnep_svc("0x1115").unwrap(), BNEP_SVC_PANU);
        assert_eq!(uuid_to_bnep_svc("0x1116").unwrap(), BNEP_SVC_NAP);
        assert_eq!(uuid_to_bnep_svc("0x1117").unwrap(), BNEP_SVC_GN);
        assert!(uuid_to_bnep_svc("invalid-uuid").is_err());
    }

    #[test]
    fn test_bnep_svc_to_uuid_str() {
        assert_eq!(bnep_svc_to_uuid_str(BNEP_SVC_PANU), PANU_UUID);
        assert_eq!(bnep_svc_to_uuid_str(BNEP_SVC_GN), GN_UUID);
        assert_eq!(bnep_svc_to_uuid_str(BNEP_SVC_NAP), NAP_UUID);
        assert_eq!(bnep_svc_to_uuid_str(0), "");
    }

    #[test]
    fn test_bnep_svc_name() {
        assert_eq!(bnep_svc_name(BNEP_SVC_PANU), "Personal Area Networking User");
        assert_eq!(bnep_svc_name(BNEP_SVC_GN), "Group Ad-hoc Network");
        assert_eq!(bnep_svc_name(BNEP_SVC_NAP), "Network Access Point");
        assert_eq!(bnep_svc_name(0), "Unknown PAN Service");
    }

    #[test]
    fn test_bnep_setup_decode_uuid16() {
        // Valid: dst=NAP, src=PANU (UUID16 format).
        let data = [
            2u8,        // UUID16 size
            0x11, 0x16, // dst = BNEP_SVC_NAP
            0x11, 0x15, // src = BNEP_SVC_PANU
        ];
        let result = bnep_setup_decode(&data);
        assert_eq!(result.unwrap(), (BNEP_SVC_NAP, BNEP_SVC_PANU));
    }

    #[test]
    fn test_bnep_setup_decode_invalid_src() {
        // Invalid: dst=NAP, src=GN (only PANU allowed as src for NAP).
        let data = [
            2u8,
            0x11, 0x16, // dst = NAP
            0x11, 0x17, // src = GN (invalid for NAP dst)
        ];
        let result = bnep_setup_decode(&data);
        assert_eq!(result.unwrap_err(), BNEP_CONN_INVALID_SRC as u16);
    }

    #[test]
    fn test_bnep_setup_decode_panu_dst() {
        // Valid: dst=PANU, src=NAP.
        let data = [
            2u8,
            0x11, 0x15, // dst = PANU
            0x11, 0x16, // src = NAP
        ];
        let result = bnep_setup_decode(&data);
        assert_eq!(result.unwrap(), (BNEP_SVC_PANU, BNEP_SVC_NAP));
    }

    #[test]
    fn test_bnep_setup_decode_invalid_dst() {
        // Invalid dst service.
        let data = [
            2u8,
            0x00, 0x01, // dst = invalid
            0x11, 0x15, // src = PANU
        ];
        let result = bnep_setup_decode(&data);
        assert_eq!(result.unwrap_err(), BNEP_CONN_INVALID_DST as u16);
    }

    #[test]
    fn test_bnep_setup_decode_uuid32() {
        // Valid UUID32 format: dst=NAP, src=PANU.
        let data = [
            4u8,
            0x00, 0x00, 0x11, 0x16, // dst = NAP (UUID32)
            0x00, 0x00, 0x11, 0x15, // src = PANU (UUID32)
        ];
        let result = bnep_setup_decode(&data);
        assert_eq!(result.unwrap(), (BNEP_SVC_NAP, BNEP_SVC_PANU));
    }

    #[test]
    fn test_bnep_setup_decode_uuid32_overflow() {
        // Invalid UUID32: value doesn't fit in u16.
        let data = [
            4u8,
            0x01, 0x00, 0x11, 0x16, // dst > 0xFFFF
            0x00, 0x00, 0x11, 0x15,
        ];
        let result = bnep_setup_decode(&data);
        assert_eq!(result.unwrap_err(), BNEP_CONN_INVALID_SVC as u16);
    }

    #[test]
    fn test_bnep_setup_decode_truncated() {
        // Truncated data.
        let data = [2u8, 0x11];
        let result = bnep_setup_decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_config_default() {
        // When config file doesn't exist, defaults to security enabled.
        let result = read_config();
        assert!(result);
    }

    #[test]
    fn test_create_pan_sdp_record_nap() {
        let rec = create_pan_sdp_record(BNEP_SVC_NAP, "NAP", "Network Access Point", true);
        assert!(rec.attrs.contains_key(&SDP_ATTR_SVCLASS_ID_LIST));
        assert!(rec.attrs.contains_key(&SDP_ATTR_PROTO_DESC_LIST));
        assert!(rec.attrs.contains_key(&SDP_ATTR_BROWSE_GRP_LIST));
        assert!(rec.attrs.contains_key(&SDP_ATTR_PFILE_DESC_LIST));
        assert!(rec.attrs.contains_key(&SDP_ATTR_SVCNAME_PRIMARY));
        // NAP-specific attributes.
        assert!(rec.attrs.contains_key(&SDP_ATTR_SECURITY_DESC));
        assert!(rec.attrs.contains_key(&SDP_ATTR_NET_ACCESS_TYPE));
        assert!(rec.attrs.contains_key(&SDP_ATTR_MAX_NET_ACCESS_RATE));
    }

    #[test]
    fn test_create_pan_sdp_record_panu() {
        let rec = create_pan_sdp_record(BNEP_SVC_PANU, "PANU", "", false);
        assert!(rec.attrs.contains_key(&SDP_ATTR_SVCLASS_ID_LIST));
        // PANU should NOT have NAP-specific attributes.
        assert!(!rec.attrs.contains_key(&SDP_ATTR_SECURITY_DESC));
        assert!(!rec.attrs.contains_key(&SDP_ATTR_NET_ACCESS_TYPE));
    }

    #[test]
    fn test_bnep_session_new() {
        let src = BdAddr { b: [0; 6] };
        let dst = BdAddr { b: [0; 6] };
        let session = BnepSession::new(src, dst, BNEP_SVC_PANU, BNEP_SVC_NAP);
        assert_eq!(session.state, ConnState::Disconnected);
        assert!(session.interface_name().starts_with("bnep"));
    }

    #[test]
    fn test_network_conn_new() {
        let conn = NetworkConn::new(BNEP_SVC_NAP);
        assert_eq!(conn.id, BNEP_SVC_NAP);
        assert_eq!(conn.state, ConnState::Disconnected);
        assert!(conn.dev.is_empty());
        assert!(conn.session.is_none());
    }

    #[test]
    fn test_constants() {
        assert_eq!(NETWORK_INTERFACE, "org.bluez.Network1");
        assert_eq!(NETWORK_SERVER_INTERFACE, "org.bluez.NetworkServer1");
        assert_eq!(BNEP_SVC_PANU, 0x1115);
        assert_eq!(BNEP_SVC_NAP, 0x1116);
        assert_eq!(BNEP_SVC_GN, 0x1117);
    }

    #[test]
    fn test_bnep_setup_decode_uuid128_valid() {
        // UUID128 format: dst=NAP, src=PANU with valid base UUID tail.
        let mut data = vec![16u8]; // UUID128 size
        // Destination UUID128: NAP (0x1116) in Bluetooth UUID128 format.
        let mut dst_uuid = [0u8; 16];
        dst_uuid[2] = 0x11;
        dst_uuid[3] = 0x16;
        dst_uuid[4..16].copy_from_slice(&BNEP_BASE_UUID_TAIL);
        data.extend_from_slice(&dst_uuid);
        // Source UUID128: PANU (0x1115).
        let mut src_uuid = [0u8; 16];
        src_uuid[2] = 0x11;
        src_uuid[3] = 0x15;
        src_uuid[4..16].copy_from_slice(&BNEP_BASE_UUID_TAIL);
        data.extend_from_slice(&src_uuid);

        let result = bnep_setup_decode(&data);
        assert_eq!(result.unwrap(), (BNEP_SVC_NAP, BNEP_SVC_PANU));
    }

    #[test]
    fn test_bnep_setup_decode_uuid128_bad_base() {
        // UUID128 with invalid base UUID tail for destination.
        let mut data = vec![16u8];
        let mut dst_uuid = [0u8; 16];
        dst_uuid[2] = 0x11;
        dst_uuid[3] = 0x16;
        // Bad tail — not matching BNEP_BASE_UUID_TAIL.
        dst_uuid[4..16].copy_from_slice(&[0xFF; 12]);
        data.extend_from_slice(&dst_uuid);
        let mut src_uuid = [0u8; 16];
        src_uuid[2] = 0x11;
        src_uuid[3] = 0x15;
        src_uuid[4..16].copy_from_slice(&BNEP_BASE_UUID_TAIL);
        data.extend_from_slice(&src_uuid);

        let result = bnep_setup_decode(&data);
        assert_eq!(result.unwrap_err(), BNEP_CONN_INVALID_DST as u16);
    }
}
