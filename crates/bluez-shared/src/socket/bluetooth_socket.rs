// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! Async Bluetooth socket abstraction replacing `btio/btio.c` and `btio/btio.h`.
//!
//! Provides [`BluetoothSocket`] — an async-ready Bluetooth socket wrapping
//! `libc` POSIX socket operations with [`tokio::io::unix::AsyncFd`]
//! for L2CAP, RFCOMM, SCO, and ISO transport protocols.
//!
//! The C BtIO variadic option API (`BtIOOption` enum with 31 variants) is
//! replaced by a type-safe [`SocketBuilder`] with a fluent builder pattern.
//! GLib `GIOChannel` + `g_io_add_watch` async I/O is replaced by
//! `AsyncFd<OwnedFd>` reactor integration.
//!
//! # Safety
//!
//! This module is a designated FFI boundary for kernel Bluetooth socket
//! operations (`AF_BLUETOOTH`).  The Linux kernel does not expose Bluetooth
//! sockets through any safe Rust abstraction, so raw `libc` calls with
//! `unsafe` blocks are required.  Every `unsafe` block contains a
//! `// SAFETY:` comment documenting the invariant that makes it sound.
#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use nix::errno::Errno;
use thiserror::Error;

use crate::sys::bluetooth::{
    AF_BLUETOOTH, BASE_MAX_LENGTH, BDADDR_ANY, BDADDR_BREDR, BDADDR_LE_PUBLIC, BT_DEFER_SETUP,
    BT_FLUSHABLE, BT_ISO_BASE, BT_ISO_QOS, BT_MODE, BT_MODE_BASIC, BT_MODE_ERTM,
    BT_MODE_EXT_FLOWCTL, BT_MODE_LE_FLOWCTL, BT_MODE_STREAMING, BT_PHY, BT_RCVMTU, BT_SECURITY,
    BT_SNDMTU, BT_VOICE, BTPROTO_ISO, BTPROTO_L2CAP, BTPROTO_RFCOMM, BTPROTO_SCO, SOL_BLUETOOTH,
    SOL_L2CAP, SOL_RFCOMM, SOL_SCO, bdaddr_t, bt_iso_qos, bt_security, bt_voice,
};
use crate::sys::iso::{ISO_MAX_NUM_BIS, sockaddr_iso, sockaddr_iso_with_bc};
use crate::sys::l2cap::{
    L2CAP_CONNINFO, L2CAP_LM, L2CAP_LM_AUTH, L2CAP_LM_ENCRYPT, L2CAP_LM_MASTER, L2CAP_LM_SECURE,
    L2CAP_MODE_BASIC, L2CAP_MODE_ECRED, L2CAP_MODE_ERTM, L2CAP_MODE_LE_FLOWCTL,
    L2CAP_MODE_STREAMING, L2CAP_OPTIONS, l2cap_conninfo, l2cap_options, sockaddr_l2,
};
use crate::sys::rfcomm::{
    RFCOMM_CONNINFO, RFCOMM_LM, RFCOMM_LM_AUTH, RFCOMM_LM_ENCRYPT, RFCOMM_LM_MASTER,
    RFCOMM_LM_SECURE, rfcomm_conninfo, sockaddr_rc,
};
use crate::sys::sco::{SCO_CONNINFO, SCO_OPTIONS, sco_conninfo, sco_options, sockaddr_sco};

// ---------------------------------------------------------------------------
// Error types — replaces GLib GError / BT_IO_ERROR domain
// ---------------------------------------------------------------------------

/// Bluetooth socket error type encompassing all failure modes.
#[derive(Debug, Error)]
pub enum BtSocketError {
    /// Invalid or conflicting arguments supplied to builder or setter.
    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),

    /// A POSIX socket syscall failed.
    #[error("Socket operation failed: {0}")]
    SocketError(#[from] Errno),

    /// A standard I/O error (used by tokio `AsyncFd` operations).
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Non-blocking connect completed with an error.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Operation requires a connected socket but the socket is not connected.
    #[error("Not connected")]
    NotConnected,

    /// Attempted to connect a socket that is already connected.
    #[error("Already connected")]
    AlreadyConnected,

    /// Operation not supported for the current transport type.
    #[error("Operation not supported for this transport")]
    NotSupported,
}

/// Convenience alias used throughout this module.
pub type Result<T> = std::result::Result<T, BtSocketError>;

// ---------------------------------------------------------------------------
// BtTransport — replaces BtIOType from btio.c line 48-54
// ---------------------------------------------------------------------------

/// Bluetooth transport protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BtTransport {
    /// L2CAP logical link (SEQPACKET).
    L2cap,
    /// RFCOMM serial emulation (STREAM).
    Rfcomm,
    /// SCO synchronous voice link (SEQPACKET).
    Sco,
    /// ISO isochronous audio link (SEQPACKET).
    Iso,
}

impl BtTransport {
    /// Convert from a raw kernel protocol number (`BTPROTO_*`).
    ///
    /// Returns `None` for unrecognised values.
    #[must_use]
    pub fn from_protocol(proto: i32) -> Option<Self> {
        match proto {
            p if p == BTPROTO_L2CAP => Some(BtTransport::L2cap),
            p if p == BTPROTO_RFCOMM => Some(BtTransport::Rfcomm),
            p if p == BTPROTO_SCO => Some(BtTransport::Sco),
            p if p == BTPROTO_ISO => Some(BtTransport::Iso),
            _ => None,
        }
    }

    /// Convert to the raw kernel protocol number (`BTPROTO_*`).
    #[must_use]
    pub fn to_protocol(self) -> i32 {
        match self {
            BtTransport::L2cap => BTPROTO_L2CAP,
            BtTransport::Rfcomm => BTPROTO_RFCOMM,
            BtTransport::Sco => BTPROTO_SCO,
            BtTransport::Iso => BTPROTO_ISO,
        }
    }

    /// Return the `SOCK_*` type constant for this transport.
    fn sock_type(self) -> libc::c_int {
        match self {
            BtTransport::L2cap | BtTransport::Sco | BtTransport::Iso => libc::SOCK_SEQPACKET,
            BtTransport::Rfcomm => libc::SOCK_STREAM,
        }
    }
}

// ---------------------------------------------------------------------------
// SecLevel — replaces BtIOSecLevel from btio.h line 27-32
// ---------------------------------------------------------------------------

/// Bluetooth security level matching `BT_SECURITY_*` kernel values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SecLevel {
    /// SDP-only — no security required.
    Sdp = 0,
    /// Low security — authentication (for LE: unauthenticated pairing).
    Low = 1,
    /// Medium security — authentication + encryption.
    Medium = 2,
    /// High security — authenticated pairing + encryption.
    High = 3,
}

impl SecLevel {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => SecLevel::Sdp,
            1 => SecLevel::Low,
            2 => SecLevel::Medium,
            _ => SecLevel::High,
        }
    }
}

impl From<u8> for SecLevel {
    fn from(v: u8) -> Self {
        Self::from_u8(v)
    }
}

impl From<SecLevel> for u8 {
    fn from(l: SecLevel) -> u8 {
        l as u8
    }
}

// ---------------------------------------------------------------------------
// L2capMode — replaces BtIOMode from btio.h line 34-41
// ---------------------------------------------------------------------------

/// L2CAP channel mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum L2capMode {
    /// Basic mode (unreliable, no retransmission).
    Basic = 0,
    /// Enhanced Retransmission Mode.
    Ertm = 1,
    /// Streaming mode (unidirectional, isochronous-ish).
    Streaming = 2,
    /// LE Flow Control mode (LE CoC).
    LeFlowctl = 3,
    /// Extended flow control / Enhanced Credit-Based (L2CAP ECRED).
    ExtFlowctl = 4,
    /// ISO transport (not a real L2CAP mode — used for transport detection).
    Iso = 5,
}

impl L2capMode {
    /// Convert to the kernel `L2CAP_MODE_*` wire value used in
    /// [`l2cap_options::mode`].
    ///
    /// Returns `None` for [`L2capMode::Iso`] which is not a real L2CAP mode.
    #[must_use]
    pub fn to_l2cap_mode(self) -> Option<u8> {
        match self {
            L2capMode::Basic => Some(L2CAP_MODE_BASIC),
            L2capMode::Ertm => Some(L2CAP_MODE_ERTM),
            L2capMode::Streaming => Some(L2CAP_MODE_STREAMING),
            L2capMode::LeFlowctl => Some(L2CAP_MODE_LE_FLOWCTL),
            L2capMode::ExtFlowctl => Some(L2CAP_MODE_ECRED),
            L2capMode::Iso => None,
        }
    }

    /// Convert to the kernel `BT_MODE_*` value used with `BT_MODE` sockopt.
    fn to_bt_mode(self) -> Option<u8> {
        match self {
            L2capMode::Basic => Some(BT_MODE_BASIC),
            L2capMode::Ertm => Some(BT_MODE_ERTM),
            L2capMode::Streaming => Some(BT_MODE_STREAMING),
            L2capMode::LeFlowctl => Some(BT_MODE_LE_FLOWCTL),
            L2capMode::ExtFlowctl => Some(BT_MODE_EXT_FLOWCTL),
            L2capMode::Iso => None,
        }
    }

    /// Construct from kernel `L2CAP_MODE_*` wire value.
    fn from_l2cap_mode(v: u8) -> Self {
        match v {
            x if x == L2CAP_MODE_BASIC => L2capMode::Basic,
            x if x == L2CAP_MODE_ERTM => L2capMode::Ertm,
            x if x == L2CAP_MODE_STREAMING => L2capMode::Streaming,
            x if x == L2CAP_MODE_LE_FLOWCTL => L2capMode::LeFlowctl,
            x if x == L2CAP_MODE_ECRED => L2capMode::ExtFlowctl,
            _ => L2capMode::Basic,
        }
    }

    /// Construct from kernel `BT_MODE_*` value.
    fn from_bt_mode(v: u8) -> Self {
        match v {
            x if x == BT_MODE_BASIC => L2capMode::Basic,
            x if x == BT_MODE_ERTM => L2capMode::Ertm,
            x if x == BT_MODE_STREAMING => L2capMode::Streaming,
            x if x == BT_MODE_LE_FLOWCTL => L2capMode::LeFlowctl,
            x if x == BT_MODE_EXT_FLOWCTL => L2capMode::ExtFlowctl,
            _ => L2capMode::Basic,
        }
    }
}

// ---------------------------------------------------------------------------
// SocketPriority
// ---------------------------------------------------------------------------

/// Socket priority level (maps to `SO_PRIORITY` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SocketPriority {
    /// Default priority.
    Normal = 0,
    /// Elevated priority (value 6 matching btio.c).
    High = 6,
}

impl SocketPriority {
    fn from_i32(v: i32) -> Self {
        if v >= 6 { SocketPriority::High } else { SocketPriority::Normal }
    }
}

// ---------------------------------------------------------------------------
// SocketOptions — replaces `struct set_opts` from btio.c lines 56-90
// ---------------------------------------------------------------------------

/// Socket configuration options, used by [`SocketBuilder`] and
/// [`BluetoothSocket::set_options`].
///
/// `Option::None` fields indicate "leave at kernel default" (corresponding
/// to the `-1` / unset sentinel in the C `struct set_opts`).
#[derive(Clone)]
pub struct SocketOptions {
    /// Source BD address (default: `BDADDR_ANY`).
    pub src: bdaddr_t,
    /// Source address type (default: `BDADDR_BREDR`).
    pub src_type: u8,
    /// Destination BD address (default: `BDADDR_ANY`).
    pub dst: bdaddr_t,
    /// Destination address type (default: `BDADDR_BREDR`).
    pub dst_type: u8,
    /// Deferred setup timeout in seconds (default: 30).
    pub defer: u32,
    /// Security level.
    pub sec_level: Option<SecLevel>,
    /// RFCOMM channel number.
    pub channel: Option<u16>,
    /// L2CAP PSM (Protocol/Service Multiplexer).
    pub psm: Option<u16>,
    /// L2CAP CID (Channel Identifier).
    pub cid: Option<u16>,
    /// Overall MTU (sets both IMTU and OMTU when used in builder).
    pub mtu: Option<u16>,
    /// Incoming (receive) MTU.
    pub imtu: Option<u16>,
    /// Outgoing (send) MTU.
    pub omtu: Option<u16>,
    /// Central (master) role preference (`None` = kernel default).
    pub central: Option<bool>,
    /// L2CAP channel mode (default: Basic).
    pub mode: L2capMode,
    /// Flushable flag for L2CAP (`None` = kernel default).
    pub flushable: Option<bool>,
    /// Socket priority.
    pub priority: SocketPriority,
    /// SCO voice setting.
    pub voice: Option<u16>,
    /// PHY preference bitmask.
    pub phy: Option<u32>,
    /// ACL handle (read-only, set during connection).
    pub handle: Option<u16>,
    /// Encryption key size (read-only via getter).
    pub key_size: Option<u8>,
    /// ISO Quality-of-Service parameters.
    pub qos: Option<bt_iso_qos>,
    /// ISO Broadcast Audio Source Endpoint (BASE) data.
    pub base: Option<Vec<u8>>,
    /// ISO broadcast SID.
    pub iso_bc_sid: Option<u8>,
    /// ISO broadcast number of BIS streams.
    pub iso_bc_num_bis: Option<u8>,
    /// ISO broadcast BIS indices.
    pub iso_bc_bis: Vec<u8>,
}

impl Default for SocketOptions {
    /// Defaults match btio.c `parse_set_opts` initial values exactly.
    fn default() -> Self {
        Self {
            src: BDADDR_ANY,
            src_type: BDADDR_BREDR,
            dst: BDADDR_ANY,
            dst_type: BDADDR_BREDR,
            defer: 30,
            sec_level: None,
            channel: None,
            psm: None,
            cid: None,
            mtu: None,
            imtu: None,
            omtu: None,
            central: None,
            mode: L2capMode::Basic,
            flushable: None,
            priority: SocketPriority::Normal,
            voice: None,
            phy: None,
            handle: None,
            key_size: None,
            qos: None,
            base: None,
            iso_bc_sid: None,
            iso_bc_num_bis: None,
            iso_bc_bis: Vec::new(),
        }
    }
}

impl std::fmt::Debug for SocketOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketOptions")
            .field("src", &self.src)
            .field("src_type", &self.src_type)
            .field("dst", &self.dst)
            .field("dst_type", &self.dst_type)
            .field("defer", &self.defer)
            .field("sec_level", &self.sec_level)
            .field("channel", &self.channel)
            .field("psm", &self.psm)
            .field("cid", &self.cid)
            .field("mtu", &self.mtu)
            .field("imtu", &self.imtu)
            .field("omtu", &self.omtu)
            .field("central", &self.central)
            .field("mode", &self.mode)
            .field("flushable", &self.flushable)
            .field("priority", &self.priority)
            .field("voice", &self.voice)
            .field("phy", &self.phy)
            .field("handle", &self.handle)
            .field("key_size", &self.key_size)
            .field("qos", &self.qos.is_some())
            .field("base", &self.base)
            .field("iso_bc_sid", &self.iso_bc_sid)
            .field("iso_bc_num_bis", &self.iso_bc_num_bis)
            .field("iso_bc_bis", &self.iso_bc_bis)
            .finish()
    }
}

// ===========================================================================
// Low-level syscall helpers
// ===========================================================================

/// Create a raw `AF_BLUETOOTH` socket with `SOCK_CLOEXEC | SOCK_NONBLOCK`.
fn bt_socket_raw(sock_type: libc::c_int, protocol: libc::c_int) -> Result<OwnedFd> {
    // SAFETY: socket() is a safe syscall with valid AF_BLUETOOTH constants.
    let fd = unsafe {
        libc::socket(
            AF_BLUETOOTH as libc::c_int,
            sock_type | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            protocol,
        )
    };
    if fd < 0 {
        return Err(BtSocketError::SocketError(Errno::last()));
    }
    // SAFETY: fd >= 0 is a valid newly-created file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Bind a socket to a typed sockaddr structure.
fn bt_bind<T>(fd: RawFd, addr: &T) -> Result<()> {
    // SAFETY: addr is a valid reference to a repr(C) sockaddr struct.
    let ret = unsafe {
        libc::bind(
            fd,
            (addr as *const T).cast::<libc::sockaddr>(),
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 { Err(BtSocketError::SocketError(Errno::last())) } else { Ok(()) }
}

/// Bind with explicit address length (for variable-size ISO broadcast addrs).
fn bt_bind_len(fd: RawFd, addr: *const u8, len: libc::socklen_t) -> Result<()> {
    // SAFETY: addr points to a valid sockaddr of at least `len` bytes.
    let ret = unsafe { libc::bind(fd, addr.cast::<libc::sockaddr>(), len) };
    if ret < 0 { Err(BtSocketError::SocketError(Errno::last())) } else { Ok(()) }
}

/// Non-blocking connect — `EINPROGRESS`/`EAGAIN` treated as success.
fn bt_connect<T>(fd: RawFd, addr: &T) -> Result<()> {
    // SAFETY: addr is a valid repr(C) sockaddr struct.
    let ret = unsafe {
        libc::connect(
            fd,
            (addr as *const T).cast::<libc::sockaddr>(),
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = Errno::last();
        if err == Errno::EINPROGRESS || err == Errno::EAGAIN {
            Ok(())
        } else {
            Err(BtSocketError::SocketError(err))
        }
    } else {
        Ok(())
    }
}

/// Typed `setsockopt` wrapper.
fn bt_setsockopt<T: Copy>(fd: RawFd, level: libc::c_int, name: libc::c_int, val: &T) -> Result<()> {
    // SAFETY: val is a valid reference to a Copy type of known size.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (val as *const T).cast::<libc::c_void>(),
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 { Err(BtSocketError::SocketError(Errno::last())) } else { Ok(()) }
}

/// Variable-length `setsockopt` wrapper for byte slices.
fn bt_setsockopt_bytes(fd: RawFd, level: libc::c_int, name: libc::c_int, val: &[u8]) -> Result<()> {
    // SAFETY: val is a valid byte slice.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            val.as_ptr().cast::<libc::c_void>(),
            val.len() as libc::socklen_t,
        )
    };
    if ret < 0 { Err(BtSocketError::SocketError(Errno::last())) } else { Ok(()) }
}

/// Typed `getsockopt` wrapper.
fn bt_getsockopt<T: Copy>(fd: RawFd, level: libc::c_int, name: libc::c_int) -> Result<T> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut val: T = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: zeroed buffer of correct size; kernel writes at most size_of::<T>().
    let ret = unsafe {
        libc::getsockopt(fd, level, name, (&raw mut val).cast::<libc::c_void>(), &raw mut len)
    };
    if ret < 0 { Err(BtSocketError::SocketError(Errno::last())) } else { Ok(val) }
}

/// Variable-length `getsockopt` returning byte count written by kernel.
fn bt_getsockopt_bytes(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    buf: &mut [u8],
) -> Result<usize> {
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: buf is a valid mutable slice.
    let ret = unsafe {
        libc::getsockopt(fd, level, name, buf.as_mut_ptr().cast::<libc::c_void>(), &raw mut len)
    };
    if ret < 0 { Err(BtSocketError::SocketError(Errno::last())) } else { Ok(len as usize) }
}

/// Typed `getsockname`.
fn bt_getsockname<T: Copy>(fd: RawFd) -> Result<T> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut addr: T = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: zeroed buffer of correct size.
    let ret =
        unsafe { libc::getsockname(fd, (&raw mut addr).cast::<libc::sockaddr>(), &raw mut len) };
    if ret < 0 { Err(BtSocketError::SocketError(Errno::last())) } else { Ok(addr) }
}

/// Typed `getpeername`.
fn bt_getpeername<T: Copy>(fd: RawFd) -> Result<T> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut addr: T = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: zeroed buffer of correct size.
    let ret =
        unsafe { libc::getpeername(fd, (&raw mut addr).cast::<libc::sockaddr>(), &raw mut len) };
    if ret < 0 { Err(BtSocketError::SocketError(Errno::last())) } else { Ok(addr) }
}

/// `listen(2)` wrapper.
fn bt_listen(fd: RawFd, backlog: libc::c_int) -> Result<()> {
    // SAFETY: fd is a valid socket file descriptor.
    let ret = unsafe { libc::listen(fd, backlog) };
    if ret < 0 { Err(BtSocketError::SocketError(Errno::last())) } else { Ok(()) }
}

/// Check `SO_ERROR` on a socket (used after non-blocking connect).
fn bt_so_error(fd: RawFd) -> Result<i32> {
    bt_getsockopt::<libc::c_int>(fd, libc::SOL_SOCKET, libc::SO_ERROR)
}

// ===========================================================================
// Public safe socket-option helpers (used by att/transport.rs and others)
// ===========================================================================

/// Query a raw integer socket option (safe wrapper for `getsockopt`).
///
/// This is a public, safe API for use by other crate modules (e.g.,
/// `att/transport.rs`) that need to query integer-typed socket options
/// without duplicating unsafe `getsockopt` calls.
pub fn bt_sockopt_get_int(fd: RawFd, level: libc::c_int, optname: libc::c_int) -> io::Result<i32> {
    let mut val: libc::c_int = 0;
    let mut len: libc::socklen_t = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is a valid open socket descriptor; `val` is a properly
    // aligned c_int buffer with `len` set to its size.
    let ret = unsafe {
        libc::getsockopt(fd, level, optname, (&raw mut val).cast::<libc::c_void>(), &raw mut len)
    };
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(val) }
}

/// Set a raw integer socket option (safe wrapper for `setsockopt`).
///
/// Public, safe API for use by other crate modules that need to set
/// integer-typed socket options without duplicating unsafe code.
pub fn bt_sockopt_set_int(
    fd: RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    val: libc::c_int,
) -> io::Result<()> {
    let len: libc::socklen_t = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is a valid open socket; `val` points to a single c_int.
    let ret = unsafe {
        libc::setsockopt(fd, level, optname, (&raw const val).cast::<libc::c_void>(), len)
    };
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Get the `bt_security` structure for a Bluetooth socket.
///
/// Safe wrapper around `getsockopt(SOL_BLUETOOTH, BT_SECURITY)`.
pub fn bt_sockopt_get_security(fd: RawFd) -> io::Result<bt_security> {
    let mut sec = bt_security { level: 0, key_size: 0 };
    let mut len: libc::socklen_t = mem::size_of::<bt_security>() as libc::socklen_t;
    // SAFETY: fd is a valid Bluetooth socket; sec is properly sized.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_BLUETOOTH,
            BT_SECURITY,
            (&raw mut sec).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(sec) }
}

/// Set the `bt_security` structure on a Bluetooth socket.
///
/// Safe wrapper around `setsockopt(SOL_BLUETOOTH, BT_SECURITY)`.
pub fn bt_sockopt_set_security(fd: RawFd, sec: &bt_security) -> io::Result<()> {
    let len: libc::socklen_t = mem::size_of::<bt_security>() as libc::socklen_t;
    // SAFETY: fd is a valid Bluetooth socket; sec is properly sized.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_BLUETOOTH,
            BT_SECURITY,
            (sec as *const bt_security).cast::<libc::c_void>(),
            len,
        )
    };
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Get the L2CAP options (for MTU query) on a Bluetooth socket.
///
/// Safe wrapper around `getsockopt(SOL_L2CAP, L2CAP_OPTIONS)`.
pub fn bt_sockopt_get_l2cap_options(fd: RawFd) -> io::Result<l2cap_options> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer types.
    let mut opts: l2cap_options = unsafe { mem::zeroed() };
    let mut len: libc::socklen_t = mem::size_of::<l2cap_options>() as libc::socklen_t;
    // SAFETY: fd is a valid L2CAP socket; opts is properly sized.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_L2CAP,
            L2CAP_OPTIONS,
            (&raw mut opts).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(opts) }
}

/// Retrieve the local socket address as `sockaddr_l2`.
///
/// Safe wrapper around `getsockname(2)` for L2CAP sockets.
pub fn bt_getsockname_l2(fd: RawFd) -> io::Result<sockaddr_l2> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut addr: sockaddr_l2 = unsafe { mem::zeroed() };
    let mut len: libc::socklen_t = mem::size_of::<sockaddr_l2>() as libc::socklen_t;
    // SAFETY: fd is a valid L2CAP socket; addr is properly sized.
    let ret =
        unsafe { libc::getsockname(fd, (&raw mut addr).cast::<libc::sockaddr>(), &raw mut len) };
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(addr) }
}

/// Set `SO_PRIORITY` on a raw file descriptor.
///
/// Safe wrapper for `setsockopt(SOL_SOCKET, SO_PRIORITY)`.
pub fn bt_sockopt_set_priority(fd: RawFd, priority: i32) -> io::Result<()> {
    bt_sockopt_set_int(fd, libc::SOL_SOCKET, libc::SO_PRIORITY, priority)
}

/// Write data to a raw file descriptor using `writev` (scatter-gather).
///
/// Safe wrapper around `nix::sys::uio::writev` that encapsulates the
/// `BorrowedFd::borrow_raw` unsafe call.
pub fn bt_writev(fd: RawFd, data: &[io::IoSlice<'_>]) -> io::Result<usize> {
    // SAFETY: The caller guarantees `fd` is a valid, open file descriptor
    // obtained from a BluetoothSocket or similar owner that keeps it alive.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    nix::sys::uio::writev(borrowed, data).map_err(|e| io::Error::from_raw_os_error(e as i32))
}

// ===========================================================================
// Public address query helpers
// ===========================================================================

/// Get the local (source) Bluetooth address and address-type for a raw fd.
///
/// This is a public safe wrapper around the internal `get_src` helper,
/// dispatching by transport type (`L2CAP`, `RFCOMM`, `SCO`, `ISO`).
pub fn bt_get_source_address(fd: RawFd, transport: BtTransport) -> Result<(bdaddr_t, u8)> {
    get_src(fd, transport)
}

/// Get the remote (destination) Bluetooth address and address-type for a raw fd.
///
/// This is a public safe wrapper around the internal `get_dst` helper,
/// dispatching by transport type (`L2CAP`, `RFCOMM`, `SCO`, `ISO`).
pub fn bt_get_dest_address(fd: RawFd, transport: BtTransport) -> Result<(bdaddr_t, u8)> {
    get_dst(fd, transport)
}

// ===========================================================================
// Transport-specific bind operations
// ===========================================================================

/// Bind an L2CAP socket (btio.c lines 290-316).
fn l2cap_bind(fd: RawFd, src: &bdaddr_t, src_type: u8, psm: u16, cid: u16) -> Result<()> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut addr: sockaddr_l2 = unsafe { mem::zeroed() };
    addr.l2_family = AF_BLUETOOTH as u16;
    addr.l2_bdaddr = *src;
    addr.l2_bdaddr_type = src_type;
    addr.l2_psm = psm.to_le();
    addr.l2_cid = cid.to_le();
    bt_bind(fd, &addr)
}

/// Bind an RFCOMM socket (btio.c lines 698-714).
fn rfcomm_bind(fd: RawFd, src: &bdaddr_t, channel: u8) -> Result<()> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut addr: sockaddr_rc = unsafe { mem::zeroed() };
    addr.rc_family = AF_BLUETOOTH as u16;
    addr.rc_bdaddr = *src;
    addr.rc_channel = channel;
    bt_bind(fd, &addr)
}

/// Bind a SCO socket (btio.c lines 755-771).
fn sco_bind(fd: RawFd, src: &bdaddr_t) -> Result<()> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut addr: sockaddr_sco = unsafe { mem::zeroed() };
    addr.sco_family = AF_BLUETOOTH as u16;
    addr.sco_bdaddr = *src;
    bt_bind(fd, &addr)
}

/// Bind an ISO socket (btio.c lines 795-821).
///
/// For broadcast servers (`dst` ≠ `BDADDR_ANY`), appends `sockaddr_iso_bc`
/// with BIS selection parameters.
fn iso_bind(
    fd: RawFd,
    src: &bdaddr_t,
    src_type: u8,
    dst: &bdaddr_t,
    dst_type: u8,
    sid: u8,
    num_bis: u8,
    bis: &[u8],
) -> Result<()> {
    if dst.b != BDADDR_ANY.b {
        // Broadcast bind — use combined struct
        // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
        let mut full: sockaddr_iso_with_bc = unsafe { mem::zeroed() };
        full.base.iso_family = AF_BLUETOOTH as u16;
        full.base.iso_bdaddr = *src;
        full.base.iso_bdaddr_type = src_type;
        full.bc.bc_bdaddr = *dst;
        full.bc.bc_bdaddr_type = dst_type;
        full.bc.bc_sid = sid;
        full.bc.bc_num_bis = num_bis;
        let copy_len = bis.len().min(ISO_MAX_NUM_BIS as usize);
        full.bc.bc_bis[..copy_len].copy_from_slice(&bis[..copy_len]);
        bt_bind_len(
            fd,
            (&raw const full).cast::<u8>(),
            mem::size_of::<sockaddr_iso_with_bc>() as libc::socklen_t,
        )
    } else {
        // Unicast bind
        // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
        let mut addr: sockaddr_iso = unsafe { mem::zeroed() };
        addr.iso_family = AF_BLUETOOTH as u16;
        addr.iso_bdaddr = *src;
        addr.iso_bdaddr_type = src_type;
        bt_bind(fd, &addr)
    }
}

// ===========================================================================
// Transport-specific connect operations
// ===========================================================================

/// L2CAP connect (btio.c lines 318-346).
fn l2cap_connect(fd: RawFd, dst: &bdaddr_t, dst_type: u8, psm: u16, cid: u16) -> Result<()> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut addr: sockaddr_l2 = unsafe { mem::zeroed() };
    addr.l2_family = AF_BLUETOOTH as u16;
    addr.l2_bdaddr = *dst;
    addr.l2_bdaddr_type = dst_type;
    addr.l2_psm = psm.to_le();
    addr.l2_cid = cid.to_le();
    bt_connect(fd, &addr)
}

/// RFCOMM connect (btio.c lines 716-737).
fn rfcomm_connect(fd: RawFd, dst: &bdaddr_t, channel: u8) -> Result<()> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut addr: sockaddr_rc = unsafe { mem::zeroed() };
    addr.rc_family = AF_BLUETOOTH as u16;
    addr.rc_bdaddr = *dst;
    addr.rc_channel = channel;
    bt_connect(fd, &addr)
}

/// SCO connect (btio.c lines 773-793).
fn sco_connect(fd: RawFd, dst: &bdaddr_t) -> Result<()> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut addr: sockaddr_sco = unsafe { mem::zeroed() };
    addr.sco_family = AF_BLUETOOTH as u16;
    addr.sco_bdaddr = *dst;
    bt_connect(fd, &addr)
}

/// ISO connect (btio.c lines 773-793 adapted for ISO).
fn iso_connect(fd: RawFd, dst: &bdaddr_t, dst_type: u8) -> Result<()> {
    // SAFETY: zeroing a repr(C) packed struct is valid; all fields are integer/array types.
    let mut addr: sockaddr_iso = unsafe { mem::zeroed() };
    addr.iso_family = AF_BLUETOOTH as u16;
    addr.iso_bdaddr = *dst;
    addr.iso_bdaddr_type = dst_type;
    bt_connect(fd, &addr)
}

// ===========================================================================
// Security level helpers (btio.c lines 348-538)
// ===========================================================================

/// Map `SecLevel` to L2CAP link-manager security flags.
fn sec_level_to_lm_l2cap(level: SecLevel) -> u16 {
    match level {
        SecLevel::Sdp => 0,
        SecLevel::Low => L2CAP_LM_AUTH,
        SecLevel::Medium => L2CAP_LM_AUTH | L2CAP_LM_ENCRYPT,
        SecLevel::High => L2CAP_LM_AUTH | L2CAP_LM_ENCRYPT | L2CAP_LM_SECURE,
    }
}

/// Map L2CAP link-manager flags to `SecLevel`.
fn lm_l2cap_to_sec_level(flags: u16) -> SecLevel {
    if flags & L2CAP_LM_SECURE != 0 {
        SecLevel::High
    } else if flags & L2CAP_LM_ENCRYPT != 0 {
        SecLevel::Medium
    } else if flags & L2CAP_LM_AUTH != 0 {
        SecLevel::Low
    } else {
        SecLevel::Sdp
    }
}

/// Map `SecLevel` to RFCOMM link-manager security flags.
fn sec_level_to_lm_rfcomm(level: SecLevel) -> u32 {
    match level {
        SecLevel::Sdp => 0,
        SecLevel::Low => RFCOMM_LM_AUTH,
        SecLevel::Medium => RFCOMM_LM_AUTH | RFCOMM_LM_ENCRYPT,
        SecLevel::High => RFCOMM_LM_AUTH | RFCOMM_LM_ENCRYPT | RFCOMM_LM_SECURE,
    }
}

/// Map RFCOMM link-manager flags to `SecLevel`.
fn lm_rfcomm_to_sec_level(flags: u32) -> SecLevel {
    if flags & RFCOMM_LM_SECURE != 0 {
        SecLevel::High
    } else if flags & RFCOMM_LM_ENCRYPT != 0 {
        SecLevel::Medium
    } else if flags & RFCOMM_LM_AUTH != 0 {
        SecLevel::Low
    } else {
        SecLevel::Sdp
    }
}

/// Set L2CAP link-manager fallback security (btio.c `l2cap_set_lm`).
fn l2cap_set_lm(fd: RawFd, level: SecLevel) -> Result<()> {
    let mut lm: u16 = bt_getsockopt(fd, SOL_L2CAP, L2CAP_LM as libc::c_int)?;
    lm &= !(L2CAP_LM_AUTH | L2CAP_LM_ENCRYPT | L2CAP_LM_SECURE);
    lm |= sec_level_to_lm_l2cap(level);
    bt_setsockopt(fd, SOL_L2CAP, L2CAP_LM as libc::c_int, &lm)
}

/// Get L2CAP link-manager fallback security (btio.c `l2cap_get_lm`).
fn l2cap_get_lm(fd: RawFd) -> Result<SecLevel> {
    let lm: u16 = bt_getsockopt(fd, SOL_L2CAP, L2CAP_LM as libc::c_int)?;
    Ok(lm_l2cap_to_sec_level(lm))
}

/// Set RFCOMM link-manager fallback security (btio.c `rfcomm_set_lm`).
fn rfcomm_set_lm(fd: RawFd, level: SecLevel) -> Result<()> {
    let mut lm: u32 = bt_getsockopt(fd, SOL_RFCOMM, RFCOMM_LM as libc::c_int)?;
    lm &= !(RFCOMM_LM_AUTH | RFCOMM_LM_ENCRYPT | RFCOMM_LM_SECURE);
    lm |= sec_level_to_lm_rfcomm(level);
    bt_setsockopt(fd, SOL_RFCOMM, RFCOMM_LM as libc::c_int, &lm)
}

/// Get RFCOMM link-manager fallback security (btio.c `rfcomm_get_lm`).
fn rfcomm_get_lm(fd: RawFd) -> Result<SecLevel> {
    let lm: u32 = bt_getsockopt(fd, SOL_RFCOMM, RFCOMM_LM as libc::c_int)?;
    Ok(lm_rfcomm_to_sec_level(lm))
}

/// Set security level via `BT_SECURITY` with `ENOPROTOOPT` fallback to
/// LM-based flags (btio.c lines 389-429 `set_sec_level`).
fn set_sec_level(fd: RawFd, transport: BtTransport, level: SecLevel) -> Result<()> {
    let sec = bt_security { level: level as u8, key_size: 0 };
    match bt_setsockopt(fd, SOL_BLUETOOTH, BT_SECURITY as libc::c_int, &sec) {
        Ok(()) => Ok(()),
        Err(BtSocketError::SocketError(Errno::ENOPROTOOPT)) => {
            // Kernel too old for BT_SECURITY — fall back to LM flags.
            match transport {
                BtTransport::L2cap => l2cap_set_lm(fd, level),
                BtTransport::Rfcomm => rfcomm_set_lm(fd, level),
                _ => Err(BtSocketError::NotSupported),
            }
        }
        Err(e) => Err(e),
    }
}

/// Get security level via `BT_SECURITY` with `ENOPROTOOPT` fallback
/// (btio.c lines 431-468 `get_sec_level`).
fn get_sec_level(fd: RawFd, transport: BtTransport) -> Result<SecLevel> {
    match bt_getsockopt::<bt_security>(fd, SOL_BLUETOOTH, BT_SECURITY as libc::c_int) {
        Ok(sec) => Ok(SecLevel::from_u8(sec.level)),
        Err(BtSocketError::SocketError(Errno::ENOPROTOOPT)) => match transport {
            BtTransport::L2cap => l2cap_get_lm(fd),
            BtTransport::Rfcomm => rfcomm_get_lm(fd),
            _ => Err(BtSocketError::NotSupported),
        },
        Err(e) => Err(e),
    }
}

/// Get encryption key size from `BT_SECURITY` (btio.c `get_key_size`).
fn get_key_size(fd: RawFd) -> Result<u8> {
    let sec: bt_security = bt_getsockopt(fd, SOL_BLUETOOTH, BT_SECURITY as libc::c_int)?;
    Ok(sec.key_size)
}

/// Get PHY preferences via `BT_PHY`.
fn get_phy(fd: RawFd) -> Result<u32> {
    bt_getsockopt(fd, SOL_BLUETOOTH, BT_PHY as libc::c_int)
}

/// Set `SO_PRIORITY` (btio.c `set_priority`).
fn set_priority(fd: RawFd, priority: SocketPriority) -> Result<()> {
    let val: libc::c_int = priority as libc::c_int;
    bt_setsockopt(fd, libc::SOL_SOCKET, libc::SO_PRIORITY, &val)
}

/// Get `SO_PRIORITY` (btio.c `get_priority`).
fn get_priority(fd: RawFd) -> Result<SocketPriority> {
    let val: libc::c_int = bt_getsockopt(fd, libc::SOL_SOCKET, libc::SO_PRIORITY)?;
    Ok(SocketPriority::from_i32(val))
}

// ===========================================================================
// L2CAP option helpers (btio.c lines 547-696)
// ===========================================================================

/// Set LE incoming MTU via `BT_RCVMTU`.
fn set_le_imtu(fd: RawFd, imtu: u16) -> Result<()> {
    bt_setsockopt(fd, SOL_BLUETOOTH, BT_RCVMTU as libc::c_int, &imtu)
}

/// Set LE mode via `BT_MODE`.
fn set_le_mode(fd: RawFd, mode: L2capMode) -> Result<()> {
    if let Some(bt_mode) = mode.to_bt_mode() {
        bt_setsockopt(fd, SOL_BLUETOOTH, BT_MODE as libc::c_int, &bt_mode)
    } else {
        Err(BtSocketError::NotSupported)
    }
}

/// Set L2CAP options (IMTU, OMTU, mode) via `L2CAP_OPTIONS` sockopt.
///
/// Falls back to LE-specific `BT_RCVMTU`/`BT_MODE` if `L2CAP_OPTIONS`
/// is not supported (btio.c `set_l2opts` lines 584-638).
fn set_l2opts(fd: RawFd, imtu: Option<u16>, omtu: Option<u16>, mode: L2capMode) -> Result<()> {
    let l2cap_mode = mode.to_l2cap_mode().unwrap_or(0xFF);

    match bt_getsockopt::<l2cap_options>(fd, SOL_L2CAP, L2CAP_OPTIONS as libc::c_int) {
        Ok(mut l2o) => {
            if let Some(v) = imtu {
                l2o.imtu = v;
            }
            if let Some(v) = omtu {
                l2o.omtu = v;
            }
            if l2cap_mode != 0xFF {
                l2o.mode = l2cap_mode;
            }
            bt_setsockopt(fd, SOL_L2CAP, L2CAP_OPTIONS as libc::c_int, &l2o)
        }
        Err(BtSocketError::SocketError(Errno::ENOPROTOOPT | Errno::EPROTONOSUPPORT)) => {
            // LE socket — fall back to BT_RCVMTU / BT_MODE
            if let Some(v) = imtu {
                set_le_imtu(fd, v)?;
            }
            set_le_mode(fd, mode)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Set L2CAP master/slave role via `L2CAP_LM` (btio.c `l2cap_set_central`).
fn l2cap_set_central(fd: RawFd, central: bool) -> Result<()> {
    let mut lm: u16 = bt_getsockopt(fd, SOL_L2CAP, L2CAP_LM as libc::c_int)?;
    if central {
        lm |= L2CAP_LM_MASTER;
    } else {
        lm &= !L2CAP_LM_MASTER;
    }
    bt_setsockopt(fd, SOL_L2CAP, L2CAP_LM as libc::c_int, &lm)
}

/// Set L2CAP flushable flag via `BT_FLUSHABLE`.
fn l2cap_set_flushable(fd: RawFd, flushable: bool) -> Result<()> {
    let val: u32 = u32::from(flushable);
    bt_setsockopt(fd, SOL_BLUETOOTH, BT_FLUSHABLE as libc::c_int, &val)
}

/// Get L2CAP flushable flag.
fn l2cap_get_flushable(fd: RawFd) -> Result<bool> {
    let val: u32 = bt_getsockopt(fd, SOL_BLUETOOTH, BT_FLUSHABLE as libc::c_int)?;
    Ok(val != 0)
}

/// Orchestrate L2CAP socket option setting (btio.c `l2cap_set` lines 647-696).
fn l2cap_set(fd: RawFd, opts: &SocketOptions) -> Result<()> {
    // Determine if this is a BR/EDR or LE socket by checking src_type.
    let is_le = opts.src_type != BDADDR_BREDR;

    // Set MTU and mode.
    if !is_le {
        // BR/EDR path: use L2CAP_OPTIONS with retry logic.
        if let Err(e) = set_l2opts(fd, opts.imtu, opts.omtu, opts.mode) {
            // If imtu was not specified (None) and set failed, retry with
            // explicit zero (auto-negotiate) — mirrors btio.c retry with imtu=-1
            if opts.imtu.is_none() {
                set_l2opts(fd, Some(0), opts.omtu, opts.mode)?;
            } else {
                return Err(e);
            }
        }
    } else {
        // LE path: use BT_RCVMTU / BT_MODE directly.
        if let Some(imtu) = opts.imtu {
            set_le_imtu(fd, imtu)?;
        }
        let _ = set_le_mode(fd, opts.mode);
    }

    // Set central role.
    if let Some(central) = opts.central {
        l2cap_set_central(fd, central)?;
    }

    // Set flushable.
    if let Some(flushable) = opts.flushable {
        l2cap_set_flushable(fd, flushable)?;
    }

    // Set priority.
    if opts.priority != SocketPriority::Normal {
        set_priority(fd, opts.priority)?;
    }

    // Set security level.
    if let Some(level) = opts.sec_level {
        set_sec_level(fd, BtTransport::L2cap, level)?;
    }

    Ok(())
}

// ===========================================================================
// RFCOMM option helpers (btio.c lines 739-753)
// ===========================================================================

/// Set RFCOMM master/slave role via `RFCOMM_LM` (btio.c `rfcomm_set_central`).
fn rfcomm_set_central(fd: RawFd, central: bool) -> Result<()> {
    let mut lm: u32 = bt_getsockopt(fd, SOL_RFCOMM, RFCOMM_LM as libc::c_int)?;
    if central {
        lm |= RFCOMM_LM_MASTER;
    } else {
        lm &= !RFCOMM_LM_MASTER;
    }
    bt_setsockopt(fd, SOL_RFCOMM, RFCOMM_LM as libc::c_int, &lm)
}

/// Orchestrate RFCOMM socket option setting (btio.c `rfcomm_set`).
fn rfcomm_set(fd: RawFd, opts: &SocketOptions) -> Result<()> {
    if let Some(level) = opts.sec_level {
        set_sec_level(fd, BtTransport::Rfcomm, level)?;
    }
    if let Some(central) = opts.central {
        rfcomm_set_central(fd, central)?;
    }
    Ok(())
}

// ===========================================================================
// SCO option helpers (btio.c lines 823-863)
// ===========================================================================

/// Orchestrate SCO socket option setting (btio.c `sco_set`).
fn sco_set(fd: RawFd, opts: &SocketOptions) -> Result<()> {
    // Set MTU.
    if opts.mtu.is_some() || opts.imtu.is_some() {
        let mtu_val = opts.mtu.or(opts.imtu).unwrap_or(0);
        if mtu_val > 0 {
            let mut sco_opt: sco_options = bt_getsockopt(fd, SOL_SCO, SCO_OPTIONS as libc::c_int)?;
            sco_opt.mtu = mtu_val;
            bt_setsockopt(fd, SOL_SCO, SCO_OPTIONS as libc::c_int, &sco_opt)?;
        }
    }

    // Set voice setting.
    if let Some(voice_val) = opts.voice {
        if voice_val != 0 {
            let bv = bt_voice { setting: voice_val };
            bt_setsockopt(fd, SOL_BLUETOOTH, BT_VOICE as libc::c_int, &bv)?;
        }
    }

    Ok(())
}

// ===========================================================================
// ISO option helpers (btio.c lines 865-916)
// ===========================================================================

/// Set ISO QoS parameters via `BT_ISO_QOS` (btio.c `iso_set_qos`).
fn iso_set_qos(fd: RawFd, qos: &bt_iso_qos) -> Result<()> {
    bt_setsockopt(fd, SOL_BLUETOOTH, BT_ISO_QOS as libc::c_int, qos)
}

/// Set ISO BASE data via `BT_ISO_BASE` (btio.c `iso_set_base`).
fn iso_set_base(fd: RawFd, base: &[u8]) -> Result<()> {
    if base.len() > BASE_MAX_LENGTH {
        return Err(BtSocketError::InvalidArguments(format!(
            "BASE length {} exceeds maximum {BASE_MAX_LENGTH}",
            base.len()
        )));
    }
    bt_setsockopt_bytes(fd, SOL_BLUETOOTH, BT_ISO_BASE as libc::c_int, base)
}

// ===========================================================================
// Address / connection-info getters
// ===========================================================================

/// Get local (source) address and address type by transport.
fn get_src(fd: RawFd, transport: BtTransport) -> Result<(bdaddr_t, u8)> {
    match transport {
        BtTransport::L2cap => {
            let addr: sockaddr_l2 = bt_getsockname(fd)?;
            Ok((addr.l2_bdaddr, addr.l2_bdaddr_type))
        }
        BtTransport::Rfcomm => {
            let addr: sockaddr_rc = bt_getsockname(fd)?;
            Ok((addr.rc_bdaddr, BDADDR_BREDR))
        }
        BtTransport::Sco => {
            let addr: sockaddr_sco = bt_getsockname(fd)?;
            Ok((addr.sco_bdaddr, BDADDR_BREDR))
        }
        BtTransport::Iso => {
            let addr: sockaddr_iso = bt_getsockname(fd)?;
            Ok((addr.iso_bdaddr, addr.iso_bdaddr_type))
        }
    }
}

/// Get remote (destination) address and address type by transport.
fn get_dst(fd: RawFd, transport: BtTransport) -> Result<(bdaddr_t, u8)> {
    match transport {
        BtTransport::L2cap => {
            let addr: sockaddr_l2 = bt_getpeername(fd)?;
            Ok((addr.l2_bdaddr, addr.l2_bdaddr_type))
        }
        BtTransport::Rfcomm => {
            let addr: sockaddr_rc = bt_getpeername(fd)?;
            Ok((addr.rc_bdaddr, BDADDR_BREDR))
        }
        BtTransport::Sco => {
            let addr: sockaddr_sco = bt_getpeername(fd)?;
            Ok((addr.sco_bdaddr, BDADDR_BREDR))
        }
        BtTransport::Iso => {
            let addr: sockaddr_iso = bt_getpeername(fd)?;
            Ok((addr.iso_bdaddr, addr.iso_bdaddr_type))
        }
    }
}

/// Get L2CAP connection info (handle + dev_class).
fn l2cap_get_info(fd: RawFd) -> Result<l2cap_conninfo> {
    bt_getsockopt(fd, SOL_L2CAP, L2CAP_CONNINFO as libc::c_int)
}

/// Get RFCOMM connection info (handle + dev_class).
fn rfcomm_get_info(fd: RawFd) -> Result<rfcomm_conninfo> {
    bt_getsockopt(fd, SOL_RFCOMM, RFCOMM_CONNINFO as libc::c_int)
}

/// Get SCO connection info (handle + dev_class).
fn sco_get_info(fd: RawFd) -> Result<sco_conninfo> {
    bt_getsockopt(fd, SOL_SCO, SCO_CONNINFO as libc::c_int)
}

/// Get LE incoming MTU via `BT_RCVMTU`.
fn get_le_imtu(fd: RawFd) -> Result<u16> {
    bt_getsockopt(fd, SOL_BLUETOOTH, BT_RCVMTU as libc::c_int)
}

/// Get LE outgoing MTU via `BT_SNDMTU`.
fn get_le_omtu(fd: RawFd) -> Result<u16> {
    bt_getsockopt(fd, SOL_BLUETOOTH, BT_SNDMTU as libc::c_int)
}

/// Get LE mode via `BT_MODE`.
fn get_le_mode(fd: RawFd) -> Result<L2capMode> {
    let mode: u8 = bt_getsockopt(fd, SOL_BLUETOOTH, BT_MODE as libc::c_int)?;
    Ok(L2capMode::from_bt_mode(mode))
}

/// Get ISO QoS via `BT_ISO_QOS`.
fn iso_get_qos(fd: RawFd) -> Result<bt_iso_qos> {
    bt_getsockopt(fd, SOL_BLUETOOTH, BT_ISO_QOS as libc::c_int)
}

/// Get ISO BASE data via `BT_ISO_BASE`.
fn iso_get_base(fd: RawFd) -> Result<Vec<u8>> {
    let mut buf = [0u8; BASE_MAX_LENGTH];
    let len = bt_getsockopt_bytes(fd, SOL_BLUETOOTH, BT_ISO_BASE as libc::c_int, &mut buf)?;
    Ok(buf[..len].to_vec())
}

/// Get MTU pair `(imtu, omtu)` for an L2CAP socket.
///
/// First tries LE-specific `BT_RCVMTU`/`BT_SNDMTU`, then falls back to
/// `L2CAP_OPTIONS` for BR/EDR (btio.c l2cap_get MTU logic lines 1137-1200).
fn l2cap_get_mtu(fd: RawFd) -> Result<(u16, u16)> {
    // Try LE path first (cheaper and always correct for LE).
    if let (Ok(imtu), Ok(omtu)) = (get_le_imtu(fd), get_le_omtu(fd)) {
        return Ok((imtu, omtu));
    }
    // Fall back to L2CAP_OPTIONS for BR/EDR.
    let l2o: l2cap_options = bt_getsockopt(fd, SOL_L2CAP, L2CAP_OPTIONS as libc::c_int)?;
    Ok((l2o.imtu, l2o.omtu))
}

/// Get L2CAP mode, trying LE path first then L2CAP_OPTIONS.
fn l2cap_get_mode(fd: RawFd) -> Result<L2capMode> {
    match get_le_mode(fd) {
        Ok(mode) => Ok(mode),
        Err(_) => {
            let l2o: l2cap_options = bt_getsockopt(fd, SOL_L2CAP, L2CAP_OPTIONS as libc::c_int)?;
            Ok(L2capMode::from_l2cap_mode(l2o.mode))
        }
    }
}

// ===========================================================================
// Socket creation factory (replaces btio.c `create_io` lines 1984-2064)
// ===========================================================================

/// Create and configure a raw Bluetooth socket for the given transport.
///
/// `server`: if `true`, bind with the source PSM/channel (for listeners);
/// if `false`, bind with PSM/channel = 0 (for clients).
fn create_socket(transport: BtTransport, opts: &SocketOptions, server: bool) -> Result<OwnedFd> {
    let fd = bt_socket_raw(transport.sock_type(), transport.to_protocol())?;
    let raw = fd.as_raw_fd();

    // Transport-specific bind.
    match transport {
        BtTransport::L2cap => {
            let psm = if server { opts.psm.unwrap_or(0) } else { 0 };
            let cid = if server { opts.cid.unwrap_or(0) } else { 0 };
            l2cap_bind(raw, &opts.src, opts.src_type, psm, cid)?;
        }
        BtTransport::Rfcomm => {
            let ch = if server { opts.channel.unwrap_or(0) as u8 } else { 0 };
            rfcomm_bind(raw, &opts.src, ch)?;
        }
        BtTransport::Sco => {
            sco_bind(raw, &opts.src)?;
        }
        BtTransport::Iso => {
            let sid = opts.iso_bc_sid.unwrap_or(0);
            let num_bis = opts.iso_bc_num_bis.unwrap_or(0);
            iso_bind(
                raw,
                &opts.src,
                opts.src_type,
                &opts.dst,
                opts.dst_type,
                sid,
                num_bis,
                &opts.iso_bc_bis,
            )?;
        }
    }

    // Transport-specific option setting.
    match transport {
        BtTransport::L2cap => l2cap_set(raw, opts)?,
        BtTransport::Rfcomm => rfcomm_set(raw, opts)?,
        BtTransport::Sco => sco_set(raw, opts)?,
        BtTransport::Iso => {
            if let Some(ref qos) = opts.qos {
                iso_set_qos(raw, qos)?;
            }
            if let Some(ref base) = opts.base {
                iso_set_base(raw, base)?;
            }
        }
    }

    Ok(fd)
}

/// Auto-detect transport from builder options (btio.c `parse_set_opts` logic).
fn detect_transport(opts: &SocketOptions) -> BtTransport {
    if opts.psm.is_some() || opts.cid.is_some() {
        BtTransport::L2cap
    } else if opts.channel.is_some() {
        BtTransport::Rfcomm
    } else if opts.mode == L2capMode::Iso {
        BtTransport::Iso
    } else {
        BtTransport::Sco
    }
}

// ===========================================================================
// SocketBuilder — builder pattern replacing BtIOOption variadic parsing
// ===========================================================================

/// Builder for creating Bluetooth sockets.
///
/// Replaces the variadic `BtIOOption` parsing from `btio.c` lines 920-1070.
/// Auto-detects transport from options (PSM/CID → L2CAP, CHANNEL → RFCOMM,
/// MODE=Iso → ISO, default → SCO), or allows explicit override via
/// [`transport()`](SocketBuilder::transport).
///
/// Terminal methods [`connect()`](SocketBuilder::connect) and
/// [`listen()`](SocketBuilder::listen) consume the builder and produce
/// a [`BluetoothSocket`] or [`BluetoothListener`] respectively.
pub struct SocketBuilder {
    transport: Option<BtTransport>,
    opts: SocketOptions,
}

impl SocketBuilder {
    /// Create a new builder with default options.
    pub fn new() -> Self {
        Self { transport: None, opts: SocketOptions::default() }
    }

    // ---- Addressing ----

    /// Set source address from a colon-separated string (e.g. "AA:BB:CC:DD:EE:FF").
    /// Maps to `BT_IO_OPT_SOURCE`.
    pub fn source(mut self, addr: &str) -> Self {
        self.opts.src = parse_bdaddr(addr);
        self
    }

    /// Set source address directly from a `bdaddr_t`.
    /// Maps to `BT_IO_OPT_SOURCE_BDADDR`.
    pub fn source_bdaddr(mut self, addr: bdaddr_t) -> Self {
        self.opts.src = addr;
        self
    }

    /// Set source address type (BDADDR_BREDR / BDADDR_LE_PUBLIC / BDADDR_LE_RANDOM).
    /// Maps to `BT_IO_OPT_SOURCE_TYPE`.
    pub fn source_type(mut self, addr_type: u8) -> Self {
        self.opts.src_type = addr_type;
        self
    }

    /// Set destination address from a colon-separated string.
    /// Maps to `BT_IO_OPT_DEST`.
    pub fn dest(mut self, addr: &str) -> Self {
        self.opts.dst = parse_bdaddr(addr);
        self
    }

    /// Set destination address directly from a `bdaddr_t`.
    /// Maps to `BT_IO_OPT_DEST_BDADDR`.
    pub fn dest_bdaddr(mut self, addr: bdaddr_t) -> Self {
        self.opts.dst = addr;
        self
    }

    /// Set destination address type.
    /// Maps to `BT_IO_OPT_DEST_TYPE`.
    pub fn dest_type(mut self, addr_type: u8) -> Self {
        self.opts.dst_type = addr_type;
        self
    }

    // ---- Connection parameters ----

    /// Set deferred setup timeout in seconds (default: 30).
    /// Maps to `BT_IO_OPT_DEFER_TIMEOUT`.
    pub fn defer_timeout(mut self, timeout: u32) -> Self {
        self.opts.defer = timeout;
        self
    }

    /// Set security level.
    /// Maps to `BT_IO_OPT_SEC_LEVEL`.
    pub fn sec_level(mut self, level: SecLevel) -> Self {
        self.opts.sec_level = Some(level);
        self
    }

    /// Set minimum encryption key size.
    /// Maps to `BT_IO_OPT_KEY_SIZE`.
    pub fn key_size(mut self, size: u8) -> Self {
        self.opts.key_size = Some(size);
        self
    }

    /// Set RFCOMM channel number.
    /// Maps to `BT_IO_OPT_CHANNEL` / `BT_IO_OPT_SOURCE_CHANNEL` /
    /// `BT_IO_OPT_DEST_CHANNEL`.
    pub fn channel(mut self, channel: u16) -> Self {
        self.opts.channel = Some(channel);
        self
    }

    /// Set L2CAP PSM.
    /// Maps to `BT_IO_OPT_PSM`.
    pub fn psm(mut self, psm: u16) -> Self {
        self.opts.psm = Some(psm);
        self
    }

    /// Set L2CAP CID (connection identifier).
    /// Maps to `BT_IO_OPT_CID`.
    pub fn cid(mut self, cid: u16) -> Self {
        self.opts.cid = Some(cid);
        self
    }

    /// Set overall MTU (sets both imtu and omtu).
    /// Maps to `BT_IO_OPT_MTU`.
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.opts.mtu = Some(mtu);
        self.opts.imtu = Some(mtu);
        self.opts.omtu = Some(mtu);
        self
    }

    /// Set outgoing MTU.
    /// Maps to `BT_IO_OPT_OMTU`.
    pub fn omtu(mut self, omtu: u16) -> Self {
        self.opts.omtu = Some(omtu);
        self
    }

    /// Set incoming MTU.
    /// Maps to `BT_IO_OPT_IMTU`.
    pub fn imtu(mut self, imtu: u16) -> Self {
        self.opts.imtu = Some(imtu);
        self
    }

    /// Set central (master) role preference.
    /// Maps to `BT_IO_OPT_CENTRAL`.
    pub fn central(mut self, is_central: bool) -> Self {
        self.opts.central = Some(is_central);
        self
    }

    /// Set ACL handle hint (mostly for read-back; rarely set by callers).
    /// Maps to `BT_IO_OPT_HANDLE`.
    pub fn handle(mut self, handle: u16) -> Self {
        self.opts.handle = Some(handle);
        self
    }

    /// Set device class hint.
    ///
    /// Maps to `BT_IO_OPT_CLASS`.  Device class is a read-only attribute
    /// in the kernel — this method exists for API completeness but has no
    /// socket-level side-effect.
    pub fn class(self, dev_class: u32) -> Self {
        // Device class is a read-only getter in the C code; no socket option.
        // Consume the value to satisfy the compiler.
        let _ = dev_class;
        self
    }

    /// Set L2CAP channel mode.
    /// Maps to `BT_IO_OPT_MODE`.
    pub fn mode(mut self, mode: L2capMode) -> Self {
        self.opts.mode = mode;
        self
    }

    /// Set L2CAP flushable flag.
    /// Maps to `BT_IO_OPT_FLUSHABLE`.
    pub fn flushable(mut self, flush: bool) -> Self {
        self.opts.flushable = Some(flush);
        self
    }

    /// Set socket priority.
    /// Maps to `BT_IO_OPT_PRIORITY`.
    pub fn priority(mut self, pri: SocketPriority) -> Self {
        self.opts.priority = pri;
        self
    }

    /// Set SCO voice setting.
    /// Maps to `BT_IO_OPT_VOICE`.
    pub fn voice(mut self, setting: u16) -> Self {
        self.opts.voice = Some(setting);
        self
    }

    /// Set PHY preference bitmask.
    /// Maps to `BT_IO_OPT_PHY`.
    pub fn phy(mut self, phy: u32) -> Self {
        self.opts.phy = Some(phy);
        self
    }

    /// Set ISO QoS parameters.
    /// Maps to `BT_IO_OPT_QOS`.
    pub fn qos(mut self, qos: bt_iso_qos) -> Self {
        self.opts.qos = Some(qos);
        self
    }

    /// Set ISO Broadcast Announcement BASE data.
    /// Maps to `BT_IO_OPT_BASE`.
    pub fn base(mut self, base: &[u8]) -> Self {
        self.opts.base = Some(base.to_vec());
        self
    }

    /// Set ISO broadcast SID.
    /// Maps to `BT_IO_OPT_ISO_BC_SID`.
    pub fn iso_bc_sid(mut self, sid: u8) -> Self {
        self.opts.iso_bc_sid = Some(sid);
        self
    }

    /// Set ISO broadcast number of BIS.
    /// Maps to `BT_IO_OPT_ISO_BC_NUM_BIS`.
    pub fn iso_bc_num_bis(mut self, num: u8) -> Self {
        self.opts.iso_bc_num_bis = Some(num);
        self
    }

    /// Set ISO broadcast BIS indices.
    /// Maps to `BT_IO_OPT_ISO_BC_BIS`.
    pub fn iso_bc_bis(mut self, bis: &[u8]) -> Self {
        self.opts.iso_bc_bis = bis.to_vec();
        self
    }

    /// Explicitly set the transport type, overriding auto-detection.
    pub fn transport(mut self, t: BtTransport) -> Self {
        self.transport = Some(t);
        self
    }

    // ---- Terminal methods ----

    /// Create an outgoing (client) connection.
    ///
    /// Replaces `bt_io_connect` from `btio.c` lines 2066-2124.
    ///
    /// 1. Auto-detect transport if not explicitly set.
    /// 2. Create and bind a non-blocking socket.
    /// 3. Initiate the transport-specific connect (EINPROGRESS is expected).
    /// 4. Register with tokio, wait for writability.
    /// 5. Confirm connection via `SO_ERROR`.
    pub async fn connect(mut self) -> Result<BluetoothSocket> {
        // Apply MODE=Iso side-effects: switch addr types to LE_PUBLIC if BREDR.
        if self.opts.mode == L2capMode::Iso {
            if self.opts.src_type == BDADDR_BREDR {
                self.opts.src_type = BDADDR_LE_PUBLIC;
            }
            if self.opts.dst_type == BDADDR_BREDR {
                self.opts.dst_type = BDADDR_LE_PUBLIC;
            }
        }

        let transport = self.transport.unwrap_or_else(|| detect_transport(&self.opts));
        let fd = create_socket(transport, &self.opts, false)?;
        let raw = fd.as_raw_fd();

        // Deferred setup for ExtFlowctl / ISO (btio.c lines 2079-2088).
        if (self.opts.mode == L2capMode::ExtFlowctl || transport == BtTransport::Iso)
            && self.opts.defer > 0
        {
            let val: u32 = 1;
            bt_setsockopt(raw, SOL_BLUETOOTH, BT_DEFER_SETUP as libc::c_int, &val)?;
        }

        // Transport-specific connect.
        match transport {
            BtTransport::L2cap => {
                l2cap_connect(
                    raw,
                    &self.opts.dst,
                    self.opts.dst_type,
                    self.opts.psm.unwrap_or(0),
                    self.opts.cid.unwrap_or(0),
                )?;
            }
            BtTransport::Rfcomm => {
                rfcomm_connect(raw, &self.opts.dst, self.opts.channel.unwrap_or(0) as u8)?;
            }
            BtTransport::Sco => {
                sco_connect(raw, &self.opts.dst)?;
            }
            BtTransport::Iso => {
                iso_connect(raw, &self.opts.dst, self.opts.dst_type)?;
            }
        }

        // Wrap in AsyncFd (fd is already O_NONBLOCK from bt_socket_raw).
        let async_fd = AsyncFd::new(fd).map_err(BtSocketError::IoError)?;

        // Wait for connection completion (replaces connect_cb in btio.c).
        let mut guard = async_fd.writable().await.map_err(BtSocketError::IoError)?;

        // Check SO_ERROR to verify successful connection.
        let err = bt_so_error(async_fd.as_raw_fd())?;
        if err != 0 {
            return Err(BtSocketError::ConnectionFailed(format!(
                "connect failed with SO_ERROR {}",
                err
            )));
        }
        guard.retain_ready();

        Ok(BluetoothSocket { fd: async_fd, transport })
    }

    /// Create a listening (server) socket.
    ///
    /// Replaces `bt_io_listen` from `btio.c` lines 2126-2171.
    ///
    /// 1. Auto-detect transport.
    /// 2. Create and bind socket with the source PSM/channel.
    /// 3. Optionally set `BT_DEFER_SETUP`.
    /// 4. Call `listen(fd, 5)`.
    /// 5. Wrap in [`BluetoothListener`].
    pub async fn listen(mut self) -> Result<BluetoothListener> {
        // Apply MODE=Iso side-effects.
        if self.opts.mode == L2capMode::Iso {
            if self.opts.src_type == BDADDR_BREDR {
                self.opts.src_type = BDADDR_LE_PUBLIC;
            }
            if self.opts.dst_type == BDADDR_BREDR {
                self.opts.dst_type = BDADDR_LE_PUBLIC;
            }
        }

        let transport = self.transport.unwrap_or_else(|| detect_transport(&self.opts));
        let fd = create_socket(transport, &self.opts, true)?;
        let raw = fd.as_raw_fd();

        // Set deferred setup if requested (btio.c lines 2142-2150).
        if self.opts.defer > 0 {
            let val: u32 = 1;
            bt_setsockopt(raw, SOL_BLUETOOTH, BT_DEFER_SETUP as libc::c_int, &val)?;
        }

        // Listen with backlog of 5 (matches btio.c).
        bt_listen(raw, 5)?;

        let async_fd = AsyncFd::new(fd).map_err(BtSocketError::IoError)?;

        Ok(BluetoothListener { fd: async_fd, transport })
    }
}

impl Default for SocketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Helper — parse colon-separated BD_ADDR string
// ===========================================================================

/// Parse a "XX:XX:XX:XX:XX:XX" Bluetooth address string into `bdaddr_t`.
///
/// Returns `BDADDR_ANY` on parse failure (matching GLib `str2ba` behaviour in btio.c).
fn parse_bdaddr(s: &str) -> bdaddr_t {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return BDADDR_ANY;
    }
    let mut b = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        match u8::from_str_radix(part, 16) {
            Ok(v) => b[5 - i] = v, // bdaddr_t is in reverse (little-endian) order
            Err(_) => return BDADDR_ANY,
        }
    }
    bdaddr_t { b }
}

// ===========================================================================
// BluetoothSocket — main connected socket wrapper
// ===========================================================================

/// Async Bluetooth socket wrapping a non-blocking kernel socket via
/// [`tokio::io::unix::AsyncFd`].
///
/// Replaces the `GIOChannel`-based socket from `btio.c`.  Supports L2CAP,
/// RFCOMM, SCO, and ISO transports with full option get/set and async I/O.
///
/// Obtain an instance via [`BluetoothSocket::builder().connect()`] (outgoing)
/// or via [`BluetoothListener::accept()`] (incoming).
pub struct BluetoothSocket {
    fd: AsyncFd<OwnedFd>,
    transport: BtTransport,
}

impl BluetoothSocket {
    /// Wrap an existing, already-connected file descriptor.
    ///
    /// The caller must ensure:
    /// - `fd` is an `AF_BLUETOOTH` socket.
    /// - `fd` is set to `O_NONBLOCK`.
    /// - `transport` matches the protocol of the socket.
    pub fn from_fd(fd: OwnedFd, transport: BtTransport) -> Result<Self> {
        // Ensure O_NONBLOCK is set (belt-and-suspenders).
        let raw = fd.as_raw_fd();
        // SAFETY: raw fd is valid because we hold the OwnedFd. F_GETFL is
        // always safe to call on a valid fd.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 {
            return Err(BtSocketError::IoError(io::Error::last_os_error()));
        }
        if (flags & libc::O_NONBLOCK) == 0 {
            // SAFETY: raw fd is valid, F_SETFL with O_NONBLOCK is safe.
            let ret = unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if ret < 0 {
                return Err(BtSocketError::IoError(io::Error::last_os_error()));
            }
        }
        let async_fd = AsyncFd::new(fd).map_err(BtSocketError::IoError)?;
        Ok(Self { fd: async_fd, transport })
    }

    /// Create a new [`SocketBuilder`] for constructing a socket.
    pub fn builder() -> SocketBuilder {
        SocketBuilder::new()
    }

    /// Return the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Return the transport protocol of this socket.
    pub fn transport(&self) -> BtTransport {
        self.transport
    }

    // ---- Deferred accept (btio.c bt_io_accept lines 1790-1849) ----

    /// Accept a deferred connection.
    ///
    /// Must be called on a socket that was connected or accepted with
    /// `BT_DEFER_SETUP` enabled. Reads 1 byte to acknowledge the deferred
    /// setup handshake.
    pub async fn accept_deferred(&self) -> Result<()> {
        let mut guard = self.fd.writable().await.map_err(BtSocketError::IoError)?;

        // Read 1 byte to acknowledge deferred setup (btio.c line 1815).
        let mut buf = [0u8; 1];
        match guard.try_io(|inner| {
            let raw = inner.as_raw_fd();
            // SAFETY: raw fd is valid while AsyncFd borrows OwnedFd.
            let n = unsafe { libc::read(raw, buf.as_mut_ptr().cast(), 1) };
            if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n) }
        }) {
            Ok(inner_result) => {
                inner_result.map_err(BtSocketError::IoError)?;
            }
            Err(_would_block) => {
                // Not ready yet — wait for readable and retry.
                let mut rguard = self.fd.readable().await.map_err(BtSocketError::IoError)?;
                rguard
                    .try_io(|inner| {
                        let raw = inner.as_raw_fd();
                        // SAFETY: fd is a valid open socket; reading 1 byte into a properly sized buffer.
                        let n = unsafe { libc::read(raw, buf.as_mut_ptr().cast(), 1) };
                        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n) }
                    })
                    .map_err(|_| {
                        BtSocketError::IoError(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "deferred accept not ready",
                        ))
                    })?
                    .map_err(BtSocketError::IoError)?;
            }
        }
        Ok(())
    }

    // ---- Broadcast accept (btio.c bt_io_bcast_accept lines 1851-1921) ----

    /// Accept an ISO broadcast connection with BIS selection.
    ///
    /// 1. Read 1 byte deferred ack.
    /// 2. Bind with broadcast parameters (SID, BIS indices).
    pub async fn accept_broadcast(
        &self,
        src: &bdaddr_t,
        src_type: u8,
        sid: u8,
        bis_indices: &[u8],
    ) -> Result<()> {
        let raw = self.fd.as_raw_fd();

        // Read 1 byte to ack deferred setup.
        self.accept_deferred().await?;

        // Bind with broadcast parameters.
        let num_bis = bis_indices.len().min(ISO_MAX_NUM_BIS as usize) as u8;
        iso_bind(raw, src, src_type, &BDADDR_ANY, 0, sid, num_bis, bis_indices)?;

        Ok(())
    }

    // ---- Option set/get dispatch ----

    /// Apply socket options from a [`SocketOptions`] struct.
    ///
    /// Dispatches to the appropriate transport-specific setter.
    pub fn set_options(&self, opts: &SocketOptions) -> Result<()> {
        let raw = self.fd.as_raw_fd();
        match self.transport {
            BtTransport::L2cap => l2cap_set(raw, opts),
            BtTransport::Rfcomm => rfcomm_set(raw, opts),
            BtTransport::Sco => sco_set(raw, opts),
            BtTransport::Iso => {
                if let Some(ref qos) = opts.qos {
                    iso_set_qos(raw, qos)?;
                }
                if let Some(ref base) = opts.base {
                    iso_set_base(raw, base)?;
                }
                Ok(())
            }
        }
    }

    /// Get the local (source) Bluetooth address and address type.
    pub fn source_address(&self) -> Result<(bdaddr_t, u8)> {
        get_src(self.fd.as_raw_fd(), self.transport)
    }

    /// Get the remote (destination) Bluetooth address and address type.
    pub fn dest_address(&self) -> Result<(bdaddr_t, u8)> {
        get_dst(self.fd.as_raw_fd(), self.transport)
    }

    /// Get the current security level.
    pub fn security_level(&self) -> Result<SecLevel> {
        get_sec_level(self.fd.as_raw_fd(), self.transport)
    }

    /// Get the encryption key size.
    pub fn key_size(&self) -> Result<u8> {
        get_key_size(self.fd.as_raw_fd())
    }

    /// Get MTU pair `(imtu, omtu)` for this socket.
    ///
    /// Returns transport-appropriate MTU values:
    /// - L2CAP: uses `L2CAP_OPTIONS` or LE `BT_RCVMTU`/`BT_SNDMTU` fallback.
    /// - RFCOMM: returns (imtu=0, omtu=0) — RFCOMM has stream semantics.
    /// - SCO: uses `SCO_OPTIONS`.
    /// - ISO: uses `BT_ISO_QOS` in/out SDU sizes.
    pub fn mtu(&self) -> Result<(u16, u16)> {
        let raw = self.fd.as_raw_fd();
        match self.transport {
            BtTransport::L2cap => l2cap_get_mtu(raw),
            BtTransport::Rfcomm => Ok((0, 0)),
            BtTransport::Sco => {
                let opts: sco_options = bt_getsockopt(raw, SOL_SCO, SCO_OPTIONS as libc::c_int)?;
                Ok((opts.mtu, opts.mtu))
            }
            BtTransport::Iso => {
                let qos = iso_get_qos(raw)?;
                // SAFETY: bt_iso_qos is a union; ucast is the default CIG path.
                let ucast = unsafe { qos.ucast };
                Ok((ucast.in_qos.sdu, ucast.out_qos.sdu))
            }
        }
    }

    /// Get the ACL connection handle.
    pub fn handle(&self) -> Result<u16> {
        let raw = self.fd.as_raw_fd();
        match self.transport {
            BtTransport::L2cap => {
                let info = l2cap_get_info(raw)?;
                Ok(info.hci_handle)
            }
            BtTransport::Rfcomm => {
                let info = rfcomm_get_info(raw)?;
                Ok(info.hci_handle)
            }
            BtTransport::Sco => {
                let info = sco_get_info(raw)?;
                Ok(info.hci_handle)
            }
            BtTransport::Iso => {
                // ISO uses the same L2CAP conninfo path.
                let info = l2cap_get_info(raw)?;
                Ok(info.hci_handle)
            }
        }
    }

    /// Get the device class from connection info.
    pub fn dev_class(&self) -> Result<[u8; 3]> {
        let raw = self.fd.as_raw_fd();
        match self.transport {
            BtTransport::L2cap => {
                let info = l2cap_get_info(raw)?;
                Ok(info.dev_class)
            }
            BtTransport::Rfcomm => {
                let info = rfcomm_get_info(raw)?;
                Ok(info.dev_class)
            }
            BtTransport::Sco => {
                let info = sco_get_info(raw)?;
                Ok(info.dev_class)
            }
            BtTransport::Iso => Ok([0; 3]),
        }
    }

    /// Get the PHY preference value.
    pub fn phy(&self) -> Result<u32> {
        get_phy(self.fd.as_raw_fd())
    }

    /// Get the current L2CAP channel mode. Only meaningful for L2CAP transport.
    pub fn mode(&self) -> Result<L2capMode> {
        match self.transport {
            BtTransport::L2cap => l2cap_get_mode(self.fd.as_raw_fd()),
            BtTransport::Iso => Ok(L2capMode::Iso),
            _ => Err(BtSocketError::NotSupported),
        }
    }

    /// Get the L2CAP flushable state. Only meaningful for L2CAP transport.
    pub fn flushable(&self) -> Result<bool> {
        match self.transport {
            BtTransport::L2cap => l2cap_get_flushable(self.fd.as_raw_fd()),
            _ => Err(BtSocketError::NotSupported),
        }
    }

    /// Get the socket priority.
    pub fn priority(&self) -> Result<SocketPriority> {
        get_priority(self.fd.as_raw_fd())
    }

    /// Get ISO Broadcast Announcement BASE data.
    ///
    /// Returns the raw BASE octets via `BT_ISO_BASE` getsockopt.
    /// Only meaningful for ISO transport.
    pub fn iso_base(&self) -> Result<Vec<u8>> {
        match self.transport {
            BtTransport::Iso => iso_get_base(self.fd.as_raw_fd()),
            _ => Err(BtSocketError::NotSupported),
        }
    }

    /// Get ISO QoS parameters.
    ///
    /// Returns the `bt_iso_qos` union via `BT_ISO_QOS` getsockopt.
    /// Only meaningful for ISO transport.
    pub fn iso_qos(&self) -> Result<bt_iso_qos> {
        match self.transport {
            BtTransport::Iso => iso_get_qos(self.fd.as_raw_fd()),
            _ => Err(BtSocketError::NotSupported),
        }
    }

    // ---- Async I/O ----

    /// Wait for the socket to become readable.
    pub async fn readable(&self) -> Result<()> {
        self.fd.readable().await.map_err(BtSocketError::IoError)?.retain_ready();
        Ok(())
    }

    /// Wait for the socket to become writable.
    pub async fn writable(&self) -> Result<()> {
        self.fd.writable().await.map_err(BtSocketError::IoError)?.retain_ready();
        Ok(())
    }

    /// Read data from the socket.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await.map_err(BtSocketError::IoError)?;

            match guard.try_io(|inner| {
                let raw = inner.as_raw_fd();
                // SAFETY: raw fd is valid while AsyncFd borrows OwnedFd; buf is valid.
                let n = unsafe { libc::recv(raw, buf.as_mut_ptr().cast(), buf.len(), 0) };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
            }) {
                Ok(result) => return result.map_err(BtSocketError::IoError),
                Err(_would_block) => continue,
            }
        }
    }

    /// Write data to the socket.
    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.writable().await.map_err(BtSocketError::IoError)?;

            match guard.try_io(|inner| {
                let raw = inner.as_raw_fd();
                // SAFETY: raw fd is valid while AsyncFd borrows OwnedFd; buf is valid.
                let n =
                    unsafe { libc::send(raw, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
            }) {
                Ok(result) => return result.map_err(BtSocketError::IoError),
                Err(_would_block) => continue,
            }
        }
    }

    /// Scatter-gather write (replaces `io_send` using `writev` from `io.h`).
    pub async fn send_vectored(&self, bufs: &[io::IoSlice<'_>]) -> Result<usize> {
        loop {
            let mut guard = self.fd.writable().await.map_err(BtSocketError::IoError)?;

            match guard.try_io(|inner| {
                let raw = inner.as_raw_fd();
                // SAFETY: raw fd valid, iov pointers valid for the call duration.
                let n =
                    unsafe { libc::writev(raw, bufs.as_ptr().cast(), bufs.len() as libc::c_int) };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
            }) {
                Ok(result) => return result.map_err(BtSocketError::IoError),
                Err(_would_block) => continue,
            }
        }
    }

    /// Wait until the remote end disconnects (HUP/ERR).
    ///
    /// Replaces the disconnect handler registration from `io.h`
    /// (`io_set_disconnect_handler`).
    pub async fn wait_disconnect(&self) -> Result<()> {
        // AsyncFd provides readiness that includes HUP and ERR.
        // We poll for both read and write — HUP sets both.
        loop {
            let mut guard = self
                .fd
                .ready(Interest::READABLE | Interest::WRITABLE)
                .await
                .map_err(BtSocketError::IoError)?;

            if guard.ready().is_read_closed() || guard.ready().is_write_closed() {
                return Ok(());
            }

            // Check SO_ERROR to see if there's an actual error condition.
            let err = bt_so_error(self.fd.as_raw_fd())?;
            if err != 0 {
                return Ok(());
            }

            // Not disconnected yet — yield to prevent busy-spinning.
            guard.retain_ready();
            tokio::task::yield_now().await;
        }
    }

    /// Shutdown the socket.
    pub fn shutdown(&self, how: std::net::Shutdown) -> Result<()> {
        let how_c = match how {
            std::net::Shutdown::Read => libc::SHUT_RD,
            std::net::Shutdown::Write => libc::SHUT_WR,
            std::net::Shutdown::Both => libc::SHUT_RDWR,
        };
        // SAFETY: raw fd is valid while BluetoothSocket exists.
        let ret = unsafe { libc::shutdown(self.fd.as_raw_fd(), how_c) };
        if ret < 0 { Err(BtSocketError::IoError(io::Error::last_os_error())) } else { Ok(()) }
    }
}

impl AsRawFd for BluetoothSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

// ===========================================================================
// BluetoothListener — listening socket wrapper
// ===========================================================================

/// Async Bluetooth listening socket.
///
/// Replaces `bt_io_listen` + `server_cb` from `btio.c`.  Call
/// [`accept()`](BluetoothListener::accept) to receive incoming connections.
pub struct BluetoothListener {
    fd: AsyncFd<OwnedFd>,
    transport: BtTransport,
}

impl BluetoothListener {
    /// Accept an incoming connection.
    ///
    /// Replaces `server_cb` from `btio.c` lines 248-279.  Blocks
    /// asynchronously until a peer connects, then returns a connected
    /// [`BluetoothSocket`].
    pub async fn accept(&self) -> Result<BluetoothSocket> {
        loop {
            let mut guard = self.fd.readable().await.map_err(BtSocketError::IoError)?;

            match guard.try_io(|inner| {
                let raw = inner.as_raw_fd();
                // accept4 with CLOEXEC|NONBLOCK — directly use libc here
                // so the closure returns io::Result as try_io requires.
                // SAFETY: raw fd is valid for accept4; flags are well-known constants.
                let nfd = unsafe {
                    libc::accept4(
                        raw,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    )
                };
                if nfd < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    // SAFETY: nfd is a newly-created valid fd from accept4.
                    Ok(unsafe { OwnedFd::from_raw_fd(nfd) })
                }
            }) {
                Ok(Ok(nfd)) => {
                    return BluetoothSocket::from_fd(nfd, self.transport);
                }
                Ok(Err(e)) => return Err(BtSocketError::IoError(e)),
                Err(_would_block) => continue,
            }
        }
    }

    /// Accept with deferred setup.
    ///
    /// Returns a socket in deferred state — the caller must call
    /// [`BluetoothSocket::accept_deferred()`] to complete the handshake.
    /// This pattern is used when a "confirm" callback was used in the
    /// original C code to inspect the peer before accepting.
    pub async fn accept_deferred(&self) -> Result<BluetoothSocket> {
        // Same as accept — the socket was created with BT_DEFER_SETUP,
        // so the returned socket is automatically in deferred state.
        self.accept().await
    }

    /// Return the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Return the transport protocol.
    pub fn transport(&self) -> BtTransport {
        self.transport
    }
}

impl AsRawFd for BluetoothListener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

// ---------------------------------------------------------------------------
// Unit Tests — exercises each unsafe wrapper path
// ---------------------------------------------------------------------------
//
// AF_BLUETOOTH sockets require a Bluetooth controller; these tests use
// Unix/TCP sockets (which share the same libc syscall paths) to verify
// that the safe wrappers around getsockopt, setsockopt, getsockname,
// writev, read, etc. correctly invoke the underlying libc calls and
// propagate results.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{IoSlice, Read, Write};
    use std::os::unix::net::UnixStream;

    /// Helper: create a connected Unix stream pair for testing.
    fn unix_pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().expect("UnixStream::pair")
    }

    // -----------------------------------------------------------------------
    // bt_sockopt_get_int / bt_sockopt_set_int
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_sockopt_get_int_valid_option() {
        // SO_RCVBUF is a valid int-type socket option on any socket.
        let (a, _b) = unix_pair();
        let result = bt_sockopt_get_int(a.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF);
        assert!(result.is_ok(), "getsockopt SO_RCVBUF should succeed: {:?}", result);
        assert!(result.unwrap() > 0, "receive buffer should be positive");
    }

    #[test]
    fn test_bt_sockopt_set_int_valid_option() {
        let (a, _b) = unix_pair();
        let result = bt_sockopt_set_int(a.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF, 8192);
        assert!(result.is_ok(), "setsockopt SO_SNDBUF should succeed: {:?}", result);
    }

    #[test]
    fn test_bt_sockopt_get_int_invalid_fd() {
        let result = bt_sockopt_get_int(-1, libc::SOL_SOCKET, libc::SO_RCVBUF);
        assert!(result.is_err(), "getsockopt on invalid fd should fail");
    }

    #[test]
    fn test_bt_sockopt_set_int_invalid_fd() {
        let result = bt_sockopt_set_int(-1, libc::SOL_SOCKET, libc::SO_SNDBUF, 8192);
        assert!(result.is_err(), "setsockopt on invalid fd should fail");
    }

    // -----------------------------------------------------------------------
    // bt_sockopt_get_security / bt_sockopt_set_security
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_sockopt_get_security_non_bt_socket() {
        // Non-BT sockets return an error for BT_SECURITY.
        let (a, _b) = unix_pair();
        let result = bt_sockopt_get_security(a.as_raw_fd());
        assert!(result.is_err(), "BT_SECURITY on Unix socket should fail");
    }

    #[test]
    fn test_bt_sockopt_set_security_non_bt_socket() {
        let (a, _b) = unix_pair();
        let sec = bt_security { level: 1, key_size: 0 };
        let result = bt_sockopt_set_security(a.as_raw_fd(), &sec);
        assert!(result.is_err(), "BT_SECURITY set on Unix socket should fail");
    }

    // -----------------------------------------------------------------------
    // bt_sockopt_get_l2cap_options
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_sockopt_get_l2cap_options_non_bt_socket() {
        let (a, _b) = unix_pair();
        let result = bt_sockopt_get_l2cap_options(a.as_raw_fd());
        assert!(result.is_err(), "L2CAP options on Unix socket should fail");
    }

    // -----------------------------------------------------------------------
    // bt_getsockname_l2
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_getsockname_l2_exercises_unsafe_path() {
        // getsockname(2) succeeds on any valid fd — it copies whatever
        // sockaddr the kernel has. On a Unix socket the returned family
        // is AF_UNIX, not AF_BLUETOOTH, but the call itself exercises
        // the unsafe libc::getsockname wrapper.
        let (a, _b) = unix_pair();
        let result = bt_getsockname_l2(a.as_raw_fd());
        assert!(result.is_ok(), "getsockname should succeed on any valid fd");
        // The returned struct is valid but the family won't be AF_BLUETOOTH.
        let addr = result.unwrap();
        assert_ne!(addr.l2_family, AF_BLUETOOTH as u16);
    }

    #[test]
    fn test_bt_getsockname_l2_invalid_fd() {
        // Use a closed fd to exercise error path.
        let (a, _b) = unix_pair();
        let raw = a.as_raw_fd();
        drop(a);
        let result = bt_getsockname_l2(raw);
        assert!(result.is_err(), "getsockname on closed fd should fail");
    }

    // -----------------------------------------------------------------------
    // bt_writev
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_writev_basic() {
        let (a, mut b) = unix_pair();
        let data1 = b"hello";
        let data2 = b" world";
        let iov = [IoSlice::new(data1), IoSlice::new(data2)];
        let written = bt_writev(a.as_raw_fd(), &iov);
        assert!(written.is_ok(), "writev should succeed: {:?}", written);
        assert_eq!(written.unwrap(), 11);

        let mut buf = [0u8; 64];
        let n = b.read(&mut buf).expect("read");
        assert_eq!(&buf[..n], b"hello world");
    }

    #[test]
    fn test_bt_writev_closed_fd() {
        // Use a closed fd (not -1 which triggers a debug_assert) to
        // exercise the writev error path.
        let (a, _b) = unix_pair();
        let raw = a.as_raw_fd();
        drop(a);
        let iov = [IoSlice::new(b"data")];
        let result = bt_writev(raw, &iov);
        assert!(result.is_err(), "writev on closed fd should fail");
    }

    // -----------------------------------------------------------------------
    // bt_sockopt_set_priority
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_sockopt_set_priority() {
        let (a, _b) = unix_pair();
        let result = bt_sockopt_set_priority(a.as_raw_fd(), 6);
        // SO_PRIORITY may or may not be supported on Unix sockets,
        // but the unsafe getsockopt/setsockopt path is exercised.
        let _ = result;
    }

    // -----------------------------------------------------------------------
    // bt_get_source_address / bt_get_dest_address
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_get_source_address_exercises_path() {
        // On a Unix socket, getsockname succeeds but the returned
        // sockaddr is AF_UNIX. The function's unsafe getsockname path
        // is exercised regardless.
        let (a, _b) = unix_pair();
        let _result = bt_get_source_address(a.as_raw_fd(), BtTransport::L2cap);
        // Result may be Ok (interpreting AF_UNIX sockaddr as BT) or Err —
        // the important thing is the unsafe path executed without UB.
    }

    #[test]
    fn test_bt_get_dest_address_exercises_path() {
        let (a, _b) = unix_pair();
        let _result = bt_get_dest_address(a.as_raw_fd(), BtTransport::L2cap);
        // Same as above — exercises the unsafe getpeername path.
    }

    #[test]
    fn test_bt_get_source_address_closed_fd() {
        let (a, _b) = unix_pair();
        let raw = a.as_raw_fd();
        drop(a);
        let result = bt_get_source_address(raw, BtTransport::L2cap);
        assert!(result.is_err(), "source address on closed fd should fail");
    }

    #[test]
    fn test_bt_get_dest_address_closed_fd() {
        let (a, _b) = unix_pair();
        let raw = a.as_raw_fd();
        drop(a);
        let result = bt_get_dest_address(raw, BtTransport::L2cap);
        assert!(result.is_err(), "dest address on closed fd should fail");
    }

    // -----------------------------------------------------------------------
    // SocketOptions / SocketBuilder default construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_socket_options_default() {
        let opts = SocketOptions::default();
        assert_eq!(opts.psm, None);
        assert_eq!(opts.cid, None);
        assert_eq!(opts.imtu, None);
        assert_eq!(opts.omtu, None);
        assert_eq!(opts.sec_level, None);
        assert_eq!(opts.channel, None);
        assert_eq!(opts.mode, L2capMode::Basic);
        assert_eq!(opts.priority, SocketPriority::Normal);
    }

    #[test]
    fn test_socket_builder_new() {
        let builder = SocketBuilder::new();
        // SocketBuilder should be constructable without panic.
        let _ = builder;
    }

    // -----------------------------------------------------------------------
    // Enum conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sec_level_from_u8() {
        assert!(matches!(SecLevel::from(0_u8), SecLevel::Sdp));
        assert!(matches!(SecLevel::from(1_u8), SecLevel::Low));
        assert!(matches!(SecLevel::from(2_u8), SecLevel::Medium));
        assert!(matches!(SecLevel::from(3_u8), SecLevel::High));
        // Out-of-range maps to High per the from_u8 implementation.
        assert!(matches!(SecLevel::from(99_u8), SecLevel::High));
    }

    #[test]
    fn test_sec_level_to_u8() {
        assert_eq!(u8::from(SecLevel::Sdp), 0);
        assert_eq!(u8::from(SecLevel::Low), 1);
        assert_eq!(u8::from(SecLevel::Medium), 2);
        assert_eq!(u8::from(SecLevel::High), 3);
    }

    #[test]
    fn test_bt_transport_from_protocol() {
        assert_eq!(BtTransport::from_protocol(BTPROTO_L2CAP), Some(BtTransport::L2cap));
        assert_eq!(BtTransport::from_protocol(BTPROTO_RFCOMM), Some(BtTransport::Rfcomm));
        assert_eq!(BtTransport::from_protocol(BTPROTO_SCO), Some(BtTransport::Sco));
        assert_eq!(BtTransport::from_protocol(BTPROTO_ISO), Some(BtTransport::Iso));
        assert_eq!(BtTransport::from_protocol(9999), None);
    }

    #[test]
    fn test_bt_transport_to_protocol() {
        assert_eq!(BtTransport::L2cap.to_protocol(), BTPROTO_L2CAP);
        assert_eq!(BtTransport::Rfcomm.to_protocol(), BTPROTO_RFCOMM);
        assert_eq!(BtTransport::Sco.to_protocol(), BTPROTO_SCO);
        assert_eq!(BtTransport::Iso.to_protocol(), BTPROTO_ISO);
    }

    #[test]
    fn test_l2cap_mode_to_wire() {
        assert!(L2capMode::Basic.to_l2cap_mode().is_some());
        assert!(L2capMode::Ertm.to_l2cap_mode().is_some());
        assert!(L2capMode::Streaming.to_l2cap_mode().is_some());
        // Iso mode is not a real L2CAP mode.
        assert!(L2capMode::Iso.to_l2cap_mode().is_none());
    }

    #[test]
    fn test_l2cap_mode_debug() {
        // Exercises the Debug derive.
        assert_eq!(format!("{:?}", L2capMode::Basic), "Basic");
        assert_eq!(format!("{:?}", L2capMode::Ertm), "Ertm");
    }

    // -----------------------------------------------------------------------
    // read_with_timeout (exercises the unsafe libc::read path)
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_on_valid_fd() {
        let (mut a, b) = unix_pair();
        a.write_all(b"x").expect("write");
        let mut buf = [0u8; 1];
        // Read using raw fd — exercises the libc::read unsafe path.
        // SAFETY: fd is valid and buf is properly sized.
        let n = unsafe { libc::read(b.as_raw_fd(), buf.as_mut_ptr().cast(), 1) };
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'x');
    }

    // -----------------------------------------------------------------------
    // BtSocketError Display (via thiserror derive)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bt_socket_error_display() {
        let err = BtSocketError::InvalidArguments("test reason".into());
        let msg = format!("{}", err);
        assert!(msg.contains("test reason"), "display should contain reason: {msg}");

        let err = BtSocketError::IoError(std::io::Error::from_raw_os_error(libc::EINVAL));
        assert!(!format!("{}", err).is_empty());

        let err = BtSocketError::NotConnected;
        assert!(format!("{}", err).contains("Not connected"));
    }
}
