// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared infrastructure for BlueZ integration testers.
//!
//! This crate provides the common types, utilities, and test runner
//! infrastructure used by all 12 integration tester binaries in the
//! `bluez-tools` workspace crate.
//!
//! # Major components
//!
//! * **TX/RX socket timestamping** — [`TxTstampData`], [`rx_timestamp_check`],
//!   [`recv_tstamp`], [`rx_timestamping_init`] — Linux `SO_TIMESTAMPING`
//!   helpers ported from `tools/tester.h`.
//! * **Ethtool probing** — [`test_ethtool_get_ts_info`] verifies the Bluetooth
//!   HCI transport exposes the expected timestamping capabilities.
//! * **QEMU-based test runner** — [`TestRunner`] orchestrates VM-based test
//!   execution, ported from `tools/test-runner.c`.
//! * **Error handling** — [`TesterError`] is the crate-wide error enum.
//!
//! # Re-exports
//!
//! Key types from `bluez_shared::tester` are re-exported so that binary
//! consumers can write `use bluez_tools::{TesterContext, TestCase, …}`.

#![deny(warnings)]

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::ffi::CString;
use std::fs;
use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::path::Path;

use bluez_shared::sys::bluetooth::{BT_SCM_ERROR, BTPROTO_SCO, PF_BLUETOOTH, SOL_BLUETOOTH};
pub use bluez_shared::tester::{TestCase, TesterContext, TesterResult};

// ---------------------------------------------------------------------------
// Kernel-level constants (from linux/net_tstamp.h, linux/errqueue.h, etc.)
// ---------------------------------------------------------------------------

/// Software TX-schedule timestamp (bit 8 in recent kernels).
pub const SOF_TIMESTAMPING_TX_SCHED: u32 = libc::SOF_TIMESTAMPING_TX_SCHED;

/// Software TX timestamp (bit 1).
pub const SOF_TIMESTAMPING_TX_SOFTWARE: u32 = libc::SOF_TIMESTAMPING_TX_SOFTWARE;

/// Software RX timestamp (bit 3).
pub const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = libc::SOF_TIMESTAMPING_RX_SOFTWARE;

/// Hardware RX timestamp (bit 2).
pub const SOF_TIMESTAMPING_RX_HARDWARE: u32 = libc::SOF_TIMESTAMPING_RX_HARDWARE;

/// Generic "software timestamping supported" flag (bit 4).
pub const SOF_TIMESTAMPING_SOFTWARE: u32 = libc::SOF_TIMESTAMPING_SOFTWARE;

/// Only return timestamp, not original payload (bit 11).
pub const SOF_TIMESTAMPING_OPT_TSONLY: u32 = libc::SOF_TIMESTAMPING_OPT_TSONLY;

/// Per-packet TX timestamp id tracking (bit 7).
pub const SOF_TIMESTAMPING_OPT_ID: u32 = libc::SOF_TIMESTAMPING_OPT_ID;

/// TX completion timestamp — compatibility shim for kernels that do not yet
/// define this constant.  Matches `linux/net_tstamp.h` value `1 << 18`.
pub const SOF_TIMESTAMPING_TX_COMPLETION: u32 = 1 << 18;

/// Combination of all TX-record flags including the completion flag.
///
/// Equivalent to the kernel's `SOF_TIMESTAMPING_TX_RECORD_MASK` ORed with
/// [`SOF_TIMESTAMPING_TX_COMPLETION`].
pub const TS_TX_RECORD_MASK: u32 = libc::SOF_TIMESTAMPING_TX_HARDWARE
    | SOF_TIMESTAMPING_TX_SOFTWARE
    | SOF_TIMESTAMPING_TX_SCHED
    | libc::SOF_TIMESTAMPING_TX_ACK
    | SOF_TIMESTAMPING_TX_COMPLETION;

// `SCM_TSTAMP_*` constants from `linux/net_tstamp.h`.  Not present in the
// `libc` crate, so defined locally with kernel-ABI values.

/// `SCM_TSTAMP_SND` — software-send timestamp type tag.
const SCM_TSTAMP_SND: u32 = 0;

/// `SCM_TSTAMP_SCHED` — scheduled timestamp type tag.
const SCM_TSTAMP_SCHED: u32 = 1;

/// `SCM_TSTAMP_ACK` — acknowledgement timestamp type tag.
const SCM_TSTAMP_ACK: u32 = 2;

/// TX completion timestamp type tag — one past `SCM_TSTAMP_ACK`.
pub const SCM_TSTAMP_COMPLETION: u32 = SCM_TSTAMP_ACK + 1;

/// Maximum number of expect entries in [`TxTstampData`].
const TX_TSTAMP_EXPECT_MAX: usize = 16;

/// Sentinel value indicating "not yet assigned" or "consumed" in expect arrays.
const TSTAMP_SENTINEL: u32 = 0xFFFF;

/// Ethtool command code for `ETHTOOL_GET_TS_INFO` (from `linux/ethtool.h`).
const ETHTOOL_GET_TS_INFO: u32 = 0x41;

/// `HWTSTAMP_TX_OFF` — no hardware TX timestamping.
const HWTSTAMP_TX_OFF: u32 = 0;

/// `HWTSTAMP_FILTER_NONE` — no hardware RX filtering.
const HWTSTAMP_FILTER_NONE: u32 = 0;

// ---------------------------------------------------------------------------
// FFI structures
// ---------------------------------------------------------------------------

/// Kernel `struct scm_timestamping` — three-element timespec array returned in
/// an `SCM_TIMESTAMPING` ancillary message.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct ScmTimestamping {
    ts: [libc::timespec; 3],
}

/// Kernel `struct ethtool_ts_info` — timestamping capability report returned by
/// the `ETHTOOL_GET_TS_INFO` ioctl.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EthtoolTsInfo {
    cmd: u32,
    so_timestamping: u32,
    phc_index: i32,
    tx_types: u32,
    tx_reserved: [u32; 3],
    rx_filters: u32,
    rx_reserved: [u32; 3],
}

impl Default for EthtoolTsInfo {
    fn default() -> Self {
        Self {
            cmd: ETHTOOL_GET_TS_INFO,
            so_timestamping: 0,
            phc_index: 0,
            tx_types: 0,
            tx_reserved: [0; 3],
            rx_filters: 0,
            rx_reserved: [0; 3],
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by tester infrastructure and timestamping helpers.
#[derive(Debug, thiserror::Error)]
pub enum TesterError {
    /// Expected timestamp was not found in control messages.
    #[error("Timestamp missing")]
    TimestampMissing,

    /// A timestamp was received when none was expected.
    #[error("Spurious timestamp")]
    SpuriousTimestamp,

    /// Timestamp value is out of the expected range.
    #[error("Bad timestamp value")]
    BadTimestamp,

    /// More timestamps than expected were received.
    #[error("Too many timestamps")]
    TooManyTimestamps,

    /// The timestamp type tag did not match any expected entry.
    #[error("Bad timestamp type: {0}")]
    BadTimestampType(u32),

    /// The timestamp id did not match the expected id.
    #[error("Bad timestamp id: {0}")]
    BadTimestampId(u32),

    /// Underlying I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Underlying nix/errno error.
    #[error("Nix error: {0}")]
    Nix(#[from] nix::Error),

    /// Socket creation failed.
    #[error("Socket creation failed: {0}")]
    SocketFailed(String),

    /// Ethtool capability check returned unexpected values.
    #[error("Ethtool check failed")]
    EthtoolCheckFailed,

    /// Test was aborted before completion.
    #[error("Test aborted")]
    TestAborted,

    /// Test failed with a descriptive message.
    #[error("Test failed: {0}")]
    TestFailed(String),
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Convert a whole-second value to nanoseconds.
///
/// Equivalent to the C macro `SEC_NSEC(t)`.
#[inline]
pub const fn sec_nsec(t: i64) -> i64 {
    t * 1_000_000_000
}

/// Convert a [`libc::timespec`] to a single nanosecond count.
#[inline]
pub fn ts_nsec(ts: &libc::timespec) -> i64 {
    sec_nsec(ts.tv_sec) + ts.tv_nsec
}

/// Retrieve `CLOCK_REALTIME` as a single nanosecond count.
///
/// Used for timestamp freshness validation.
#[allow(unsafe_code)]
fn clock_gettime_ns() -> Result<i64, TesterError> {
    let mut ts: libc::timespec = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes into a valid stack-allocated timespec.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc != 0 {
        return Err(TesterError::Io(io::Error::last_os_error()));
    }
    Ok(ts_nsec(&ts))
}

/// Advance a raw pointer past the current `cmsghdr` to the next one inside a
/// `msghdr`, returning a null pointer when there are no more headers.
///
/// This is the manual equivalent of `CMSG_NXTHDR` which is not exposed for
/// Linux targets by the `libc` crate.
#[allow(unsafe_code)]
fn cmsg_nxthdr(mhdr: *const libc::msghdr, cmsg: *const libc::cmsghdr) -> *mut libc::cmsghdr {
    // SAFETY: pointer arithmetic within the bounds of the control buffer owned
    // by the caller.  We validate the length field and buffer boundary before
    // dereferencing.
    unsafe {
        let cmsg_len = (*cmsg).cmsg_len;
        let aligned = (cmsg_len + mem::size_of::<usize>() - 1) & !(mem::size_of::<usize>() - 1);
        let next = (cmsg as *const u8).add(aligned) as *mut libc::cmsghdr;
        let end = ((*mhdr).msg_control as *const u8).add((*mhdr).msg_controllen);
        if (next as *const u8).add(mem::size_of::<libc::cmsghdr>()) > end {
            std::ptr::null_mut()
        } else {
            next
        }
    }
}

// ---------------------------------------------------------------------------
// TX Timestamping — TxTstampData
// ---------------------------------------------------------------------------

/// TX socket-timestamping tracker, ported from `struct tx_tstamp_data` in
/// `tools/tester.h`.
///
/// Tracks expected and received TX timestamps for a single socket, using the
/// Linux `SO_TIMESTAMPING` error-queue mechanism.
#[derive(Debug, Clone)]
pub struct TxTstampData {
    /// Array of `(id, type)` pairs — entries set to sentinels are unused or
    /// already consumed.
    /// Array of `(id, type)` pairs for expected timestamps.
    pub expect: [(u32, u32); TX_TSTAMP_EXPECT_MAX],
    /// Number of entries consumed (received and validated) so far.
    pub pos: usize,
    /// Number of entries queued (expected) so far.
    pub count: usize,
    /// Current transmit identifier counter.
    pub sent: u32,
    /// `SO_TIMESTAMPING` flags active on this socket.
    pub so_timestamping: u32,
    /// `true` for stream (byte-counting) semantics; `false` for packet.
    pub stream: bool,
}

impl Default for TxTstampData {
    fn default() -> Self {
        Self {
            expect: [(TSTAMP_SENTINEL, TSTAMP_SENTINEL); TX_TSTAMP_EXPECT_MAX],
            pos: 0,
            count: 0,
            sent: 0,
            so_timestamping: 0,
            stream: false,
        }
    }
}

impl TxTstampData {
    /// Re-initialise the tracker, setting the `SO_TIMESTAMPING` flags and
    /// stream mode.
    ///
    /// Equivalent to `tx_tstamp_init` in `tools/tester.h`.
    pub fn tx_tstamp_init(&mut self, so_timestamping: u32, stream: bool) {
        *self = Self::default();
        self.so_timestamping = so_timestamping;
        self.stream = stream;
    }

    /// Register the expected timestamps for a single send of `len` bytes,
    /// returning the number of new expect entries added.
    ///
    /// Equivalent to `tx_tstamp_expect` in `tools/tester.h`.
    pub fn tx_tstamp_expect(&mut self, len: usize) -> i32 {
        let start = self.count;

        if self.stream && len > 0 {
            self.sent += (len as u32).saturating_sub(1);
        }

        if self.so_timestamping & SOF_TIMESTAMPING_TX_SCHED != 0 {
            assert!(self.count < TX_TSTAMP_EXPECT_MAX, "tx_tstamp_expect: overflow");
            self.expect[self.count] = (self.sent, SCM_TSTAMP_SCHED);
            self.count += 1;
        }

        if self.so_timestamping & SOF_TIMESTAMPING_TX_SOFTWARE != 0 {
            assert!(self.count < TX_TSTAMP_EXPECT_MAX, "tx_tstamp_expect: overflow");
            self.expect[self.count] = (self.sent, SCM_TSTAMP_SND);
            self.count += 1;
        }

        if self.so_timestamping & SOF_TIMESTAMPING_TX_COMPLETION != 0 {
            assert!(self.count < TX_TSTAMP_EXPECT_MAX, "tx_tstamp_expect: overflow");
            self.expect[self.count] = (self.sent, SCM_TSTAMP_COMPLETION);
            self.count += 1;
        }

        if !self.stream || len > 0 {
            self.sent += 1;
        }

        (self.count - start) as i32
    }

    /// Receive and validate pending TX timestamps from the socket error queue.
    ///
    /// Returns the number of timestamps still outstanding (`count - pos`).
    ///
    /// Equivalent to `tx_tstamp_recv` in `tools/tester.h`.
    #[allow(unsafe_code)]
    pub fn tx_tstamp_recv(&mut self, sk: RawFd, len: i32) -> Result<usize, TesterError> {
        let mut ctrl_buf = [0u8; 512];
        let mut data_buf = [0u8; 1024];
        let mut iov =
            libc::iovec { iov_base: data_buf.as_mut_ptr().cast(), iov_len: data_buf.len() };

        // SAFETY: zeroing a POD struct is safe.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl_buf.as_mut_ptr().cast();
        msg.msg_controllen = ctrl_buf.len() as _;

        // SAFETY: msg points to stack-allocated buffers with correct lengths.
        let ret = unsafe { libc::recvmsg(sk, &mut msg, libc::MSG_ERRQUEUE) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            let raw = e.raw_os_error().unwrap_or(0);
            if raw == libc::EAGAIN || raw == libc::EWOULDBLOCK {
                return Ok(self.count - self.pos);
            }
            tracing::warn!("Failed to read from errqueue: {}", e);
            return Err(TesterError::Io(e));
        }

        // Payload length check.
        let opt_tsonly = self.so_timestamping & SOF_TIMESTAMPING_OPT_TSONLY != 0;
        if opt_tsonly {
            if ret != 0 {
                tracing::warn!("Packet copied back to errqueue");
                return Err(TesterError::TestFailed("OPT_TSONLY payload non-zero".into()));
            }
        } else if len > ret as i32 {
            tracing::warn!("Packet not copied back to errqueue: {}", ret);
            return Err(TesterError::TestFailed("payload too short".into()));
        }

        // Walk ancillary messages.
        let mut tss_opt: Option<ScmTimestamping> = None;
        let mut serr_opt: Option<libc::sock_extended_err> = None;

        // SAFETY: CMSG_FIRSTHDR reads valid msg_control from above.
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            // SAFETY: cmsg is within the control buffer bounds.
            let hdr = unsafe { &*cmsg };
            if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_TIMESTAMPING {
                // SAFETY: kernel guarantees data is valid ScmTimestamping.
                let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
                let tss: ScmTimestamping = unsafe { std::ptr::read_unaligned(data_ptr.cast()) };
                tss_opt = Some(tss);
            }
            if hdr.cmsg_level == SOL_BLUETOOTH && hdr.cmsg_type == BT_SCM_ERROR {
                // SAFETY: kernel guarantees data is valid sock_extended_err.
                let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
                let se: libc::sock_extended_err =
                    unsafe { std::ptr::read_unaligned(data_ptr.cast()) };
                serr_opt = Some(se);
            }
            cmsg = cmsg_nxthdr(&msg, cmsg);
        }

        let tss = match tss_opt {
            Some(t) => t,
            None => {
                tracing::warn!("SCM_TIMESTAMPING not found");
                return Err(TesterError::TimestampMissing);
            }
        };

        let serr = match serr_opt {
            Some(s) => s,
            None => {
                tracing::warn!("BT_SCM_ERROR not found");
                return Err(TesterError::TimestampMissing);
            }
        };

        // Validate the extended error header.
        if serr.ee_errno != libc::ENOMSG as u32 {
            tracing::warn!("BT_SCM_ERROR wrong for timestamping");
            return Err(TesterError::TestFailed("bad ee_errno".into()));
        }
        if serr.ee_origin != libc::SO_EE_ORIGIN_TIMESTAMPING {
            tracing::warn!("BT_SCM_ERROR wrong for timestamping");
            return Err(TesterError::TestFailed("bad ee_origin".into()));
        }

        // Validate timestamp freshness (software timestamp in slot 0).
        let ts_ns = ts_nsec(&tss.ts[0]);
        let now_ns = clock_gettime_ns()?;
        if now_ns < ts_ns || now_ns > ts_ns + sec_nsec(10) {
            tracing::warn!("nonsense in timestamp");
            return Err(TesterError::BadTimestamp);
        }

        if self.pos >= self.count {
            tracing::warn!("Too many timestamps");
            return Err(TesterError::TooManyTimestamps);
        }

        // Find first unreceived timestamp of the right type.
        let ts_type = serr.ee_info;
        let mut matched_idx: Option<usize> = None;
        for i in 0..self.count {
            if self.expect[i].1 >= TSTAMP_SENTINEL {
                continue;
            }
            if ts_type == self.expect[i].1 {
                self.expect[i].1 = TSTAMP_SENTINEL;
                matched_idx = Some(i);
                break;
            }
        }

        let idx = match matched_idx {
            Some(i) => i,
            None => {
                tracing::warn!("Bad timestamp type {}", ts_type);
                return Err(TesterError::BadTimestampType(ts_type));
            }
        };

        let ts_id = serr.ee_data;
        if self.so_timestamping & SOF_TIMESTAMPING_OPT_ID != 0 && ts_id != self.expect[idx].0 {
            tracing::warn!("Bad timestamp id {}", ts_id);
            return Err(TesterError::BadTimestampId(ts_id));
        }

        tracing::info!("Got valid TX timestamp {} (type {}, id {})", idx, ts_type, ts_id,);

        self.pos += 1;
        Ok(self.count - self.pos)
    }
}

// ---------------------------------------------------------------------------
// RX Timestamping
// ---------------------------------------------------------------------------

/// Validate that a received `msghdr` contains the expected RX timestamp.
///
/// `flags` is the set of `SOF_TIMESTAMPING_RX_*` flags that were requested.
/// `expect_t_hw` is the expected hardware timestamp in nanoseconds (when
/// hardware timestamping is active).
///
/// Equivalent to `rx_timestamp_check` in `tools/tester.h`.
#[allow(unsafe_code)]
pub fn rx_timestamp_check(
    msg: &libc::msghdr,
    flags: u32,
    expect_t_hw: i64,
) -> Result<(), TesterError> {
    let want_sw = flags & SOF_TIMESTAMPING_RX_SOFTWARE != 0;
    let want_hw = flags & SOF_TIMESTAMPING_RX_HARDWARE != 0;

    // Walk cmsgs looking for SCM_TIMESTAMPING at SOL_SOCKET.
    let mut t: i64 = 0;
    let mut t_hw: i64 = 0;
    let mut found_tss = false;

    // SAFETY: CMSG_FIRSTHDR reads valid msg_control from the caller.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg as *const _) };
    while !cmsg.is_null() {
        // SAFETY: cmsg pointer is within the control buffer.
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_TIMESTAMPING {
            // SAFETY: kernel guarantees data is a valid scm_timestamping.
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            let tss: ScmTimestamping = unsafe { std::ptr::read_unaligned(data_ptr.cast()) };
            t = ts_nsec(&tss.ts[0]);
            t_hw = ts_nsec(&tss.ts[2]);
            found_tss = true;
            break;
        }
        cmsg = cmsg_nxthdr(msg as *const _, cmsg);
    }

    if !found_tss {
        if !want_sw && !want_hw {
            return Ok(());
        }
        tracing::warn!("RX timestamp missing");
        return Err(TesterError::TimestampMissing);
    } else if !want_sw && !want_hw {
        tracing::warn!("Spurious RX timestamp");
        return Err(TesterError::SpuriousTimestamp);
    }

    if want_sw {
        let now_ns = clock_gettime_ns()?;
        if now_ns < t || now_ns > t + sec_nsec(10) {
            tracing::warn!("Software RX timestamp bad time");
            return Err(TesterError::BadTimestamp);
        }
        tracing::info!("Got valid RX software timestamp");
    }

    if want_hw {
        if t_hw != expect_t_hw {
            tracing::warn!("Bad hardware RX timestamp: {} != {}", t_hw, expect_t_hw,);
            return Err(TesterError::BadTimestamp);
        }
        tracing::info!("Got valid hardware RX timestamp");
    }

    Ok(())
}

/// Receive a single datagram and optionally validate its RX timestamp.
///
/// Equivalent to `recv_tstamp` in `tools/tester.h`.
#[allow(unsafe_code)]
pub fn recv_tstamp(sk: RawFd, buf: &mut [u8], tstamp: bool) -> Result<usize, TesterError> {
    let mut ctrl_buf = [0u8; 512];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };

    // SAFETY: zeroing a POD struct is safe.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl_buf.as_mut_ptr().cast();
    msg.msg_controllen = ctrl_buf.len() as _;

    // SAFETY: msg points to valid stack-allocated buffers.
    let ret = unsafe { libc::recvmsg(sk, &mut msg, 0) };
    if ret < 0 {
        return Err(TesterError::Io(io::Error::last_os_error()));
    }

    if tstamp {
        rx_timestamp_check(&msg, SOF_TIMESTAMPING_RX_SOFTWARE, 0)?;
    }

    Ok(ret as usize)
}

/// Enable RX timestamping on a socket by setting `SO_TIMESTAMPING`.
///
/// Only the RX-related bits of `flags` are relevant; if none are set the
/// function returns immediately.
///
/// Equivalent to `rx_timestamping_init` in `tools/tester.h`.
#[allow(unsafe_code)]
pub fn rx_timestamping_init(fd: RawFd, flags: u32) -> Result<(), TesterError> {
    let rx_mask = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_RX_HARDWARE;
    if flags & rx_mask == 0 {
        return Ok(());
    }

    let val = flags & rx_mask;
    // SAFETY: setsockopt is called with valid fd and correctly-sized value.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            (&val as *const u32).cast(),
            mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        tracing::warn!("failed to set SO_TIMESTAMPING");
        return Err(TesterError::Io(e));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Ethtool TS info probe
// ---------------------------------------------------------------------------

/// Verify the Bluetooth HCI transport exposes expected timestamping caps.
///
/// Creates a `PF_BLUETOOTH` socket, issues `SIOCETHTOOL` with
/// `ETHTOOL_GET_TS_INFO`, and compares the returned capabilities against
/// the expected set.
///
/// Equivalent to `test_ethtool_get_ts_info` in `tools/tester.h`.
#[allow(unsafe_code)]
pub fn test_ethtool_get_ts_info(
    index: u32,
    proto: i32,
    sco_flowctl: bool,
) -> Result<(), TesterError> {
    // SAFETY: creating an AF_BLUETOOTH socket is a valid syscall.
    let sk = unsafe { libc::socket(PF_BLUETOOTH, libc::SOCK_SEQPACKET, proto) };
    if sk < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EPROTONOSUPPORT) {
            return Err(TesterError::TestAborted);
        }
        tracing::warn!("test_ethtool_get_ts_info: socket creation failed: {}", e);
        return Err(TesterError::SocketFailed(e.to_string()));
    }

    let ifname = format!("hci{index}");
    let ifname_c = match CString::new(ifname.clone()) {
        Ok(c) => c,
        Err(e) => {
            // SAFETY: closing a valid fd.
            unsafe {
                libc::close(sk);
            }
            return Err(TesterError::TestFailed(e.to_string()));
        }
    };

    // SAFETY: zeroing a POD struct is safe.
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = ifname_c.as_bytes_with_nul();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ);
    // SAFETY: copying the interface name into the fixed-size buffer.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr().cast(),
            copy_len,
        );
    }

    let mut ts_info = EthtoolTsInfo::default();
    ifr.ifr_ifru.ifru_data = (&raw mut ts_info).cast();

    // SAFETY: ioctl with SIOCETHTOOL on a valid socket fd.
    let rc = unsafe { libc::ioctl(sk, libc::SIOCETHTOOL as libc::c_ulong, &mut ifr) };
    // SAFETY: close the socket.
    unsafe {
        libc::close(sk);
    }

    if rc < 0 {
        let e = io::Error::last_os_error();
        tracing::warn!("SIOCETHTOOL failed");
        return Err(TesterError::Io(e));
    }

    let mut expected_so = SOF_TIMESTAMPING_TX_SOFTWARE
        | SOF_TIMESTAMPING_RX_SOFTWARE
        | SOF_TIMESTAMPING_SOFTWARE
        | SOF_TIMESTAMPING_TX_COMPLETION;

    if proto == BTPROTO_SCO && !sco_flowctl {
        expected_so &= !SOF_TIMESTAMPING_TX_COMPLETION;
    }

    if ts_info.cmd != ETHTOOL_GET_TS_INFO
        || ts_info.so_timestamping != expected_so
        || ts_info.phc_index != -1
        || ts_info.tx_types != (1 << HWTSTAMP_TX_OFF)
        || ts_info.rx_filters != (1 << HWTSTAMP_FILTER_NONE)
    {
        tracing::warn!("bad ethtool_ts_info");
        return Err(TesterError::EthtoolCheckFailed);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// TestRunner — QEMU-based integration test infrastructure
// ---------------------------------------------------------------------------

/// Mount table entry for guest-side pseudo-filesystem setup.
struct MountEntry {
    fstype: &'static str,
    target: &'static str,
    flags: libc::c_ulong,
}

/// Default mount table used during guest init to set up the virtual
/// filesystem environment before any test daemons are launched.
const MOUNT_TABLE: &[MountEntry] = &[
    MountEntry {
        fstype: "sysfs",
        target: "/sys",
        flags: libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
    },
    MountEntry {
        fstype: "proc",
        target: "/proc",
        flags: libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
    },
    MountEntry { fstype: "devtmpfs", target: "/dev", flags: libc::MS_NOSUID },
    MountEntry { fstype: "devpts", target: "/dev/pts", flags: libc::MS_NOSUID | libc::MS_NOEXEC },
    MountEntry {
        fstype: "tmpfs",
        target: "/dev/shm",
        flags: libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
    },
    MountEntry {
        fstype: "tmpfs",
        target: "/run",
        flags: libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
    },
    MountEntry {
        fstype: "tmpfs",
        target: "/tmp",
        flags: libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
    },
    MountEntry { fstype: "debugfs", target: "/sys/kernel/debug", flags: 0 },
];

/// Configuration overlay directories that need writeable tmpfs mounts.
const CONFIG_TABLE: &[&str] =
    &["/var/lib/bluetooth", "/etc/bluetooth", "/etc/dbus-1", "/usr/share/dbus-1"];

/// QEMU binary search paths, tried in order.
const QEMU_SEARCH: &[&str] = &[
    "qemu-system-x86_64",
    "/usr/bin/qemu-system-x86_64",
    "qemu-system-i386",
    "/usr/bin/qemu-system-i386",
];

/// Kernel image search paths, tried in order.
const KERNEL_SEARCH: &[&str] =
    &["bzImage", "arch/x86/boot/bzImage", "vmlinux", "arch/x86_64/boot/bzImage"];

/// QEMU-based integration test runner.
///
/// Orchestrates virtual-machine lifecycle for running BlueZ integration tests
/// inside an isolated QEMU guest. On the host side it locates QEMU and a
/// kernel image, constructs the VM command line, and waits for completion.
/// When running as PID 1 inside the guest it mounts pseudo-filesystems,
/// starts D-Bus/Bluetooth/monitor daemons, executes the test binary, and
/// shuts down.
///
/// Equivalent to the infrastructure in `tools/test-runner.c`.
#[derive(Debug, Default)]
pub struct TestRunner {
    /// Path to the QEMU binary (resolved by `find_qemu`).
    pub qemu_binary: Option<String>,
    /// Path to the kernel image (resolved by `find_kernel`).
    pub kernel_image: Option<String>,
    /// Whether to run tests automatically and exit.
    pub run_auto: bool,
    /// Start a system D-Bus daemon.
    pub start_dbus: bool,
    /// Start a session D-Bus daemon.
    pub start_dbus_session: bool,
    /// Start `bluetoothd`.
    pub start_daemon: bool,
    /// Start `btmon`.
    pub start_monitor: bool,
    /// Number of virtual Bluetooth devices.
    pub num_devs: u32,
    /// Number of HCI emulators to create via btvirt.
    pub num_emulator: u32,
    /// Audio server type (e.g. "pipewire").
    pub audio_server: Option<String>,
    /// USB device specification for QEMU passthrough.
    pub usb_dev: Option<String>,
    /// Use host CPU for QEMU (KVM acceleration).
    pub host_cpu: bool,
}

impl TestRunner {
    /// Create a new `TestRunner` from command-line arguments.
    ///
    /// Parses a standard set of long options matching the C `test-runner.c`
    /// `getopt_long` table: `--auto`, `--dbus`, `--dbus-session`,
    /// `--daemon`, `--monitor`, `--emulator <N>`, `--audio <server>`,
    /// `--unix`, `--usb <dev>`, `--qemu <path>`, `--qemu-host-cpu`,
    /// `--kernel <path>`.
    pub fn new(args: &[String]) -> Self {
        let mut runner = Self::default();

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-a" | "--auto" => runner.run_auto = true,
                "-b" | "--dbus" => runner.start_dbus = true,
                "-s" | "--dbus-session" => runner.start_dbus_session = true,
                "-d" | "--daemon" => runner.start_daemon = true,
                "-m" | "--monitor" => runner.start_monitor = true,
                "-l" | "--emulator" => {
                    i += 1;
                    if i < args.len() {
                        runner.num_emulator = args[i].parse().unwrap_or(0);
                    }
                }
                "-A" | "--audio" => {
                    i += 1;
                    if i < args.len() {
                        runner.audio_server = Some(args[i].clone());
                    }
                }
                "-U" | "--usb" => {
                    i += 1;
                    if i < args.len() {
                        runner.usb_dev = Some(args[i].clone());
                    }
                }
                "-q" | "--qemu" => {
                    i += 1;
                    if i < args.len() {
                        runner.qemu_binary = Some(args[i].clone());
                    }
                }
                "-k" | "--kernel" => {
                    i += 1;
                    if i < args.len() {
                        runner.kernel_image = Some(args[i].clone());
                    }
                }
                "-H" | "--qemu-host-cpu" => runner.host_cpu = true,
                other => {
                    // If it looks like a plain number, treat it as num_devs.
                    if let Ok(n) = other.parse::<u32>() {
                        runner.num_devs = n;
                    }
                }
            }
            i += 1;
        }

        runner
    }

    /// Locate a QEMU system emulator binary on the host.
    ///
    /// If `self.qemu_binary` is already set (via `--qemu`), that path is
    /// verified to exist. Otherwise the standard search paths are tried.
    /// Returns `Ok(path)` or `Err` if no binary is found.
    pub fn find_qemu(&mut self) -> Result<String, TesterError> {
        if let Some(ref qemu) = self.qemu_binary {
            if Path::new(qemu).exists() {
                return Ok(qemu.clone());
            }
            return Err(TesterError::TestFailed(format!("QEMU binary not found: {qemu}")));
        }

        for candidate in QEMU_SEARCH {
            // Check PATH via `which`.
            if let Ok(output) = std::process::Command::new("which").arg(candidate).output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    self.qemu_binary = Some(path.clone());
                    return Ok(path);
                }
            }
            // Check absolute path.
            if Path::new(candidate).exists() {
                self.qemu_binary = Some((*candidate).to_string());
                return Ok((*candidate).to_string());
            }
        }

        Err(TesterError::TestFailed("No QEMU binary found".to_string()))
    }

    /// Locate a Linux kernel image for the QEMU guest.
    ///
    /// If `self.kernel_image` is already set (via `--kernel`), that path is
    /// verified. Otherwise standard search paths are tried.
    pub fn find_kernel(&mut self) -> Result<String, TesterError> {
        if let Some(ref kernel) = self.kernel_image {
            if Path::new(kernel).exists() {
                return Ok(kernel.clone());
            }
            return Err(TesterError::TestFailed(format!("Kernel image not found: {kernel}")));
        }

        for candidate in KERNEL_SEARCH {
            if Path::new(candidate).exists() {
                self.kernel_image = Some((*candidate).to_string());
                return Ok((*candidate).to_string());
            }
        }

        Err(TesterError::TestFailed("No kernel image found".to_string()))
    }

    /// Launch QEMU with the resolved binary and kernel, wiring up a
    /// virtio-9p root share, serial console, and the test binary's
    /// kernel command-line parameters.
    ///
    /// Returns the QEMU process exit status.
    ///
    /// Equivalent to `start_qemu` in `tools/test-runner.c`.
    pub async fn start_qemu(
        &self,
        test_binary: &str,
        test_args: &[String],
    ) -> Result<i32, TesterError> {
        let qemu = self
            .qemu_binary
            .as_deref()
            .ok_or_else(|| TesterError::TestFailed("QEMU binary not set".into()))?;
        let kernel = self
            .kernel_image
            .as_deref()
            .ok_or_else(|| TesterError::TestFailed("Kernel image not set".into()))?;

        let home = std::env::current_dir().map_err(TesterError::Io)?.to_string_lossy().to_string();

        // Build kernel command line.
        let mut cmdline_parts: Vec<String> = vec![
            "console=ttyS0".to_string(),
            "rootfstype=9p".to_string(),
            "rootflags=trans=virtio,version=9p2000.L".to_string(),
            "root=/dev/root".to_string(),
            "ro".to_string(),
            "init=/usr/libexec/bluetooth/tests/test-runner".to_string(),
            format!("TESTHOME={home}"),
        ];

        if self.start_dbus {
            cmdline_parts.push("TESTDBUS=1".to_string());
        }
        if self.start_dbus_session {
            cmdline_parts.push("TESTDBUSSESSION=1".to_string());
        }
        if self.start_daemon {
            cmdline_parts.push("TESTDAEMON=1".to_string());
        }
        if self.start_monitor {
            cmdline_parts.push("TESTMONITOR=1".to_string());
        }
        if self.num_emulator > 0 {
            cmdline_parts.push(format!("TESTEMULATOR={}", self.num_emulator));
        }
        if self.num_devs > 0 {
            cmdline_parts.push(format!("TESTDEVS={}", self.num_devs));
        }
        if self.run_auto {
            cmdline_parts.push("TESTAUTO=1".to_string());
        }
        if let Some(ref audio) = self.audio_server {
            cmdline_parts.push(format!("TESTAUDIO={audio}"));
        }

        // Append the test binary and its arguments.
        let mut test_cmdline = test_binary.to_string();
        for arg in test_args {
            test_cmdline.push(' ');
            test_cmdline.push_str(arg);
        }
        cmdline_parts.push(format!("TESTARGS={test_cmdline}"));

        let kernel_cmdline = cmdline_parts.join(" ");

        let mut cmd = tokio::process::Command::new(qemu);
        cmd.args(["-nodefaults", "-no-user-config"]);
        cmd.args(["-monitor", "none"]);
        cmd.args(["-display", "none"]);
        cmd.args(["-machine", "type=q35,accel=kvm:tcg"]);
        cmd.args(["-m", "256M"]);
        cmd.args(["-net", "none"]);
        cmd.arg("-no-reboot");

        if self.host_cpu {
            cmd.args(["-cpu", "host"]);
        }

        // Root filesystem via virtio-9p.
        cmd.args(["-device", "virtio-9p-pci,fsdev=root,mount_tag=/dev/root"]);
        cmd.args(["-fsdev", "local,id=root,path=/,security_model=passthrough,readonly=on"]);

        // USB passthrough if configured.
        if let Some(ref usb) = self.usb_dev {
            cmd.args(["-usb", "-device", &format!("usb-host,{usb}")]);
        }

        // Serial console.
        cmd.args(["-chardev", "stdio,id=con"]);
        cmd.args(["-serial", "chardev:con"]);

        cmd.args(["-kernel", kernel]);
        cmd.args(["-append", &kernel_cmdline]);

        tracing::info!("Starting QEMU: {} {}", qemu, kernel);
        tracing::debug!("Kernel cmdline: {}", kernel_cmdline);

        let mut child = cmd.spawn().map_err(TesterError::Io)?;
        let status = child.wait().await.map_err(TesterError::Io)?;

        Ok(status.code().unwrap_or(1))
    }

    /// Prepare the guest-side filesystem sandbox.
    ///
    /// Called when running as PID 1 inside the QEMU guest. Mounts
    /// pseudo-filesystems from `MOUNT_TABLE` and creates writable tmpfs
    /// overlays for the configuration directories in `CONFIG_TABLE`.
    ///
    /// Equivalent to the guest init path in `tools/test-runner.c`.
    #[allow(unsafe_code)]
    pub fn prepare_sandbox(&self) -> Result<(), TesterError> {
        use std::ffi::CString;

        // Mount pseudo-filesystems.
        for entry in MOUNT_TABLE {
            let target_c =
                CString::new(entry.target).map_err(|e| TesterError::TestFailed(e.to_string()))?;
            let fstype_c =
                CString::new(entry.fstype).map_err(|e| TesterError::TestFailed(e.to_string()))?;

            // Create target directory if it doesn't exist.
            let _ = fs::create_dir_all(entry.target);

            // SAFETY: mount() with valid C-string arguments and flags.
            let rc = unsafe {
                libc::mount(
                    fstype_c.as_ptr(),
                    target_c.as_ptr(),
                    fstype_c.as_ptr(),
                    entry.flags,
                    std::ptr::null(),
                )
            };
            if rc < 0 {
                let e = io::Error::last_os_error();
                tracing::warn!("Failed to mount {} on {}: {}", entry.fstype, entry.target, e,);
                // Non-fatal — continue with remaining mounts.
            } else {
                tracing::debug!("Mounted {} on {}", entry.fstype, entry.target);
            }
        }

        // Create config overlay directories.
        for dir in CONFIG_TABLE {
            let _ = fs::create_dir_all(dir);
            let target_c =
                CString::new(*dir).map_err(|e| TesterError::TestFailed(e.to_string()))?;
            let tmpfs_c =
                CString::new("tmpfs").map_err(|e| TesterError::TestFailed(e.to_string()))?;

            // SAFETY: mount() with valid C-string arguments.
            let rc = unsafe {
                libc::mount(
                    tmpfs_c.as_ptr(),
                    target_c.as_ptr(),
                    tmpfs_c.as_ptr(),
                    0,
                    std::ptr::null(),
                )
            };
            if rc < 0 {
                let e = io::Error::last_os_error();
                tracing::warn!("Failed to mount tmpfs on {}: {}", dir, e);
            } else {
                tracing::debug!("Config overlay mounted on {}", dir);
            }
        }

        // Write D-Bus system configuration if dbus is requested.
        if self.start_dbus {
            let dbus_conf_dir = "/etc/dbus-1";
            let _ = fs::create_dir_all(dbus_conf_dir);
            let conf = r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=/run/dbus/system_bus_socket</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#;
            let conf_path = format!("{dbus_conf_dir}/system.conf");
            fs::write(&conf_path, conf).map_err(TesterError::Io)?;
            tracing::debug!("Wrote D-Bus system config to {}", conf_path);
        }

        Ok(())
    }

    /// Execute the test suite inside the QEMU guest.
    ///
    /// Spawns supporting daemons (D-Bus, bluetoothd, btmon, btvirt, audio
    /// servers) according to the configuration parsed from the kernel
    /// command line, runs the test binary, collects the exit code, and
    /// tears down all child processes.
    ///
    /// When `run_auto` is set the function returns immediately after the
    /// test binary exits.  Otherwise it enters a waitpid loop, monitoring
    /// child processes until all have exited or a SIGTERM is received.
    ///
    /// Equivalent to `run_tests` in `tools/test-runner.c`.
    #[allow(unsafe_code)]
    pub async fn run_tests(
        &self,
        test_binary: &str,
        test_args: &[String],
    ) -> Result<i32, TesterError> {
        let mut children: Vec<tokio::process::Child> = Vec::new();

        // Start D-Bus system daemon.
        if self.start_dbus {
            let dbus_socket_dir = "/run/dbus";
            let _ = fs::create_dir_all(dbus_socket_dir);
            tracing::info!("Starting D-Bus system daemon");
            let child = tokio::process::Command::new("dbus-daemon")
                .args(["--system", "--nofork", "--nopidfile", "--nosyslog"])
                .spawn()
                .map_err(TesterError::Io)?;
            children.push(child);
            // Give D-Bus a moment to start.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        // Start D-Bus session daemon.
        if self.start_dbus_session {
            tracing::info!("Starting D-Bus session daemon");
            let child = tokio::process::Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--nopidfile", "--nosyslog"])
                .arg("--address=unix:path=/tmp/dbus-session")
                .spawn()
                .map_err(TesterError::Io)?;
            // SAFETY: set_var is unsafe in edition 2024; we are the sole thread
            // touching this variable at this point during guest init.
            unsafe {
                std::env::set_var("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/dbus-session");
            }
            children.push(child);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        // Start btvirt (virtual HCI devices).
        if self.num_emulator > 0 {
            tracing::info!("Starting btvirt with {} emulators", self.num_emulator);
            let mut cmd = tokio::process::Command::new("btvirt");
            for _ in 0..self.num_emulator {
                cmd.arg("-l");
            }
            match cmd.spawn() {
                Ok(child) => children.push(child),
                Err(e) => tracing::warn!("Failed to start btvirt: {}", e),
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        // Start btmon.
        if self.start_monitor {
            tracing::info!("Starting btmon");
            match tokio::process::Command::new("btmon").spawn() {
                Ok(child) => children.push(child),
                Err(e) => tracing::warn!("Failed to start btmon: {}", e),
            }
        }

        // Start bluetoothd.
        if self.start_daemon {
            tracing::info!("Starting bluetoothd");
            let mut cmd = tokio::process::Command::new("bluetoothd");
            cmd.args(["--nodetach", "--debug"]);
            match cmd.spawn() {
                Ok(child) => children.push(child),
                Err(e) => tracing::warn!("Failed to start bluetoothd: {}", e),
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // Start audio server (PipeWire / WirePlumber).
        if let Some(ref audio) = self.audio_server {
            tracing::info!("Starting audio server: {}", audio);
            match audio.as_str() {
                "pipewire" => {
                    if let Ok(child) = tokio::process::Command::new("pipewire").spawn() {
                        children.push(child);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    if let Ok(child) = tokio::process::Command::new("wireplumber").spawn() {
                        children.push(child);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                other => {
                    tracing::warn!("Unknown audio server type: {}", other);
                }
            }
        }

        // Run the actual test binary.
        tracing::info!("Running test binary: {}", test_binary);
        let mut test_cmd = tokio::process::Command::new(test_binary);
        test_cmd.args(test_args);
        let mut test_child = test_cmd.spawn().map_err(TesterError::Io)?;
        let test_status = test_child.wait().await.map_err(TesterError::Io)?;
        let exit_code = test_status.code().unwrap_or(1);

        tracing::info!("Test exited with code {}", exit_code);

        // Tear down all daemon children.
        for mut child in children {
            let _ = child.kill().await;
        }

        Ok(exit_code)
    }
}
