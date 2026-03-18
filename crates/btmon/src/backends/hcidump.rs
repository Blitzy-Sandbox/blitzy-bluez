// SPDX-License-Identifier: GPL-2.0-or-later
//! Legacy raw HCI socket tracing backend for btmon.
//!
//! Complete Rust rewrite of `monitor/hcidump.c` (409 lines) and
//! `monitor/hcidump.h` (12 lines). Provides fallback HCI packet capture
//! using raw HCI sockets with `HCI_CHANNEL_RAW` when `HCI_CHANNEL_MONITOR`
//! is unavailable on the running kernel.
//!
//! The GLib mainloop-based event callbacks from the C implementation are
//! replaced with tokio async tasks using [`AsyncFd`] for readiness
//! notification on raw Bluetooth sockets. All `callback_t fn + void *user_data`
//! patterns are replaced with owned async state.
//!
//! # Cmsg Parsing
//!
//! HCI sockets provide direction (`HCI_CMSG_DIR`) and timestamp
//! (`HCI_CMSG_TSTAMP`) data as ancillary control messages at `SOL_HCI`
//! level. Because `nix 0.29`'s `ControlMessageOwned::Unknown` variant has
//! private fields and cannot expose non-standard protocol cmsg payloads,
//! this module uses `libc::recvmsg` directly with manual `CMSG_FIRSTHDR` /
//! `CMSG_NXTHDR` iteration for reliable extraction of HCI-specific cmsg
//! data.
//!
//! # Safety
//!
//! This module is a designated FFI boundary for raw Bluetooth HCI socket
//! operations. Unsafe blocks are used for: `AF_BLUETOOTH` socket creation,
//! `setsockopt` for HCI filter/options, `bind` to HCI controllers, `ioctl`
//! for `HCIGETDEVINFO`/`HCIGETDEVLIST`, and `recvmsg` with manual cmsg
//! parsing. Each unsafe site includes a `// SAFETY:` comment documenting
//! the invariant.
// All FFI operations delegated to safe wrappers in bluez_shared::sys::ffi_helpers.

use std::io::{Error, IoSliceMut, Result};
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;

use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;

use nix::sys::socket::MsgFlags;

use tracing::{error, warn};

use crate::packet;

use bluez_shared::sys::bluetooth::{AF_BLUETOOTH, BTPROTO_HCI, SOL_HCI, bdaddr_t};
use bluez_shared::sys::ffi_helpers as ffi;
use bluez_shared::sys::hci::{
    EVT_SI_DEVICE, EVT_STACK_INTERNAL, HCI_ACLDATA_PKT, HCI_CHANNEL_RAW, HCI_CMSG_DIR,
    HCI_CMSG_TSTAMP, HCI_COMMAND_PKT, HCI_DATA_DIR, HCI_DEV_NONE, HCI_DEV_REG, HCI_DEV_UNREG,
    HCI_EVENT_HDR_SIZE, HCI_EVENT_PKT, HCI_FILTER, HCI_MAX_DEV, HCI_MAX_FRAME_SIZE,
    HCI_SCODATA_PKT, HCI_TIME_STAMP, HCIGETDEVINFO, HCIGETDEVLIST, evt_si_device,
    evt_stack_internal, hci_dev_info, hci_dev_list_req, hci_dev_req, hci_event_hdr, hci_filter,
    hci_filter_all_events, hci_filter_all_ptypes, hci_filter_clear, hci_filter_set_event,
    hci_filter_set_ptype, sockaddr_hci,
};

/// Per-device tracking state for an open HCI raw socket.
///
/// Replaces C `struct hcidump_data` (lines 34–37 of `hcidump.c`).
/// The [`AsyncFd`]-wrapped [`OwnedFd`] provides both async readiness
/// notification (replacing `mainloop_add_fd` with `EPOLLIN`) and RAII-based
/// socket cleanup via [`Drop`], replacing the manual `free_data()` cleanup
/// function from the C implementation (lines 39–46 of `hcidump.c`).
struct HcidumpData {
    /// HCI controller index (e.g., 0 for hci0, `HCI_DEV_NONE` for
    /// the stack-internal monitoring socket).
    index: u16,
    /// Async-ready owned HCI socket. Wraps the raw fd in [`AsyncFd`] for
    /// tokio readiness notification and in [`OwnedFd`] for automatic close
    /// on drop.
    fd: AsyncFd<OwnedFd>,
}

/// Format a [`bdaddr_t`] as a standard Bluetooth address string
/// (`XX:XX:XX:XX:XX:XX`).
///
/// The bytes are displayed in reverse order (most significant first),
/// matching the standard Bluetooth address display convention used by
/// `ba2str()` in the BlueZ C codebase.
fn ba2str(ba: &bdaddr_t) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        ba.b[5], ba.b[4], ba.b[3], ba.b[2], ba.b[1], ba.b[0]
    )
}

/// Create a raw HCI socket for the specified controller index with full
/// packet capture configuration.
///
/// Replaces C `open_hci_dev()` (lines 48–95 of `hcidump.c`). Creates an
/// `AF_BLUETOOTH` raw socket, configures the HCI filter to capture all
/// packet types and events, enables directional and timestamped capture,
/// and binds to the specified controller.
fn open_hci_dev(index: u16) -> Result<OwnedFd> {
    // SAFETY: Creating an AF_BLUETOOTH raw HCI socket. This is a designated
    // unsafe FFI boundary site for kernel socket creation. The socket family
    // (AF_BLUETOOTH), type (SOCK_RAW|SOCK_CLOEXEC), and protocol (BTPROTO_HCI)
    // are all valid kernel-defined constants for Bluetooth HCI sockets.
    let fd = ffi::raw_socket(AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, BTPROTO_HCI);
    if fd < 0 {
        error!("Failed to create HCI raw socket for hci{}", index);
        return Err(Error::last_os_error());
    }

    // SAFETY: fd is a valid file descriptor just created by socket().
    // Wrapping in OwnedFd ensures automatic cleanup on all error paths.
    let owned_fd = ffi::raw_owned_fd(fd);
    let raw_fd = owned_fd.as_raw_fd();

    // Configure HCI filter to capture all packet types and all events
    let mut flt: hci_filter = ffi::raw_zeroed();
    hci_filter_clear(&mut flt);
    hci_filter_all_ptypes(&mut flt);
    hci_filter_all_events(&mut flt);

    // SAFETY: setsockopt with SOL_HCI/HCI_FILTER on a valid HCI socket fd.
    // The filter struct is properly initialized and correctly sized.
    let ret = ffi::raw_setsockopt(raw_fd, SOL_HCI, HCI_FILTER, &flt);
    if ret < 0 {
        error!("Failed to set HCI filter for hci{}", index);
        return Err(Error::last_os_error());
    }

    // Enable directional capture (HCI_DATA_DIR) — provides incoming/outgoing
    // indication via cmsg ancillary data on each received packet
    let opt: libc::c_int = 1;

    // SAFETY: setsockopt with SOL_HCI/HCI_DATA_DIR on a valid HCI socket fd.
    // opt is a properly-sized c_int value.
    let ret = ffi::raw_setsockopt(raw_fd, SOL_HCI, HCI_DATA_DIR, &opt);
    if ret < 0 {
        error!("Failed to enable HCI_DATA_DIR for hci{}", index);
        return Err(Error::last_os_error());
    }

    // Enable timestamped capture (HCI_TIME_STAMP) — provides kernel-level
    // packet timestamps via cmsg ancillary data
    // SAFETY: setsockopt with SOL_HCI/HCI_TIME_STAMP on a valid HCI socket fd.
    // opt is a properly-sized c_int value.
    let ret = ffi::raw_setsockopt(raw_fd, SOL_HCI, HCI_TIME_STAMP, &opt);
    if ret < 0 {
        error!("Failed to enable HCI_TIME_STAMP for hci{}", index);
        return Err(Error::last_os_error());
    }

    // Bind to the specified HCI controller on the RAW channel
    let addr = sockaddr_hci {
        hci_family: AF_BLUETOOTH as u16,
        hci_dev: index,
        hci_channel: HCI_CHANNEL_RAW,
    };

    // SAFETY: bind with a properly initialized sockaddr_hci struct on a valid
    // HCI socket fd. The address family, device index, and channel are all
    // valid kernel-defined values.
    let ret = ffi::raw_bind(raw_fd, &addr);
    if ret < 0 {
        error!("Failed to bind HCI socket for hci{}", index);
        return Err(Error::last_os_error());
    }

    Ok(owned_fd)
}

/// Perform `recvmsg` on a raw HCI socket and extract HCI-specific cmsg
/// ancillary data (direction and timestamp).
///
/// Uses `libc::recvmsg` directly because HCI cmsg types (`SOL_HCI` level)
/// are not handled by nix 0.29's type-safe `ControlMessageOwned` API.
/// [`IoSliceMut`] is used for iov buffer management and [`MsgFlags`]
/// provides the `MSG_DONTWAIT` flag constant.
///
/// Returns `(bytes_received, direction, timestamp)` on success. Direction
/// is -1 if no `HCI_CMSG_DIR` was present. Returns `WouldBlock` error when
/// no data is available (compatible with `AsyncFd::try_io`).
fn hci_recvmsg(
    fd: RawFd,
    data_buf: &mut [u8],
    mut cmsg_buf: Vec<u8>,
) -> Result<(usize, i32, libc::timeval)> {
    let mut iov_slice = IoSliceMut::new(data_buf);

    // SAFETY: Constructing a msghdr for recvmsg. IoSliceMut is
    // #[repr(transparent)] over libc::iovec on Unix, so the pointer cast
    // is valid. The cmsg buffer is properly sized and aligned.
    let mut mhdr: libc::msghdr = ffi::raw_zeroed();
    mhdr.msg_iov = ptr::addr_of_mut!(iov_slice).cast::<libc::iovec>();
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
    mhdr.msg_controllen = cmsg_buf.capacity();

    // SAFETY: recvmsg on a valid raw HCI socket fd with a properly
    // constructed msghdr. MSG_DONTWAIT ensures non-blocking operation.
    let ret = ffi::raw_recvmsg(fd, &mut mhdr, MsgFlags::MSG_DONTWAIT.bits());
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    let len = ret as usize;

    // Extract HCI-specific cmsg ancillary data via manual CMSG iteration.
    // HCI sockets provide direction (HCI_CMSG_DIR) and timestamp
    // (HCI_CMSG_TSTAMP) at SOL_HCI level.
    let mut dir: i32 = -1;
    let mut tv: libc::timeval = ffi::raw_zeroed();

    // SAFETY: CMSG_FIRSTHDR reads the msg_controllen field of a valid
    // msghdr filled by recvmsg. Returns null if no cmsg data is present.
    let mut cmsg: *mut libc::cmsghdr = match ffi::raw_cmsg_firsthdr(&mhdr) {
        Some(p) => p,
        None => return Ok((len, dir, tv)),
    };
    while !cmsg.is_null() {
        // SAFETY: cmsg is a valid pointer to a cmsghdr within the control
        // message buffer, as returned by CMSG_FIRSTHDR / CMSG_NXTHDR.
        let (cmsg_level, cmsg_type, data_ptr) = ffi::raw_cmsg_read(cmsg);
        if cmsg_level == SOL_HCI {
            // SAFETY: CMSG_DATA returns a pointer to the data portion of
            // a valid cmsghdr. Length is validated by cmsg_len.

            if cmsg_type == HCI_CMSG_DIR {
                // SAFETY: HCI_CMSG_DIR payload is a c_int (4 bytes).
                // The kernel guarantees this size for this cmsg type.
                dir = ffi::raw_read_unaligned_ptr::<i32>(data_ptr);
            } else if cmsg_type == HCI_CMSG_TSTAMP {
                // SAFETY: HCI_CMSG_TSTAMP payload is a struct timeval.
                // The kernel guarantees this size for this cmsg type.
                tv = ffi::raw_read_unaligned_ptr::<libc::timeval>(data_ptr);
            }
        }
        // SAFETY: CMSG_NXTHDR advances to the next cmsghdr within the
        // control buffer bounds set by msg_controllen.
        cmsg = match ffi::raw_cmsg_nxthdr(&mhdr, cmsg) {
            Some(p) => p,
            None => break,
        };
    }

    Ok((len, dir, tv))
}

/// Process a single packet received from a per-device HCI raw socket and
/// dispatch it to the btmon packet decoder.
///
/// Replaces the inner logic of C `device_callback()` (lines 97–168 of
/// `hcidump.c`). Performs `recvmsg` with `MSG_DONTWAIT`, extracts direction
/// and timestamp from cmsg ancillary data, and dispatches the packet to the
/// appropriate decoder based on the HCI packet type indicator byte.
fn recv_and_dispatch_device(fd: RawFd, index: u16) -> Result<()> {
    let mut buf = [0u8; HCI_MAX_FRAME_SIZE * 2];
    let cmsg_size = nix::cmsg_space!(libc::c_int, libc::timeval);

    let (len, dir, tv) = hci_recvmsg(fd, &mut buf, cmsg_size)?;

    // Skip packets without valid direction or with zero length
    // (matching C: if (dir < 0 || len < 1) return;)
    if dir < 0 || len < 1 {
        return Ok(());
    }

    // Dispatch based on HCI packet type indicator (first byte of frame)
    let pkt_type = buf[0];
    let data = &buf[1..len];
    let data_len = len - 1;

    match pkt_type {
        HCI_COMMAND_PKT => {
            packet::packet_hci_command(&tv, None, index, data, data_len);
        }
        HCI_EVENT_PKT => {
            packet::packet_hci_event(&tv, None, index, data, data_len);
        }
        HCI_ACLDATA_PKT => {
            packet::packet_hci_acldata(&tv, None, index, dir != 0, data, data_len);
        }
        HCI_SCODATA_PKT => {
            packet::packet_hci_scodata(&tv, None, index, dir != 0, data, data_len);
        }
        _ => {}
    }

    Ok(())
}

/// Async read loop for a per-device HCI raw socket.
///
/// Replaces the combination of `mainloop_add_fd(fd, EPOLLIN, device_callback,
/// data, free_data)` from the C implementation. Uses [`AsyncFd`] for async
/// readiness notification and `try_io` for non-blocking packet reads.
///
/// The loop runs until the socket encounters an error (equivalent to
/// `EPOLLERR`/`EPOLLHUP` handling in the C code), at which point the task
/// terminates and the socket is automatically closed via [`OwnedFd::drop`].
async fn device_read_loop(data: HcidumpData) {
    let index = data.index;
    loop {
        let mut guard = match data.fd.readable().await {
            Ok(guard) => guard,
            Err(e) => {
                error!("AsyncFd readable error for hci{}: {}", index, e);
                break;
            }
        };

        match guard.try_io(|fd| recv_and_dispatch_device(fd.as_raw_fd(), index)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                error!("Packet receive error for hci{}: {}", index, e);
                break;
            }
            Err(_would_block) => continue,
        }
    }
}

/// Open a per-device HCI raw socket and spawn an async read task.
///
/// Replaces C `open_device()` (lines 170–192 of `hcidump.c`). Creates the
/// HCI socket via [`open_hci_dev`], wraps it in [`AsyncFd`], and spawns an
/// async task for continuous packet reading. On error, the device is
/// silently skipped with a warning log.
fn open_device(index: u16) {
    let fd = match open_hci_dev(index) {
        Ok(fd) => fd,
        Err(e) => {
            warn!("Failed to open HCI device hci{}: {}", index, e);
            return;
        }
    };

    let async_fd = match AsyncFd::new(fd) {
        Ok(afd) => afd,
        Err(e) => {
            error!("Failed to create AsyncFd for hci{}: {}", index, e);
            return;
        }
    };

    let data = HcidumpData { index, fd: async_fd };

    let _handle: JoinHandle<()> = tokio::spawn(device_read_loop(data));
}

/// Query HCI device information from the kernel via the `HCIGETDEVINFO` ioctl.
///
/// Replaces C `device_info()` (lines 194–212 of `hcidump.c`). Returns the
/// device type (high nibble of `type_`), bus type (low nibble), Bluetooth
/// address, and device name (first 8 bytes, null-terminated). On ioctl
/// failure, returns default fallback values (`0xFF` for type and bus, zeroed
/// address and empty name) matching the C error handling behavior.
fn device_info(fd: RawFd, index: u16) -> (u8, u8, bdaddr_t, String) {
    // SAFETY: zeroed() produces a valid all-zeros hci_dev_info struct.
    let mut di: hci_dev_info = ffi::raw_zeroed();
    di.dev_id = index;

    // SAFETY: HCIGETDEVINFO ioctl on a valid HCI socket fd with a properly
    // initialized hci_dev_info struct. The kernel reads dev_id and fills the
    // remaining fields. The buffer is correctly sized for the ioctl.
    let ret = ffi::raw_ioctl_with_mut(fd, libc::c_ulong::from(HCIGETDEVINFO), &mut di);
    if ret < 0 {
        warn!("HCIGETDEVINFO failed for hci{}: {}", index, Error::last_os_error());
        let empty_bdaddr: bdaddr_t = ffi::raw_zeroed();
        return (0xFF, 0xFF, empty_bdaddr, String::new());
    }

    // Extract type (high nibble) and bus (low nibble) from the combined
    // type_ field, matching C: *type = di.type >> 4; *bus = di.type & 0x0f;
    let type_ = { di.type_ } >> 4;
    let bus = { di.type_ } & 0x0F;

    // Convert the 8-byte name to a Rust string, terminating at the first
    // null byte. Use lossy conversion to handle any non-UTF8 device names.
    let name_bytes = { di.name };
    let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
    let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();

    let bdaddr = { di.bdaddr };

    (type_, bus, bdaddr, name)
}

/// Enumerate existing HCI devices via the `HCIGETDEVLIST` ioctl and open
/// each one for packet capture.
///
/// Replaces C `device_list()` (lines 214–255 of `hcidump.c`). Uses a
/// dynamically-sized buffer to accommodate the flexible array member in
/// [`hci_dev_list_req`]. For each discovered device, queries device info,
/// registers it with the packet decoder, and opens it for capture.
fn device_list(fd: RawFd, max_dev: u16) {
    // Allocate buffer for hci_dev_list_req header + max_dev * hci_dev_req
    // entries. This handles the C flexible array member pattern where
    // dev_req[0] is a zero-length trailing array.
    let req_size = size_of::<hci_dev_list_req>() + (max_dev as usize) * size_of::<hci_dev_req>();
    let mut buf = vec![0u8; req_size];

    let dl = buf.as_mut_ptr().cast::<hci_dev_list_req>();
    // SAFETY: dl points to a zeroed buffer of sufficient size for the
    // hci_dev_list_req header. Setting dev_num tells the kernel the
    // maximum number of device entries we can receive.
    // Write dev_num field (u16 at offset 0) directly into the buffer.
    buf[..2].copy_from_slice(&max_dev.to_ne_bytes());

    // SAFETY: HCIGETDEVLIST ioctl on a valid HCI socket fd with a properly
    // sized buffer containing dev_num = max_dev. The kernel fills dev_req
    // entries and updates dev_num to the actual count.
    let ret = ffi::raw_ioctl_ptr(fd, libc::c_ulong::from(HCIGETDEVLIST), dl);
    if ret < 0 {
        error!("HCIGETDEVLIST failed: {}", Error::last_os_error());
        return;
    }

    // SAFETY: After successful ioctl, dev_num contains the actual number
    // of devices (<= max_dev), and the buffer contains that many valid
    // hci_dev_req entries following the header.
    let num_devs = ffi::raw_deref_ptr(dl as *const hci_dev_list_req).dev_num as usize;
    let dev_reqs_ptr =
        ffi::raw_byte_offset_cast::<hci_dev_req>(dl as *const u8, size_of::<hci_dev_list_req>());

    for i in 0..num_devs {
        // SAFETY: i < num_devs which was bounded by max_dev, and we
        // allocated max_dev * size_of::<hci_dev_req>() bytes for the
        // device request array. read_unaligned handles packed struct access.
        let dr: hci_dev_req = {
            let p = ffi::raw_ptr_add(dev_reqs_ptr, i);
            ffi::raw_read_unaligned_ptr::<hci_dev_req>(p as *const u8)
        };

        // SAFETY: addr_of! + read_unaligned for safe access to potentially
        // misaligned u16 field in packed struct hci_dev_req.
        let dev_id = ffi::raw_read_packed_field_ptr(std::ptr::addr_of!(dr.dev_id));

        // Get current timestamp for the packet_new_index event
        let mut tv: libc::timeval = ffi::raw_zeroed();
        ffi::raw_gettimeofday(&mut tv);

        let (type_, bus, bdaddr, name) = device_info(fd, dev_id);
        let label = ba2str(&bdaddr);

        packet::packet_new_index(&tv, dev_id, &label, type_, bus, &name);
        open_device(dev_id);
    }
}

/// Create the stack-internal event monitoring socket.
///
/// Replaces C `open_stack_internal()` (lines 257–300 of `hcidump.c`).
/// Creates a raw HCI socket filtered to receive ONLY [`EVT_STACK_INTERNAL`]
/// events, bound to [`HCI_DEV_NONE`] to receive events from all controllers.
/// After socket setup, enumerates existing devices via [`device_list`].
fn open_stack_internal() -> Result<OwnedFd> {
    // SAFETY: Creating an AF_BLUETOOTH raw HCI socket for stack-internal
    // event monitoring. Same designated unsafe FFI boundary as open_hci_dev().
    let fd = ffi::raw_socket(AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, BTPROTO_HCI);
    if fd < 0 {
        error!("Failed to create stack-internal HCI socket");
        return Err(Error::last_os_error());
    }

    // SAFETY: fd is a valid file descriptor just created by socket().
    let owned_fd = ffi::raw_owned_fd(fd);
    let raw_fd = owned_fd.as_raw_fd();

    // Configure HCI filter for ONLY HCI_EVENT_PKT type and
    // EVT_STACK_INTERNAL event — this socket monitors exclusively for
    // device registration/unregistration events
    let mut flt: hci_filter = ffi::raw_zeroed();
    hci_filter_clear(&mut flt);
    hci_filter_set_ptype(HCI_EVENT_PKT, &mut flt);
    hci_filter_set_event(EVT_STACK_INTERNAL, &mut flt);

    // SAFETY: setsockopt with SOL_HCI/HCI_FILTER on a valid HCI socket fd.
    let ret = ffi::raw_setsockopt(raw_fd, SOL_HCI, HCI_FILTER, &flt);
    if ret < 0 {
        error!("Failed to set stack-internal HCI filter");
        return Err(Error::last_os_error());
    }

    // Enable timestamped capture for stack-internal events
    let opt: libc::c_int = 1;
    // SAFETY: setsockopt with SOL_HCI/HCI_TIME_STAMP on a valid HCI socket fd.
    let ret = ffi::raw_setsockopt(raw_fd, SOL_HCI, HCI_TIME_STAMP, &opt);
    if ret < 0 {
        error!("Failed to enable HCI_TIME_STAMP for stack-internal socket");
        return Err(Error::last_os_error());
    }

    // Bind to HCI_DEV_NONE to receive events from all controllers
    let addr = sockaddr_hci {
        hci_family: AF_BLUETOOTH as u16,
        hci_dev: HCI_DEV_NONE,
        hci_channel: HCI_CHANNEL_RAW,
    };

    // SAFETY: bind with a properly initialized sockaddr_hci on a valid
    // HCI socket fd. HCI_DEV_NONE means "all devices".
    let ret = ffi::raw_bind(raw_fd, &addr);
    if ret < 0 {
        error!("Failed to bind stack-internal HCI socket");
        return Err(Error::last_os_error());
    }

    // Enumerate and open existing HCI devices before starting the monitor
    device_list(raw_fd, HCI_MAX_DEV);

    Ok(owned_fd)
}

/// Process a single stack-internal event from the monitoring socket.
///
/// Replaces the inner logic of C `stack_internal_callback()` (lines 302–381
/// of `hcidump.c`). Handles `HCI_DEV_REG` (new device registration) and
/// `HCI_DEV_UNREG` (device removal) events by parsing the nested HCI event
/// structures and dispatching to the packet decoder.
fn recv_stack_internal(fd: RawFd) -> Result<()> {
    let mut buf = [0u8; HCI_MAX_FRAME_SIZE];
    let cmsg_size = nix::cmsg_space!(libc::timeval);

    let (len, _dir, tv) = hci_recvmsg(fd, &mut buf, cmsg_size)?;

    // Minimum packet size: 1 (type indicator) + HCI_EVENT_HDR_SIZE (2) +
    // size_of::<evt_stack_internal>() (2) + size_of::<evt_si_device>() (4) = 9
    let min_size =
        1 + HCI_EVENT_HDR_SIZE + size_of::<evt_stack_internal>() + size_of::<evt_si_device>();
    if len < min_size {
        return Ok(());
    }

    // Verify packet type indicator is HCI_EVENT_PKT (0x04)
    if buf[0] != HCI_EVENT_PKT {
        return Ok(());
    }

    // Parse hci_event_hdr at buf[1..3]
    // SAFETY: len >= min_size (9) ensures buf[1..3] is within bounds.
    // read_unaligned handles the packed struct correctly.
    let eh: hci_event_hdr = ffi::raw_read_unaligned::<hci_event_hdr>(&buf, 1).unwrap();
    if eh.evt != EVT_STACK_INTERNAL {
        return Ok(());
    }

    // Parse evt_stack_internal at buf[3..5]
    let si_offset = 1 + HCI_EVENT_HDR_SIZE;
    // SAFETY: len >= min_size ensures buf[si_offset..si_offset+2] is valid.
    let si: evt_stack_internal =
        ffi::raw_read_unaligned::<evt_stack_internal>(&buf, si_offset).unwrap();
    // SAFETY: addr_of! + read_unaligned for safe access to potentially
    // misaligned u16 field in packed struct.
    let si_type = ffi::raw_read_packed_field_ptr(std::ptr::addr_of!(si.type_));
    if si_type != u16::from(EVT_SI_DEVICE) {
        return Ok(());
    }

    // Parse evt_si_device at buf[5..9]
    let sd_offset = si_offset + size_of::<evt_stack_internal>();
    // SAFETY: len >= min_size ensures buf[sd_offset..sd_offset+4] is valid.
    let sd: evt_si_device = ffi::raw_read_unaligned::<evt_si_device>(&buf, sd_offset).unwrap();

    // SAFETY: addr_of! + read_unaligned for safe access to potentially
    // misaligned u16 fields in packed struct evt_si_device.
    let sd_event = ffi::raw_read_packed_field_ptr(std::ptr::addr_of!(sd.event));
    let sd_dev_id = ffi::raw_read_packed_field_ptr(std::ptr::addr_of!(sd.dev_id));

    if sd_event == u16::from(HCI_DEV_REG) {
        let (type_, bus, bdaddr, name) = device_info(fd, sd_dev_id);
        let label = ba2str(&bdaddr);
        packet::packet_new_index(&tv, sd_dev_id, &label, type_, bus, &name);
        open_device(sd_dev_id);
    } else if sd_event == u16::from(HCI_DEV_UNREG) {
        // Use all-zeros bdaddr (bdaddr_any) for unregistration events,
        // matching C: ba2str(&bdaddr_any, str)
        let empty_bdaddr: bdaddr_t = ffi::raw_zeroed();
        let label = ba2str(&empty_bdaddr);
        packet::packet_del_index(&tv, sd_dev_id, &label);
    }

    Ok(())
}

/// Async read loop for the stack-internal event monitoring socket.
///
/// Replaces the `mainloop_add_fd(fd, EPOLLIN, stack_internal_callback,
/// data, free_data)` registration from the C implementation. Continuously
/// monitors for HCI device registration/unregistration events and dispatches
/// them to the packet decoder and device opener.
async fn stack_internal_read_loop(data: HcidumpData) {
    loop {
        let mut guard = match data.fd.readable().await {
            Ok(guard) => guard,
            Err(e) => {
                error!("AsyncFd readable error for stack-internal socket: {}", e);
                break;
            }
        };

        match guard.try_io(|fd| recv_stack_internal(fd.as_raw_fd())) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                error!("Stack-internal receive error: {}", e);
                break;
            }
            Err(_would_block) => continue,
        }
    }
}

/// Start the legacy hcidump-style raw HCI socket tracing backend.
///
/// Replaces C `hcidump_tracing()` (lines 383–408 of `hcidump.c`). Creates
/// the stack-internal event monitoring socket (which also enumerates and
/// opens existing devices during setup), then spawns an async task for
/// continuous event monitoring.
///
/// This backend is used as a fallback when `HCI_CHANNEL_MONITOR` is not
/// available on the running kernel.
///
/// # Errors
///
/// Returns an error if the stack-internal monitoring socket cannot be
/// created or configured.
pub async fn hcidump_tracing() -> Result<()> {
    let fd = open_stack_internal()?;

    let async_fd = AsyncFd::new(fd).map_err(|e| {
        error!("Failed to create AsyncFd for stack-internal socket: {}", e);
        e
    })?;

    let data = HcidumpData { index: HCI_DEV_NONE, fd: async_fd };

    let _handle: JoinHandle<()> = tokio::spawn(stack_internal_read_loop(data));

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit Tests — exercises the key parsing and formatting functions in this
// module, covering the ffi_helpers-based packed-struct read paths.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ba2str — Bluetooth address formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_ba2str_zero_address() {
        let ba = bdaddr_t { b: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00] };
        assert_eq!(ba2str(&ba), "00:00:00:00:00:00");
    }

    #[test]
    fn test_ba2str_typical_address() {
        // Bytes are stored least-significant-first in bdaddr_t but
        // displayed most-significant-first.
        let ba = bdaddr_t { b: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] };
        assert_eq!(ba2str(&ba), "FF:EE:DD:CC:BB:AA");
    }

    #[test]
    fn test_ba2str_all_ff() {
        let ba = bdaddr_t { b: [0xFF; 6] };
        assert_eq!(ba2str(&ba), "FF:FF:FF:FF:FF:FF");
    }

    // -----------------------------------------------------------------------
    // HCI filter manipulation helpers (re-exported from bluez_shared::sys::hci)
    // -----------------------------------------------------------------------

    #[test]
    fn test_hci_filter_clear_and_set() {
        let mut flt: hci_filter = ffi::raw_zeroed();
        hci_filter_clear(&mut flt);
        // After clear, all bits should be zero.
        assert_eq!(flt.type_mask, 0);
        assert_eq!(flt.event_mask, [0u32; 2]);

        // Set specific packet types.
        hci_filter_set_ptype(HCI_COMMAND_PKT, &mut flt);
        hci_filter_set_ptype(HCI_ACLDATA_PKT, &mut flt);
        assert_ne!(flt.type_mask, 0, "type_mask should have bits set");

        // Set a standard event (event code < 64 fits in the 2-word mask).
        // Event 0x0E = HCI Command Complete
        hci_filter_set_event(0x0E, &mut flt);
        let has_bits = flt.event_mask[0] != 0 || flt.event_mask[1] != 0;
        assert!(has_bits, "event_mask should have bits set");
    }

    #[test]
    fn test_hci_filter_all_ptypes_and_events() {
        let mut flt: hci_filter = ffi::raw_zeroed();
        hci_filter_clear(&mut flt);
        hci_filter_all_ptypes(&mut flt);
        assert_ne!(flt.type_mask, 0, "all packet types should set bits");

        hci_filter_all_events(&mut flt);
        assert_eq!(flt.event_mask, [0xFFFF_FFFF, 0xFFFF_FFFF]);
    }

    // -----------------------------------------------------------------------
    // Packed struct read via ffi::raw_read_unaligned
    // -----------------------------------------------------------------------

    #[test]
    fn test_raw_read_unaligned_hci_event_hdr() {
        // Simulate a buffer containing an HCI event header at offset 1
        // (after the packet type indicator byte).
        let mut buf = [0u8; 16];
        buf[0] = HCI_EVENT_PKT; // packet type indicator
        buf[1] = EVT_STACK_INTERNAL; // event code
        buf[2] = 6; // parameter total length

        let hdr: hci_event_hdr = ffi::raw_read_unaligned::<hci_event_hdr>(&buf, 1).unwrap();
        assert_eq!(hdr.evt, EVT_STACK_INTERNAL);
        assert_eq!(hdr.plen, 6);
    }

    #[test]
    fn test_raw_read_unaligned_evt_stack_internal() {
        // Build a stack_internal event with a known type.
        let mut buf = [0u8; 16];
        let si_type: u16 = EVT_SI_DEVICE.into();
        buf[0..2].copy_from_slice(&si_type.to_ne_bytes());

        let si: evt_stack_internal =
            ffi::raw_read_unaligned::<evt_stack_internal>(&buf, 0).unwrap();
        let read_type = ffi::raw_read_packed_field_ptr(std::ptr::addr_of!(si.type_));
        assert_eq!(read_type, u16::from(EVT_SI_DEVICE));
    }

    #[test]
    fn test_raw_read_unaligned_evt_si_device() {
        // Build a evt_si_device struct in a buffer.
        let mut buf = [0u8; 16];
        let event_val: u16 = HCI_DEV_REG.into();
        let dev_id_val: u16 = 42;
        buf[0..2].copy_from_slice(&event_val.to_ne_bytes());
        buf[2..4].copy_from_slice(&dev_id_val.to_ne_bytes());

        let sd: evt_si_device = ffi::raw_read_unaligned::<evt_si_device>(&buf, 0).unwrap();
        let event = ffi::raw_read_packed_field_ptr(std::ptr::addr_of!(sd.event));
        let dev_id = ffi::raw_read_packed_field_ptr(std::ptr::addr_of!(sd.dev_id));
        assert_eq!(event, u16::from(HCI_DEV_REG));
        assert_eq!(dev_id, 42);
    }

    #[test]
    fn test_raw_read_unaligned_out_of_bounds() {
        // Attempting to read beyond buffer bounds should return None.
        let buf = [0u8; 2];
        let result = ffi::raw_read_unaligned::<hci_event_hdr>(&buf, 1);
        assert!(result.is_none(), "read beyond buffer should return None");
    }

    // -----------------------------------------------------------------------
    // ffi::raw_zeroed for repr(C) packed structs
    // -----------------------------------------------------------------------

    #[test]
    fn test_raw_zeroed_hci_dev_info() {
        let di: hci_dev_info = ffi::raw_zeroed();
        // Use read_unaligned for packed struct field access.
        let dev_id: u16 = ffi::raw_read_packed_field_ptr(std::ptr::addr_of!(di.dev_id));
        let type_: u8 = ffi::raw_read_packed_field_ptr(std::ptr::addr_of!(di.type_));
        assert_eq!(dev_id, 0);
        assert_eq!(type_, 0);
    }

    #[test]
    fn test_raw_zeroed_sockaddr_hci() {
        let addr: sockaddr_hci = ffi::raw_zeroed();
        assert_eq!(addr.hci_family, 0);
        assert_eq!(addr.hci_dev, 0);
        assert_eq!(addr.hci_channel, 0);
    }

    // -----------------------------------------------------------------------
    // recv_and_dispatch_device min-size validation (white-box)
    // -----------------------------------------------------------------------

    #[test]
    fn test_min_packet_size_constants() {
        // Verify the minimum size calculation is correct:
        // 1 (type) + HCI_EVENT_HDR_SIZE (2) + sizeof(evt_stack_internal) (2)
        // + sizeof(evt_si_device) (4) = 9
        let min =
            1 + HCI_EVENT_HDR_SIZE + size_of::<evt_stack_internal>() + size_of::<evt_si_device>();
        assert_eq!(min, 9, "expected minimum stack-internal packet size");
    }
}
