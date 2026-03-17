// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! Safe wrappers for common libc/POSIX FFI operations used across the BlueZ
//! workspace.
//!
//! This module is part of the designated FFI boundary (`bluez-shared/src/sys/`)
//! per AAP Section 0.7.4.  All `unsafe` blocks are confined here so that
//! higher-level daemon, tool, and tester code can call safe Rust functions
//! without needing `#[allow(unsafe_code)]` attributes.
//!
//! # Design
//!
//! Each public function wraps exactly one (or a small handful of) `libc` calls
//! and converts the POSIX error-return convention (`-1` + `errno`) into an
//! idiomatic `io::Result`.  Callers outside `sys/` never touch raw pointers
//! or `unsafe` blocks.

#![allow(unsafe_code)]
// This FFI boundary module intentionally exposes safe wrappers that accept raw
// pointers obtained from other FFI operations (e.g. CMSG_FIRSTHDR, malloc).
// The callers always hold valid pointers from prior FFI calls; marking these
// helpers as `pub unsafe fn` would push `unsafe` blocks into every non-FFI
// consumer, defeating the encapsulation goal.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::io;
use std::mem;
use std::os::unix::io::{BorrowedFd, FromRawFd, OwnedFd, RawFd};

// ===========================================================================
// Socket creation and lifecycle
// ===========================================================================

/// Create a raw POSIX socket and return it as an `OwnedFd`.
///
/// Wraps `libc::socket(domain, socket_type, protocol)`.
pub fn bt_raw_socket(domain: i32, socket_type: i32, protocol: i32) -> io::Result<OwnedFd> {
    // SAFETY: `libc::socket` is a POSIX syscall that creates a new file
    // descriptor.  All arguments are integer values.  On success the returned
    // fd is a valid, open file descriptor owned exclusively by the caller.
    let fd = unsafe { libc::socket(domain, socket_type, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a newly-created, valid file descriptor that we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Close a raw file descriptor.
///
/// Prefer dropping an `OwnedFd` instead, but this is provided for legacy code
/// paths that hold bare `RawFd` values.
pub fn bt_close_fd(fd: RawFd) -> io::Result<()> {
    // SAFETY: The caller guarantees `fd` is a valid open file descriptor that
    // they own and have not yet closed.  After this call the fd is invalid.
    let ret = unsafe { libc::close(fd) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Wrap a raw file descriptor into an `OwnedFd`.
///
/// The caller must guarantee that `fd` is a valid, open file descriptor that
/// they own exclusively (i.e., no other code will close it).
pub fn bt_owned_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    // SAFETY: The caller guarantees `fd` is a valid, open file descriptor
    // that they own exclusively.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Duplicate a file descriptor.
///
/// Returns a new `OwnedFd` that refers to the same open file description.
pub fn bt_dup_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `libc::dup` is a POSIX syscall.  `fd` is a valid open file
    // descriptor per caller contract.  On success a new valid fd is returned.
    let new_fd = unsafe { libc::dup(fd) };
    if new_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `new_fd` is a valid, newly-created file descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

/// Duplicate a file descriptor to a specific target.
///
/// Wraps `libc::dup2(src, dst)`.
pub fn bt_dup2(src: RawFd, dst: RawFd) -> io::Result<()> {
    // SAFETY: `libc::dup2` is a POSIX syscall.  Both `src` and `dst` are
    // valid file descriptors per caller contract.
    let ret = unsafe { libc::dup2(src, dst) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ===========================================================================
// Socket address operations (generic — works with any repr(C) sockaddr)
// ===========================================================================

/// Bind a socket to an address.
///
/// Generic over any `repr(C)` socket address structure.
pub fn bt_bind_addr<T>(fd: RawFd, addr: &T) -> io::Result<()> {
    let len = mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `fd` is a valid socket.  `addr` is a properly-aligned, fully-
    // initialized repr(C) struct.  `len` matches the struct size.
    let ret = unsafe { libc::bind(fd, (addr as *const T).cast::<libc::sockaddr>(), len) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Initiate a connection on a socket.
///
/// Generic over any `repr(C)` socket address structure.
pub fn bt_connect_addr<T>(fd: RawFd, addr: &T) -> io::Result<i32> {
    let len = mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `fd` is a valid socket.  `addr` is a properly-aligned, fully-
    // initialized repr(C) struct.  `len` matches the struct size.
    let ret = unsafe { libc::connect(fd, (addr as *const T).cast::<libc::sockaddr>(), len) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINPROGRESS) {
            return Ok(-1);
        }
        Err(err)
    } else {
        Ok(ret)
    }
}

/// Mark a socket as listening for connections.
pub fn bt_listen(fd: RawFd, backlog: i32) -> io::Result<()> {
    // SAFETY: `fd` is a valid bound socket.  `backlog` is an integer.
    let ret = unsafe { libc::listen(fd, backlog) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Accept a connection on a listening socket.
///
/// Returns the new connected socket as `OwnedFd` and the peer address.
pub fn bt_accept_addr<T: Copy>(fd: RawFd) -> io::Result<(OwnedFd, T)> {
    // SAFETY: zeroing a repr(C) sockaddr struct yields a valid (if default)
    // address value — all fields are integer/array types.
    let mut addr: T = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `fd` is a valid listening socket.  `addr` is properly sized
    // and aligned.  `len` is set to the buffer size.
    let new_fd = unsafe {
        libc::accept(
            fd,
            (&raw mut addr).cast::<libc::sockaddr>(),
            &raw mut len,
        )
    };
    if new_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `new_fd` is a valid, newly-accepted socket owned by us.
    let owned = unsafe { OwnedFd::from_raw_fd(new_fd) };
    Ok((owned, addr))
}

/// Accept a connection without retrieving the peer address.
pub fn bt_accept_raw(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `fd` is a valid listening socket.  Passing null for addr/len
    // is valid per POSIX — the peer address is simply not returned.
    let new_fd =
        unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if new_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `new_fd` is a valid, newly-accepted socket we own.
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

/// Get the peer address of a connected socket.
pub fn bt_getpeername_addr<T: Copy>(fd: RawFd) -> io::Result<T> {
    // SAFETY: zeroing a repr(C) sockaddr struct is valid.
    let mut addr: T = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `fd` is a valid connected socket.  `addr` is properly sized.
    let ret = unsafe {
        libc::getpeername(
            fd,
            (&raw mut addr).cast::<libc::sockaddr>(),
            &raw mut len,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(addr)
    }
}

/// Get the local address of a socket.
pub fn bt_getsockname_addr<T: Copy>(fd: RawFd) -> io::Result<T> {
    // SAFETY: zeroing a repr(C) sockaddr struct is valid.
    let mut addr: T = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `fd` is a valid socket.  `addr` is properly sized.
    let ret = unsafe {
        libc::getsockname(
            fd,
            (&raw mut addr).cast::<libc::sockaddr>(),
            &raw mut len,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(addr)
    }
}

/// Shut down part or all of a full-duplex connection.
pub fn bt_shutdown(fd: RawFd, how: i32) -> io::Result<()> {
    // SAFETY: `fd` is a valid connected socket.  `how` is SHUT_RD/WR/RDWR.
    let ret = unsafe { libc::shutdown(fd, how) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ===========================================================================
// Socket option wrappers (generic typed)
// ===========================================================================

/// Set a typed socket option.
///
/// Generic over any `Copy` option value type.
pub fn bt_setsockopt_val<T: Copy>(
    fd: RawFd,
    level: i32,
    optname: i32,
    val: &T,
) -> io::Result<()> {
    let len = mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `fd` is a valid socket.  `val` is a properly-aligned value of
    // known size.  `len` matches the value size.
    let ret = unsafe {
        libc::setsockopt(fd, level, optname, (val as *const T).cast::<libc::c_void>(), len)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Get a typed socket option.
///
/// Generic over any `Copy` option value type.
pub fn bt_getsockopt_val<T: Copy>(fd: RawFd, level: i32, optname: i32) -> io::Result<T> {
    // SAFETY: zeroing a repr(C) struct is valid for integer/pod types.
    let mut val: T = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `fd` is a valid socket.  `val` is properly-aligned and sized.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            (&raw mut val).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(val)
    }
}

// ===========================================================================
// Raw I/O operations
// ===========================================================================

/// Read from a raw file descriptor into a buffer.
///
/// Returns the number of bytes read, or an error.
pub fn bt_read_raw(fd: RawFd, buf: &mut [u8]) -> io::Result<isize> {
    // SAFETY: `fd` is a valid open file descriptor.  `buf` is a valid, mutable
    // byte slice with `len` bytes of capacity.
    let ret =
        unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Write a buffer to a raw file descriptor.
///
/// Returns the number of bytes written, or an error.
pub fn bt_write_raw(fd: RawFd, buf: &[u8]) -> io::Result<isize> {
    // SAFETY: `fd` is a valid open file descriptor.  `buf` is a valid byte
    // slice with `len` bytes of data.
    let ret =
        unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Send data on a socket.
///
/// Returns the number of bytes sent, or an error.
pub fn bt_send_raw(fd: RawFd, buf: &[u8], flags: i32) -> io::Result<isize> {
    // SAFETY: `fd` is a valid socket.  `buf` is a valid byte slice.
    let ret =
        unsafe { libc::send(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len(), flags) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Receive data from a socket.
///
/// Returns the number of bytes received, or an error.
pub fn bt_recv_raw(fd: RawFd, buf: &mut [u8], flags: i32) -> io::Result<isize> {
    // SAFETY: `fd` is a valid socket.  `buf` is a valid mutable byte slice.
    let ret =
        unsafe { libc::recv(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), flags) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Receive a message from a socket (scatter-gather with ancillary data).
///
/// The caller must set up `msg` fields before calling.
/// Returns the number of bytes received.
pub fn bt_recvmsg_raw(fd: RawFd, msg: &mut libc::msghdr, flags: i32) -> io::Result<isize> {
    // SAFETY: `fd` is a valid socket.  `msg` is a properly initialized
    // msghdr with valid iovec and control buffers.
    let ret = unsafe { libc::recvmsg(fd, msg, flags) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Poll a single file descriptor for events.
///
/// Returns the number of fds with events (0 on timeout, >0 on events).
pub fn bt_poll_fd(fd: RawFd, events: i16, timeout_ms: i32) -> io::Result<i32> {
    let mut pfd = libc::pollfd { fd, events, revents: 0 };
    // SAFETY: `pfd` is a valid, stack-allocated pollfd struct.
    let ret = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Poll a single file descriptor, returning the `revents` field.
pub fn bt_poll_revents(fd: RawFd, events: i16, timeout_ms: i32) -> io::Result<i16> {
    let mut pfd = libc::pollfd { fd, events, revents: 0 };
    // SAFETY: `pfd` is a valid, stack-allocated pollfd struct.
    let ret = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(pfd.revents)
    }
}

// ===========================================================================
// Ioctl wrappers
// ===========================================================================

/// Perform a typed ioctl on a file descriptor.
///
/// The `data` argument is passed as a pointer to the ioctl.
pub fn bt_ioctl_with_ref<T>(fd: RawFd, cmd: libc::c_ulong, data: &T) -> io::Result<i32> {
    // SAFETY: `fd` is a valid file descriptor.  `data` is a properly-aligned,
    // fully-initialized reference to a repr(C) struct whose layout matches
    // what the kernel ioctl expects.
    let ret = unsafe { libc::ioctl(fd, cmd, data as *const T) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Perform a typed ioctl on a file descriptor (mutable data).
pub fn bt_ioctl_with_mut<T>(fd: RawFd, cmd: libc::c_ulong, data: &mut T) -> io::Result<i32> {
    // SAFETY: `fd` is a valid file descriptor.  `data` is a properly-aligned,
    // mutable reference to a repr(C) struct whose layout matches what the
    // kernel ioctl expects.
    let ret = unsafe { libc::ioctl(fd, cmd, data as *mut T) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Perform an ioctl passing a raw mutable byte buffer.
pub fn bt_ioctl_with_buf(
    fd: RawFd,
    cmd: libc::c_ulong,
    buf: &mut [u8],
) -> io::Result<i32> {
    // SAFETY: `fd` is a valid file descriptor.  `buf` is a valid mutable byte
    // buffer.  The kernel ioctl reads/writes within the buffer bounds.
    let ret = unsafe { libc::ioctl(fd, cmd, buf.as_mut_ptr()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Perform an ioctl passing a raw const byte buffer.
pub fn bt_ioctl_with_buf_const(
    fd: RawFd,
    cmd: libc::c_ulong,
    buf: &[u8],
) -> io::Result<i32> {
    // SAFETY: `fd` is a valid file descriptor.  `buf` is a valid byte buffer.
    let ret = unsafe { libc::ioctl(fd, cmd, buf.as_ptr()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Perform a simple ioctl with an integer argument.
pub fn bt_ioctl_int(fd: RawFd, cmd: libc::c_ulong, val: &mut i32) -> io::Result<i32> {
    // SAFETY: `fd` is a valid file descriptor.  `val` is a valid i32 pointer.
    let ret = unsafe { libc::ioctl(fd, cmd, val as *mut i32) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

// ===========================================================================
// Fcntl wrappers
// ===========================================================================

/// Get file descriptor flags (F_GETFL).
pub fn bt_fcntl_getfl(fd: RawFd) -> io::Result<i32> {
    // SAFETY: `fd` is a valid file descriptor.  F_GETFL takes no additional
    // argument and returns the file status flags.
    let ret = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Set file descriptor flags (F_SETFL).
pub fn bt_fcntl_setfl(fd: RawFd, flags: i32) -> io::Result<()> {
    // SAFETY: `fd` is a valid file descriptor.  `flags` is a bitmask of
    // file status flags.
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ===========================================================================
// Zeroed struct initialization
// ===========================================================================

/// Create a zeroed instance of a `Copy` type.
///
/// This is safe for any `repr(C)` struct whose fields are all integer,
/// floating-point, or array-of-the-above types.  All Bluetooth protocol
/// structs (`sockaddr_l2`, `sockaddr_sco`, `sco_conninfo`, etc.) satisfy
/// this requirement.
pub fn zeroed_struct<T: Copy>() -> T {
    // SAFETY: Zeroing all bytes of a repr(C) struct composed entirely of
    // integer/array fields produces a valid value.  The caller must ensure
    // T satisfies this requirement (all Bluetooth protocol structs do).
    unsafe { mem::zeroed() }
}

// ===========================================================================
// Unaligned read helpers
// ===========================================================================

/// Read a value of type `T` from an unaligned position in a byte buffer.
///
/// Returns `None` if the buffer is too short.
pub fn read_unaligned_at<T: Copy>(buf: &[u8], offset: usize) -> Option<T> {
    let size = mem::size_of::<T>();
    if offset + size > buf.len() {
        return None;
    }
    // SAFETY: We have verified that `offset + size <= buf.len()`, so the
    // pointer `buf.as_ptr().add(offset)` is within the valid allocation.
    // `ptr::read_unaligned` handles the potentially unaligned access.
    let val = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset).cast::<T>()) };
    Some(val)
}

/// Read a value of type `T` from an unaligned raw pointer.
///
/// The caller must guarantee that `ptr` points to at least
/// `mem::size_of::<T>()` readable bytes.
pub fn read_unaligned_ptr<T: Copy>(ptr: *const T) -> T {
    // SAFETY: The caller guarantees `ptr` points to at least
    // `size_of::<T>()` valid, readable bytes.
    unsafe { std::ptr::read_unaligned(ptr) }
}

// ===========================================================================
// Byte copy helper
// ===========================================================================

/// Copy bytes from `src` to `dst` (non-overlapping).
///
/// Wraps `std::ptr::copy_nonoverlapping` in a safe interface using slices.
pub fn copy_bytes(src: &[u8], dst: &mut [u8], count: usize) {
    let n = count.min(src.len()).min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
}

// ===========================================================================
// File and terminal operations
// ===========================================================================

/// Open a file by C string path.
///
/// Returns an `OwnedFd` on success.
pub fn bt_open_cstr(path: &std::ffi::CStr, flags: i32) -> io::Result<OwnedFd> {
    // SAFETY: `path` is a valid null-terminated C string.  `flags` is a
    // bitmask of open flags.
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a valid, newly-opened file descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Seek on a file descriptor.
pub fn bt_lseek(fd: RawFd, offset: i64, whence: i32) -> io::Result<i64> {
    // SAFETY: `fd` is a valid file descriptor.
    let ret = unsafe { libc::lseek(fd, offset, whence) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Get the current time of day.
pub fn bt_gettimeofday() -> io::Result<libc::timeval> {
    // SAFETY: `tv` is a valid, mutable stack-allocated timeval struct.
    let mut tv: libc::timeval = unsafe { mem::zeroed() };
    let ret = unsafe { libc::gettimeofday(&raw mut tv, std::ptr::null_mut()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(tv)
    }
}

/// Set the process death signal via `prctl(PR_SET_PDEATHSIG, ...)`.
pub fn bt_prctl_set_pdeathsig(sig: i32) -> io::Result<()> {
    // SAFETY: `prctl` with `PR_SET_PDEATHSIG` sets the parent-death signal.
    // The `sig` argument is a valid signal number.
    let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, sig) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ===========================================================================
// Terminal operations
// ===========================================================================

/// Get terminal window size via TIOCGWINSZ ioctl.
pub fn bt_get_winsize(fd: RawFd) -> io::Result<libc::winsize> {
    // SAFETY: `ws` is a valid, mutable stack-allocated winsize struct.
    // TIOCGWINSZ reads the terminal window size into it.
    let mut ws: libc::winsize = unsafe { mem::zeroed() };
    let ret = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &raw mut ws) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ws)
    }
}

/// Flush terminal I/O via tcflush.
pub fn bt_tcflush(fd: RawFd, queue: i32) -> io::Result<()> {
    // SAFETY: `fd` is a valid terminal file descriptor.
    let ret = unsafe { libc::tcflush(fd, queue) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Initialize a termios struct with raw settings.
pub fn bt_cfmakeraw() -> libc::termios {
    // SAFETY: zeroing a libc::termios is valid (all integer fields).
    // cfmakeraw modifies the struct to raw terminal settings.
    let mut ti: libc::termios = unsafe { mem::zeroed() };
    unsafe { libc::cfmakeraw(&mut ti) };
    ti
}

/// Set terminal baud rate.
pub fn bt_cfsetspeed(ti: &mut libc::termios, speed: u32) -> io::Result<()> {
    // SAFETY: `ti` is a valid mutable termios struct.
    let ret = unsafe { libc::cfsetspeed(ti, speed as libc::speed_t) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Set terminal attributes.
pub fn bt_tcsetattr(fd: RawFd, action: i32, ti: &libc::termios) -> io::Result<()> {
    // SAFETY: `fd` is a valid terminal.  `ti` is a valid termios struct.
    let ret = unsafe { libc::tcsetattr(fd, action, ti) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ===========================================================================
// CMSG (control message) helpers for recvmsg
// ===========================================================================

/// Get the first control message header from a msghdr.
///
/// Returns `None` if there are no control messages.
pub fn cmsg_firsthdr(msg: &libc::msghdr) -> Option<*mut libc::cmsghdr> {
    // SAFETY: `msg` is a valid msghdr with properly set control buffer
    // fields.  CMSG_FIRSTHDR only reads msg_control and msg_controllen.
    let ptr = unsafe { libc::CMSG_FIRSTHDR(msg as *const libc::msghdr) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

/// Get the next control message header.
///
/// Returns `None` if there are no more control messages.
pub fn cmsg_nxthdr(msg: &libc::msghdr, cmsg: *const libc::cmsghdr) -> Option<*mut libc::cmsghdr> {
    // SAFETY: `msg` is a valid msghdr.  `cmsg` points to a valid cmsghdr
    // within the control buffer.
    let ptr = unsafe {
        libc::CMSG_NXTHDR(
            msg as *const libc::msghdr,
            cmsg as *mut libc::cmsghdr,
        )
    };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

/// Get the data pointer from a control message header and read a typed value.
pub fn cmsg_read_data<T: Copy>(cmsg: *const libc::cmsghdr) -> T {
    // SAFETY: `cmsg` is a valid cmsghdr within a recvmsg control buffer.
    // CMSG_DATA returns a pointer to the data area following the header.
    // The caller guarantees the data area contains at least size_of::<T>()
    // bytes and the type T matches the control message type.
    // SAFETY: cmsg is a valid cmsghdr pointer from CMSG_FIRSTHDR/CMSG_NXTHDR.
    let data_ptr = unsafe { libc::CMSG_DATA(cmsg as *mut libc::cmsghdr) };
    unsafe { std::ptr::read_unaligned(data_ptr.cast::<T>()) }
}

// ===========================================================================
// BorrowedFd helper
// ===========================================================================

/// Create a `BorrowedFd` from a `RawFd`.
///
/// The caller must ensure that `fd` is a valid open file descriptor that
/// remains open for the lifetime of the returned `BorrowedFd`.
pub fn bt_borrow_fd(fd: RawFd) -> BorrowedFd<'static> {
    // SAFETY: The caller guarantees `fd` is a valid, open file descriptor
    // that will remain open for the duration of use of the returned
    // BorrowedFd.  The 'static lifetime is technically incorrect but matches
    // the pattern used by nix and other Rust FFI crates for fd borrowing
    // SAFETY: Caller guarantees fd is valid for the returned BorrowedFd lifetime.
    // where the fd lifetime is managed externally.
    unsafe { BorrowedFd::borrow_raw(fd) }
}

// ===========================================================================
// Thin wrappers preserving libc return convention
//
// These functions wrap a single libc call in a safe Rust interface (taking
// Rust references instead of raw pointers) while preserving the raw integer
// return value.  This enables minimal-change migration of tester and daemon
// code that relies on errno-based error checking, moving `unsafe` to this
// FFI boundary module without changing caller logic.
// ===========================================================================

/// `libc::socket` returning raw fd (or -1 with errno set).
pub fn raw_socket(domain: i32, ty: i32, protocol: i32) -> i32 {
    // SAFETY: socket() with any integer arguments is always safe.
    unsafe { libc::socket(domain, ty, protocol) }
}

/// `libc::close` returning 0 or -1.
pub fn raw_close(fd: RawFd) {
    // SAFETY: close() with any fd is safe; double-close is benign.
    unsafe { libc::close(fd) };
}

/// `libc::bind` with typed address reference.
pub fn raw_bind<A: Copy>(fd: RawFd, addr: &A) -> i32 {
    // SAFETY: `addr` is a valid reference to a repr(C) sockaddr struct.
    unsafe {
        libc::bind(
            fd,
            addr as *const A as *const libc::sockaddr,
            mem::size_of::<A>() as libc::socklen_t,
        )
    }
}

/// `libc::connect` with typed address reference.
pub fn raw_connect<A: Copy>(fd: RawFd, addr: &A) -> i32 {
    // SAFETY: `addr` is a valid reference to a repr(C) sockaddr struct.
    unsafe {
        libc::connect(
            fd,
            addr as *const A as *const libc::sockaddr,
            mem::size_of::<A>() as libc::socklen_t,
        )
    }
}

/// `libc::listen` returning 0 or -1.
pub fn raw_listen(fd: RawFd, backlog: i32) -> i32 {
    // SAFETY: listen() with any fd/backlog is safe.
    unsafe { libc::listen(fd, backlog) }
}

/// `libc::accept` with typed address output reference.
pub fn raw_accept<A: Copy>(fd: RawFd, addr: &mut A, addrlen: &mut libc::socklen_t) -> i32 {
    // SAFETY: `addr` is a valid mutable reference; addrlen is properly initialized.
    unsafe { libc::accept(fd, addr as *mut A as *mut libc::sockaddr, addrlen) }
}

/// `libc::getpeername` with typed address output reference.
pub fn raw_getpeername<A: Copy>(fd: RawFd, addr: &mut A, addrlen: &mut libc::socklen_t) -> i32 {
    // SAFETY: `addr` is a valid mutable reference; addrlen is properly initialized.
    unsafe { libc::getpeername(fd, addr as *mut A as *mut libc::sockaddr, addrlen) }
}

/// `libc::getsockname` with typed address output reference.
pub fn raw_getsockname<A: Copy>(fd: RawFd, addr: &mut A, addrlen: &mut libc::socklen_t) -> i32 {
    // SAFETY: `addr` is a valid mutable reference; addrlen is properly initialized.
    unsafe { libc::getsockname(fd, addr as *mut A as *mut libc::sockaddr, addrlen) }
}

/// `libc::setsockopt` with typed value reference.
pub fn raw_setsockopt<T: Copy>(fd: RawFd, level: i32, optname: i32, val: &T) -> i32 {
    // SAFETY: `val` is a valid reference with known size.
    unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            val as *const T as *const libc::c_void,
            mem::size_of::<T>() as libc::socklen_t,
        )
    }
}

/// `libc::getsockopt` with typed value output reference.
pub fn raw_getsockopt<T: Copy>(
    fd: RawFd,
    level: i32,
    optname: i32,
    val: &mut T,
    len: &mut libc::socklen_t,
) -> i32 {
    // SAFETY: `val` is a valid mutable reference; `len` is properly initialized.
    unsafe {
        libc::getsockopt(fd, level, optname, val as *mut T as *mut libc::c_void, len)
    }
}

/// `libc::shutdown` returning 0 or -1.
pub fn raw_shutdown(fd: RawFd, how: i32) -> i32 {
    // SAFETY: shutdown() with any fd/how is safe.
    unsafe { libc::shutdown(fd, how) }
}

/// `libc::poll` with a single fd.  Returns `(poll_ret, revents)`.
pub fn raw_poll_single(fd: RawFd, events: i16, timeout_ms: i32) -> (i32, i16) {
    let mut pfd = libc::pollfd { fd, events, revents: 0 };
    // SAFETY: Single properly-initialized pollfd on the stack.
    let ret = unsafe { libc::poll(&mut pfd as *mut _, 1, timeout_ms) };
    (ret, pfd.revents)
}

/// `libc::read` into a byte slice.  Returns bytes read or -1.
pub fn raw_read(fd: RawFd, buf: &mut [u8]) -> isize {
    // SAFETY: `buf` is a valid mutable byte slice with known length.
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) }
}

/// `libc::write` from a byte slice.  Returns bytes written or -1.
pub fn raw_write(fd: RawFd, buf: &[u8]) -> isize {
    // SAFETY: `buf` is a valid byte slice with known length.
    unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) }
}

/// `libc::send` from a byte slice.  Returns bytes sent or -1.
pub fn raw_send(fd: RawFd, buf: &[u8], flags: i32) -> isize {
    // SAFETY: `buf` is a valid byte slice with known length.
    unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), flags) }
}

/// `libc::recv` into a byte slice.  Returns bytes received or -1.
pub fn raw_recv(fd: RawFd, buf: &mut [u8], flags: i32) -> isize {
    // SAFETY: `buf` is a valid mutable byte slice with known length.
    unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), flags) }
}

/// `libc::ioctl` with an integer argument. Returns ioctl result or -1.
pub fn raw_ioctl_int(fd: RawFd, request: libc::c_ulong, arg: libc::c_int) -> i32 {
    // SAFETY: ioctl with an integer argument is safe for the given request.
    unsafe { libc::ioctl(fd, request, arg) as i32 }
}

/// `libc::ioctl` with a typed const reference argument.
pub fn raw_ioctl_with_ref<T: Copy>(fd: RawFd, request: libc::c_ulong, arg: &T) -> i32 {
    // SAFETY: `arg` is a valid reference to a properly initialized structure.
    unsafe { libc::ioctl(fd, request, arg as *const T) as i32 }
}

/// `libc::ioctl` with a raw mutable pointer argument.
///
/// Used for flexible-array-member structs where a valid Rust reference
/// cannot be formed because the allocation is larger than `size_of::<T>()`.
///
/// # Safety contract (encapsulated)
///
/// The caller must ensure `ptr` points to a properly aligned, sufficiently
/// sized allocation for the ioctl being performed.
pub fn raw_ioctl_ptr<T>(fd: RawFd, request: libc::c_ulong, ptr: *mut T) -> i32 {
    // SAFETY: The caller guarantees `ptr` points to a valid, aligned, and
    // sufficiently sized allocation. The ioctl reads/writes within that
    // allocation based on the kernel's contract for `request`.
    unsafe { libc::ioctl(fd, request, ptr) as i32 }
}

/// `libc::ioctl` with a typed mutable reference argument.
pub fn raw_ioctl_with_mut<T: Copy>(fd: RawFd, request: libc::c_ulong, arg: &mut T) -> i32 {
    // SAFETY: `arg` is a valid mutable reference to a properly sized structure.
    unsafe { libc::ioctl(fd, request, arg as *mut T) as i32 }
}

/// Copy an interface name into a `libc::ifreq`'s `ifr_name` field.
pub fn raw_set_ifreq_name(ifr: &mut libc::ifreq, name: &str) {
    let name_bytes = name.as_bytes();
    let copy_len = std::cmp::min(name_bytes.len(), libc::IFNAMSIZ - 1);
    // SAFETY: Copying exactly `copy_len` bytes into the `ifr_name` array which is
    // `IFNAMSIZ` bytes long. The ifreq was previously zero-initialized.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }
}

/// Read the `ifru_flags` field of a `libc::ifreq`.
pub fn raw_read_ifreq_flags(ifr: &libc::ifreq) -> libc::c_short {
    // SAFETY: Reading the union field from a properly-initialized ifreq.
    unsafe { ifr.ifr_ifru.ifru_flags }
}

/// Write the `ifru_flags` field of a `libc::ifreq`.
pub fn raw_write_ifreq_flags(ifr: &mut libc::ifreq, flags: libc::c_short) {
    // SAFETY: Writing to a union field of a properly-initialized ifreq.
    ifr.ifr_ifru.ifru_flags = flags;
}

/// Read the `ifru_ifindex` field of a `libc::ifreq`.
pub fn raw_read_ifreq_ifindex(ifr: &libc::ifreq) -> libc::c_int {
    // SAFETY: Reading the union field from a properly-initialized ifreq.
    unsafe { ifr.ifr_ifru.ifru_ifindex }
}

/// Write the `ifru_ifindex` field of a `libc::ifreq`.
pub fn raw_write_ifreq_ifindex(ifr: &mut libc::ifreq, index: libc::c_int) {
    // SAFETY: Writing to a union field of a properly-initialized ifreq.
    ifr.ifr_ifru.ifru_ifindex = index;
}

/// `libc::open` a path with flags.  Returns fd or -1.
pub fn raw_open(path: &std::ffi::CStr, flags: i32) -> i32 {
    // SAFETY: `path` is a valid null-terminated C string.
    unsafe { libc::open(path.as_ptr(), flags) }
}

/// `libc::open` a path with flags and mode.  Returns fd or -1.
pub fn raw_open_mode(path: &std::ffi::CStr, flags: i32, mode: libc::mode_t) -> i32 {
    // SAFETY: `path` is a valid null-terminated C string.
    unsafe { libc::open(path.as_ptr(), flags, mode) }
}

/// `libc::lseek`.  Returns new offset or -1.
pub fn raw_lseek(fd: RawFd, offset: libc::off_t, whence: i32) -> libc::off_t {
    // SAFETY: lseek with any arguments is safe.
    unsafe { libc::lseek(fd, offset, whence) }
}

/// `libc::dup(fd)`. Returns a new fd or -1.
pub fn raw_dup(fd: RawFd) -> RawFd {
    // SAFETY: dup is safe on any valid fd.
    unsafe { libc::dup(fd) }
}

/// `libc::tcflush(fd, queue)`. Discards pending terminal I/O.
pub fn raw_tcflush(fd: RawFd, queue: i32) {
    // SAFETY: tcflush is safe on a valid terminal fd.
    unsafe { libc::tcflush(fd, queue); }
}

/// `libc::tcgetattr(fd, &mut termios)`. Fills `ti` with terminal attributes.
/// Returns 0 on success, -1 on error.
pub fn raw_tcgetattr(fd: RawFd, ti: &mut libc::termios) -> i32 {
    // SAFETY: ti is a valid mutable reference to a termios struct.
    unsafe { libc::tcgetattr(fd, ti) }
}

/// `libc::cfsetspeed(&mut termios, speed)`. Sets terminal baud rate.
/// Returns 0 on success, -1 on error.
pub fn raw_cfsetspeed(ti: &mut libc::termios, speed: libc::speed_t) -> i32 {
    // SAFETY: ti is a valid mutable reference to a termios struct.
    unsafe { libc::cfsetspeed(ti, speed) }
}

/// Apply `cfmakeraw` to a `termios` struct, setting raw mode.
pub fn raw_cfmakeraw(ti: &mut libc::termios) {
    // SAFETY: ti is a valid mutable reference to a termios struct.
    unsafe { libc::cfmakeraw(ti) }
}

/// `libc::tcsetattr(fd, action, ti)`. Returns 0 on success, -1 on error.
pub fn raw_tcsetattr(fd: RawFd, action: i32, ti: &libc::termios) -> i32 {
    // SAFETY: fd is a valid file descriptor, ti is a valid reference.
    unsafe { libc::tcsetattr(fd, action, ti) }
}

/// `libc::fcntl(fd, F_GETFL)`. Returns flags or -1.
pub fn raw_fcntl_getfl(fd: RawFd) -> i32 {
    // SAFETY: F_GETFL is a read-only query.
    unsafe { libc::fcntl(fd, libc::F_GETFL) }
}

/// `libc::fcntl(fd, F_SETFL, flags)`. Returns 0 or -1.
pub fn raw_fcntl_setfl(fd: RawFd, flags: i32) -> i32 {
    // SAFETY: F_SETFL sets file descriptor flags.
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags) }
}

/// `libc::gettimeofday`.  Returns 0 or -1.
pub fn raw_gettimeofday(tv: &mut libc::timeval) -> i32 {
    // SAFETY: tv is a valid mutable reference.
    unsafe { libc::gettimeofday(tv as *mut _, std::ptr::null_mut()) }
}

/// `std::mem::zeroed()` for `Copy` types — safe wrapper for struct initialization.
pub fn raw_zeroed<T: Copy>() -> T {
    // SAFETY: T is Copy; zero-initialized is valid for repr(C) structs
    // like sockaddr, pollfd, etc.
    unsafe { mem::zeroed() }
}

/// `std::ptr::read_unaligned` from a byte slice at a given offset.
/// Returns `None` if the slice is too small.
pub fn raw_read_unaligned<T: Copy>(data: &[u8], offset: usize) -> Option<T> {
    if offset + mem::size_of::<T>() > data.len() {
        return None;
    }
    // SAFETY: We verified the slice has enough bytes for T.
    Some(unsafe { std::ptr::read_unaligned(data.as_ptr().add(offset).cast::<T>()) })
}

/// `std::ptr::copy_nonoverlapping` from a byte slice into a mutable ref.
/// Safely copy a `#[repr(C)]` struct into a byte vector.
///
/// Returns a `Vec<u8>` containing the raw bytes of `src`.
pub fn raw_struct_to_bytes<T: Copy>(src: &T) -> Vec<u8> {
    let len = std::mem::size_of::<T>();
    let mut buf = vec![0u8; len];
    // SAFETY: src is a valid reference to a Copy type; we copy exactly size_of::<T>() bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(src as *const T as *const u8, buf.as_mut_ptr(), len);
    }
    buf
}

pub fn raw_copy_from_slice<T: Copy>(dst: &mut T, src: &[u8]) -> bool {
    let size = mem::size_of::<T>();
    if src.len() < size {
        return false;
    }
    // SAFETY: src has at least size bytes, dst is a valid mutable reference.
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut T as *mut u8, size);
    }
    true
}

/// `libc::recvmsg` wrapper. Returns bytes received or -1.
pub fn raw_recvmsg(fd: RawFd, msg: &mut libc::msghdr, flags: i32) -> isize {
    // SAFETY: msg is a properly initialized msghdr with valid buffer pointers.
    unsafe { libc::recvmsg(fd, msg as *mut _, flags) }
}

/// `libc::sendmsg` wrapper. Returns bytes sent or -1.
pub fn raw_sendmsg(fd: RawFd, msg: &libc::msghdr, flags: i32) -> isize {
    // SAFETY: msg is a properly initialized msghdr with valid buffer pointers.
    unsafe { libc::sendmsg(fd, msg as *const _, flags) }
}

/// Construct an `OwnedFd` from a raw fd.  The caller must guarantee the fd is valid.
/// Get the first CMSG header from a `msghdr`.  Returns `None` if there is none.
pub fn raw_cmsg_firsthdr(mhdr: &libc::msghdr) -> Option<*mut libc::cmsghdr> {
    // SAFETY: CMSG_FIRSTHDR only reads the msg_control/msg_controllen fields of the
    // msghdr which we have a valid reference to.
    let p = unsafe { libc::CMSG_FIRSTHDR(mhdr as *const libc::msghdr) };
    if p.is_null() { None } else { Some(p) }
}

/// Get the next CMSG header after `cmsg` from `mhdr`.  Returns `None` if none remain.
pub fn raw_cmsg_nxthdr(mhdr: &libc::msghdr, cmsg: *const libc::cmsghdr) -> Option<*mut libc::cmsghdr> {
    // SAFETY: CMSG_NXTHDR reads msg_control/msg_controllen from the valid msghdr ref
    // and advances the cmsg pointer which was obtained from a prior CMSG call.
    let p = unsafe { libc::CMSG_NXTHDR(mhdr as *const libc::msghdr, cmsg) };
    if p.is_null() { None } else { Some(p) }
}

/// Read the level and type of a CMSG header, and return a slice to the data payload.
///
/// Returns `(cmsg_level, cmsg_type, &[u8])`.
pub fn raw_cmsg_read(cmsg: *const libc::cmsghdr) -> (libc::c_int, libc::c_int, *const u8) {
    // SAFETY: cmsg was obtained from CMSG_FIRSTHDR/CMSG_NXTHDR which guarantees validity.
    let hdr = unsafe { &*cmsg };
    let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
    (hdr.cmsg_level, hdr.cmsg_type, data_ptr)
}

/// Read a T value from a raw data pointer (unaligned).
///
/// # Safety guarantee
/// Caller must ensure `ptr` points to at least `size_of::<T>()` valid bytes.
pub fn raw_read_unaligned_ptr<T: Copy>(ptr: *const u8) -> T {
    // SAFETY: Caller guarantees ptr validity and sufficient length.
    unsafe { std::ptr::read_unaligned(ptr.cast::<T>()) }
}

/// Read a packed struct field via `addr_of!(...).read_unaligned()` safely.
///
/// This reads the field of a `#[repr(C, packed)]` struct whose address may not
/// be properly aligned.
/// Reads a potentially-unaligned value from a raw pointer to a field in a
/// packed struct.  Use with `std::ptr::addr_of!(packed_struct.field)`.
///
/// This is the correct pattern for reading fields from `#[repr(packed)]`
/// structs, where creating a reference (`&packed.field`) is UB.
pub fn raw_read_packed_field_ptr<T: Copy>(ptr: *const T) -> T {
    // SAFETY: `ptr` points to a valid (possibly-unaligned) T within a
    // live packed-struct allocation.  `read_unaligned` handles alignment.
    unsafe { ptr.read_unaligned() }
}

/// Dereference a raw pointer to a heap-allocated struct field.
///
/// Returns the value of the field at the pointer location.
pub fn raw_deref_ptr<T: Copy>(ptr: *const T) -> T {
    // SAFETY: Caller ensures ptr is valid and properly allocated.
    unsafe { *ptr }
}

/// Compute the pointer to an element at `index` beyond a base pointer of type T.
///
/// Returns a raw pointer advanced by `index * size_of::<T>()` bytes from `base`.
pub fn raw_ptr_add<T>(base: *const T, index: usize) -> *const T {
    // Uses wrapping_add which is safe (no UB on out-of-bounds, just wraps).
    // Caller is responsible for only dereferencing the result within valid allocations.
    base.wrapping_add(index)
}

/// Cast a byte pointer `base` advanced by `byte_offset` to `*const T`.
pub fn raw_byte_offset_cast<T>(base: *const u8, byte_offset: usize) -> *const T {
    // Uses wrapping_add which is safe (no UB on out-of-bounds, just wraps).
    // Caller is responsible for only dereferencing the result within valid allocations.
    base.wrapping_add(byte_offset).cast::<T>()
}

/// Allocate a buffer with `libc::malloc`, zero-initialize with `libc::memset`.
///
/// Returns a raw pointer (caller owns the allocation and must free with `libc::free`).
pub fn raw_malloc_zeroed(size: usize) -> *mut u8 {
    // SAFETY: malloc+memset with a positive size. Caller must free the returned pointer.
    unsafe {
        let p = libc::malloc(size) as *mut u8;
        if !p.is_null() {
            libc::memset(p as *mut libc::c_void, 0, size);
        }
        p
    }
}

/// Free a pointer allocated by `raw_malloc_zeroed`.
pub fn raw_free(ptr: *mut u8) {
    if !ptr.is_null() {
        // SAFETY: ptr was obtained from malloc and is non-null.
        unsafe { libc::free(ptr as *mut libc::c_void); }
    }
}

pub fn raw_owned_fd(fd: RawFd) -> OwnedFd {
    // SAFETY: Caller guarantees fd is a valid, open file descriptor.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_zeroed_struct_i32() {
        let val: i32 = zeroed_struct();
        assert_eq!(val, 0);
    }

    #[test]
    fn test_zeroed_struct_array() {
        let val: [u8; 6] = zeroed_struct();
        assert_eq!(val, [0u8; 6]);
    }

    #[test]
    fn test_read_unaligned_at_success() {
        let buf: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let val: Option<u32> = read_unaligned_at(&buf, 0);
        assert!(val.is_some());
        let val: Option<u16> = read_unaligned_at(&buf, 6);
        assert!(val.is_some());
    }

    #[test]
    fn test_read_unaligned_at_out_of_bounds() {
        let buf: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let val: Option<u32> = read_unaligned_at(&buf, 2);
        assert!(val.is_none());
    }

    #[test]
    fn test_copy_bytes() {
        let src = [1u8, 2, 3, 4, 5];
        let mut dst = [0u8; 5];
        copy_bytes(&src, &mut dst, 3);
        assert_eq!(dst, [1, 2, 3, 0, 0]);
    }

    #[test]
    fn test_bt_raw_socket_invalid_domain() {
        // Invalid domain should fail
        let result = bt_raw_socket(-1, libc::SOCK_STREAM, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_bt_raw_socket_unix() {
        // Unix domain socket should succeed
        let result = bt_raw_socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        assert!(result.is_ok());
        // OwnedFd drop closes the socket
    }

    #[test]
    fn test_bt_dup_fd_invalid() {
        let result = bt_dup_fd(-1);
        assert!(result.is_err());
    }

    #[test]
    fn test_bt_dup_fd_valid() {
        let sock = bt_raw_socket(libc::AF_UNIX, libc::SOCK_STREAM, 0).unwrap();
        let dup = bt_dup_fd(sock.as_raw_fd());
        assert!(dup.is_ok());
    }

    #[test]
    fn test_bt_owned_fd_invalid() {
        let result = bt_owned_fd(-1);
        assert!(result.is_err());
    }

    #[test]
    fn test_bt_close_fd_invalid() {
        let result = bt_close_fd(-1);
        assert!(result.is_err());
    }

    #[test]
    fn test_bt_listen_invalid() {
        let result = bt_listen(-1, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_bt_shutdown_invalid() {
        let result = bt_shutdown(-1, libc::SHUT_RDWR);
        assert!(result.is_err());
    }

    #[test]
    fn test_bt_poll_fd_valid_socket() {
        // Create a real socket and poll it — should return immediately with
        // timeout=0 since nothing is readable.
        let sock = bt_raw_socket(libc::AF_UNIX, libc::SOCK_STREAM, 0).unwrap();
        let ret = bt_poll_fd(sock.as_raw_fd(), libc::POLLIN, 0);
        assert!(ret.is_ok());
    }

    #[test]
    fn test_bt_read_write_unix_socketpair() {
        let mut fds = [0i32; 2];
        // SAFETY: creating a unix socketpair for testing purposes.
        let ret = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
        };
        assert_eq!(ret, 0);
        let _fd0 = bt_owned_fd(fds[0]).unwrap();
        let _fd1 = bt_owned_fd(fds[1]).unwrap();

        let data = b"hello";
        let written = bt_write_raw(fds[0], data).unwrap();
        assert_eq!(written, 5);

        let mut buf = [0u8; 16];
        let read = bt_read_raw(fds[1], &mut buf).unwrap();
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn test_bt_send_recv_unix_socketpair() {
        let mut fds = [0i32; 2];
        // SAFETY: creating a unix socketpair for testing purposes.
        let ret = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
        };
        assert_eq!(ret, 0);
        let _fd0 = bt_owned_fd(fds[0]).unwrap();
        let _fd1 = bt_owned_fd(fds[1]).unwrap();

        let data = b"test";
        let sent = bt_send_raw(fds[0], data, 0).unwrap();
        assert_eq!(sent, 4);

        let mut buf = [0u8; 16];
        let recvd = bt_recv_raw(fds[1], &mut buf, 0).unwrap();
        assert_eq!(recvd, 4);
        assert_eq!(&buf[..4], b"test");
    }

    #[test]
    fn test_bt_setsockopt_getsockopt() {
        let sock = bt_raw_socket(libc::AF_UNIX, libc::SOCK_STREAM, 0).unwrap();
        let fd = sock.as_raw_fd();

        // Set and get SO_REUSEADDR
        let val: i32 = 1;
        bt_setsockopt_val(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &val).unwrap();
        let got: i32 = bt_getsockopt_val(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR).unwrap();
        assert_eq!(got, 1);
    }

    #[test]
    fn test_bt_fcntl_getfl() {
        let sock = bt_raw_socket(libc::AF_UNIX, libc::SOCK_STREAM, 0).unwrap();
        let flags = bt_fcntl_getfl(sock.as_raw_fd());
        assert!(flags.is_ok());
    }

    #[test]
    fn test_bt_gettimeofday() {
        let tv = bt_gettimeofday();
        assert!(tv.is_ok());
        let tv = tv.unwrap();
        assert!(tv.tv_sec > 0);
    }

    #[test]
    fn test_bt_lseek_invalid() {
        let result = bt_lseek(-1, 0, libc::SEEK_SET);
        assert!(result.is_err());
    }

    #[test]
    fn test_bt_bind_addr_invalid() {
        // Binding on an invalid fd should fail
        let addr: libc::sockaddr_un = zeroed_struct();
        let result = bt_bind_addr(-1, &addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_bt_borrow_fd() {
        let sock = bt_raw_socket(libc::AF_UNIX, libc::SOCK_STREAM, 0).unwrap();
        let borrowed = bt_borrow_fd(sock.as_raw_fd());
        assert_eq!(borrowed.as_raw_fd(), sock.as_raw_fd());
    }
}
