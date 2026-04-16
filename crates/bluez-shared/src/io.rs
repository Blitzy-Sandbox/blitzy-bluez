// SPDX-License-Identifier: GPL-2.0-or-later
//
// Async I/O abstraction replacing src/shared/io.h + io-mainloop.c
//
// C's callback pattern (io_set_read_handler + callback + user_data) is replaced
// by async methods: `io.readable().await`, `io.writable().await` in a
// `tokio::select!` loop.

use std::io::{self, IoSlice};
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

/// Async wrapper around a raw file descriptor for Bluetooth sockets.
///
/// Replaces the C `struct io` from `io-mainloop.c`. Instead of registering
/// callbacks for read/write/disconnect, callers use async methods:
///
/// ```ignore
/// loop {
///     tokio::select! {
///         _ = bt_io.readable() => { /* read data */ }
///         _ = bt_io.writable() => { /* write data */ }
///     }
/// }
/// ```
pub struct BluetoothIo {
    inner: AsyncFd<OwnedFd>,
}

impl BluetoothIo {
    /// Create a new `BluetoothIo` from an owned file descriptor.
    ///
    /// The fd must already be set to non-blocking mode.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let inner = AsyncFd::new(fd)?;
        Ok(Self { inner })
    }

    /// Create from a raw fd, taking ownership.
    ///
    /// # Safety
    /// The fd must be a valid open file descriptor that the caller owns.
    /// It must be in non-blocking mode.
    pub unsafe fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::new(owned)
    }

    /// Wait until the fd is readable.
    pub async fn readable(&self) -> io::Result<()> {
        self.inner.readable().await?.retain_ready();
        Ok(())
    }

    /// Wait until the fd is writable.
    pub async fn writable(&self) -> io::Result<()> {
        self.inner.writable().await?.retain_ready();
        Ok(())
    }

    /// Wait for the fd to become ready for the given interest.
    pub async fn ready(&self, interest: Interest) -> io::Result<()> {
        self.inner.ready(interest).await?.retain_ready();
        Ok(())
    }

    /// Send data on the socket. Waits for writability, then writes.
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                let fd = inner.as_raw_fd();
                // SAFETY: fd is valid, data is a valid buffer
                let ret = unsafe {
                    libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), 0)
                };
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Send vectored data (scatter-gather I/O). Replaces C's `io_send()`.
    pub async fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                let fd = inner.as_raw_fd();
                // SAFETY: fd is valid, bufs are valid IoSlice references
                let ret = unsafe {
                    libc::writev(
                        fd,
                        bufs.as_ptr() as *const libc::iovec,
                        bufs.len() as libc::c_int,
                    )
                };
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive data from the socket. Waits for readability, then reads.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                let fd = inner.as_raw_fd();
                // SAFETY: fd is valid, buf is a valid mutable buffer
                let ret = unsafe {
                    libc::recv(
                        fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Shutdown the socket (both read and write directions).
    pub fn shutdown(&self) -> io::Result<()> {
        let fd = self.inner.as_raw_fd();
        // SAFETY: fd is valid
        let ret = unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Get a reference to the inner `AsyncFd` for advanced use cases.
    pub fn async_fd(&self) -> &AsyncFd<OwnedFd> {
        &self.inner
    }
}

impl AsRawFd for BluetoothIo {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsFd for BluetoothIo {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a non-blocking Unix socketpair, portable across Linux and macOS.
    fn socketpair_nonblock() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        // SAFETY: fds is a valid array
        let ret = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
        };
        assert_eq!(ret, 0);
        // Set non-blocking via fcntl (portable)
        for &fd in &fds {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                let fdflags = libc::fcntl(fd, libc::F_GETFD);
                libc::fcntl(fd, libc::F_SETFD, fdflags | libc::FD_CLOEXEC);
            }
        }
        unsafe {
            (
                OwnedFd::from_raw_fd(fds[0]),
                OwnedFd::from_raw_fd(fds[1]),
            )
        }
    }

    #[tokio::test]
    async fn test_bluetooth_io_from_socketpair() {
        let (fd1, fd2) = socketpair_nonblock();
        let io1 = BluetoothIo::new(fd1).unwrap();
        let io2 = BluetoothIo::new(fd2).unwrap();

        let sent = io1.send(b"hello").await.unwrap();
        assert_eq!(sent, 5);

        let mut buf = [0u8; 16];
        let received = io2.recv(&mut buf).await.unwrap();
        assert_eq!(received, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[tokio::test]
    async fn test_send_vectored() {
        let (fd1, fd2) = socketpair_nonblock();
        let io1 = BluetoothIo::new(fd1).unwrap();
        let io2 = BluetoothIo::new(fd2).unwrap();

        let bufs = [IoSlice::new(b"hel"), IoSlice::new(b"lo")];
        let sent = io1.send_vectored(&bufs).await.unwrap();
        assert_eq!(sent, 5);

        let mut buf = [0u8; 16];
        let received = io2.recv(&mut buf).await.unwrap();
        assert_eq!(received, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[tokio::test]
    async fn test_shutdown() {
        let (fd1, fd2) = socketpair_nonblock();
        let io1 = BluetoothIo::new(fd1).unwrap();
        let _io2 = BluetoothIo::new(fd2).unwrap();

        assert!(io1.shutdown().is_ok());
    }

    #[test]
    fn test_as_raw_fd() {
        let (fd1, _fd2) = socketpair_nonblock();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let raw = fd1.as_raw_fd();
            let io = BluetoothIo::new(fd1).unwrap();
            assert_eq!(io.as_raw_fd(), raw);
        });
    }
}
