// SPDX-License-Identifier: GPL-2.0-or-later
//
// btio — Type-safe Bluetooth socket builder
//
// Replaces btio/btio.c (~2,268 LOC) with a Rust builder pattern for
// constructing L2CAP, RFCOMM, SCO, and ISO sockets.

use std::io;

use bluez_shared::addr::BdAddr;

/// Bluetooth socket transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtSocketType {
    L2cap,
    Rfcomm,
    Sco,
    Iso,
}

/// Bluetooth security level (maps to BT_SECURITY levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BtSecurityLevel {
    Low = 1,
    Medium = 2,
    High = 3,
    Fips = 4,
}

/// Entry point for creating Bluetooth sockets.
pub struct BtSocket;

impl BtSocket {
    pub fn l2cap() -> BtSocketBuilder {
        BtSocketBuilder::new(BtSocketType::L2cap)
    }

    pub fn rfcomm() -> BtSocketBuilder {
        BtSocketBuilder::new(BtSocketType::Rfcomm)
    }

    pub fn sco() -> BtSocketBuilder {
        BtSocketBuilder::new(BtSocketType::Sco)
    }

    pub fn iso() -> BtSocketBuilder {
        BtSocketBuilder::new(BtSocketType::Iso)
    }
}

/// Builder for configuring and creating Bluetooth sockets.
#[derive(Debug)]
pub struct BtSocketBuilder {
    sock_type: BtSocketType,
    source: Option<BdAddr>,
    dest: Option<BdAddr>,
    psm: Option<u16>,
    channel: Option<u8>,
    cid: Option<u16>,
    security: Option<BtSecurityLevel>,
    mtu: Option<u16>,
    imtu: Option<u16>,
    omtu: Option<u16>,
    master: bool,
    mode: Option<u8>,
    flushable: bool,
}

impl BtSocketBuilder {
    fn new(sock_type: BtSocketType) -> Self {
        Self {
            sock_type,
            source: None,
            dest: None,
            psm: None,
            channel: None,
            cid: None,
            security: None,
            mtu: None,
            imtu: None,
            omtu: None,
            master: false,
            mode: None,
            flushable: false,
        }
    }

    /// Set the local (source) address.
    pub fn source(mut self, addr: &BdAddr) -> Self {
        self.source = Some(*addr);
        self
    }

    /// Set the remote (destination) address.
    pub fn dest(mut self, addr: &BdAddr) -> Self {
        self.dest = Some(*addr);
        self
    }

    /// Set the L2CAP PSM.
    pub fn psm(mut self, psm: u16) -> Self {
        self.psm = Some(psm);
        self
    }

    /// Set the RFCOMM channel.
    pub fn channel(mut self, ch: u8) -> Self {
        self.channel = Some(ch);
        self
    }

    /// Set the L2CAP CID.
    pub fn cid(mut self, cid: u16) -> Self {
        self.cid = Some(cid);
        self
    }

    /// Set the security level.
    pub fn security(mut self, level: BtSecurityLevel) -> Self {
        self.security = Some(level);
        self
    }

    /// Set symmetric MTU (both input and output).
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set input (receive) MTU.
    pub fn imtu(mut self, mtu: u16) -> Self {
        self.imtu = Some(mtu);
        self
    }

    /// Set output (send) MTU.
    pub fn omtu(mut self, mtu: u16) -> Self {
        self.omtu = Some(mtu);
        self
    }

    /// Request master role.
    pub fn master(mut self, v: bool) -> Self {
        self.master = v;
        self
    }

    /// Set L2CAP mode.
    pub fn mode(mut self, mode: u8) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Set flushable flag for L2CAP.
    pub fn flushable(mut self, v: bool) -> Self {
        self.flushable = v;
        self
    }

    /// Returns the configured socket type.
    pub fn sock_type(&self) -> BtSocketType {
        self.sock_type
    }

    /// Initiate an outgoing connection.
    ///
    /// On Linux, creates an `AF_BLUETOOTH` socket, applies options,
    /// binds to source if specified, and connects to the destination.
    /// On non-Linux platforms, returns `Unsupported`.
    pub fn connect(self) -> io::Result<BtConnection> {
        #[cfg(target_os = "linux")]
        {
            return self.connect_linux();
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Bluetooth {:?} connect not available on this platform",
                    self.sock_type
                ),
            ))
        }
    }

    /// Bind and listen for incoming connections.
    ///
    /// On Linux, creates an `AF_BLUETOOTH` socket, sets `SO_REUSEADDR`,
    /// binds, and listens with a backlog.
    /// On non-Linux platforms, returns `Unsupported`.
    pub fn listen(self) -> io::Result<BtListener> {
        #[cfg(target_os = "linux")]
        {
            return self.listen_linux();
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Bluetooth {:?} listen not available on this platform",
                    self.sock_type
                ),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Linux-only socket implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_bt {
    //! Bluetooth socket constants and address structures for Linux.
    //!
    //! These are not in the `nix` crate because `AF_BLUETOOTH` and the
    //! corresponding `sockaddr_*` types are Linux kernel-specific.

    pub const AF_BLUETOOTH: libc::c_int = 31;
    pub const BTPROTO_L2CAP: libc::c_int = 0;
    pub const BTPROTO_RFCOMM: libc::c_int = 3;
    pub const BTPROTO_SCO: libc::c_int = 2;
    pub const BTPROTO_ISO: libc::c_int = 6;

    /// BT_SECURITY socket option level / optname.
    pub const SOL_BLUETOOTH: libc::c_int = 274;
    pub const BT_SECURITY: libc::c_int = 4;
    pub const BT_RCVMTU: libc::c_int = 13;
    pub const BT_SNDMTU: libc::c_int = 14;
    pub const BT_FLUSHABLE: libc::c_int = 8;
    pub const BT_POWER: libc::c_int = 9;
    pub const BT_MODE: libc::c_int = 15;

    /// `struct bt_security` for BT_SECURITY socket option.
    #[repr(C)]
    pub struct BtSecurity {
        pub level: u8,
        pub key_size: u8,
    }

    /// `struct sockaddr_l2` for L2CAP sockets.
    #[repr(C)]
    pub struct SockaddrL2 {
        pub l2_family: u16,
        pub l2_psm: u16, // little-endian
        pub l2_bdaddr: [u8; 6],
        pub l2_cid: u16, // little-endian
        pub l2_bdaddr_type: u8,
    }

    /// `struct sockaddr_rc` for RFCOMM sockets.
    #[repr(C)]
    pub struct SockaddrRc {
        pub rc_family: u16,
        pub rc_bdaddr: [u8; 6],
        pub rc_channel: u8,
    }

    /// `struct sockaddr_sco` for SCO sockets.
    #[repr(C)]
    pub struct SockaddrSco {
        pub sco_family: u16,
        pub sco_bdaddr: [u8; 6],
    }

    impl SockaddrL2 {
        pub fn size() -> libc::socklen_t {
            std::mem::size_of::<Self>() as libc::socklen_t
        }
    }
    impl SockaddrRc {
        pub fn size() -> libc::socklen_t {
            std::mem::size_of::<Self>() as libc::socklen_t
        }
    }
    impl SockaddrSco {
        pub fn size() -> libc::socklen_t {
            std::mem::size_of::<Self>() as libc::socklen_t
        }
    }
}

#[cfg(target_os = "linux")]
impl BtSocketBuilder {
    /// Return the `(socket_type, protocol)` pair for the selected transport.
    fn sock_params(&self) -> (libc::c_int, libc::c_int) {
        match self.sock_type {
            BtSocketType::L2cap => (libc::SOCK_SEQPACKET, linux_bt::BTPROTO_L2CAP),
            BtSocketType::Rfcomm => (libc::SOCK_STREAM, linux_bt::BTPROTO_RFCOMM),
            BtSocketType::Sco => (libc::SOCK_SEQPACKET, linux_bt::BTPROTO_SCO),
            BtSocketType::Iso => (libc::SOCK_SEQPACKET, linux_bt::BTPROTO_ISO),
        }
    }

    /// Create the raw socket and set common options.
    fn create_socket(&self) -> io::Result<i32> {
        let (stype, proto) = self.sock_params();

        // Safety: socket() is a standard POSIX syscall.
        let fd = unsafe {
            libc::socket(
                linux_bt::AF_BLUETOOTH,
                stype | libc::SOCK_CLOEXEC,
                proto,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Apply security level if requested.
        if let Some(level) = self.security {
            let sec = linux_bt::BtSecurity {
                level: level as u8,
                key_size: 0,
            };
            // Safety: setsockopt with correctly-sized BtSecurity struct on a
            // valid fd.
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    linux_bt::SOL_BLUETOOTH,
                    linux_bt::BT_SECURITY,
                    &sec as *const linux_bt::BtSecurity as *const libc::c_void,
                    std::mem::size_of::<linux_bt::BtSecurity>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            }
        }

        // Apply MTU options for L2CAP / ISO.
        if matches!(self.sock_type, BtSocketType::L2cap | BtSocketType::Iso) {
            let imtu = self.imtu.or(self.mtu);
            let omtu = self.omtu.or(self.mtu);
            if let Some(val) = imtu {
                let val_u16 = val;
                // Safety: setsockopt with a u16 value on a valid fd.
                let ret = unsafe {
                    libc::setsockopt(
                        fd,
                        linux_bt::SOL_BLUETOOTH,
                        linux_bt::BT_RCVMTU,
                        &val_u16 as *const u16 as *const libc::c_void,
                        std::mem::size_of::<u16>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    unsafe { libc::close(fd) };
                    return Err(err);
                }
            }
            if let Some(val) = omtu {
                let val_u16 = val;
                // Safety: setsockopt with a u16 value on a valid fd.
                let ret = unsafe {
                    libc::setsockopt(
                        fd,
                        linux_bt::SOL_BLUETOOTH,
                        linux_bt::BT_SNDMTU,
                        &val_u16 as *const u16 as *const libc::c_void,
                        std::mem::size_of::<u16>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    unsafe { libc::close(fd) };
                    return Err(err);
                }
            }
        }

        // Apply L2CAP mode if set.
        if let Some(mode_val) = self.mode {
            if self.sock_type == BtSocketType::L2cap {
                // Safety: setsockopt with a u8 value on a valid fd.
                let ret = unsafe {
                    libc::setsockopt(
                        fd,
                        linux_bt::SOL_BLUETOOTH,
                        linux_bt::BT_MODE,
                        &mode_val as *const u8 as *const libc::c_void,
                        std::mem::size_of::<u8>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    unsafe { libc::close(fd) };
                    return Err(err);
                }
            }
        }

        // Apply flushable flag for L2CAP.
        if self.flushable && self.sock_type == BtSocketType::L2cap {
            let val: u32 = 1;
            // Safety: setsockopt with a u32 value on a valid fd.
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    linux_bt::SOL_BLUETOOTH,
                    linux_bt::BT_FLUSHABLE,
                    &val as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            }
        }

        Ok(fd)
    }

    /// Bind the socket to the given source address.
    fn bind_socket(&self, fd: i32) -> io::Result<()> {
        let src = self.source.unwrap_or(BdAddr::ANY);

        match self.sock_type {
            BtSocketType::L2cap | BtSocketType::Iso => {
                let addr = linux_bt::SockaddrL2 {
                    l2_family: linux_bt::AF_BLUETOOTH as u16,
                    l2_psm: self.psm.unwrap_or(0).to_le(),
                    l2_bdaddr: src.0,
                    l2_cid: self.cid.unwrap_or(0).to_le(),
                    l2_bdaddr_type: 0,
                };
                // Safety: bind() with a correctly-sized sockaddr_l2 on a valid fd.
                let ret = unsafe {
                    libc::bind(
                        fd,
                        &addr as *const linux_bt::SockaddrL2 as *const libc::sockaddr,
                        linux_bt::SockaddrL2::size(),
                    )
                };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            BtSocketType::Rfcomm => {
                let addr = linux_bt::SockaddrRc {
                    rc_family: linux_bt::AF_BLUETOOTH as u16,
                    rc_bdaddr: src.0,
                    rc_channel: self.channel.unwrap_or(0),
                };
                // Safety: bind() with a correctly-sized sockaddr_rc on a valid fd.
                let ret = unsafe {
                    libc::bind(
                        fd,
                        &addr as *const linux_bt::SockaddrRc as *const libc::sockaddr,
                        linux_bt::SockaddrRc::size(),
                    )
                };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            BtSocketType::Sco => {
                let addr = linux_bt::SockaddrSco {
                    sco_family: linux_bt::AF_BLUETOOTH as u16,
                    sco_bdaddr: src.0,
                };
                // Safety: bind() with a correctly-sized sockaddr_sco on a valid fd.
                let ret = unsafe {
                    libc::bind(
                        fd,
                        &addr as *const linux_bt::SockaddrSco as *const libc::sockaddr,
                        linux_bt::SockaddrSco::size(),
                    )
                };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    /// Linux implementation of `connect()`.
    fn connect_linux(self) -> io::Result<BtConnection> {
        let dest = self.dest.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination address required")
        })?;

        let fd = self.create_socket()?;

        // Bind to source if specified, or to BDADDR_ANY for L2CAP/RFCOMM.
        if self.source.is_some() || self.psm.is_some() || self.cid.is_some() || self.channel.is_some() {
            if let Err(e) = self.bind_socket(fd) {
                // Safety: fd is valid; we are cleaning up after bind failure.
                unsafe { libc::close(fd) };
                return Err(e);
            }
        }

        // Connect to destination.
        let ret = match self.sock_type {
            BtSocketType::L2cap | BtSocketType::Iso => {
                let addr = linux_bt::SockaddrL2 {
                    l2_family: linux_bt::AF_BLUETOOTH as u16,
                    l2_psm: self.psm.unwrap_or(0).to_le(),
                    l2_bdaddr: dest.0,
                    l2_cid: self.cid.unwrap_or(0).to_le(),
                    l2_bdaddr_type: 0,
                };
                // Safety: connect() with a correctly-sized sockaddr_l2.
                unsafe {
                    libc::connect(
                        fd,
                        &addr as *const linux_bt::SockaddrL2 as *const libc::sockaddr,
                        linux_bt::SockaddrL2::size(),
                    )
                }
            }
            BtSocketType::Rfcomm => {
                let addr = linux_bt::SockaddrRc {
                    rc_family: linux_bt::AF_BLUETOOTH as u16,
                    rc_bdaddr: dest.0,
                    rc_channel: self.channel.unwrap_or(1),
                };
                // Safety: connect() with a correctly-sized sockaddr_rc.
                unsafe {
                    libc::connect(
                        fd,
                        &addr as *const linux_bt::SockaddrRc as *const libc::sockaddr,
                        linux_bt::SockaddrRc::size(),
                    )
                }
            }
            BtSocketType::Sco => {
                let addr = linux_bt::SockaddrSco {
                    sco_family: linux_bt::AF_BLUETOOTH as u16,
                    sco_bdaddr: dest.0,
                };
                // Safety: connect() with a correctly-sized sockaddr_sco.
                unsafe {
                    libc::connect(
                        fd,
                        &addr as *const linux_bt::SockaddrSco as *const libc::sockaddr,
                        linux_bt::SockaddrSco::size(),
                    )
                }
            }
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            // Safety: fd is valid; we are cleaning up after connect failure.
            unsafe { libc::close(fd) };
            return Err(err);
        }

        Ok(BtConnection { _fd: fd })
    }

    /// Linux implementation of `listen()`.
    fn listen_linux(self) -> io::Result<BtListener> {
        let fd = self.create_socket()?;

        // Set SO_REUSEADDR.
        let opt: libc::c_int = 1;
        // Safety: setsockopt with SOL_SOCKET/SO_REUSEADDR on a valid fd.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &opt as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        // Bind to local address.
        if let Err(e) = self.bind_socket(fd) {
            unsafe { libc::close(fd) };
            return Err(e);
        }

        // Listen with a reasonable backlog.
        // Safety: listen() on a valid, bound socket fd.
        let ret = unsafe { libc::listen(fd, 5) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        Ok(BtListener { _fd: fd })
    }
}

/// An established Bluetooth connection.
pub struct BtConnection {
    _fd: i32,
}

impl BtConnection {
    /// Returns the underlying file descriptor.
    pub fn fd(&self) -> i32 {
        self._fd
    }

    /// Send data over the connection.
    ///
    /// On Linux, calls `libc::send` on the underlying fd.
    /// On non-Linux, returns `Unsupported`.
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            // Safety: send() on a valid connected socket fd with a valid
            // data pointer and length.
            let ret = unsafe {
                libc::send(
                    self._fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    0,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(ret as usize);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = data;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "send not available on this platform",
            ))
        }
    }

    /// Receive data from the connection.
    ///
    /// On Linux, calls `libc::recv` on the underlying fd.
    /// On non-Linux, returns `Unsupported`.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            // Safety: recv() on a valid connected socket fd with a valid
            // buffer pointer and length.
            let ret = unsafe {
                libc::recv(
                    self._fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(ret as usize);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = buf;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "recv not available on this platform",
            ))
        }
    }
}

/// A listening Bluetooth socket.
pub struct BtListener {
    _fd: i32,
}

impl BtListener {
    /// Accept an incoming connection.
    ///
    /// On Linux, calls `libc::accept` on the listener fd.
    /// On non-Linux, returns `Unsupported`.
    pub fn accept(&self) -> io::Result<BtConnection> {
        #[cfg(target_os = "linux")]
        {
            // Safety: accept() on a valid listening socket fd.  We pass
            // null for the peer address since we do not need it here.
            let fd = unsafe { libc::accept(self._fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(BtConnection { _fd: fd });
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "accept not available on this platform",
            ))
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for BtConnection {
    fn drop(&mut self) {
        // Safety: close() on a valid fd that we own.
        unsafe { libc::close(self._fd) };
    }
}

#[cfg(target_os = "linux")]
impl Drop for BtListener {
    fn drop(&mut self) {
        // Safety: close() on a valid fd that we own.
        unsafe { libc::close(self._fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2cap_builder() {
        let src = BdAddr::ANY;
        let dst = BdAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

        let builder = BtSocket::l2cap()
            .source(&src)
            .dest(&dst)
            .psm(0x0001)
            .mtu(672)
            .security(BtSecurityLevel::Medium);

        assert_eq!(builder.sock_type(), BtSocketType::L2cap);

        // connect returns Err on non-Linux
        let result = builder.connect();
        assert!(result.is_err());
    }

    #[test]
    fn test_rfcomm_builder() {
        let dst = BdAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let builder = BtSocket::rfcomm()
            .dest(&dst)
            .channel(1)
            .security(BtSecurityLevel::High)
            .master(true);

        assert_eq!(builder.sock_type(), BtSocketType::Rfcomm);

        let result = builder.listen();
        assert!(result.is_err());
    }

    #[test]
    fn test_security_levels() {
        assert!(BtSecurityLevel::Low < BtSecurityLevel::Medium);
        assert!(BtSecurityLevel::Medium < BtSecurityLevel::High);
        assert!(BtSecurityLevel::High < BtSecurityLevel::Fips);

        assert_eq!(BtSecurityLevel::Low as u8, 1);
        assert_eq!(BtSecurityLevel::Fips as u8, 4);
    }
}
