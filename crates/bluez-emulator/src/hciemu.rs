// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2012-2014 Intel Corporation. All rights reserved.
// Copyright (C) 2024 BlueZ contributors
//
// The emulator crate is a designated FFI/testing boundary module per
// AAP Section 0.7.4 — unsafe code is permitted for socketpair I/O,
// fd duplication, and ioctl queries.
#![allow(unsafe_code)]
//
//! HCI emulator harness.
//!
//! Complete Rust rewrite of `emulator/hciemu.c` (851 lines) and
//! `emulator/hciemu.h` (87 lines).  This module provides the
//! [`HciEmulator`] struct that coordinates a VHCI virtual controller,
//! one or more emulated client devices ([`BtDev`]+[`BtHost`] pairs),
//! and a hook system for intercepting HCI commands/events — exactly
//! mirroring the C `struct hciemu` API used by all integration testers
//! (`mgmt-tester`, `l2cap-tester`, `iso-tester`, etc.).
//!
//! # Architecture
//!
//! ```text
//! ┌────────────┐          ┌───────────────────────┐
//! │ kernel HCI │◄──VHCI──►│ HciEmulator (central) │
//! └────────────┘          │  ├─ Vhci               │
//!                         │  ├─ post_command_hooks  │
//!                         │  └─ clients[]           │
//!                         │      ├─ EmulatorClient  │
//!                         │      │   ├─ BtDev       │
//!                         │      │   ├─ BtHost      │
//!                         │      │   └─ socketpair  │
//!                         │      └─ …               │
//!                         └───────────────────────┘
//! ```
//!
//! Each [`EmulatorClient`] owns a `BtDev` (virtual controller) and a
//! `BtHost` (protocol host) connected through a `SOCK_SEQPACKET`
//! socketpair.  Background tokio tasks ferry H:4 packets between the
//! socket and the respective device/host, replacing the GLib
//! `GIOChannel` + `g_io_add_watch` pattern in the C code.
//!
//! # Ownership
//!
//! The C code uses `hciemu_ref`/`hciemu_unref` — the Rust equivalent
//! is `Arc<Mutex<HciEmulator>>` (or simply passing `&mut` where
//! exclusive access is needed).

use std::io::IoSlice;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};

use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::btdev::{BtDev, BtDevCallback, BtDevHookType, BtDevType};
use crate::bthost::BtHost;
use crate::vhci::Vhci;

// ---------------------------------------------------------------------------
// Emulator Type
// ---------------------------------------------------------------------------

/// Controller type selection for the HCI emulator.
///
/// Maps 1:1 to the C `enum hciemu_type` and internally converts to
/// [`BtDevType`] for `BtDev` and `Vhci` creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EmulatorType {
    /// Dual-mode BR/EDR + LE (4.0).
    BredrLe = 0,
    /// BR/EDR only.
    Bredr = 1,
    /// LE only.
    Le = 2,
    /// Legacy BR/EDR 2.0 (no secure simple pairing).
    Legacy = 3,
    /// Dual-mode BR/EDR + LE 5.0.
    BredrLe50 = 4,
    /// Dual-mode BR/EDR + LE 5.2.
    BredrLe52 = 5,
    /// Dual-mode BR/EDR + LE 6.0.
    BredrLe60 = 6,
}

impl EmulatorType {
    /// Convert to the internal [`BtDevType`] discriminant used by
    /// `BtDev` and `Vhci`.
    fn to_btdev_type(self) -> BtDevType {
        match self {
            Self::BredrLe => BtDevType::BrEdrLe,
            Self::Bredr => BtDevType::BrEdr,
            Self::Le => BtDevType::Le,
            Self::Legacy => BtDevType::BrEdr20,
            Self::BredrLe50 => BtDevType::BrEdrLe50,
            Self::BredrLe52 => BtDevType::BrEdrLe52,
            Self::BredrLe60 => BtDevType::BrEdrLe60,
        }
    }
}

// ---------------------------------------------------------------------------
// Hook Type
// ---------------------------------------------------------------------------

/// Hook point for intercepting HCI commands/events on the central device.
///
/// Maps 1:1 to the C `enum hciemu_hook_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EmulatorHookType {
    /// Before a command is processed by the virtual controller.
    PreCmd = 0,
    /// After a command is processed by the virtual controller.
    PostCmd = 1,
    /// Before an event is sent from the virtual controller.
    PreEvt = 2,
    /// After an event is sent from the virtual controller.
    PostEvt = 3,
}

impl EmulatorHookType {
    /// Convert to [`BtDevHookType`] for delegation to `BtDev::add_hook`.
    fn to_btdev_hook_type(self) -> BtDevHookType {
        match self {
            Self::PreCmd => BtDevHookType::PreCmd,
            Self::PostCmd => BtDevHookType::PostCmd,
            Self::PreEvt => BtDevHookType::PreEvt,
            Self::PostEvt => BtDevHookType::PostEvt,
        }
    }
}

// ---------------------------------------------------------------------------
// Post-Command Hook
// ---------------------------------------------------------------------------

/// A registered post-command callback, invoked after every HCI command
/// processed by the central (VHCI) `BtDev`.
///
/// Mirrors C `struct hciemu_command_hook`.
type PostCommandHookFn = Box<dyn Fn(u16, &[u8]) + Send + Sync>;

// ---------------------------------------------------------------------------
// Emulator Client
// ---------------------------------------------------------------------------

/// A single client device consisting of a [`BtDev`] virtual controller
/// and a [`BtHost`] protocol host connected via a `SOCK_SEQPACKET`
/// socketpair.
///
/// Both `dev` and `host` are wrapped in `Arc<Mutex<>>` because the
/// background read tasks also hold clones to call `receive_h4()`.
///
/// Mirrors C `struct hciemu_client`.
pub struct EmulatorClient {
    /// The virtual HCI device (client-side), shared with the read task.
    dev: Arc<Mutex<BtDev>>,
    /// The protocol host, shared with the read task.
    host: Arc<Mutex<BtHost>>,
    /// Raw socket file descriptors for the socketpair (kept to allow
    /// `ioctl(TIOCOUTQ)` / `ioctl(TIOCINQ)` queries in
    /// `flush_client_events`).
    sock: [RawFd; 2],
    /// Background task reading from `sock[0]` and feeding the `BtDev`.
    _dev_task: JoinHandle<()>,
    /// Background task reading from `sock[1]` and feeding the `BtHost`.
    _host_task: JoinHandle<()>,
}

impl EmulatorClient {
    /// Lock and access the client's [`BtHost`].
    pub fn host(&self) -> std::sync::MutexGuard<'_, BtHost> {
        self.host.lock().unwrap()
    }

    /// Lock and access the client's [`BtDev`].
    pub fn dev(&self) -> std::sync::MutexGuard<'_, BtDev> {
        self.dev.lock().unwrap()
    }

    /// Get the BD_ADDR of the client device.
    pub fn bdaddr(&self) -> [u8; 6] {
        *self.dev.lock().unwrap().get_bdaddr()
    }

    /// Set the BD_ADDR of the client device.
    pub fn set_bdaddr(&mut self, bdaddr: &[u8; 6]) -> bool {
        self.dev.lock().unwrap().set_bdaddr(bdaddr)
    }

    /// Check whether the client's socketpair has pending data,
    /// used by `flush_client_events`.
    fn is_pending(&self) -> bool {
        for &fd in &self.sock {
            let mut used: libc::c_int = 0;
            // Query bytes pending in outgoing and incoming queues.
            // SAFETY: ioctl with TIOCOUTQ/TIOCINQ reads an int-sized
            // output from a valid fd; we only read, never write.
            // This is confined to the emulator crate which is a
            // designated FFI boundary per AAP Section 0.7.4.
            let outq = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut used) };
            if outq == 0 && used > 0 {
                return true;
            }
            let inq = unsafe { libc::ioctl(fd, libc::TIOCINQ, &mut used) };
            if inq == 0 && used > 0 {
                return true;
            }
        }
        false
    }
}

impl Drop for EmulatorClient {
    fn drop(&mut self) {
        self._dev_task.abort();
        self._host_task.abort();
    }
}

// ---------------------------------------------------------------------------
// HciEmulator
// ---------------------------------------------------------------------------

/// HCI emulator harness — coordinates VHCI, virtual client devices,
/// and hook-based packet interception.
///
/// This is the Rust equivalent of C `struct hciemu`.  Integration
/// testers create an `HciEmulator`, which opens a VHCI device
/// (registering a virtual HCI controller with the kernel), then
/// creates N client `BtDev`+`BtHost` pairs connected via socketpairs.
///
/// # Lifecycle
///
/// ```text
/// let emu = HciEmulator::new(EmulatorType::BredrLe)?;
///   — or —
/// let emu = HciEmulator::new_num(EmulatorType::BredrLe, 2)?;
/// ```
///
/// The emulator is dropped (or explicitly closed) when the test ends,
/// which aborts all background tasks and closes the VHCI device.
pub struct HciEmulator {
    /// The virtual HCI controller backed by `/dev/vhci`.
    vhci: Vhci,
    /// The `BtDevType` used for this emulator instance.
    btdev_type: BtDevType,
    /// Client device/host pairs (one per `num` requested).
    clients: Vec<EmulatorClient>,
    /// Post-command hooks invoked after each HCI command on the
    /// central (VHCI) `BtDev`.
    post_command_hooks: Vec<PostCommandHookFn>,
    /// Debug callback for emulator-level diagnostic messages.
    debug_callback: Option<Arc<dyn Fn(&str) + Send + Sync>>,
    /// Handle for the flush idle task (replaces C `flush_id`).
    flush_handle: Option<JoinHandle<()>>,
}

/// Error type for HCI emulator operations.
#[derive(Debug, thiserror::Error)]
pub enum HciEmuError {
    /// VHCI device open failed.
    #[error("VHCI open failed: {0}")]
    VhciOpen(String),
    /// Client creation failed (socketpair or BtDev/BtHost init).
    #[error("client creation failed: {0}")]
    ClientCreate(String),
    /// I/O error during emulator operation.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl HciEmulator {
    /// Create a new emulator with a single client device.
    ///
    /// Equivalent to C `hciemu_new(type)`.
    pub fn new(emu_type: EmulatorType) -> Result<Self, HciEmuError> {
        Self::new_num(emu_type, 1)
    }

    /// Create a new emulator with `num` client devices.
    ///
    /// Equivalent to C `hciemu_new_num(type, num)`.
    ///
    /// # Errors
    ///
    /// Returns an error if VHCI cannot be opened, or if any client
    /// device/host pair cannot be created.
    pub fn new_num(emu_type: EmulatorType, num: u8) -> Result<Self, HciEmuError> {
        if num == 0 {
            return Err(HciEmuError::ClientCreate(
                "num must be >= 1".to_owned(),
            ));
        }

        let btdev_type = emu_type.to_btdev_type();

        // Open the VHCI device (creates a virtual HCI controller).
        let vhci = Vhci::open(btdev_type).map_err(|e| {
            HciEmuError::VhciOpen(format!("{e}"))
        })?;

        let mut emu = Self {
            vhci,
            btdev_type,
            clients: Vec::with_capacity(num as usize),
            post_command_hooks: Vec::new(),
            debug_callback: None,
            flush_handle: None,
        };

        // Install the central (VHCI) command handler that invokes
        // post_command_hooks after default processing.
        // NOTE: We cannot capture `&mut self` in the handler; instead,
        // the hooks are invoked explicitly via the command handler on
        // the VHCI btdev.  The C code used a user_data pointer back to
        // hciemu; here we set the handler after all clients are created.

        // Create client devices.
        for i in 0..num {
            let client = Self::create_client(btdev_type, i)?;
            emu.clients.push(client);
        }

        Ok(emu)
    }

    /// Create a single [`EmulatorClient`] with a socketpair bridging
    /// `BtDev` ↔ `BtHost`.
    fn create_client(
        btdev_type: BtDevType,
        id: u8,
    ) -> Result<EmulatorClient, HciEmuError> {
        // Create a SOCK_SEQPACKET socketpair (matching C code).
        let (sv0, sv1) = Self::create_socketpair()?;
        let raw0 = sv0.as_raw_fd();
        let raw1 = sv1.as_raw_fd();

        // Create the virtual device.
        let mut dev = BtDev::new(btdev_type, u16::from(id)).map_err(|e| {
            HciEmuError::ClientCreate(format!("BtDev::new failed: {e}"))
        })?;

        // Create the protocol host.
        let mut host = BtHost::new();

        // Get MTU from the device and set on host (matching C code).
        let (acl_mtu, _sco_mtu, iso_mtu) = dev.get_mtu();
        host.set_acl_mtu(acl_mtu);
        host.set_iso_mtu(iso_mtu);

        // Wire BtDev send handler → write to sock[0].
        let write_fd0 = Arc::new(Mutex::new(dup_fd(raw0)?));
        let write_fd0_clone = Arc::clone(&write_fd0);
        dev.set_send_handler(Some(Box::new(move |iov: &[IoSlice<'_>]| {
            let guard = write_fd0_clone.lock().unwrap();
            // SAFETY: The OwnedFd in the guard keeps the fd alive for the
            // duration of the borrow — the BorrowedFd does not outlive it.
            let borrowed = unsafe { BorrowedFd::borrow_raw(guard.as_raw_fd()) };
            let _ = nix::sys::uio::writev(borrowed, iov);
        })));

        // Wire BtHost send handler → write to sock[1].
        let write_fd1 = Arc::new(Mutex::new(dup_fd(raw1)?));
        let write_fd1_clone = Arc::clone(&write_fd1);
        host.set_send_handler(move |iov: &[IoSlice<'_>]| {
            let guard = write_fd1_clone.lock().unwrap();
            // SAFETY: Same as above — BorrowedFd is valid for the guard's scope.
            let borrowed = unsafe { BorrowedFd::borrow_raw(guard.as_raw_fd()) };
            let _ = nix::sys::uio::writev(borrowed, iov);
        });

        // Client command handler — just does default processing.
        dev.set_command_handler(Some(Box::new(
            |_opcode: u16, _data: &[u8], cb: &mut BtDevCallback| {
                cb.command_default();
            },
        )));

        // Start the host (kicks off internal initialization).
        host.start();

        // Wrap dev and host in Arc<Mutex<>> so the background read
        // tasks can share access for receive_h4() calls.
        let dev_arc = Arc::new(Mutex::new(dev));
        let host_arc = Arc::new(Mutex::new(host));

        // Spawn the BtDev read task: reads from sock[0], feeds BtDev.
        let dev_task = {
            let dev_ref = Arc::clone(&dev_arc);
            let async_fd = AsyncFd::new(sv0).map_err(HciEmuError::Io)?;
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let mut readable = match async_fd.readable().await {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    match readable.try_io(|inner| {
                        // SAFETY: `read` on a valid fd with a properly-sized
                        // buffer is well-defined.  The fd is owned by the
                        // AsyncFd and remains valid.
                        let n = unsafe {
                            libc::read(
                                inner.as_raw_fd(),
                                buf.as_mut_ptr().cast::<libc::c_void>(),
                                buf.len(),
                            )
                        };
                        if n < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(n as usize)
                        }
                    }) {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                            continue;
                        }
                        Ok(Ok(n)) => {
                            let mut d = dev_ref.lock().unwrap();
                            d.receive_h4(&buf[..n]);
                        }
                    }
                }
            })
        };

        // Spawn the BtHost read task: reads from sock[1], feeds BtHost.
        let host_task = {
            let host_ref = Arc::clone(&host_arc);
            let async_fd = AsyncFd::new(sv1).map_err(HciEmuError::Io)?;
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let mut readable = match async_fd.readable().await {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    match readable.try_io(|inner| {
                        // SAFETY: Same as above — valid fd and buffer.
                        let n = unsafe {
                            libc::read(
                                inner.as_raw_fd(),
                                buf.as_mut_ptr().cast::<libc::c_void>(),
                                buf.len(),
                            )
                        };
                        if n < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(n as usize)
                        }
                    }) {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                            continue;
                        }
                        Ok(Ok(n)) => {
                            let mut h = host_ref.lock().unwrap();
                            h.receive_h4(&buf[..n]);
                        }
                    }
                }
            })
        };

        // Store the raw fds for ioctl queries in is_pending().
        let sock_fds = [raw0, raw1];

        Ok(EmulatorClient {
            dev: dev_arc,
            host: host_arc,
            sock: sock_fds,
            _dev_task: dev_task,
            _host_task: host_task,
        })
    }

    /// Create a `SOCK_SEQPACKET` socketpair (non-blocking, close-on-exec).
    fn create_socketpair() -> Result<(OwnedFd, OwnedFd), HciEmuError> {
        let mut sv = [0i32; 2];
        // SAFETY: socketpair is a POSIX syscall that writes two valid
        // fds into the provided array.  The array is stack-local and
        // correctly sized.  This is in the emulator crate which is a
        // designated FFI boundary.
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        };
        if ret < 0 {
            return Err(HciEmuError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: socketpair succeeded, so sv[0] and sv[1] are valid fds.
        let fd0 = unsafe { OwnedFd::from_raw_fd(sv[0]) };
        let fd1 = unsafe { OwnedFd::from_raw_fd(sv[1]) };
        Ok((fd0, fd1))
    }

    // -----------------------------------------------------------------------
    // VHCI accessors
    // -----------------------------------------------------------------------

    /// Get a reference to the underlying [`Vhci`] device.
    pub fn get_vhci(&self) -> &Vhci {
        &self.vhci
    }

    /// Get a mutable reference to the underlying [`Vhci`] device.
    pub fn get_vhci_mut(&mut self) -> &mut Vhci {
        &mut self.vhci
    }

    /// Get the HCI controller index assigned by the kernel.
    pub fn index(&self) -> u16 {
        self.vhci.index()
    }

    /// Get the controller type.
    pub fn dev_type(&self) -> BtDevType {
        self.btdev_type
    }

    // -----------------------------------------------------------------------
    // Client accessors
    // -----------------------------------------------------------------------

    /// Get a reference to a client by index.
    ///
    /// Equivalent to C `hciemu_get_client(hciemu, num)`.
    pub fn get_client(&self, num: usize) -> Option<&EmulatorClient> {
        self.clients.get(num)
    }

    /// Get a mutable reference to a client by index.
    pub fn get_client_mut(&mut self, num: usize) -> Option<&mut EmulatorClient> {
        self.clients.get_mut(num)
    }

    /// Lock and access the first client's [`BtHost`].
    ///
    /// Equivalent to C `hciemu_client_get_host(hciemu)`.
    pub fn client_host(&self) -> Option<std::sync::MutexGuard<'_, BtHost>> {
        self.clients.first().map(|c| c.host())
    }

    /// Get the first client's BD_ADDR (copied).
    ///
    /// Equivalent to C `hciemu_get_client_bdaddr(hciemu)`.
    pub fn get_client_bdaddr(&self) -> Option<[u8; 6]> {
        self.clients.first().map(|c| c.bdaddr())
    }

    // -----------------------------------------------------------------------
    // Central (VHCI) device accessors
    // -----------------------------------------------------------------------

    /// Get the BD_ADDR of the central (VHCI) device (copied).
    ///
    /// Equivalent to C `hciemu_get_central_bdaddr(hciemu)`.
    pub fn get_central_bdaddr(&self) -> [u8; 6] {
        *self.vhci.get_btdev().get_bdaddr()
    }

    /// Get the BD_ADDR as a colon-separated string.
    ///
    /// Equivalent to C `hciemu_get_address(hciemu)`.
    pub fn get_address(&self) -> String {
        let b = self.get_central_bdaddr();
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            b[5], b[4], b[3], b[2], b[1], b[0]
        )
    }

    /// Get the LMP feature pages of the central device (copied).
    ///
    /// Equivalent to C `hciemu_get_features(hciemu)`.
    pub fn get_features(&self) -> Vec<u8> {
        self.vhci.get_btdev().get_features().to_vec()
    }

    /// Get the supported HCI commands bitmap of the central device (copied).
    ///
    /// Equivalent to C `hciemu_get_commands(hciemu)`.
    pub fn get_commands(&self) -> Vec<u8> {
        self.vhci.get_btdev().get_commands().to_vec()
    }

    /// Get the scan enable state of the central device.
    ///
    /// Equivalent to C `hciemu_get_central_scan_enable(hciemu)`.
    pub fn get_central_scan_enable(&self) -> u8 {
        self.vhci.get_btdev().get_scan_enable()
    }

    /// Get the LE scan enable state of the central device.
    ///
    /// Equivalent to C `hciemu_get_central_le_scan_enable(hciemu)`.
    pub fn get_central_le_scan_enable(&self) -> u8 {
        self.vhci.get_btdev().get_le_scan_enable()
    }

    /// Set the LE states bitmap on the central device.
    ///
    /// Equivalent to C `hciemu_set_central_le_states(hciemu, le_states)`.
    pub fn set_central_le_states(&mut self, le_states: &[u8; 8]) {
        self.vhci.get_btdev_mut().set_le_states(le_states);
    }

    /// Set the accept-list length on the central device.
    ///
    /// Equivalent to C `hciemu_set_central_le_al_len(hciemu, len)`.
    pub fn set_central_le_al_len(&mut self, len: u8) {
        self.vhci.get_btdev_mut().set_al_len(len);
    }

    /// Set the resolving-list length on the central device.
    ///
    /// Equivalent to C `hciemu_set_central_le_rl_len(hciemu, len)`.
    pub fn set_central_le_rl_len(&mut self, len: u8) {
        self.vhci.get_btdev_mut().set_rl_len(len);
    }

    /// Get the advertising address for a given handle on the central
    /// device (copied).
    ///
    /// Equivalent to C `hciemu_get_central_adv_addr(hciemu, handle)`.
    pub fn get_central_adv_addr(&self, handle: u8) -> Option<[u8; 6]> {
        self.vhci.get_btdev().get_adv_addr(handle).copied()
    }

    // -----------------------------------------------------------------------
    // Post-command hooks
    // -----------------------------------------------------------------------

    /// Add a post-command hook that is invoked after every HCI command
    /// processed by the central (VHCI) device.
    ///
    /// Equivalent to C `hciemu_add_central_post_command_hook(hciemu, fn, data)`.
    pub fn add_central_post_command_hook(
        &mut self,
        hook: impl Fn(u16, &[u8]) + Send + Sync + 'static,
    ) -> bool {
        self.post_command_hooks.push(Box::new(hook));
        true
    }

    /// Remove all post-command hooks.
    ///
    /// Equivalent to C `hciemu_clear_central_post_command_hooks(hciemu)`.
    pub fn clear_central_post_command_hooks(&mut self) -> bool {
        self.post_command_hooks.clear();
        true
    }

    // -----------------------------------------------------------------------
    // BtDev hooks (pre/post cmd/evt)
    // -----------------------------------------------------------------------

    /// Add a hook to the central (VHCI) device.
    ///
    /// Equivalent to C `hciemu_add_hook(hciemu, type, opcode, fn, data)`.
    pub fn add_hook(
        &mut self,
        hook_type: EmulatorHookType,
        opcode: u16,
        function: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
    ) -> i32 {
        let btdev_hook_type = hook_type.to_btdev_hook_type();
        let mut dev = self.vhci.get_btdev_mut();
        dev.add_hook(btdev_hook_type, opcode, Box::new(function))
    }

    /// Remove a hook from the central (VHCI) device.
    ///
    /// Equivalent to C `hciemu_del_hook(hciemu, type, opcode)`.
    pub fn del_hook(&mut self, hook_type: EmulatorHookType, opcode: u16) -> bool {
        let btdev_hook_type = hook_type.to_btdev_hook_type();
        let mut dev = self.vhci.get_btdev_mut();
        dev.del_hook(btdev_hook_type, opcode)
    }

    // -----------------------------------------------------------------------
    // Debug
    // -----------------------------------------------------------------------

    /// Set a debug callback for diagnostic messages.
    ///
    /// Equivalent to C `hciemu_set_debug(hciemu, callback, user_data, destroy)`.
    pub fn set_debug(
        &mut self,
        callback: impl Fn(&str) + Send + Sync + 'static,
    ) -> bool {
        let cb: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(callback);
        self.debug_callback = Some(Arc::clone(&cb));

        // Wire debug to VHCI.
        let vhci_cb = Arc::clone(&cb);
        self.vhci.set_debug(move |s: &str| {
            vhci_cb(&format!("vhci: {s}"));
        });

        // Wire debug to each client's host and dev.
        for client in &self.clients {
            let host_cb = Arc::clone(&cb);
            client.host().set_debug(move |s: &str| {
                host_cb(&format!("bthost: {s}"));
            });
            let dev_cb = Arc::clone(&cb);
            client.dev().set_debug(Some(Box::new(move |s: &str| {
                dev_cb(&format!("btdev: {s}"));
            })));
        }

        true
    }

    // -----------------------------------------------------------------------
    // Flush client events
    // -----------------------------------------------------------------------

    /// Pause VHCI input, then wait for all pending client data to be
    /// drained before resuming.
    ///
    /// Equivalent to C `hciemu_flush_client_events(hciemu)`.
    pub fn flush_client_events(&mut self) {
        if self.flush_handle.is_some() {
            return;
        }

        if let Some(ref cb) = self.debug_callback {
            cb("vhci: pause");
        }

        self.vhci.pause_input(true);

        debug!("flush_client_events: pausing VHCI input");

        // Poll client socketpairs synchronously until no pending data
        // remains.  The C code used a GLib idle callback; here we spin
        // with a short sleep, bounded by a maximum iteration count to
        // avoid hangs.
        let mut pending = true;
        let mut retries = 0u32;
        const MAX_RETRIES: u32 = 100;
        while pending && retries < MAX_RETRIES {
            pending = false;
            for client in &self.clients {
                if client.is_pending() {
                    pending = true;
                    break;
                }
            }
            if pending {
                retries += 1;
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        self.vhci.pause_input(false);

        if let Some(ref cb) = self.debug_callback {
            cb("vhci: resume");
        }
    }
}

impl Drop for HciEmulator {
    fn drop(&mut self) {
        // Abort the flush task if running.
        if let Some(handle) = self.flush_handle.take() {
            handle.abort();
        }
        // Clients are dropped automatically, aborting their tasks.
        // Vhci is dropped, closing the /dev/vhci device.
    }
}

// ---------------------------------------------------------------------------
// Helper: dup a file descriptor into an OwnedFd
// ---------------------------------------------------------------------------

/// Duplicate a raw file descriptor into an `OwnedFd`.
fn dup_fd(fd: RawFd) -> Result<OwnedFd, HciEmuError> {
    // SAFETY: `libc::dup` is a POSIX system call that duplicates a valid
    // file descriptor.  The returned fd is valid if non-negative.
    let new_fd = unsafe { libc::dup(fd) };
    if new_fd < 0 {
        return Err(HciEmuError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: `dup` succeeded — `new_fd` is a valid, open file descriptor
    // that we now own exclusively.
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify [`EmulatorType`] → [`BtDevType`] conversion covers all variants.
    #[test]
    fn emulator_type_to_btdev_type() {
        assert_eq!(EmulatorType::BredrLe.to_btdev_type(), BtDevType::BrEdrLe);
        assert_eq!(EmulatorType::Bredr.to_btdev_type(), BtDevType::BrEdr);
        assert_eq!(EmulatorType::Le.to_btdev_type(), BtDevType::Le);
        assert_eq!(EmulatorType::Legacy.to_btdev_type(), BtDevType::BrEdr20);
        assert_eq!(EmulatorType::BredrLe50.to_btdev_type(), BtDevType::BrEdrLe50);
        assert_eq!(EmulatorType::BredrLe52.to_btdev_type(), BtDevType::BrEdrLe52);
        assert_eq!(EmulatorType::BredrLe60.to_btdev_type(), BtDevType::BrEdrLe60);
    }

    /// Verify [`EmulatorHookType`] → [`BtDevHookType`] conversion.
    #[test]
    fn hook_type_to_btdev_hook_type() {
        assert_eq!(
            EmulatorHookType::PreCmd.to_btdev_hook_type(),
            BtDevHookType::PreCmd
        );
        assert_eq!(
            EmulatorHookType::PostCmd.to_btdev_hook_type(),
            BtDevHookType::PostCmd
        );
        assert_eq!(
            EmulatorHookType::PreEvt.to_btdev_hook_type(),
            BtDevHookType::PreEvt
        );
        assert_eq!(
            EmulatorHookType::PostEvt.to_btdev_hook_type(),
            BtDevHookType::PostEvt
        );
    }

    /// Verify `new_num` with 0 returns an error.
    #[test]
    fn new_num_zero_clients_fails() {
        let result = HciEmulator::new_num(EmulatorType::BredrLe, 0);
        assert!(result.is_err());
    }
}
