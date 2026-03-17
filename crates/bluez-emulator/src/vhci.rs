// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/bluez-emulator/src/vhci.rs — Virtual HCI (VHCI) bridge
//
// Complete Rust rewrite of BlueZ emulator/vhci.c (333 lines) and
// emulator/vhci.h (34 lines). Creates kernel-visible hciN virtual
// controllers via `/dev/vhci`, shuttling H:4 frames between the kernel
// and a `BtDev` virtual controller through `AsyncFd`.
//
// This is a **designated `unsafe` boundary module** — `unsafe` blocks are
// required for `/dev/vhci` open/read/write, file descriptor duplication,
// and debugfs file operations. Every `unsafe` block carries a `// SAFETY:`
// comment documenting the invariant.
#![allow(unsafe_code)]

use std::io::IoSlice;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::io::unix::AsyncFd;
use tokio::task::{JoinHandle, spawn};

use crate::btdev::{BtDev, BtDevType};

// ---------------------------------------------------------------------------
// Constants (matching kernel / C macros)
// ---------------------------------------------------------------------------

/// Debugfs root for Bluetooth controllers.
const DEBUGFS_PATH: &str = "/sys/kernel/debug/bluetooth";

/// Sysfs path for devcoredump entries.
const DEVCORE_PATH: &str = "/sys/class/devcoredump";

/// H:4 vendor-specific packet type used by the VHCI create handshake.
const HCI_VENDOR_PKT: u8 = 0xff;

/// Opcode for primary (BR/EDR + LE) controller in the VHCI create request.
const HCI_PRIMARY: u8 = 0x00;

/// Opcode for AMP controller in the VHCI create request.
const HCI_AMP: u8 = 0x01;

/// Maximum H:4 frame size read from `/dev/vhci` per iteration.
const READ_BUF_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Wire-format structures (matching kernel's `struct vhci_create_req/rsp`)
// ---------------------------------------------------------------------------

/// VHCI controller creation request written to `/dev/vhci`.
///
/// Wire format: `[pkt_type (1 byte)][opcode (1 byte)]` — 2 bytes total.
#[repr(C, packed)]
struct VhciCreateReq {
    pkt_type: u8,
    opcode: u8,
}

/// VHCI controller creation response read from `/dev/vhci`.
///
/// Wire format: `[pkt_type (1 byte)][opcode (1 byte)][index (2 bytes LE)]`
/// — 4 bytes total.
#[repr(C, packed)]
struct VhciCreateRsp {
    pkt_type: u8,
    opcode: u8,
    index: u16,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during VHCI operations.
#[derive(Debug, thiserror::Error)]
pub enum VhciError {
    /// Failed to open `/dev/vhci` character device.
    #[error("failed to open /dev/vhci: {0}")]
    Open(std::io::Error),

    /// Failed to write the VHCI create request.
    #[error("failed to write VHCI create request: {0}")]
    WriteRequest(std::io::Error),

    /// Failed to read the VHCI create response.
    #[error("failed to read VHCI create response: {0}")]
    ReadResponse(std::io::Error),

    /// The VHCI create response did not match the expected format.
    #[error(
        "invalid VHCI create response: expected pkt_type=0xff opcode={expected_opcode:#04x}, \
         got pkt_type={actual_pkt_type:#04x} opcode={actual_opcode:#04x}"
    )]
    InvalidResponse {
        /// The expected opcode in the VHCI response.
        expected_opcode: u8,
        /// The actual packet type received.
        actual_pkt_type: u8,
        /// The actual opcode received.
        actual_opcode: u8,
    },

    /// Failed to create `AsyncFd` for the VHCI file descriptor.
    #[error("failed to create AsyncFd: {0}")]
    AsyncFd(std::io::Error),

    /// Failed to create the underlying `BtDev` virtual controller.
    #[error("failed to create BtDev: {0}")]
    BtDev(#[from] crate::btdev::BtDevError),

    /// A debugfs file operation failed.
    #[error("debugfs operation failed on '{path}': {source}")]
    Debugfs {
        /// The debugfs file path that was being accessed.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// No devcoredump entry found in sysfs.
    #[error("devcoredump entry not found in {0}")]
    DevcdNotFound(String),

    /// Generic I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to duplicate a file descriptor.
    #[error("failed to duplicate file descriptor: {0}")]
    Dup(std::io::Error),
}

// ---------------------------------------------------------------------------
// Vhci — public struct (replaces `struct vhci`)
// ---------------------------------------------------------------------------

/// Virtual HCI bridge that creates a kernel-visible `hciN` controller via
/// `/dev/vhci` and shuttles H:4 frames between the kernel and a [`BtDev`]
/// virtual controller.
///
/// # Lifecycle
///
/// 1. [`Vhci::open`] opens `/dev/vhci`, performs the create handshake, wraps
///    the fd in `AsyncFd`, creates a `BtDev`, and spawns the async read loop.
/// 2. Incoming H:4 frames from the kernel are read by the background task and
///    forwarded to `BtDev::receive_h4`.
/// 3. Outgoing H:4 frames generated by `BtDev` are written back to the fd
///    through the registered send handler using `writev`.
/// 4. On [`Drop`], the read task is aborted and all fds are closed.
pub struct Vhci {
    /// Controller type stored for reference.
    dev_type: BtDevType,
    /// Kernel hci index returned by the VHCI create response.
    index: u16,
    /// Master file descriptor for `/dev/vhci`, kept alive for the entire
    /// lifetime of this struct. Shared via `Arc` with the write handler.
    fd: Arc<OwnedFd>,
    /// The virtual controller, shared with the background read task via
    /// `Arc<Mutex<…>>` so that both the read loop and public API methods
    /// can access it safely.
    btdev: Arc<Mutex<BtDev>>,
    /// Handle for the background async read task. `None` when input is
    /// paused via [`Vhci::pause_input`].
    read_task: Option<JoinHandle<()>>,
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

impl Vhci {
    /// Open a new virtual HCI controller via `/dev/vhci`.
    ///
    /// This performs the full VHCI handshake:
    /// 1. Opens `/dev/vhci` with `O_RDWR | O_NONBLOCK`.
    /// 2. Writes a `VhciCreateReq` with the appropriate opcode.
    /// 3. Reads and validates the `VhciCreateRsp`.
    /// 4. Creates a `BtDev` with the kernel-returned hci index.
    /// 5. Registers a scatter-gather write handler on `BtDev`.
    /// 6. Spawns an async read loop that forwards kernel H:4 frames to `BtDev`.
    ///
    /// Replaces C `vhci_open()` (lines 103–167 of emulator/vhci.c).
    pub fn open(dev_type: BtDevType) -> Result<Self, VhciError> {
        // --- Step 1: Open /dev/vhci ---

        // SAFETY: /dev/vhci is a kernel-provided character device for creating
        // virtual HCI controllers. The fd is valid after a successful open()
        // and we take ownership via OwnedFd below. O_NONBLOCK is required for
        // later use with tokio AsyncFd.
        // SAFETY: Opening /dev/vhci device with O_RDWR | O_NONBLOCK. Device path is a compile-time constant.
        let raw_fd = unsafe { libc::open(c"/dev/vhci".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if raw_fd < 0 {
            return Err(VhciError::Open(std::io::Error::last_os_error()));
        }

        // --- Step 2: Write VhciCreateReq ---

        let opcode = if dev_type == BtDevType::Amp { HCI_AMP } else { HCI_PRIMARY };

        let req = VhciCreateReq { pkt_type: HCI_VENDOR_PKT, opcode };

        // SAFETY: Writing the packed VhciCreateReq struct (2 bytes) to the
        // /dev/vhci fd. The fd is valid (checked above), the pointer and
        // length are derived from the repr(C,packed) struct, matching the
        // kernel's expected wire format exactly.
        let written = unsafe {
            libc::write(
                raw_fd,
                (&raw const req).cast::<libc::c_void>(),
                mem::size_of::<VhciCreateReq>(),
            )
        };
        if written != mem::size_of::<VhciCreateReq>() as isize {
            let err = std::io::Error::last_os_error();
            // SAFETY: Closing a valid fd on error path.
            unsafe {
                libc::close(raw_fd);
            }
            return Err(VhciError::WriteRequest(err));
        }

        // --- Step 3: Read and validate VhciCreateRsp ---

        let mut rsp = VhciCreateRsp { pkt_type: 0, opcode: 0, index: 0 };

        // SAFETY: Reading the packed VhciCreateRsp struct (4 bytes) from
        // /dev/vhci. The kernel writes exactly sizeof(VhciCreateRsp) bytes
        // as the synchronous response to the create request. The buffer is
        // properly sized and aligned (repr(C,packed)).
        let read_len = unsafe {
            libc::read(
                raw_fd,
                (&raw mut rsp).cast::<libc::c_void>(),
                mem::size_of::<VhciCreateRsp>(),
            )
        };

        // Access packed fields by value (safe in edition 2024 — compiler
        // generates unaligned reads automatically).
        let rsp_pkt_type = rsp.pkt_type;
        let rsp_opcode = rsp.opcode;
        let rsp_index = rsp.index;

        if read_len != mem::size_of::<VhciCreateRsp>() as isize
            || rsp_pkt_type != HCI_VENDOR_PKT
            || rsp_opcode != req.opcode
        {
            let err = if read_len < 0 {
                VhciError::ReadResponse(std::io::Error::last_os_error())
            } else {
                VhciError::InvalidResponse {
                    expected_opcode: req.opcode,
                    actual_pkt_type: rsp_pkt_type,
                    actual_opcode: rsp_opcode,
                }
            };
            // SAFETY: Closing a valid fd on error path.
            unsafe {
                libc::close(raw_fd);
            }
            return Err(err);
        }

        // --- Step 4: Take ownership of the fd ---

        // SAFETY: raw_fd is valid (open succeeded, handshake succeeded).
        // OwnedFd takes ownership and will close the fd on drop.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let fd = Arc::new(owned_fd);

        // --- Step 5: Create BtDev ---

        let index = rsp_index;
        let mut btdev = BtDev::new(dev_type, index)?;

        // --- Step 6: Register send handler (scatter-gather write) ---

        let write_fd = Arc::clone(&fd);
        btdev.set_send_handler(Some(Box::new(move |iov: &[IoSlice<'_>]| {
            // Write H:4 frame to /dev/vhci using scatter-gather I/O.
            // Errors are silently ignored, matching C behavior (vhci.c:56-65).
            let _ = nix::sys::uio::writev(write_fd.as_fd(), iov);
        })));

        let btdev = Arc::new(Mutex::new(btdev));

        // --- Step 7: Spawn async read task ---

        let read_task = spawn_read_task(Arc::clone(&fd), Arc::clone(&btdev))?;

        Ok(Vhci { dev_type, index, fd, btdev, read_task: Some(read_task) })
    }
}

// ---------------------------------------------------------------------------
// Public API methods
// ---------------------------------------------------------------------------

impl Vhci {
    /// Enable debug logging on the underlying `BtDev`.
    ///
    /// Replaces C `vhci_set_debug()` (lines 83–90 of vhci.c).
    pub fn set_debug(&mut self, callback: impl Fn(&str) + Send + Sync + 'static) {
        let mut dev = self.btdev.lock().unwrap_or_else(|e| e.into_inner());
        dev.set_debug(Some(Box::new(callback)));
    }

    /// Pause or resume the background read loop.
    ///
    /// When `paused` is `true`, the read task is aborted — no H:4 frames
    /// will be forwarded from the kernel to `BtDev`. When `paused` is
    /// `false`, a new read task is spawned.
    ///
    /// Returns `true` on success, `false` if the read task could not be
    /// respawned.
    ///
    /// Replaces C `vhci_pause_input()` (lines 177–184 of vhci.c).
    pub fn pause_input(&mut self, paused: bool) -> bool {
        if paused {
            if let Some(task) = self.read_task.take() {
                task.abort();
            }
            true
        } else {
            // Already running — nothing to do.
            if self.read_task.is_some() {
                return true;
            }
            match spawn_read_task(Arc::clone(&self.fd), Arc::clone(&self.btdev)) {
                Ok(task) => {
                    self.read_task = Some(task);
                    true
                }
                Err(_) => false,
            }
        }
    }

    /// Obtain a shared reference to the inner `BtDev` via a `MutexGuard`.
    ///
    /// The returned guard implements `Deref<Target = BtDev>`, providing the
    /// same ergonomics as `&BtDev`.
    ///
    /// Replaces C `vhci_get_btdev()` (lines 186–192 of vhci.c).
    pub fn get_btdev(&self) -> MutexGuard<'_, BtDev> {
        self.btdev.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Obtain a mutable reference to the inner `BtDev` via a `MutexGuard`.
    ///
    /// The returned guard implements `DerefMut`, providing the same
    /// ergonomics as `&mut BtDev`.
    pub fn get_btdev_mut(&self) -> MutexGuard<'_, BtDev> {
        self.btdev.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Return the kernel hci index assigned to this virtual controller.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Return the controller type.
    pub fn dev_type(&self) -> BtDevType {
        self.dev_type
    }
}

// ---------------------------------------------------------------------------
// Debugfs helpers
// ---------------------------------------------------------------------------

impl Vhci {
    /// Write `data` to a debugfs file under this controller's hci node.
    ///
    /// Constructs the path `{DEBUGFS_PATH}/hci{index}/{option}`, opens it
    /// with `O_RDWR`, writes `data`, and validates the write completed fully.
    ///
    /// Replaces C `vhci_debugfs_write()` (lines 194–220 of vhci.c).
    fn debugfs_write(&self, option: &str, data: &[u8]) -> Result<(), VhciError> {
        use std::io::Write;

        let path = format!("{DEBUGFS_PATH}/hci{}/{option}", self.index);

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| VhciError::Debugfs { path: path.clone(), source: e })?;

        let written =
            file.write(data).map_err(|e| VhciError::Debugfs { path: path.clone(), source: e })?;

        if written != data.len() {
            return Err(VhciError::Debugfs {
                path,
                source: std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "incomplete debugfs write",
                ),
            });
        }

        Ok(())
    }

    /// Set the `force_suspend` debugfs toggle.
    ///
    /// Replaces C `vhci_set_force_suspend()` (lines 222–229 of vhci.c).
    pub fn set_force_suspend(&self, enable: bool) -> Result<(), VhciError> {
        let val = if enable { b'Y' } else { b'N' };
        self.debugfs_write("force_suspend", &[val])
    }

    /// Set the `force_wakeup` debugfs toggle.
    ///
    /// Replaces C `vhci_set_force_wakeup()` (lines 231–238 of vhci.c).
    pub fn set_force_wakeup(&self, enable: bool) -> Result<(), VhciError> {
        let val = if enable { b'Y' } else { b'N' };
        self.debugfs_write("force_wakeup", &[val])
    }

    /// Set the MSFT vendor opcode via debugfs and on the `BtDev`.
    ///
    /// Writes the formatted opcode string to the `msft_opcode` debugfs node,
    /// then calls `BtDev::set_msft_opcode`.
    ///
    /// Replaces C `vhci_set_msft_opcode()` (lines 240–252 of vhci.c).
    pub fn set_msft_opcode(&self, opcode: u16) -> Result<(), VhciError> {
        // Match C format: snprintf(val, sizeof(val), "0x%4x", opcode)
        // which produces a 6-char string like "0xfc00" or "0x   1".
        let val = format!("0x{opcode:4x}");
        self.debugfs_write("msft_opcode", val.as_bytes())?;
        let mut dev = self.btdev.lock().unwrap_or_else(|e| e.into_inner());
        dev.set_msft_opcode(opcode);
        Ok(())
    }

    /// Set the `aosp_capable` debugfs toggle.
    ///
    /// Replaces C `vhci_set_aosp_capable()` (lines 254–261 of vhci.c).
    pub fn set_aosp_capable(&self, enable: bool) -> Result<(), VhciError> {
        let val = if enable { b'Y' } else { b'N' };
        self.debugfs_write("aosp_capable", &[val])
    }

    /// Set the emulator vendor opcode on the `BtDev` (no debugfs write).
    ///
    /// Replaces C `vhci_set_emu_opcode()` (lines 263–266 of vhci.c).
    pub fn set_emu_opcode(&self, opcode: u16) -> Result<(), VhciError> {
        let mut dev = self.btdev.lock().unwrap_or_else(|e| e.into_inner());
        dev.set_emu_opcode(opcode);
        Ok(())
    }

    /// Set the `force_static_address` debugfs toggle.
    ///
    /// Replaces C `vhci_set_force_static_address()` (lines 268–276 of vhci.c).
    pub fn set_force_static_address(&self, enable: bool) -> Result<(), VhciError> {
        let val = if enable { b'Y' } else { b'N' };
        self.debugfs_write("force_static_address", &[val])
    }

    /// Force a device coredump by writing data to the `force_devcoredump`
    /// debugfs node.
    ///
    /// Replaces C `vhci_force_devcd()` (lines 278–281 of vhci.c).
    pub fn force_devcd(&self, data: &[u8]) -> Result<(), VhciError> {
        self.debugfs_write("force_devcoredump", data)
    }

    /// Read a devcoredump from sysfs.
    ///
    /// Scans `/sys/class/devcoredump/` for an entry whose name contains
    /// `"devcd"`, reads its `data` file into `buf`, and writes `"0"` to
    /// mark it for cleanup (matching C lines 321–323 of vhci.c).
    ///
    /// Returns the number of bytes read on success.
    ///
    /// Replaces C `vhci_read_devcd()` (lines 283–333 of vhci.c).
    pub fn read_devcd(&self, buf: &mut [u8]) -> Result<usize, VhciError> {
        use std::io::{Read, Write};

        let entries = std::fs::read_dir(DEVCORE_PATH)?;

        let mut devcd_path = None;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.contains("devcd") {
                devcd_path = Some(entry.path());
                break;
            }
        }

        let entry_path =
            devcd_path.ok_or_else(|| VhciError::DevcdNotFound(DEVCORE_PATH.to_string()))?;

        let data_path = entry_path.join("data");

        let mut file =
            std::fs::OpenOptions::new().read(true).write(true).open(&data_path).map_err(|e| {
                VhciError::Debugfs { path: data_path.to_string_lossy().into_owned(), source: e }
            })?;

        let bytes_read = file.read(buf).map_err(|e| VhciError::Debugfs {
            path: data_path.to_string_lossy().into_owned(),
            source: e,
        })?;

        // Once the devcoredump is read, write anything to it to mark it for
        // cleanup (matching C behavior at lines 321–323).
        file.write_all(b"0").map_err(|e| VhciError::Debugfs {
            path: data_path.to_string_lossy().into_owned(),
            source: e,
        })?;

        Ok(bytes_read)
    }
}

// ---------------------------------------------------------------------------
// Drop — clean up read task and file descriptors
// ---------------------------------------------------------------------------

impl Drop for Vhci {
    /// Abort the background read task on drop. The `AsyncFd` inside the task
    /// is dropped (closing the dup'd fd), and the master fd in `self.fd` is
    /// closed when the last `Arc` reference is dropped.
    ///
    /// Replaces C `vhci_close()` / `vhci_destroy()` (lines 46–54, 169–175).
    fn drop(&mut self) {
        if let Some(task) = self.read_task.take() {
            task.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Background read task
// ---------------------------------------------------------------------------

/// Spawn the async read loop for the VHCI fd.
///
/// Duplicates the master fd (so that the read loop owns its own `OwnedFd`
/// wrapped in `AsyncFd`) and spawns a tokio task that continuously reads
/// H:4 frames from the kernel and forwards them to `BtDev::receive_h4`.
fn spawn_read_task(
    fd: Arc<OwnedFd>,
    btdev: Arc<Mutex<BtDev>>,
) -> Result<JoinHandle<()>, VhciError> {
    // SAFETY: dup() on a valid fd returns a new fd that references the same
    // open file description. The original fd remains valid and owned by the
    // Arc<OwnedFd> in the Vhci struct. The dup'd fd is wrapped in OwnedFd
    // for automatic cleanup on drop.
    let dup_raw = unsafe { libc::dup(fd.as_fd().as_raw_fd()) };
    if dup_raw < 0 {
        return Err(VhciError::Dup(std::io::Error::last_os_error()));
    }
    // SAFETY: dup_raw is a valid fd just returned by a successful dup().
    let dup_fd = unsafe { OwnedFd::from_raw_fd(dup_raw) };

    let async_fd = AsyncFd::new(dup_fd).map_err(VhciError::AsyncFd)?;

    Ok(spawn(vhci_read_loop(async_fd, btdev)))
}

/// Async read loop that shuttles H:4 frames from the kernel to `BtDev`.
///
/// This function runs as a spawned tokio task. It waits for the VHCI fd to
/// become readable, reads an H:4 frame, and forwards it to
/// `BtDev::receive_h4` for processing. The loop exits on read error or
/// zero-length read (fd closed / HUP).
///
/// Replaces C `vhci_read_callback()` (lines 67–81 of vhci.c).
async fn vhci_read_loop(async_fd: AsyncFd<OwnedFd>, btdev: Arc<Mutex<BtDev>>) {
    let mut buf = [0u8; READ_BUF_SIZE];

    loop {
        // Wait until the fd is readable.
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(_) => break,
        };

        // Attempt to read within the readiness guard. If the kernel returns
        // EAGAIN/EWOULDBLOCK, `try_io` returns `Err(TryIoError)` and we
        // loop back to wait for readability again.
        match guard.try_io(|inner| {
            // SAFETY: Reading H:4 frames from /dev/vhci kernel device.
            // The buffer is stack-allocated at 4096 bytes, sufficient for
            // any HCI H:4 frame. The fd is valid (owned by AsyncFd<OwnedFd>).
            let len = unsafe {
                libc::read(inner.as_raw_fd(), buf.as_mut_ptr().cast::<libc::c_void>(), buf.len())
            };
            if len < 0 { Err(std::io::Error::last_os_error()) } else { Ok(len as usize) }
        }) {
            // Zero-length read: fd closed / HUP.
            Ok(Ok(0)) => break,
            // Successful read: forward to BtDev.
            Ok(Ok(len)) => {
                let mut dev = btdev.lock().unwrap_or_else(|e| e.into_inner());
                dev.receive_h4(&buf[..len]);
            }
            // Read error: exit the loop.
            Ok(Err(_)) => break,
            // Would-block: go back to waiting for readability.
            Err(_would_block) => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify VhciCreateReq is exactly 2 bytes (matching C `struct vhci_create_req`).
    #[test]
    fn test_vhci_create_req_size() {
        assert_eq!(mem::size_of::<VhciCreateReq>(), 2, "VhciCreateReq must be 2 bytes");
    }

    /// Verify VhciCreateRsp is exactly 4 bytes (matching C `struct vhci_create_rsp`).
    #[test]
    fn test_vhci_create_rsp_size() {
        assert_eq!(mem::size_of::<VhciCreateRsp>(), 4, "VhciCreateRsp must be 4 bytes");
    }

    /// Verify VhciCreateReq has correct field offsets.
    #[test]
    fn test_vhci_create_req_layout() {
        let req = VhciCreateReq { pkt_type: HCI_VENDOR_PKT, opcode: HCI_PRIMARY };
        // SAFETY: Reading raw bytes of a packed struct to verify wire layout.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const req).cast::<u8>(),
                mem::size_of::<VhciCreateReq>(),
            )
        };
        assert_eq!(bytes[0], HCI_VENDOR_PKT, "pkt_type at offset 0");
        assert_eq!(bytes[1], HCI_PRIMARY, "opcode at offset 1");
    }

    /// Verify VhciCreateRsp has correct field offsets.
    #[test]
    fn test_vhci_create_rsp_layout() {
        let rsp = VhciCreateRsp { pkt_type: HCI_VENDOR_PKT, opcode: HCI_AMP, index: 0x1234 };
        // SAFETY: Reading raw bytes of a packed struct to verify wire layout.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const rsp).cast::<u8>(),
                mem::size_of::<VhciCreateRsp>(),
            )
        };
        assert_eq!(bytes[0], HCI_VENDOR_PKT, "pkt_type at offset 0");
        assert_eq!(bytes[1], HCI_AMP, "opcode at offset 1");
        // index is little-endian u16
        assert_eq!(bytes[2], 0x34, "index low byte at offset 2");
        assert_eq!(bytes[3], 0x12, "index high byte at offset 3");
    }

    /// Verify the debugfs path is constructed correctly.
    #[test]
    fn test_debugfs_path_format() {
        let index: u16 = 42;
        let option = "force_suspend";
        let path = format!("{DEBUGFS_PATH}/hci{index}/{option}");
        assert_eq!(path, "/sys/kernel/debug/bluetooth/hci42/force_suspend");
    }

    /// Verify constant values match the kernel definitions.
    #[test]
    fn test_constants() {
        assert_eq!(HCI_VENDOR_PKT, 0xff);
        assert_eq!(HCI_PRIMARY, 0x00);
        assert_eq!(HCI_AMP, 0x01);
    }

    /// Verify the devcoredump sysfs path.
    #[test]
    fn test_devcore_path() {
        assert_eq!(DEVCORE_PATH, "/sys/class/devcoredump");
    }

    /// Verify the opcode selection logic for BtDevType::Amp.
    #[test]
    fn test_opcode_selection() {
        let amp_opcode = if BtDevType::Amp == BtDevType::Amp { HCI_AMP } else { HCI_PRIMARY };
        assert_eq!(amp_opcode, HCI_AMP);

        let primary_opcode =
            if BtDevType::BrEdrLe == BtDevType::Amp { HCI_AMP } else { HCI_PRIMARY };
        assert_eq!(primary_opcode, HCI_PRIMARY);
    }

    /// Verify the MSFT opcode format string matches C `"0x%4x"`.
    #[test]
    fn test_msft_opcode_format() {
        // C: snprintf(val, sizeof(val), "0x%4x", 0xfc00) -> "0xfc00"
        assert_eq!(format!("0x{:4x}", 0xfc00_u16), "0xfc00");
        // C: snprintf(val, sizeof(val), "0x%4x", 0x0001) -> "0x   1"
        assert_eq!(format!("0x{:4x}", 0x0001_u16), "0x   1");
        // C: snprintf(val, sizeof(val), "0x%4x", 0x0000) -> "0x   0"
        assert_eq!(format!("0x{:4x}", 0x0000_u16), "0x   0");
    }
}
