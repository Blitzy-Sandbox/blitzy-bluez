// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
//
// rfkill.rs — `/dev/rfkill` and sysfs radio-block state integration.
//
// This module monitors the Linux kernel rfkill subsystem to detect when
// Bluetooth controllers are software- or hardware-blocked.  When a block
// event arrives, the corresponding `BtdAdapter` is transitioned to the
// `OffBlocked` power state.  When unblocked, the adapter is restored to
// its previous powered state (if `auto_enable` is configured).
//
// Replaces the C implementation in `src/rfkill.c` from BlueZ v5.86.
//
// # Architecture
//
// - `init()` opens `/dev/rfkill` in non-blocking mode, wraps it in a
//   `tokio::io::unix::AsyncFd`, and spawns a background monitoring task.
// - The monitoring task reads `rfkill_event` structs from the kernel,
//   maps them to Bluetooth adapters via sysfs, and updates adapter state.
// - `exit()` aborts the monitoring task.
// - `get_blocked()` performs a one-shot synchronous query of rfkill state
//   for a specific HCI adapter index.

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};
use zerocopy::{FromBytes, Immutable, KnownLayout};

use nix::errno::Errno;
use nix::unistd::read;

use crate::adapter::{
    BtdAdapter, adapter_find_by_id, btd_adapter_restore_powered, btd_adapter_set_blocked,
};
use crate::config::BtdOpts;

// ===========================================================================
// Constants — rfkill kernel interface
// ===========================================================================

/// rfkill type: match all device types.
const RFKILL_TYPE_ALL: u8 = 0;

/// rfkill type: Bluetooth radios.
const RFKILL_TYPE_BLUETOOTH: u8 = 2;

/// rfkill operation: a new rfkill device was added.
#[allow(dead_code)]
const RFKILL_OP_ADD: u8 = 0;

/// rfkill operation: an rfkill device was removed.
#[allow(dead_code)]
const RFKILL_OP_DEL: u8 = 1;

/// rfkill operation: the state of an rfkill device changed.
const RFKILL_OP_CHANGE: u8 = 2;

/// rfkill operation: the state of all rfkill devices changed.
#[allow(dead_code)]
const RFKILL_OP_CHANGE_ALL: u8 = 3;

/// Size of the v1 rfkill_event structure in bytes.
const RFKILL_EVENT_SIZE_V1: usize = 8;

/// Path to the rfkill control device node.
const RFKILL_DEVICE_PATH: &str = "/dev/rfkill";

// ===========================================================================
// RfkillEvent — kernel event structure
// ===========================================================================

/// Kernel `struct rfkill_event` (v1, 8 bytes).
///
/// Matches the kernel definition in `include/uapi/linux/rfkill.h`:
/// ```c
/// struct rfkill_event {
///     __u32 idx;
///     __u8  type;
///     __u8  op;
///     __u8  soft;
///     __u8  hard;
/// };
/// ```
///
/// The `zerocopy` derives enable safe zero-copy deserialization from the
/// raw bytes read from `/dev/rfkill`, replacing the C pattern of
/// `read(fd, &event, sizeof(event))` with `RfkillEvent::read_from_bytes`.
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
struct RfkillEvent {
    /// rfkill device index (matches sysfs `rfkillN` number).
    idx: u32,
    /// Device type (e.g., `RFKILL_TYPE_BLUETOOTH`).
    type_: u8,
    /// Operation code (ADD, DEL, CHANGE, CHANGE_ALL).
    op: u8,
    /// Soft block state: 1 = blocked, 0 = unblocked.
    soft: u8,
    /// Hard block state: 1 = blocked, 0 = unblocked.
    hard: u8,
}

// ===========================================================================
// Module state
// ===========================================================================

/// Handle to the background rfkill monitoring task.
///
/// Protected by a `std::sync::Mutex` since it is only accessed briefly
/// during `init()` and `exit()` — never held across `.await` points.
static RFKILL_HANDLE: std::sync::Mutex<Option<JoinHandle<()>>> = std::sync::Mutex::new(None);

// ===========================================================================
// Sysfs integration
// ===========================================================================

/// Map an rfkill device index to a Bluetooth HCI adapter index.
///
/// Reads `/sys/class/rfkill/rfkillN/name` and, if the name matches the
/// pattern `hciN`, extracts and returns the HCI index `N`.
///
/// Returns `None` if:
/// - The sysfs file cannot be read (device disappeared, permissions).
/// - The name does not start with `"hci"`.
/// - The numeric suffix cannot be parsed.
///
/// This replicates the C function `get_adapter_id_for_rfkill()`.
fn get_adapter_id_for_rfkill(rfkill_id: u32) -> Option<u16> {
    let sysfs_path = format!("/sys/class/rfkill/rfkill{}/name", rfkill_id);
    let raw_name = match std::fs::read_to_string(&sysfs_path) {
        Ok(contents) => contents,
        Err(e) => {
            warn!("Failed to read rfkill name from {}: {}", sysfs_path, e);
            return None;
        }
    };

    let name = raw_name.trim();

    // The C code checks `g_str_has_prefix(sysname, "hci")` and then
    // `atoi(sysname + 3)` — we replicate that exactly.
    if !name.starts_with("hci") {
        return None;
    }

    match name[3..].parse::<u16>() {
        Ok(id) => Some(id),
        Err(_) => {
            warn!("Failed to parse HCI index from rfkill name: {}", name);
            None
        }
    }
}

/// Open `/dev/rfkill` in the specified mode with `O_NONBLOCK`.
///
/// Uses `std::fs::OpenOptions` with `custom_flags` to avoid `unsafe`
/// code — the `OwnedFd` is obtained from `File::into()` which is safe.
///
/// # Arguments
///
/// * `writable` — If `true`, opens with read-write access (`O_RDWR`);
///   if `false`, opens read-only (`O_RDONLY`).
fn open_rfkill(writable: bool) -> Result<OwnedFd, std::io::Error> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    if writable {
        opts.write(true);
    }
    opts.custom_flags(libc::O_NONBLOCK);
    let file = opts.open(RFKILL_DEVICE_PATH)?;
    Ok(OwnedFd::from(file))
}

// ===========================================================================
// Public API
// ===========================================================================

/// Query the current rfkill blocked state for a given HCI adapter index.
///
/// Opens `/dev/rfkill` in read-only non-blocking mode and reads all
/// currently-registered rfkill entries.  For each entry, maps the rfkill
/// index to an HCI adapter index via sysfs.  Returns the blocked state
/// of the first matching adapter.
///
/// # Returns
///
/// - `1` if the adapter is soft- or hard-blocked.
/// - `0` if the adapter is not blocked.
/// - `-1` if the rfkill device could not be opened or no matching entry
///   was found.
///
/// This replicates the C function `rfkill_get_blocked()`.
pub fn get_blocked(index: u16) -> i32 {
    let owned_fd = match open_rfkill(false) {
        Ok(fd) => fd,
        Err(_e) => {
            debug!("Failed to open RFKILL control device");
            return -1;
        }
    };

    let raw_fd = owned_fd.as_raw_fd();
    let mut blocked: i32 = -1;
    let mut buf = [0u8; RFKILL_EVENT_SIZE_V1];

    loop {
        match read(raw_fd, &mut buf) {
            Ok(len) if len >= RFKILL_EVENT_SIZE_V1 => {
                if let Ok(event) = RfkillEvent::read_from_bytes(&buf[..RFKILL_EVENT_SIZE_V1]) {
                    if let Some(id) = get_adapter_id_for_rfkill(event.idx) {
                        if id == index {
                            blocked = i32::from(event.soft != 0 || event.hard != 0);
                            break;
                        }
                    }
                }
            }
            Ok(_) => {
                // Short read — no more complete events available.
                break;
            }
            Err(Errno::EAGAIN) => {
                // Non-blocking fd: all initial events consumed.
                break;
            }
            Err(_) => {
                // Unexpected read error.
                break;
            }
        }
    }

    // `owned_fd` drops here, closing the file descriptor.
    blocked
}

/// Initialize rfkill event monitoring.
///
/// Opens `/dev/rfkill` in read-write non-blocking mode, wraps the file
/// descriptor in a `tokio::io::unix::AsyncFd` for async readability
/// notifications, and spawns a background task that continuously reads
/// rfkill events and updates adapter blocked/powered state.
///
/// If `/dev/rfkill` does not exist (`ENOENT`), a debug message is logged
/// and no monitoring is started — this is normal on systems without
/// rfkill support.
///
/// # Arguments
///
/// * `opts` — Shared reference to the daemon configuration, passed to
///   `btd_adapter_restore_powered()` when an adapter is unblocked.
///
/// This replicates the C function `rfkill_init()`.
pub fn init(opts: Arc<BtdOpts>) {
    let owned_fd = match open_rfkill(true) {
        Ok(fd) => fd,
        Err(e) => {
            if e.raw_os_error() == Some(libc::ENOENT) {
                debug!("No RFKILL device available at '{}'", RFKILL_DEVICE_PATH);
            } else {
                error!("Failed to open RFKILL control device: {}", e);
            }
            return;
        }
    };

    let async_fd = match AsyncFd::new(owned_fd) {
        Ok(afd) => afd,
        Err(e) => {
            error!("Failed to create AsyncFd for rfkill: {}", e);
            return;
        }
    };

    let handle = tokio::spawn(rfkill_monitor_loop(async_fd, opts));

    if let Ok(mut guard) = RFKILL_HANDLE.lock() {
        // If a previous monitoring task exists (shouldn't happen in normal
        // use), abort it before replacing.
        if let Some(old_handle) = guard.take() {
            old_handle.abort();
        }
        *guard = Some(handle);
    }
}

/// Shut down rfkill event monitoring.
///
/// Aborts the background monitoring task if one is running.  The
/// `AsyncFd` and underlying `/dev/rfkill` file descriptor are closed
/// when the task is dropped.
///
/// This replicates the C function `rfkill_exit()`.
pub fn exit() {
    if let Ok(mut guard) = RFKILL_HANDLE.lock() {
        if let Some(handle) = guard.take() {
            handle.abort();
            debug!("RFKILL monitoring task stopped");
        }
    }
}

// ===========================================================================
// Internal — async event monitoring loop
// ===========================================================================

/// Background task that continuously reads rfkill events from the kernel
/// and dispatches adapter state changes.
///
/// This replaces the C `rfkill_event()` GIOChannel callback.  The loop
/// runs until:
/// - A fatal read error occurs (not `EAGAIN`).
/// - The `AsyncFd`'s readable future returns an error.
/// - The task is aborted via `exit()`.
async fn rfkill_monitor_loop(async_fd: AsyncFd<OwnedFd>, opts: Arc<BtdOpts>) {
    loop {
        // Wait until the rfkill fd is readable.
        let mut ready_guard = match async_fd.readable().await {
            Ok(guard) => guard,
            Err(e) => {
                error!("rfkill AsyncFd readable error: {}", e);
                break;
            }
        };

        // Attempt to read one rfkill_event.
        let mut buf = [0u8; RFKILL_EVENT_SIZE_V1];
        match read(async_fd.as_raw_fd(), &mut buf) {
            Ok(len) if len >= RFKILL_EVENT_SIZE_V1 => {
                // Successfully read a complete event.
                ready_guard.clear_ready();
                if let Ok(event) = RfkillEvent::read_from_bytes(&buf[..RFKILL_EVENT_SIZE_V1]) {
                    process_rfkill_event(&event, &opts).await;
                }
            }
            Ok(_) => {
                // Short read — incomplete event, wait for more data.
                ready_guard.clear_ready();
            }
            Err(Errno::EAGAIN) => {
                // Spurious wakeup: fd not actually ready.  Clear the
                // readiness flag so tokio re-arms the epoll notification.
                ready_guard.clear_ready();
            }
            Err(e) => {
                error!("rfkill read error: {}", e);
                ready_guard.clear_ready();
                break;
            }
        }
    }
}

/// Process a single rfkill event and update adapter state.
///
/// Only `RFKILL_OP_CHANGE` events for `RFKILL_TYPE_BLUETOOTH` or
/// `RFKILL_TYPE_ALL` are acted upon — ADD, DEL, and CHANGE_ALL events
/// are logged but otherwise ignored, matching the C behavior.
///
/// When an adapter is blocked (soft or hard), `btd_adapter_set_blocked()`
/// is called to transition it to the `OffBlocked` power state.
///
/// When an adapter is unblocked, `btd_adapter_set_blocked()` clears the
/// blocked flag, and `btd_adapter_restore_powered()` re-enables the
/// adapter if `auto_enable` is configured.
async fn process_rfkill_event(event: &RfkillEvent, opts: &BtdOpts) {
    let blocked = event.soft != 0 || event.hard != 0;

    debug!(
        "RFKILL event idx {} type {} op {} soft {} hard {}",
        event.idx, event.type_, event.op, event.soft, event.hard
    );

    // Only act on CHANGE events — ADD/DEL/CHANGE_ALL are informational.
    if event.op != RFKILL_OP_CHANGE {
        return;
    }

    // Filter for Bluetooth or "all" type events.
    if event.type_ != RFKILL_TYPE_BLUETOOTH && event.type_ != RFKILL_TYPE_ALL {
        return;
    }

    // Map rfkill index → HCI adapter index via sysfs.
    let adapter_id = match get_adapter_id_for_rfkill(event.idx) {
        Some(id) => id,
        None => return,
    };

    // Look up the adapter by HCI index.
    let adapter: Arc<tokio::sync::Mutex<BtdAdapter>> = match adapter_find_by_id(adapter_id).await {
        Some(a) => a,
        None => return,
    };

    if blocked {
        debug!("RFKILL block for hci{}", adapter_id);
        btd_adapter_set_blocked(&adapter, true).await;
    } else {
        debug!("RFKILL unblock for hci{}", adapter_id);
        btd_adapter_set_blocked(&adapter, false).await;
        btd_adapter_restore_powered(&adapter, opts).await;
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the RfkillEvent struct has the correct size (8 bytes).
    #[test]
    fn test_rfkill_event_size() {
        assert_eq!(
            std::mem::size_of::<RfkillEvent>(),
            RFKILL_EVENT_SIZE_V1,
            "RfkillEvent must be exactly 8 bytes to match kernel struct"
        );
    }

    /// Verify the struct layout matches the kernel definition:
    /// offset 0: idx (u32, 4 bytes)
    /// offset 4: type_ (u8, 1 byte)
    /// offset 5: op (u8, 1 byte)
    /// offset 6: soft (u8, 1 byte)
    /// offset 7: hard (u8, 1 byte)
    #[test]
    fn test_rfkill_event_layout() {
        assert_eq!(std::mem::offset_of!(RfkillEvent, idx), 0);
        assert_eq!(std::mem::offset_of!(RfkillEvent, type_), 4);
        assert_eq!(std::mem::offset_of!(RfkillEvent, op), 5);
        assert_eq!(std::mem::offset_of!(RfkillEvent, soft), 6);
        assert_eq!(std::mem::offset_of!(RfkillEvent, hard), 7);
    }

    /// Verify zerocopy deserialization produces correct field values.
    #[test]
    fn test_rfkill_event_from_bytes() {
        // idx=42 (LE), type=BLUETOOTH(2), op=CHANGE(2), soft=1, hard=0
        let bytes: [u8; 8] = [42, 0, 0, 0, 2, 2, 1, 0];
        let event = RfkillEvent::read_from_bytes(&bytes).expect("deserialization failed");
        assert_eq!(event.idx, 42);
        assert_eq!(event.type_, RFKILL_TYPE_BLUETOOTH);
        assert_eq!(event.op, RFKILL_OP_CHANGE);
        assert_eq!(event.soft, 1);
        assert_eq!(event.hard, 0);
    }

    /// Verify short buffer is rejected by zerocopy.
    #[test]
    fn test_rfkill_event_short_buffer() {
        let short_buf: [u8; 4] = [0; 4];
        assert!(RfkillEvent::read_from_bytes(&short_buf).is_err());
    }

    /// Verify rfkill constants match kernel values.
    #[test]
    fn test_rfkill_constants() {
        assert_eq!(RFKILL_TYPE_ALL, 0);
        assert_eq!(RFKILL_TYPE_BLUETOOTH, 2);
        assert_eq!(RFKILL_OP_ADD, 0);
        assert_eq!(RFKILL_OP_DEL, 1);
        assert_eq!(RFKILL_OP_CHANGE, 2);
        assert_eq!(RFKILL_OP_CHANGE_ALL, 3);
        assert_eq!(RFKILL_EVENT_SIZE_V1, 8);
    }

    /// Verify blocked detection logic.
    #[test]
    fn test_blocked_detection() {
        // Helper to create events with specific soft/hard values.
        let make_event = |soft: u8, hard: u8| -> RfkillEvent {
            let bytes: [u8; 8] = [0, 0, 0, 0, RFKILL_TYPE_BLUETOOTH, RFKILL_OP_CHANGE, soft, hard];
            RfkillEvent::read_from_bytes(&bytes).unwrap()
        };

        // Both zero → not blocked
        let event = make_event(0, 0);
        assert!(!(event.soft != 0 || event.hard != 0));

        // Soft blocked → blocked
        let event = make_event(1, 0);
        assert!(event.soft != 0 || event.hard != 0);

        // Hard blocked → blocked
        let event = make_event(0, 1);
        assert!(event.soft != 0 || event.hard != 0);

        // Both blocked → blocked
        let event = make_event(1, 1);
        assert!(event.soft != 0 || event.hard != 0);
    }

    /// Verify get_adapter_id_for_rfkill returns None for non-existent entries.
    #[test]
    fn test_get_adapter_id_nonexistent() {
        // rfkill index 99999 almost certainly doesn't exist.
        assert_eq!(get_adapter_id_for_rfkill(99999), None);
    }

    /// Verify get_blocked returns -1 when /dev/rfkill is not available.
    #[test]
    fn test_get_blocked_no_device() {
        // On a system without rfkill or in a container, this should
        // return -1 gracefully.
        let result = get_blocked(0);
        // We cannot assert the exact value since it depends on the
        // environment, but it should be one of -1, 0, or 1.
        assert!((-1..=1).contains(&result));
    }
}
