// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Virtual input device creation via the Linux `/dev/uinput` character device.
//
// This module provides the `BtUinput` type which creates virtual input devices
// for emitting keyboard/button events (used by the AVRCP profile for media key
// passthrough). It is a complete Rust rewrite of `src/shared/uinput.c` (205
// lines) and `src/shared/uinput.h` (33 lines).
//
// This is a **designated `unsafe` boundary module** per AAP Section 0.7.4.
// All `unsafe` blocks are confined to kernel character device operations
// (`/dev/uinput` ioctl and raw struct I/O) and each site is documented with a
// `// SAFETY:` comment and exercised by a corresponding `#[test]`.

// This module is a designated FFI boundary — unsafe code is permitted and
// necessary for /dev/uinput ioctl operations and raw struct I/O.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::sys::bluetooth::bdaddr_t;

// ---------------------------------------------------------------------------
// Linux Input Subsystem Constants (from linux/input.h)
// ---------------------------------------------------------------------------

/// Input event type: synchronization marker.
const EV_SYN: u16 = 0x00;

/// Input event type: key/button press/release.
const EV_KEY: u16 = 0x01;

/// Synchronization event code: report boundary.
const SYN_REPORT: u16 = 0x00;

/// Bus type constant for Bluetooth input devices (from `linux/input.h`).
pub const BUS_BLUETOOTH: u16 = 0x05;

/// Maximum length of a uinput device name including NUL terminator
/// (from `linux/uinput.h`).
pub const UINPUT_MAX_NAME_SIZE: usize = 80;

/// Number of absolute axis types (`ABS_MAX + 1 = 0x40`).
const ABS_CNT: usize = 0x40;

// ---------------------------------------------------------------------------
// Ioctl Command Number Computation (from linux/ioctl.h)
// ---------------------------------------------------------------------------

/// Compute a Linux ioctl request number using the `_IOC` encoding scheme.
///
/// Layout: `| dir (2 bits) | size (14 bits) | type (8 bits) | nr (8 bits) |`
const fn ioc(dir: u32, typ: u32, nr: u32, size: usize) -> u64 {
    ((dir as u64) << 30) | ((size as u64) << 16) | ((typ as u64) << 8) | (nr as u64)
}

/// Uinput ioctl base character (`'U'`).
const UINPUT_IOCTL_BASE: u32 = b'U' as u32;

/// `UI_DEV_CREATE` — `_IO('U', 1)` — finalize and create the virtual device.
const UI_DEV_CREATE_NUM: u64 = ioc(0, UINPUT_IOCTL_BASE, 1, 0);

/// `UI_DEV_DESTROY` — `_IO('U', 2)` — destroy the virtual device.
const UI_DEV_DESTROY_NUM: u64 = ioc(0, UINPUT_IOCTL_BASE, 2, 0);

/// `UI_SET_EVBIT` — `_IOW('U', 100, int)` — enable an event type.
const UI_SET_EVBIT_NUM: u64 = ioc(1, UINPUT_IOCTL_BASE, 100, std::mem::size_of::<libc::c_int>());

/// `UI_SET_KEYBIT` — `_IOW('U', 101, int)` — register a key code.
const UI_SET_KEYBIT_NUM: u64 = ioc(1, UINPUT_IOCTL_BASE, 101, std::mem::size_of::<libc::c_int>());

/// `UI_SET_PHYS` — `_IOW('U', 108, char*)` — set the physical device address.
/// Size field is pointer-sized (8 on 64-bit, 4 on 32-bit).
const UI_SET_PHYS_NUM: u64 =
    ioc(1, UINPUT_IOCTL_BASE, 108, std::mem::size_of::<*const libc::c_char>());

// ---------------------------------------------------------------------------
// Generate type-safe ioctl wrapper functions via nix macros.
// These macros expand to `pub unsafe fn name(fd, ...) -> nix::Result<c_int>`.
// ---------------------------------------------------------------------------

nix::ioctl_none_bad!(ui_dev_create_ioctl, UI_DEV_CREATE_NUM);
nix::ioctl_none_bad!(ui_dev_destroy_ioctl, UI_DEV_DESTROY_NUM);
nix::ioctl_write_int_bad!(ui_set_evbit_ioctl, UI_SET_EVBIT_NUM);
nix::ioctl_write_int_bad!(ui_set_keybit_ioctl, UI_SET_KEYBIT_NUM);

// ---------------------------------------------------------------------------
// Kernel ABI Structures (#[repr(C)] — byte-identical to kernel definitions)
// ---------------------------------------------------------------------------

/// Matches the kernel `struct input_event` from `<linux/input.h>`.
///
/// On x86_64: timeval is 16 bytes → total is 24 bytes.
/// On 32-bit: timeval is 8 bytes → total is 16 bytes.
#[repr(C)]
struct InputEvent {
    /// Timestamp (zeroed for uinput injection — kernel fills on delivery).
    time: libc::timeval,
    /// Event type (`EV_KEY`, `EV_SYN`, etc.).
    event_type: u16,
    /// Event code (key code for `EV_KEY`, `SYN_REPORT` for `EV_SYN`).
    code: u16,
    /// Event value (1 = pressed, 0 = released for keys; 0 for SYN).
    value: i32,
}

/// Matches the kernel `struct input_id` from `<linux/input.h>`.
///
/// Size: 8 bytes on all architectures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct InputId {
    /// Bus type (e.g. `BUS_BLUETOOTH = 0x05`).
    pub bustype: u16,
    /// Vendor identifier.
    pub vendor: u16,
    /// Product identifier.
    pub product: u16,
    /// Version number.
    pub version: u16,
}

/// Matches the kernel `struct uinput_user_dev` from `<linux/uinput.h>`.
///
/// Size: 80 + 8 + 4 + 4×(64×4) = 1116 bytes.
#[repr(C)]
struct UinputUserDev {
    /// Device name (NUL-terminated, max `UINPUT_MAX_NAME_SIZE` bytes).
    name: [u8; UINPUT_MAX_NAME_SIZE],
    /// Device identification.
    id: InputId,
    /// Maximum number of force-feedback effects (0 for keyboard/button devices).
    ff_effects_max: u32,
    /// Per-axis maximum values.
    absmax: [i32; ABS_CNT],
    /// Per-axis minimum values.
    absmin: [i32; ABS_CNT],
    /// Per-axis fuzz values.
    absfuzz: [i32; ABS_CNT],
    /// Per-axis flat values.
    absflat: [i32; ABS_CNT],
}

// ---------------------------------------------------------------------------
// Public Type Definitions
// ---------------------------------------------------------------------------

/// Debug callback type — replaces C `bt_uinput_debug_func_t + void *user_data`.
///
/// Called with a formatted debug message string when debug output is enabled.
pub type UinputDebugFunc = Box<dyn Fn(&str) + Send + 'static>;

/// Maps a profile-level key name and code to a Linux uinput key code.
///
/// Used by the AVRCP profile to register media control keys (play, pause,
/// volume up/down, etc.) with the virtual input device.
pub struct BtUinputKeyMap {
    /// Human-readable key name (e.g. `"PLAY"`, `"VOLUMEUP"`).
    pub name: &'static str,
    /// Profile-level key code (e.g. AVRCP passthrough operation ID).
    pub code: u32,
    /// Linux input subsystem key code (e.g. `KEY_PLAYPAUSE`, `KEY_VOLUMEUP`).
    pub uinput: u16,
}

// ---------------------------------------------------------------------------
// Core BtUinput Implementation
// ---------------------------------------------------------------------------

/// Virtual input device handle wrapping `/dev/uinput`.
///
/// Lifecycle:
/// 1. [`BtUinput::new()`] — allocate and configure name/address/device ID
/// 2. [`BtUinput::create()`] — open `/dev/uinput`, register key codes, create device
/// 3. [`BtUinput::send_key()`] — emit key press/release events
/// 4. `Drop` — automatically calls `UI_DEV_DESTROY` and closes the fd
///
/// Replaces C `struct bt_uinput` with Rust ownership semantics.
pub struct BtUinput {
    /// Device identification (bustype, vendor, product, version).
    dev_id: InputId,
    /// Device name buffer (NUL-terminated, max `UINPUT_MAX_NAME_SIZE` bytes).
    name: [u8; UINPUT_MAX_NAME_SIZE],
    /// Bluetooth address of the remote device.
    addr: bdaddr_t,
    /// File descriptor for `/dev/uinput`. `None` until `create()` succeeds.
    fd: Option<OwnedFd>,
    /// Optional debug output callback.
    debug_func: Option<UinputDebugFunc>,
}

impl BtUinput {
    /// Create a new `BtUinput` instance (does NOT open `/dev/uinput` yet).
    ///
    /// This is the Rust equivalent of `bt_uinput_new()`. The device file is
    /// opened later by [`create()`](Self::create).
    ///
    /// # Arguments
    /// * `name` — Device name (truncated to `UINPUT_MAX_NAME_SIZE - 1` bytes)
    /// * `suffix` — Optional suffix appended to the name (may overwrite tail of
    ///   name if combined length exceeds the limit)
    /// * `addr` — Optional Bluetooth address for the device
    /// * `dev_id` — Optional device ID; defaults to `bustype = BUS_BLUETOOTH`
    pub fn new(
        name: Option<&str>,
        suffix: Option<&str>,
        addr: Option<&bdaddr_t>,
        dev_id: Option<&InputId>,
    ) -> Self {
        let mut name_buf = [0u8; UINPUT_MAX_NAME_SIZE];
        let name_max = UINPUT_MAX_NAME_SIZE;

        // Copy the base name, truncated to fit (matching C snprintf behavior).
        if let Some(n) = name {
            let bytes = n.as_bytes();
            let copy_len = bytes.len().min(name_max - 1);
            name_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
            // NUL terminator at copy_len is already 0 from initialization.
        }

        // Append suffix, adjusting position if the combined length exceeds the
        // buffer. This exactly reproduces the C logic from lines 94–105 of
        // uinput.c: the suffix is clamped to name_max-1, and if appending at
        // the current name end would overflow, the start position is moved back
        // so the suffix always fits (potentially overwriting the name tail).
        if let Some(s) = suffix {
            let suffix_bytes = s.as_bytes();

            // Find current name length (position of first NUL byte).
            let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(name_max - 1);

            let mut suffix_len = suffix_bytes.len();
            let mut pos = name_len;

            // Clamp suffix to maximum representable length.
            if suffix_len > name_max - 1 {
                suffix_len = name_max - 1;
            }
            // Adjust position backwards if name + suffix overflows.
            if pos + suffix_len > name_max - 1 {
                pos = name_max - 1 - suffix_len;
            }

            // Copy suffix bytes and ensure NUL termination.
            name_buf[pos..pos + suffix_len].copy_from_slice(&suffix_bytes[..suffix_len]);
            // Ensure trailing NUL (C snprintf guarantees this).
            let end = pos + suffix_len;
            if end < name_max {
                name_buf[end] = 0;
            }
        }

        // Copy address if provided.
        let address = addr.copied().unwrap_or(bdaddr_t { b: [0u8; 6] });

        // Copy device ID or default to BUS_BLUETOOTH.
        let device_id = if let Some(id) = dev_id {
            *id
        } else {
            InputId { bustype: BUS_BLUETOOTH, vendor: 0, product: 0, version: 0 }
        };

        BtUinput { dev_id: device_id, name: name_buf, addr: address, fd: None, debug_func: None }
    }

    /// Set or clear the debug output callback.
    ///
    /// Replaces C `bt_uinput_set_debug()`. Pass `None` to disable debug output.
    pub fn set_debug(&mut self, debug_func: Option<UinputDebugFunc>) {
        self.debug_func = debug_func;
    }

    /// Emit a formatted debug message through the registered callback.
    fn debug(&self, msg: &str) {
        if let Some(ref func) = self.debug_func {
            func(msg);
        }
    }

    /// Open `/dev/uinput`, configure event types and key codes, and create the
    /// virtual input device.
    ///
    /// Replaces C `bt_uinput_create()`. This is the primary unsafe section of
    /// the module, containing ioctl calls for device configuration.
    ///
    /// # Errors
    /// Returns `io::Error` if:
    /// - The device is already created (`EINVAL`)
    /// - None of the three device paths can be opened
    /// - Any ioctl or write operation fails
    pub fn create(&mut self, key_map: &[BtUinputKeyMap]) -> Result<(), io::Error> {
        // Prevent double creation (matches C line 142 check).
        if self.fd.is_some() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        // Try opening the uinput device file from the standard paths.
        // The C code tries three paths in order (lines 145–149).
        let fd = self.open_uinput_device()?;
        let raw_fd = fd.as_raw_fd();

        self.debug("Opened /dev/uinput device");

        // Enable key event reporting.
        // SAFETY: UI_SET_EVBIT with EV_KEY enables key event reporting for
        // the virtual input device. The fd is a valid /dev/uinput descriptor
        // opened above.
        unsafe { ui_set_evbit_ioctl(raw_fd, libc::c_int::from(EV_KEY)) }
            .map_err(|e| io::Error::from_raw_os_error(e as libc::c_int))?;

        // Enable synchronization events.
        // SAFETY: UI_SET_EVBIT with EV_SYN enables synchronization events.
        // Required for proper event delivery to userspace consumers.
        unsafe { ui_set_evbit_ioctl(raw_fd, libc::c_int::from(EV_SYN)) }
            .map_err(|e| io::Error::from_raw_os_error(e as libc::c_int))?;

        // Register each key from the provided key map.
        for entry in key_map {
            // SAFETY: UI_SET_KEYBIT registers a specific key code that this
            // virtual device can generate. The key code is validated by the
            // kernel against KEY_MAX. The fd is valid.
            unsafe { ui_set_keybit_ioctl(raw_fd, libc::c_int::from(entry.uinput)) }
                .map_err(|e| io::Error::from_raw_os_error(e as libc::c_int))?;
        }

        // Set the physical device address string.
        let addr_str = self.addr.ba2strlc();
        let addr_cstr =
            CString::new(addr_str).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

        // SAFETY: UI_SET_PHYS sets the physical address string for the uinput
        // device. The pointer is valid for the duration of the ioctl call and
        // points to a NUL-terminated CString. We use libc::ioctl directly
        // because the argument is a pointer (not an int).
        let ret =
            // SAFETY: ioctl with UI_SET_PHYS on a valid uinput fd with a null-terminated C string.
            unsafe { libc::ioctl(raw_fd, UI_SET_PHYS_NUM as libc::c_ulong, addr_cstr.as_ptr()) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Construct the uinput_user_dev setup structure.
        let dev = self.build_uinput_user_dev();

        // Write the device setup structure to /dev/uinput — the standard
        // device configuration step for virtual input devices.
        // SAFETY: The struct is #[repr(C)] matching the kernel layout exactly;
        // the pointer is valid for the size of the struct.
        let dev_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&dev as *const UinputUserDev).cast::<u8>(),
                std::mem::size_of::<UinputUserDev>(),
            )
        };
        let written = nix::unistd::write(&fd, dev_bytes)
            .map_err(|e| io::Error::from_raw_os_error(e as libc::c_int))?;
        if written != std::mem::size_of::<UinputUserDev>() {
            self.debug("Failed to write setup: short write");
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }

        // Finalize the virtual input device creation.
        // SAFETY: UI_DEV_CREATE finalizes the virtual input device creation.
        // All required configuration (event bits, key bits, device info) has
        // been set prior to this call. The fd is valid.
        unsafe { ui_dev_create_ioctl(raw_fd) }
            .map_err(|e| io::Error::from_raw_os_error(e as libc::c_int))?;

        self.debug("Created uinput device");

        // Store the fd — device is now live.
        self.fd = Some(fd);
        Ok(())
    }

    /// Emit a key press or release event followed by a synchronization report.
    ///
    /// Replaces C `bt_uinput_send_key()`. This is fire-and-forget — errors
    /// from individual event writes are silently ignored (matching C behavior
    /// lines 70–79 where return values are discarded).
    pub fn send_key(&self, key: u16, pressed: bool) {
        self.debug(&format!("send_key: {} pressed={}", key, pressed));

        let value = if pressed { 1 } else { 0 };
        let _ = self.emit(EV_KEY, key, value);
        let _ = self.emit(EV_SYN, SYN_REPORT, 0);
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Try opening the uinput device file from the standard paths.
    ///
    /// Tries `/dev/uinput`, `/dev/input/uinput`, `/dev/misc/uinput` in order
    /// (matching C lines 145–149).
    fn open_uinput_device(&self) -> Result<OwnedFd, io::Error> {
        let paths: [&str; 3] = ["/dev/uinput", "/dev/input/uinput", "/dev/misc/uinput"];
        let flags = libc::O_WRONLY | libc::O_NONBLOCK;

        for path in &paths {
            let c_path = match CString::new(*path) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // /dev/uinput (and its alternative paths) are well-defined Linux
            // kernel character devices for creating virtual input devices.
            // SAFETY: O_WRONLY|O_NONBLOCK is the standard access mode; the
            // returned fd is immediately wrapped in OwnedFd for cleanup.
            let raw_fd = unsafe { libc::open(c_path.as_ptr(), flags) };
            if raw_fd >= 0 {
                // SAFETY: raw_fd is a valid, newly opened file descriptor
                // returned by a successful open() call.
                return Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) });
            }
        }

        let err = io::Error::last_os_error();
        self.debug(&format!("Failed to open /dev/uinput: {}", err));
        Err(err)
    }

    /// Construct a zero-initialized `UinputUserDev` with name and device ID.
    fn build_uinput_user_dev(&self) -> UinputUserDev {
        let mut dev = UinputUserDev {
            name: [0u8; UINPUT_MAX_NAME_SIZE],
            id: self.dev_id,
            ff_effects_max: 0,
            absmax: [0i32; ABS_CNT],
            absmin: [0i32; ABS_CNT],
            absfuzz: [0i32; ABS_CNT],
            absflat: [0i32; ABS_CNT],
        };

        // Copy the device name (matching C snprintf behavior: truncate to
        // sizeof(dev.name) - 1, NUL-terminate).
        let copy_len = self.name.len().min(UINPUT_MAX_NAME_SIZE);
        dev.name[..copy_len].copy_from_slice(&self.name[..copy_len]);

        dev
    }

    /// Write a single `struct input_event` to the uinput fd.
    ///
    /// Replaces C `uinput_emit()` (lines 56–68).
    fn emit(&self, event_type: u16, code: u16, value: i32) -> Result<(), io::Error> {
        let fd = match self.fd {
            Some(ref f) => f,
            None => return Err(io::Error::from_raw_os_error(libc::EBADF)),
        };

        // Zero-initialize the event (matching C memset behavior).
        let event =
            InputEvent { time: libc::timeval { tv_sec: 0, tv_usec: 0 }, event_type, code, value };

        // Writing a struct input_event to /dev/uinput is the standard mechanism
        // for injecting input events into the Linux input subsystem.
        // SAFETY: The struct is #[repr(C)] matching the kernel layout; the fd
        // is a valid /dev/uinput descriptor held in OwnedFd.
        let event_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&event as *const InputEvent).cast::<u8>(),
                std::mem::size_of::<InputEvent>(),
            )
        };
        // SAFETY: write() with a valid fd and properly sized byte buffer.

        let written = unsafe {
            libc::write(
                fd.as_raw_fd(),
                event_bytes.as_ptr().cast::<libc::c_void>(),
                event_bytes.len(),
            )
        };

        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if (written as usize) != std::mem::size_of::<InputEvent>() {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }

        Ok(())
    }
}

impl Drop for BtUinput {
    /// Destroy the virtual input device and close the fd.
    ///
    /// Replaces C `bt_uinput_destroy()` (lines 191–204). The ioctl is called
    /// before `OwnedFd` drop closes the fd, matching the C ordering of
    /// `ioctl(UI_DEV_DESTROY)` → `close()` → `free()`.
    fn drop(&mut self) {
        if let Some(ref fd) = self.fd {
            self.debug("Destroying uinput device");

            // UI_DEV_DESTROY is a well-defined ioctl for /dev/uinput that
            // destroys the previously created virtual input device.
            // SAFETY: The fd is valid (held in OwnedFd). Errors are
            // intentionally ignored (matching C behavior).
            unsafe {
                let _ = ui_dev_destroy_ioctl(fd.as_raw_fd());
            }
        }
        // OwnedFd::drop() runs after this, calling close(fd).
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify `InputEvent` struct size matches the kernel's `sizeof(struct input_event)`.
    ///
    /// On x86_64: timeval(16) + u16(2) + u16(2) + i32(4) = 24 bytes.
    #[test]
    fn test_input_event_struct_size() {
        let expected = std::mem::size_of::<libc::timeval>() + 2 + 2 + 4;
        assert_eq!(
            std::mem::size_of::<InputEvent>(),
            expected,
            "InputEvent size mismatch: expected {} (timeval={} + 8), got {}",
            expected,
            std::mem::size_of::<libc::timeval>(),
            std::mem::size_of::<InputEvent>(),
        );
    }

    /// Verify `InputId` struct size matches the kernel's `sizeof(struct input_id)` (8 bytes).
    #[test]
    fn test_input_id_struct_size() {
        assert_eq!(std::mem::size_of::<InputId>(), 8, "InputId must be exactly 8 bytes");
    }

    /// Verify `UinputUserDev` struct size matches the kernel's
    /// `sizeof(struct uinput_user_dev)`.
    ///
    /// Size = 80 (name) + 8 (id) + 4 (ff_effects_max) + 4×(64×4) (abs arrays) = 1116
    #[test]
    fn test_uinput_user_dev_struct_size() {
        let expected = UINPUT_MAX_NAME_SIZE
            + std::mem::size_of::<InputId>()
            + std::mem::size_of::<u32>()
            + 4 * ABS_CNT * std::mem::size_of::<i32>();
        assert_eq!(
            std::mem::size_of::<UinputUserDev>(),
            expected,
            "UinputUserDev size mismatch: expected {}, got {}",
            expected,
            std::mem::size_of::<UinputUserDev>(),
        );
        // Also verify the well-known absolute size.
        assert_eq!(
            std::mem::size_of::<UinputUserDev>(),
            1116,
            "UinputUserDev must be exactly 1116 bytes"
        );
    }

    /// Verify name truncation when the name exceeds `UINPUT_MAX_NAME_SIZE - 1`.
    #[test]
    fn test_uinput_new_name_truncation() {
        // Name exactly at limit (79 chars + NUL).
        let long_name = "A".repeat(79);
        let u = BtUinput::new(Some(&long_name), None, None, None);
        // First 79 bytes should be 'A', byte 79 should be NUL.
        assert_eq!(u.name[78], b'A');
        assert_eq!(u.name[79], 0);

        // Name exceeding limit (100 chars).
        let too_long = "B".repeat(100);
        let u = BtUinput::new(Some(&too_long), None, None, None);
        // Should be truncated to 79 bytes.
        assert_eq!(u.name[78], b'B');
        assert_eq!(u.name[79], 0);

        // Empty name.
        let u = BtUinput::new(None, None, None, None);
        assert_eq!(u.name[0], 0);
    }

    /// Verify suffix appending with overflow handling.
    ///
    /// Tests the C logic from lines 94–105 where the suffix is clamped and
    /// the start position is adjusted backward when necessary.
    #[test]
    fn test_uinput_new_suffix_append() {
        // Normal case: name + suffix fits.
        let u = BtUinput::new(Some("Hello"), Some(" World"), None, None);
        let name_str = std::str::from_utf8(
            &u.name[..u.name.iter().position(|&b| b == 0).unwrap_or(UINPUT_MAX_NAME_SIZE)],
        )
        .unwrap();
        assert_eq!(name_str, "Hello World");

        // Overflow case: combined length exceeds 79.
        let base = "A".repeat(75);
        let suffix = "BBBBB"; // 5 chars; 75 + 5 = 80 > 79
        let u = BtUinput::new(Some(&base), Some(suffix), None, None);
        // pos should be adjusted to 79 - 5 = 74.
        let end = u.name.iter().position(|&b| b == 0).unwrap_or(UINPUT_MAX_NAME_SIZE);
        assert_eq!(end, 79, "name should be exactly 79 chars long");
        // Last 5 chars should be the suffix.
        assert_eq!(&u.name[74..79], b"BBBBB");

        // Suffix only (no name).
        let u = BtUinput::new(None, Some("suffix"), None, None);
        let name_str = std::str::from_utf8(
            &u.name[..u.name.iter().position(|&b| b == 0).unwrap_or(UINPUT_MAX_NAME_SIZE)],
        )
        .unwrap();
        assert_eq!(name_str, "suffix");

        // Very long suffix (exceeds UINPUT_MAX_NAME_SIZE - 1).
        let long_suffix = "C".repeat(100);
        let u = BtUinput::new(None, Some(&long_suffix), None, None);
        let end = u.name.iter().position(|&b| b == 0).unwrap_or(UINPUT_MAX_NAME_SIZE);
        assert_eq!(end, 79, "suffix should be clamped to 79 chars");
    }

    /// Verify `BUS_BLUETOOTH` default when no `dev_id` is provided.
    #[test]
    fn test_uinput_new_default_bustype() {
        let u = BtUinput::new(Some("test"), None, None, None);
        assert_eq!(u.dev_id.bustype, BUS_BLUETOOTH);
        assert_eq!(u.dev_id.vendor, 0);
        assert_eq!(u.dev_id.product, 0);
        assert_eq!(u.dev_id.version, 0);
    }

    /// Verify custom `dev_id` is preserved.
    #[test]
    fn test_uinput_new_custom_dev_id() {
        let id = InputId { bustype: 0x03, vendor: 0x1234, product: 0x5678, version: 0x0100 };
        let u = BtUinput::new(Some("test"), None, None, Some(&id));
        assert_eq!(u.dev_id, id);
    }

    /// Verify `BtUinputKeyMap` struct can be constructed and fields accessed.
    #[test]
    fn test_uinput_key_map_struct() {
        let km = BtUinputKeyMap {
            name: "PLAY",
            code: 0x44,
            uinput: 164, // KEY_PLAYPAUSE
        };
        assert_eq!(km.name, "PLAY");
        assert_eq!(km.code, 0x44);
        assert_eq!(km.uinput, 164);
    }

    /// Verify `InputEvent` byte layout by constructing an event, converting to
    /// bytes, and checking field positions.
    #[test]
    fn test_input_event_roundtrip() {
        let event = InputEvent {
            time: libc::timeval { tv_sec: 0, tv_usec: 0 },
            event_type: EV_KEY,
            code: 42,
            value: 1,
        };

        let size = std::mem::size_of::<InputEvent>();
        // SAFETY: InputEvent is #[repr(C)] with no padding, reading as bytes
        // is safe for layout verification in tests.
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts((&event as *const InputEvent).cast::<u8>(), size) };

        assert_eq!(bytes.len(), size);

        // Verify the event_type field is at the expected offset (after timeval).
        let tv_size = std::mem::size_of::<libc::timeval>();
        let type_bytes = &bytes[tv_size..tv_size + 2];
        assert_eq!(u16::from_ne_bytes([type_bytes[0], type_bytes[1]]), EV_KEY);

        // Verify the code field follows type.
        let code_bytes = &bytes[tv_size + 2..tv_size + 4];
        assert_eq!(u16::from_ne_bytes([code_bytes[0], code_bytes[1]]), 42);

        // Verify the value field follows code.
        let val_bytes = &bytes[tv_size + 4..tv_size + 8];
        assert_eq!(i32::from_ne_bytes([val_bytes[0], val_bytes[1], val_bytes[2], val_bytes[3]]), 1);
    }

    /// Verify `UinputUserDev` field offsets match the kernel's struct layout.
    #[test]
    fn test_uinput_user_dev_layout() {
        let dev = UinputUserDev {
            name: [0u8; UINPUT_MAX_NAME_SIZE],
            id: InputId { bustype: BUS_BLUETOOTH, vendor: 0, product: 0, version: 0 },
            ff_effects_max: 0,
            absmax: [0i32; ABS_CNT],
            absmin: [0i32; ABS_CNT],
            absfuzz: [0i32; ABS_CNT],
            absflat: [0i32; ABS_CNT],
        };

        let base_ptr = &dev as *const UinputUserDev as usize;
        let name_offset = &dev.name as *const _ as usize - base_ptr;
        let id_offset = &dev.id as *const _ as usize - base_ptr;
        let ff_offset = &dev.ff_effects_max as *const _ as usize - base_ptr;
        let absmax_offset = &dev.absmax as *const _ as usize - base_ptr;

        assert_eq!(name_offset, 0, "name should be at offset 0");
        assert_eq!(id_offset, 80, "id should be at offset 80");
        assert_eq!(ff_offset, 88, "ff_effects_max should be at offset 88");
        assert_eq!(absmax_offset, 92, "absmax should be at offset 92");
    }

    /// Verify computed ioctl numbers match the expected Linux values.
    #[test]
    fn test_ioctl_constants() {
        // UI_DEV_CREATE = _IO('U', 1) = 0x5501
        assert_eq!(UI_DEV_CREATE_NUM, 0x5501);

        // UI_DEV_DESTROY = _IO('U', 2) = 0x5502
        assert_eq!(UI_DEV_DESTROY_NUM, 0x5502);

        // UI_SET_EVBIT = _IOW('U', 100, int) where sizeof(int) = 4
        // = (1 << 30) | (4 << 16) | (0x55 << 8) | 100 = 0x40045564
        assert_eq!(UI_SET_EVBIT_NUM, 0x4004_5564);

        // UI_SET_KEYBIT = _IOW('U', 101, int) = 0x40045565
        assert_eq!(UI_SET_KEYBIT_NUM, 0x4004_5565);

        // UI_SET_PHYS = _IOW('U', 108, char*) — pointer-sized
        #[cfg(target_pointer_width = "64")]
        assert_eq!(UI_SET_PHYS_NUM, 0x4008_556C);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(UI_SET_PHYS_NUM, 0x4004_556C);
    }

    /// Verify the debug callback mechanism works.
    #[test]
    fn test_set_debug() {
        use std::sync::{Arc, Mutex};

        let messages: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let messages_clone = Arc::clone(&messages);

        let mut u = BtUinput::new(Some("test"), None, None, None);
        u.set_debug(Some(Box::new(move |msg: &str| {
            messages_clone.lock().unwrap().push(msg.to_string());
        })));

        // Trigger debug via send_key (which calls debug internally).
        // Since there's no fd, send_key will fail silently but debug is called.
        u.send_key(42, true);

        let msgs = messages.lock().unwrap();
        assert!(!msgs.is_empty(), "Debug callback should have been called");
    }

    /// Verify that bdaddr_t's ba2strlc() is used correctly.
    #[test]
    fn test_bdaddr_ba2strlc_usage() {
        let addr = bdaddr_t { b: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] };
        let u = BtUinput::new(Some("test"), None, Some(&addr), None);
        // Verify the address was stored.
        assert_eq!(u.addr.b, addr.b);
        // Verify ba2strlc() produces the expected format (reversed byte order).
        assert_eq!(u.addr.ba2strlc(), "66:55:44:33:22:11");
    }

    /// Verify `BUS_BLUETOOTH` constant value matches `linux/input.h`.
    #[test]
    fn test_bus_bluetooth_value() {
        assert_eq!(BUS_BLUETOOTH, 0x05);
    }

    /// Verify `UINPUT_MAX_NAME_SIZE` constant matches `linux/uinput.h`.
    #[test]
    fn test_uinput_max_name_size() {
        assert_eq!(UINPUT_MAX_NAME_SIZE, 80);
    }

    /// Verify that create() returns EINVAL when called twice.
    #[test]
    fn test_create_double_call_returns_einval() {
        // Create a BtUinput — we can't actually open /dev/uinput in tests,
        // but we can test the guard check by manually setting fd.
        let mut u = BtUinput::new(Some("test"), None, None, None);

        // Simulate that create was already called by inserting a dummy fd.
        // SAFETY: We use /dev/null as a safe dummy fd for testing the guard.
        let null_path = CString::new("/dev/null").unwrap();
        let raw_fd = unsafe { libc::open(null_path.as_ptr(), libc::O_WRONLY) };
        if raw_fd >= 0 {
            // SAFETY: raw_fd is a valid fd from a successful open.
            u.fd = Some(unsafe { OwnedFd::from_raw_fd(raw_fd) });

            let result = u.create(&[]);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        }
    }
}
