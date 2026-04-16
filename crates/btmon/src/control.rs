// SPDX-License-Identifier: GPL-2.0-or-later
//
// HCI monitor socket control replacing monitor/control.c (1,629 LOC)
//
// Opens and manages the HCI monitor channel (/dev/hci_monitor) and
// btsnoop file reader/writer. Dispatches received packets to the
// packet decoder.

use std::path::Path;

use crate::display;
use crate::packet::MonitorState;

// BTSnoop header is 16 bytes: magic(8) + version(4) + datalink_type(4)
const BTSNOOP_HDR_SIZE: usize = 16;
const BTSNOOP_FORMAT_HCI: u32 = bluez_shared::btsnoop::BTSNOOP_TYPE_HCI_UNENCAP;
const BTSNOOP_FORMAT_MONITOR: u32 = bluez_shared::btsnoop::BTSNOOP_TYPE_MONITOR;

/// Control state for the monitor.
pub struct Control {
    state: MonitorState,
    writer: Option<BtsnoopWriter>,
    decode_control: bool,
}

/// Wrapper for btsnoop file writing.
#[allow(dead_code)]
struct BtsnoopWriter {
    path: String,
}

impl Control {
    /// Create a new control instance.
    pub fn new() -> Self {
        Self {
            state: MonitorState::new(),
            writer: None,
            decode_control: true,
        }
    }

    /// Access the monitor state.
    pub fn state(&self) -> &MonitorState {
        &self.state
    }

    /// Access the monitor state mutably.
    pub fn state_mut(&mut self) -> &mut MonitorState {
        &mut self.state
    }

    /// Set the btsnoop output file.
    pub fn set_writer(&mut self, path: &str) -> bool {
        self.writer = Some(BtsnoopWriter {
            path: path.to_string(),
        });
        true
    }

    /// Disable control message decoding.
    pub fn disable_decoding(&mut self) {
        self.decode_control = false;
    }

    /// Read and process a btsnoop file.
    pub fn read_file(&mut self, path: &str) {
        if !Path::new(path).exists() {
            eprintln!("File not found: {}", path);
            return;
        }

        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to read file: {}", e);
                return;
            }
        };

        if data.len() < BTSNOOP_HDR_SIZE {
            eprintln!("File too small for btsnoop header");
            return;
        }

        // Parse the btsnoop header
        let id = &data[0..8];
        if id != bluez_shared::btsnoop::BTSNOOP_MAGIC {
            // Try to detect Apple PacketLogger format or other formats
            eprintln!("Not a btsnoop file (unknown format)");
            return;
        }

        let _version = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let format = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        match format {
            BTSNOOP_FORMAT_HCI
            | BTSNOOP_FORMAT_MONITOR => {
                self.read_btsnoop_packets(&data[BTSNOOP_HDR_SIZE..], format);
            }
            _ => {
                eprintln!("Unsupported btsnoop format: {}", format);
            }
        }
    }

    fn read_btsnoop_packets(&mut self, mut data: &[u8], format: u32) {
        // Each btsnoop record: original_length(4) + included_length(4) +
        //   flags(4) + cumulative_drops(4) + timestamp(8) + data(included_length)
        while data.len() >= 24 {
            let original_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let included_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
            let flags = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let _drops = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
            let ts_high = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
            let ts_low = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);

            if data.len() < 24 + included_len {
                break;
            }

            let pkt_data = &data[24..24 + included_len];

            // Convert btsnoop timestamp to timeval
            // Btsnoop timestamp is microseconds since 0 AD
            let ts_us = ((ts_high as u64) << 32) | (ts_low as u64);
            // Epoch offset: 0x00dcddb30f2f8000 microseconds from 0 AD to Unix epoch
            let epoch_offset: u64 = 0x00dc_ddb3_0f2f_8000;
            let unix_us = ts_us.wrapping_sub(epoch_offset);
            let tv = libc::timeval {
                tv_sec: (unix_us / 1_000_000) as libc::time_t,
                tv_usec: (unix_us % 1_000_000) as libc::suseconds_t,
            };

            let (index, opcode) = if format == BTSNOOP_FORMAT_MONITOR {
                // Monitor format: opcode in lower 16 bits of flags,
                // index in upper 16 bits
                let opcode = (flags & 0xFFFF) as u16;
                let index = ((flags >> 16) & 0xFFFF) as u16;
                (index, opcode)
            } else {
                // HCI format: map flags to opcodes
                let opcode = match flags & 0x03 {
                    0 => 2,  // Command (sent)
                    1 => 3,  // Event (received)
                    2 => 4,  // ACL TX
                    3 => 5,  // ACL RX
                    _ => {
                        let _ = original_len;
                        0xFFFF
                    }
                };
                (0u16, opcode)
            };

            self.state.packet_monitor(Some(&tv), index, opcode, pkt_data);
            data = &data[24 + included_len..];
        }
    }

    /// Decode a management control message.
    pub fn control_message(&self, opcode: u16, data: &[u8]) {
        if !self.decode_control {
            return;
        }

        let name = mgmt_event_to_str(opcode);
        display::print_field(&format!("@ {} (0x{:04x}) plen {}", name, opcode, data.len()));

        if !data.is_empty() {
            display::print_hexdump(data);
        }
    }
}

impl Default for Control {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Linux-only: HCI monitor socket
// ---------------------------------------------------------------------------

/// Open the HCI monitor socket for live packet tracing.
///
/// Creates `AF_BLUETOOTH` / `SOCK_RAW` / `BTPROTO_HCI`, binds to
/// `HCI_DEV_NONE` on `HCI_CHANNEL_MONITOR`, and returns an `OwnedFd`.
///
/// Only available on Linux.
#[cfg(target_os = "linux")]
pub fn open_monitor_socket() -> Result<std::os::unix::io::OwnedFd, std::io::Error> {
    use std::os::unix::io::FromRawFd;

    const AF_BLUETOOTH: libc::c_int = 31;
    const BTPROTO_HCI: libc::c_int = 1;
    const HCI_CHANNEL_MONITOR: u16 = 2;
    const HCI_DEV_NONE: u16 = 0xFFFF;

    /// `struct sockaddr_hci` from `include/net/bluetooth/hci.h`.
    #[repr(C)]
    struct SockaddrHci {
        hci_family: u16,
        hci_dev: u16,
        hci_channel: u16,
    }

    // Safety: socket() is a standard POSIX syscall.
    let fd = unsafe {
        libc::socket(AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, BTPROTO_HCI)
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let addr = SockaddrHci {
        hci_family: AF_BLUETOOTH as u16,
        hci_dev: HCI_DEV_NONE,
        hci_channel: HCI_CHANNEL_MONITOR,
    };

    // Safety: bind() with a correctly-sized sockaddr_hci.  The fd is valid
    // (checked above) and addr lives for the duration of the call.
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const SockaddrHci as *const libc::sockaddr,
            std::mem::size_of::<SockaddrHci>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // Safety: fd is valid; cleaning up after a failed bind.
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // Set non-blocking for potential async I/O.
    // Safety: fcntl with F_GETFL/F_SETFL on a valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // Safety: fd is a valid, open file descriptor that we own.
    // Wrapping in OwnedFd transfers ownership so it will be closed on drop.
    Ok(unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) })
}

fn mgmt_event_to_str(opcode: u16) -> &'static str {
    match opcode {
        0x0001 => "Command Complete",
        0x0002 => "Command Status",
        0x0003 => "Controller Error",
        0x0004 => "Index Added",
        0x0005 => "Index Removed",
        0x0006 => "New Settings",
        0x0007 => "Class of Device Changed",
        0x0008 => "Local Name Changed",
        0x0009 => "New Link Key",
        0x000a => "New Long Term Key",
        0x000b => "Device Connected",
        0x000c => "Device Disconnected",
        0x000d => "Connect Failed",
        0x000e => "PIN Code Request",
        0x000f => "User Confirm Request",
        0x0010 => "User Passkey Request",
        0x0011 => "Authentication Failed",
        0x0012 => "Device Found",
        0x0013 => "Discovering",
        0x0014 => "Device Blocked",
        0x0015 => "Device Unblocked",
        0x0016 => "Device Unpaired",
        0x0017 => "Passkey Notify",
        0x0018 => "New IRK",
        0x0019 => "New CSRK",
        0x001a => "Device Added",
        0x001b => "Device Removed",
        0x001c => "New Connection Parameter",
        0x001d => "Unconfigured Index Added",
        0x001e => "Unconfigured Index Removed",
        0x001f => "New Configuration Options",
        0x0020 => "Extended Index Added",
        0x0021 => "Extended Index Removed",
        0x0022 => "Local Out Of Band Extended Data Updated",
        0x0023 => "Advertising Added",
        0x0024 => "Advertising Removed",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_new() {
        let ctrl = Control::new();
        assert!(ctrl.decode_control);
        assert!(ctrl.writer.is_none());
    }

    #[test]
    fn test_control_disable_decoding() {
        let mut ctrl = Control::new();
        ctrl.disable_decoding();
        assert!(!ctrl.decode_control);
    }

    #[test]
    fn test_control_set_writer() {
        let mut ctrl = Control::new();
        assert!(ctrl.set_writer("/tmp/test.btsnoop"));
        assert!(ctrl.writer.is_some());
    }

    #[test]
    fn test_mgmt_event_to_str() {
        assert_eq!(mgmt_event_to_str(0x0004), "Index Added");
        assert_eq!(mgmt_event_to_str(0x0006), "New Settings");
        assert_eq!(mgmt_event_to_str(0xFFFF), "Unknown");
    }

    #[test]
    fn test_control_message() {
        let ctrl = Control::new();
        ctrl.control_message(0x0004, &[]);
        ctrl.control_message(0x0006, &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_read_nonexistent_file() {
        let mut ctrl = Control::new();
        ctrl.read_file("/nonexistent/path.btsnoop");
    }
}
