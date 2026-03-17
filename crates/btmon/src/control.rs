// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2011-2014 Intel Corporation
// Copyright (C) 2002-2010 Marcel Holtmann <marcel@holtmann.org>

//! Control hub for btmon — transport backbone module.
//!
//! Complete Rust rewrite of `monitor/control.c` (1629 lines),
//! `monitor/control.h` (23 lines), and `monitor/tty.h` (28 lines).
//!
//! This module opens multiple ingestion sources (kernel HCI monitor/control
//! sockets, MGMT streams, Unix-domain server socket, `/dev/kmsg` tailing,
//! serial TTY framing, J-Link RTT polling) and routes frames into the packet
//! decoder, btsnoop writer, and Ellisys injection pipeline.
//!
//! # GLib Removal
//!
//! All `mainloop_add_fd(EPOLLIN, callback)` patterns are replaced with
//! `tokio::io::unix::AsyncFd::readable()` awaited in spawned tokio tasks.
//! All `callback_t fn + void *user_data` patterns are replaced with async
//! functions and owned state.
//!
//! # Safety
//!
//! This module uses `unsafe` for BPF filter attachment via `libc::setsockopt`
//! with `SO_ATTACH_FILTER` and for raw socket creation via `libc` syscalls.
//! Each `unsafe` block is a designated FFI boundary site with a `// SAFETY:`
//! comment.


use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use tokio::io::unix::AsyncFd;
use tokio::net::UnixListener;

use tracing::{debug, error, warn};

use crate::backends::ellisys;
use crate::backends::hcidump;
use crate::backends::jlink;
use crate::display;
use crate::packet::{self, PacketFilter};

use bluez_shared::capture::btsnoop::{
    BTSNOOP_FLAG_PKLG_SUPPORT, BtSnoop, BtSnoopFormat, BtSnoopOpcode, MAX_PACKET_SIZE,
};
use bluez_shared::sys::bluetooth::{AF_BLUETOOTH, BTPROTO_HCI, bdaddr_t, bt_get_le16, bt_get_le32};
use bluez_shared::sys::hci::{
    HCI_CHANNEL_CONTROL, HCI_CHANNEL_MONITOR, HCI_DEV_NONE, sockaddr_hci,
};
use bluez_shared::sys::mgmt::{
    MGMT_DEV_DISCONN_UNKNOWN, MGMT_EV_ADVERTISING_ADDED, MGMT_EV_ADVERTISING_REMOVED,
    MGMT_EV_AUTH_FAILED, MGMT_EV_CONNECT_FAILED, MGMT_EV_CONTROLLER_ERROR,
    MGMT_EV_DEVICE_CONNECTED, MGMT_EV_DEVICE_DISCONNECTED, MGMT_EV_DEVICE_FOUND,
    MGMT_EV_DISCOVERING, MGMT_EV_EXT_INDEX_ADDED, MGMT_EV_EXT_INDEX_REMOVED, MGMT_EV_INDEX_ADDED,
    MGMT_EV_INDEX_REMOVED, MGMT_EV_NEW_IRK, MGMT_EV_NEW_LINK_KEY, MGMT_EV_NEW_LONG_TERM_KEY,
    MGMT_EV_NEW_SETTINGS, MGMT_HDR_SIZE, MgmtSettings, mgmt_addr_info, mgmt_errstr,
    mgmt_ev_auth_failed, mgmt_ev_connect_failed, mgmt_ev_controller_error,
    mgmt_ev_device_connected, mgmt_ev_device_disconnected, mgmt_ev_device_found,
    mgmt_ev_discovering, mgmt_ev_local_name_changed, mgmt_ev_new_conn_param, mgmt_ev_new_csrk,
    mgmt_ev_new_irk, mgmt_ev_new_link_key, mgmt_ev_new_long_term_key, mgmt_evstr, mgmt_hdr,
    mgmt_opstr,
};
use bluez_shared::sys::ffi_helpers as ffi;

// ─── TTY Header Structures (from monitor/tty.h) ────────────────────────────

/// Packed TTY framing header matching C `struct tty_hdr`.
///
/// All multi-byte fields are little-endian on the wire.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TtyHdr {
    /// Total frame data length (includes opcode, flags, hdr_len, ext_hdr, and payload).
    pub data_len: u16,
    /// BTSnoop monitor opcode identifying the packet type.
    pub opcode: u16,
    /// Flags byte.
    pub flags: u8,
    /// Length of the extended header that follows.
    pub hdr_len: u8,
}

/// Size of the TtyHdr in bytes (matches C `sizeof(struct tty_hdr)`).
const TTY_HDR_SIZE: usize = mem::size_of::<TtyHdr>();

// TTY extended header type constants
const TTY_EXTHDR_COMMAND_DROPS: u8 = 1;
const TTY_EXTHDR_EVENT_DROPS: u8 = 2;
const TTY_EXTHDR_ACL_TX_DROPS: u8 = 3;
const TTY_EXTHDR_ACL_RX_DROPS: u8 = 4;
const TTY_EXTHDR_SCO_TX_DROPS: u8 = 5;
const TTY_EXTHDR_SCO_RX_DROPS: u8 = 6;
const TTY_EXTHDR_OTHER_DROPS: u8 = 7;
const TTY_EXTHDR_TS32: u8 = 8;

/// Map an integer baud rate value to the corresponding `libc` speed constant.
///
/// Returns `Some(speed_constant)` for known baud rates, or `None` for
/// unsupported values.
pub fn tty_get_speed(speed: i32) -> Option<u32> {
    match speed {
        9600 => Some(libc::B9600),
        19200 => Some(libc::B19200),
        38400 => Some(libc::B38400),
        57600 => Some(libc::B57600),
        115200 => Some(libc::B115200),
        230400 => Some(libc::B230400),
        460800 => Some(libc::B460800),
        500000 => Some(libc::B500000),
        576000 => Some(libc::B576000),
        921600 => Some(libc::B921600),
        1000000 => Some(libc::B1000000),
        1152000 => Some(libc::B1152000),
        1500000 => Some(libc::B1500000),
        2000000 => Some(libc::B2000000),
        2500000 => Some(libc::B2500000),
        3000000 => Some(libc::B3000000),
        3500000 => Some(libc::B3500000),
        4000000 => Some(libc::B4000000),
        _ => None,
    }
}

// ─── Module-Level Global State ──────────────────────────────────────────────

/// Active btsnoop output file for writing captured packets.
static BTSNOOP_FILE: Mutex<Option<BtSnoop>> = Mutex::new(None);

/// Whether the HCI_CHANNEL_MONITOR socket bind failed with EINVAL,
/// triggering fallback to the hcidump backend.
static HCIDUMP_FALLBACK: AtomicBool = AtomicBool::new(false);

/// Whether MGMT event decoding is enabled (default: true).
static DECODE_CONTROL: AtomicBool = AtomicBool::new(true);

/// Controller index filter (0xffff = all controllers).
static FILTER_INDEX: AtomicU16 = AtomicU16::new(HCI_DEV_NONE);

/// Server socket fd sentinel (-1 = not open).
static SERVER_FD: Mutex<RawFd> = Mutex::new(-1);

// ─── MGMT Event Pretty-Printing (replaces static mgmt_* handlers) ──────────

/// Settings string table for the `MgmtSettings` bitfield decoder.
const SETTINGS_STR: &[&str] = &[
    "powered",
    "connectable",
    "fast-connectable",
    "discoverable",
    "bondable",
    "link-security",
    "ssp",
    "br/edr",
    "hs",
    "le",
    "advertising",
    "secure-conn",
    "debug-keys",
    "privacy",
    "configuration",
    "static-addr",
    "phy",
    "wbs",
];

/// Configuration option string table.
const CONFIG_OPTIONS_STR: &[&str] = &["external", "public-address"];

fn mgmt_index_added(len: u16, buf: &[u8]) {
    println!("@ Index Added");
    packet::hexdump(&buf[..len as usize]);
}

fn mgmt_index_removed(len: u16, buf: &[u8]) {
    println!("@ Index Removed");
    packet::hexdump(&buf[..len as usize]);
}

fn mgmt_unconf_index_added(len: u16, buf: &[u8]) {
    println!("@ Unconfigured Index Added");
    packet::hexdump(&buf[..len as usize]);
}

fn mgmt_unconf_index_removed(len: u16, buf: &[u8]) {
    println!("@ Unconfigured Index Removed");
    packet::hexdump(&buf[..len as usize]);
}

fn mgmt_ext_index_added(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<bluez_shared::sys::mgmt::mgmt_ev_ext_index>();
    if (len as usize) < ev_size {
        println!("* Malformed Extended Index Added control");
        return;
    }
    let type_ = buf[0];
    let bus = buf[1];
    println!("@ Extended Index Added: {} ({})", type_, bus);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_ext_index_removed(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<bluez_shared::sys::mgmt::mgmt_ev_ext_index>();
    if (len as usize) < ev_size {
        println!("* Malformed Extended Index Removed control");
        return;
    }
    let type_ = buf[0];
    let bus = buf[1];
    println!("@ Extended Index Removed: {} ({})", type_, bus);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_controller_error_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_controller_error>();
    if (len as usize) < ev_size {
        println!("* Malformed Controller Error control");
        return;
    }
    let error_code = buf[0];
    println!("@ Controller Error: 0x{:02x}", error_code);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_new_config_options(len: u16, buf: &[u8]) {
    if (len as usize) < 4 {
        println!("* Malformed New Configuration Options control");
        return;
    }
    let options = bt_get_le32(buf);
    println!("@ New Configuration Options: 0x{:04x}", options);
    if options != 0 {
        print!("{:12}", ' ');
        for (i, name) in CONFIG_OPTIONS_STR.iter().enumerate() {
            if options & (1 << i) != 0 {
                print!("{} ", name);
            }
        }
        println!();
    }
    packet::hexdump(&buf[4..len as usize]);
}

fn mgmt_new_settings_handler(len: u16, buf: &[u8]) {
    if (len as usize) < 4 {
        println!("* Malformed New Settings control");
        return;
    }
    let settings = bt_get_le32(buf);
    let settings_bits = MgmtSettings::from_bits_truncate(settings);
    println!("@ New Settings: 0x{:04x}", settings_bits.bits());
    if settings != 0 {
        print!("{:12}", ' ');
        for (i, name) in SETTINGS_STR.iter().enumerate() {
            if settings & (1 << i) != 0 {
                print!("{} ", name);
            }
        }
        println!();
    }
    packet::hexdump(&buf[4..len as usize]);
}

fn mgmt_class_of_dev_changed(len: u16, buf: &[u8]) {
    let ev_size = 3; // dev_class[3]
    if (len as usize) < ev_size {
        println!("* Malformed Class of Device Changed control");
        return;
    }
    println!("@ Class of Device Changed: 0x{:02x}{:02x}{:02x}", buf[2], buf[1], buf[0]);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_local_name_changed_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_local_name_changed>();
    if (len as usize) < ev_size {
        println!("* Malformed Local Name Changed control");
        return;
    }
    // Extract name (249 bytes) and short_name (11 bytes) as C strings
    let name_bytes = &buf[..249];
    let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(249);
    let name = String::from_utf8_lossy(&name_bytes[..name_end]);

    let short_name_bytes = &buf[249..260];
    let short_end = short_name_bytes.iter().position(|&b| b == 0).unwrap_or(11);
    let short_name = String::from_utf8_lossy(&short_name_bytes[..short_end]);

    println!("@ Local Name Changed: {} ({})", name, short_name);
    packet::hexdump(&buf[ev_size..len as usize]);
}

/// Format a BD_ADDR from a raw 6-byte slice using `bdaddr_t::ba2str`.
fn ba2str_from_slice(addr: &[u8]) -> String {
    if addr.len() < 6 {
        return String::from("??:??:??:??:??:??");
    }
    let mut b = [0u8; 6];
    b.copy_from_slice(&addr[..6]);
    let bdaddr = bdaddr_t { b };
    bdaddr.ba2str()
}

fn mgmt_new_link_key_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_new_link_key>();
    if (len as usize) < ev_size {
        println!("* Malformed New Link Key control");
        return;
    }
    // store_hint at offset 0, then mgmt_link_key_info starting at offset 1
    // mgmt_link_key_info: addr(7 bytes: bdaddr 6 + type 1), type_ 1, val 16, pin_len 1
    let addr_start = 1; // skip store_hint
    let addr_bytes = &buf[addr_start..addr_start + 6];
    let addr_type = buf[addr_start + 6];
    let key_type = buf[addr_start + 7];

    static LINK_KEY_TYPES: &[&str] = &[
        "Combination key",
        "Local Unit key",
        "Remote Unit key",
        "Debug Combination key",
        "Unauthenticated Combination key from P-192",
        "Authenticated Combination key from P-192",
        "Changed Combination key",
        "Unauthenticated Combination key from P-256",
        "Authenticated Combination key from P-256",
    ];

    let type_str = if (key_type as usize) < LINK_KEY_TYPES.len() {
        LINK_KEY_TYPES[key_type as usize]
    } else {
        "Reserved"
    };

    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ New Link Key: {} ({}) {} ({})", addr_str, addr_type, type_str, key_type);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_new_long_term_key_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_new_long_term_key>();
    if (len as usize) < ev_size {
        println!("* Malformed New Long Term Key control");
        return;
    }
    // store_hint(1), then mgmt_ltk_info: addr(7), type_(1), master(1), enc_size(1), ...
    let addr_start = 1;
    let addr_bytes = &buf[addr_start..addr_start + 6];
    let addr_type = buf[addr_start + 6];
    let ltk_type = buf[addr_start + 7];
    let central = buf[addr_start + 8];

    let type_str = match ltk_type {
        0x00 => {
            if central != 0 {
                "Central (Unauthenticated)"
            } else {
                "Peripheral (Unauthenticated)"
            }
        }
        0x01 => {
            if central != 0 {
                "Central (Authenticated)"
            } else {
                "Peripheral (Authenticated)"
            }
        }
        0x02 => "SC (Unauthenticated)",
        0x03 => "SC (Authenticated)",
        0x04 => "SC (Debug)",
        _ => "<unknown>",
    };

    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ New Long Term Key: {} ({}) {} 0x{:02x}", addr_str, addr_type, type_str, ltk_type);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_device_connected_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_device_connected>();
    if (len as usize) < ev_size {
        println!("* Malformed Device Connected control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let flags = bt_get_le32(&buf[7..]);
    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ Device Connected: {} ({}) flags 0x{:04x}", addr_str, addr_type, flags);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_device_disconnected_handler(len: u16, buf: &[u8]) {
    let addr_info_size = mem::size_of::<mgmt_addr_info>();
    if (len as usize) < addr_info_size {
        println!("* Malformed Device Disconnected control");
        return;
    }
    let ev_size = mem::size_of::<mgmt_ev_device_disconnected>();
    let reason: u8;
    let consumed: usize;
    if (len as usize) < ev_size {
        reason = MGMT_DEV_DISCONN_UNKNOWN;
        consumed = len as usize;
    } else {
        reason = buf[addr_info_size]; // reason field after mgmt_addr_info
        consumed = ev_size;
    };

    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ Device Disconnected: {} ({}) reason {}", addr_str, addr_type, reason);
    packet::hexdump(&buf[consumed..len as usize]);
}

fn mgmt_connect_failed_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_connect_failed>();
    if (len as usize) < ev_size {
        println!("* Malformed Connect Failed control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let status = buf[7];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!(
        "@ Connect Failed: {} ({}) status 0x{:02x} [{}]",
        addr_str,
        addr_type,
        status,
        mgmt_errstr(status)
    );
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_pin_code_request(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<bluez_shared::sys::mgmt::mgmt_ev_pin_code_request>();
    if (len as usize) < ev_size {
        println!("* Malformed PIN Code Request control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let secure = buf[7];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ PIN Code Request: {} ({}) secure 0x{:02x}", addr_str, addr_type, secure);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_user_confirm_request(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<bluez_shared::sys::mgmt::mgmt_ev_user_confirm_request>();
    if (len as usize) < ev_size {
        println!("* Malformed User Confirmation Request control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let confirm_hint = buf[7];
    let value = bt_get_le32(&buf[8..]);
    let addr_str = ba2str_from_slice(addr_bytes);
    println!(
        "@ User Confirmation Request: {} ({}) hint {} value {}",
        addr_str, addr_type, confirm_hint, value
    );
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_user_passkey_request(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<bluez_shared::sys::mgmt::mgmt_ev_user_passkey_request>();
    if (len as usize) < ev_size {
        println!("* Malformed User Passkey Request control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ User Passkey Request: {} ({})", addr_str, addr_type);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_auth_failed_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_auth_failed>();
    if (len as usize) < ev_size {
        println!("* Malformed Authentication Failed control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let status = buf[7];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!(
        "@ Authentication Failed: {} ({}) status 0x{:02x} [{}]",
        addr_str,
        addr_type,
        status,
        mgmt_errstr(status)
    );
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_device_found_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_device_found>();
    if (len as usize) < ev_size {
        println!("* Malformed Device Found control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let rssi = buf[7] as i8;
    let flags = bt_get_le32(&buf[8..]);
    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ Device Found: {} ({}) rssi {} flags 0x{:04x}", addr_str, addr_type, rssi, flags);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_discovering_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_discovering>();
    if (len as usize) < ev_size {
        println!("* Malformed Discovering control");
        return;
    }
    let type_ = buf[0];
    let discovering = buf[1];
    println!("@ Discovering: 0x{:02x} ({})", discovering, type_);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_device_blocked(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_addr_info>();
    if (len as usize) < ev_size {
        println!("* Malformed Device Blocked control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ Device Blocked: {} ({})", addr_str, addr_type);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_device_unblocked(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_addr_info>();
    if (len as usize) < ev_size {
        println!("* Malformed Device Unblocked control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ Device Unblocked: {} ({})", addr_str, addr_type);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_device_unpaired(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_addr_info>();
    if (len as usize) < ev_size {
        println!("* Malformed Device Unpaired control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ Device Unpaired: {} ({})", addr_str, addr_type);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_passkey_notify(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<bluez_shared::sys::mgmt::mgmt_ev_passkey_notify>();
    if (len as usize) < ev_size {
        println!("* Malformed Passkey Notify control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let passkey = bt_get_le32(&buf[7..]);
    let entered = buf[11];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!(
        "@ Passkey Notify: {} ({}) passkey {:06} entered {}",
        addr_str, addr_type, passkey, entered
    );
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_new_irk_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_new_irk>();
    if (len as usize) < ev_size {
        println!("* Malformed New IRK control");
        return;
    }
    // store_hint(1), rpa(6), then irk_info: addr(7), val(16)
    let rpa = ba2str_from_slice(&buf[1..7]);
    let addr = ba2str_from_slice(&buf[7..13]);
    let addr_type = buf[13];
    println!("@ New IRK: {} ({}) {}", addr, addr_type, rpa);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_new_csrk_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_new_csrk>();
    if (len as usize) < ev_size {
        println!("* Malformed New CSRK control");
        return;
    }
    // store_hint(1), then csrk_info: addr(7), type_(1), val(16)
    let addr = ba2str_from_slice(&buf[1..7]);
    let addr_type = buf[7];
    let csrk_type = buf[8];
    let type_str = match csrk_type {
        0x00 => "Local Unauthenticated",
        0x01 => "Remote Unauthenticated",
        0x02 => "Local Authenticated",
        0x03 => "Remote Authenticated",
        _ => "<unknown>",
    };
    println!("@ New CSRK: {} ({}) {} ({})", addr, addr_type, type_str, csrk_type);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_device_added(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<bluez_shared::sys::mgmt::mgmt_ev_device_added>();
    if (len as usize) < ev_size {
        println!("* Malformed Device Added control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let action = buf[7];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ Device Added: {} ({}) {}", addr_str, addr_type, action);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_device_removed(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<bluez_shared::sys::mgmt::mgmt_ev_device_removed>();
    if (len as usize) < ev_size {
        println!("* Malformed Device Removed control");
        return;
    }
    let addr_bytes = &buf[..6];
    let addr_type = buf[6];
    let addr_str = ba2str_from_slice(addr_bytes);
    println!("@ Device Removed: {} ({})", addr_str, addr_type);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_new_conn_param_handler(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<mgmt_ev_new_conn_param>();
    if (len as usize) < ev_size {
        println!("* Malformed New Connection Parameter control");
        return;
    }
    let addr = ba2str_from_slice(&buf[..6]);
    let addr_type = buf[6];
    let store_hint = buf[7];
    let min = bt_get_le16(&buf[8..]);
    let max = bt_get_le16(&buf[10..]);
    let latency = bt_get_le16(&buf[12..]);
    let timeout = bt_get_le16(&buf[14..]);
    println!(
        "@ New Conn Param: {} ({}) hint {} min 0x{:04x} max 0x{:04x} latency 0x{:04x} timeout 0x{:04x}",
        addr, addr_type, store_hint, min, max, latency, timeout
    );
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_advertising_added(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<bluez_shared::sys::mgmt::mgmt_ev_advertising_added>();
    if (len as usize) < ev_size {
        println!("* Malformed Advertising Added control");
        return;
    }
    let instance = buf[0];
    println!("@ Advertising Added: {}", instance);
    packet::hexdump(&buf[ev_size..len as usize]);
}

fn mgmt_advertising_removed(len: u16, buf: &[u8]) {
    let ev_size = mem::size_of::<bluez_shared::sys::mgmt::mgmt_ev_advertising_removed>();
    if (len as usize) < ev_size {
        println!("* Malformed Advertising Removed control");
        return;
    }
    let instance = buf[0];
    println!("@ Advertising Removed: {}", instance);
    packet::hexdump(&buf[ev_size..len as usize]);
}

// ─── control_message: MGMT Event Dispatcher ─────────────────────────────────

/// Decode and print a MGMT control event.
///
/// Dispatches the MGMT event opcode to the appropriate handler function
/// for human-readable pretty-printing. Respects the `decode_enabled` flag;
/// if decoding is disabled, this function is a no-op.
///
/// This is a direct behavioral clone of C `control_message()` in
/// `monitor/control.c` lines 791-901.
pub fn control_message(opcode: u16, data: &[u8], size: u16) {
    if !DECODE_CONTROL.load(Ordering::Relaxed) {
        return;
    }

    let buf = if (size as usize) <= data.len() { &data[..size as usize] } else { data };
    let len = buf.len() as u16;

    match opcode {
        MGMT_EV_INDEX_ADDED => mgmt_index_added(len, buf),
        MGMT_EV_INDEX_REMOVED => mgmt_index_removed(len, buf),
        MGMT_EV_CONTROLLER_ERROR => mgmt_controller_error_handler(len, buf),
        MGMT_EV_NEW_SETTINGS => mgmt_new_settings_handler(len, buf),
        x if x == bluez_shared::sys::mgmt::MGMT_EV_CLASS_OF_DEV_CHANGED => {
            mgmt_class_of_dev_changed(len, buf)
        }
        x if x == bluez_shared::sys::mgmt::MGMT_EV_LOCAL_NAME_CHANGED => {
            mgmt_local_name_changed_handler(len, buf)
        }
        MGMT_EV_NEW_LINK_KEY => mgmt_new_link_key_handler(len, buf),
        MGMT_EV_NEW_LONG_TERM_KEY => mgmt_new_long_term_key_handler(len, buf),
        MGMT_EV_DEVICE_CONNECTED => mgmt_device_connected_handler(len, buf),
        MGMT_EV_DEVICE_DISCONNECTED => mgmt_device_disconnected_handler(len, buf),
        MGMT_EV_CONNECT_FAILED => mgmt_connect_failed_handler(len, buf),
        x if x == bluez_shared::sys::mgmt::MGMT_EV_PIN_CODE_REQUEST => {
            mgmt_pin_code_request(len, buf)
        }
        x if x == bluez_shared::sys::mgmt::MGMT_EV_USER_CONFIRM_REQUEST => {
            mgmt_user_confirm_request(len, buf)
        }
        x if x == bluez_shared::sys::mgmt::MGMT_EV_USER_PASSKEY_REQUEST => {
            mgmt_user_passkey_request(len, buf)
        }
        MGMT_EV_AUTH_FAILED => mgmt_auth_failed_handler(len, buf),
        MGMT_EV_DEVICE_FOUND => mgmt_device_found_handler(len, buf),
        MGMT_EV_DISCOVERING => mgmt_discovering_handler(len, buf),
        x if x == bluez_shared::sys::mgmt::MGMT_EV_DEVICE_BLOCKED => mgmt_device_blocked(len, buf),
        x if x == bluez_shared::sys::mgmt::MGMT_EV_DEVICE_UNBLOCKED => {
            mgmt_device_unblocked(len, buf)
        }
        x if x == bluez_shared::sys::mgmt::MGMT_EV_DEVICE_UNPAIRED => {
            mgmt_device_unpaired(len, buf)
        }
        x if x == bluez_shared::sys::mgmt::MGMT_EV_PASSKEY_NOTIFY => mgmt_passkey_notify(len, buf),
        MGMT_EV_NEW_IRK => mgmt_new_irk_handler(len, buf),
        x if x == bluez_shared::sys::mgmt::MGMT_EV_NEW_CSRK => mgmt_new_csrk_handler(len, buf),
        x if x == bluez_shared::sys::mgmt::MGMT_EV_DEVICE_ADDED => mgmt_device_added(len, buf),
        x if x == bluez_shared::sys::mgmt::MGMT_EV_DEVICE_REMOVED => mgmt_device_removed(len, buf),
        x if x == bluez_shared::sys::mgmt::MGMT_EV_NEW_CONN_PARAM => {
            mgmt_new_conn_param_handler(len, buf)
        }
        x if x == bluez_shared::sys::mgmt::MGMT_EV_UNCONF_INDEX_ADDED => {
            mgmt_unconf_index_added(len, buf)
        }
        x if x == bluez_shared::sys::mgmt::MGMT_EV_UNCONF_INDEX_REMOVED => {
            mgmt_unconf_index_removed(len, buf)
        }
        x if x == bluez_shared::sys::mgmt::MGMT_EV_NEW_CONFIG_OPTIONS => {
            mgmt_new_config_options(len, buf)
        }
        MGMT_EV_EXT_INDEX_ADDED => mgmt_ext_index_added(len, buf),
        MGMT_EV_EXT_INDEX_REMOVED => mgmt_ext_index_removed(len, buf),
        MGMT_EV_ADVERTISING_ADDED => mgmt_advertising_added(len, buf),
        MGMT_EV_ADVERTISING_REMOVED => mgmt_advertising_removed(len, buf),
        _ => {
            let ev_name = mgmt_evstr(opcode);
            println!("* Unknown control (code {} [{}] len {})", opcode, ev_name, size);
            packet::hexdump(buf);
        }
    }
}

// ─── Socket Management ──────────────────────────────────────────────────────

/// Create an AF_BLUETOOTH/SOCK_RAW/BTPROTO_HCI socket and bind to the
/// given HCI channel.
///
/// Replaces C `open_socket()` (control.c lines 980-1021).
///
/// On bind failure with `EINVAL`, sets the `HCIDUMP_FALLBACK` flag.
fn open_socket(channel: u16) -> Result<OwnedFd, io::Error> {
    // SAFETY: Creating an AF_BLUETOOTH raw HCI socket. This is a designated
    // unsafe FFI boundary site for kernel socket creation. The socket family
    // (AF_BLUETOOTH), type (SOCK_RAW|SOCK_CLOEXEC), and protocol (BTPROTO_HCI)
    // are all valid kernel-defined constants.
    let fd = ffi::raw_socket(
            AF_BLUETOOTH as libc::c_int,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            BTPROTO_HCI as libc::c_int,
        );
    if fd < 0 {
        let err = io::Error::last_os_error();
        error!("Failed to open channel: {}", err);
        return Err(err);
    }

    // SAFETY: fd is a valid open socket from the socket() call above.
    let owned_fd = ffi::raw_owned_fd(fd);

    let addr = sockaddr_hci {
        hci_family: AF_BLUETOOTH as u16,
        hci_dev: HCI_DEV_NONE,
        hci_channel: channel,
    };

    // SAFETY: Binding a valid Bluetooth socket with a correctly-sized sockaddr_hci.
    let ret = ffi::raw_bind(owned_fd.as_raw_fd(), &addr);
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINVAL) {
            HCIDUMP_FALLBACK.store(true, Ordering::Relaxed);
        } else {
            error!("Failed to bind channel: {}", err);
        }
        return Err(err);
    }

    // Enable SO_TIMESTAMP
    let opt: libc::c_int = 1;
    // SAFETY: Setting SO_TIMESTAMP on a valid socket fd with a valid integer option value.
    let ret = ffi::raw_setsockopt(owned_fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_TIMESTAMP, &opt);
    if ret < 0 {
        let err = io::Error::last_os_error();
        error!("Failed to enable timestamps: {}", err);
        return Err(err);
    }

    // Enable SO_PASSCRED
    // SAFETY: Setting SO_PASSCRED on a valid socket fd with a valid integer option value.
    let ret = ffi::raw_setsockopt(owned_fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PASSCRED, &opt);
    if ret < 0 {
        let err = io::Error::last_os_error();
        error!("Failed to enable credentials: {}", err);
        return Err(err);
    }

    Ok(owned_fd)
}

/// Attach a BPF socket filter to restrict packets to a specific controller index.
///
/// Replaces C `attach_index_filter()` (control.c lines 1023-1052).
fn attach_index_filter(fd: RawFd, index: u16) {
    // BPF program: accept packets where MGMT index == HCI_DEV_NONE or == index.
    // The MGMT header index field is at offset 2 (after the 2-byte opcode) as
    // a little-endian u16. We load the byte at the offset matching the C code.
    let filters: [libc::sock_filter; 6] = [
        // Load word at offset of mgmt_hdr.index (offset 2 within packet)
        // BPF_LD + BPF_W + BPF_ABS = 0x20
        libc::sock_filter { code: 0x20, jt: 0, jf: 0, k: 2 },
        // Jump if A == HCI_DEV_NONE
        libc::sock_filter {
            code: 0x15, // BPF_JMP + BPF_JEQ + BPF_K
            jt: 0,
            jf: 1,
            k: HCI_DEV_NONE as u32,
        },
        // Return pass
        libc::sock_filter {
            code: 0x06, // BPF_RET + BPF_K
            jt: 0,
            jf: 0,
            k: 0x0fff_ffff,
        },
        // Jump if A == index
        libc::sock_filter {
            code: 0x15, // BPF_JMP + BPF_JEQ + BPF_K
            jt: 0,
            jf: 1,
            k: index as u32,
        },
        // Return pass
        libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x0fff_ffff },
        // Return reject
        libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 },
    ];

    let fprog = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: Attaching a BPF filter to a valid socket with correctly-formed sock_fprog.
    let ret = ffi::raw_setsockopt(fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &fprog);
    if ret < 0 {
        warn!("Failed to attach BPF index filter: {}", io::Error::last_os_error());
    }
}

// ─── Data Callback (replaces data_callback) ─────────────────────────────────

/// Per-channel data for an open HCI socket reader task.
struct ControlData {
    channel: u16,
    fd: OwnedFd,
    buf: Vec<u8>,
}

/// Read from the HCI monitor/control socket and dispatch packets.
///
/// This replaces C `data_callback()` (control.c lines 903-978).
/// Called in a loop by the spawned tokio task for each open channel.
fn read_and_dispatch(data: &mut ControlData) {
    let mut hdr_buf = [0u8; MGMT_HDR_SIZE];
    let mut control_buf = [0u8; 64];

    let mut iov = [
        libc::iovec { iov_base: hdr_buf.as_mut_ptr() as *mut libc::c_void, iov_len: MGMT_HDR_SIZE },
        libc::iovec {
            iov_base: data.buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: data.buf.len(),
        },
    ];

    let mut msg: libc::msghdr = ffi::raw_zeroed();
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = 2;
    msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control_buf.len();

    loop {
        // SAFETY: recvmsg on a valid socket fd with properly initialized msghdr.
        let len = ffi::raw_recvmsg(data.fd.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT);
        if len < 0 {
            break;
        }
        if (len as usize) < MGMT_HDR_SIZE {
            break;
        }

        // Parse SCM_TIMESTAMP and SCM_CREDENTIALS from cmsg
        let mut tv: Option<libc::timeval> = None;
        let mut cred: Option<libc::ucred> = None;

        // Parse cmsg ancillary data for timestamp and credentials.
        let mut cmsg_ptr: *mut libc::cmsghdr = match ffi::raw_cmsg_firsthdr(&msg) {
            Some(p) => p,
            None => std::ptr::null_mut(),
        };
        while !cmsg_ptr.is_null() {
            let (cmsg_level, cmsg_type, data_ptr) = ffi::raw_cmsg_read(cmsg_ptr);
            if cmsg_level == libc::SOL_SOCKET {
                if cmsg_type == libc::SCM_TIMESTAMP {
                    tv = Some(ffi::raw_read_unaligned_ptr::<libc::timeval>(data_ptr));
                }
                if cmsg_type == libc::SCM_CREDENTIALS {
                    cred = Some(ffi::raw_read_unaligned_ptr::<libc::ucred>(data_ptr));
                }
            }
            cmsg_ptr = match ffi::raw_cmsg_nxthdr(&msg, cmsg_ptr) {
                Some(p) => p,
                None => break,
            };
        }

        // Parse MGMT header fields (little-endian)
        let opcode = u16::from_le_bytes([hdr_buf[0], hdr_buf[1]]);
        let index = u16::from_le_bytes([hdr_buf[2], hdr_buf[3]]);
        let pktlen = u16::from_le_bytes([hdr_buf[4], hdr_buf[5]]) as usize;

        let default_tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
        let tv_ref = tv.as_ref().unwrap_or(&default_tv);

        let pkt_data = &data.buf[..pktlen.min(data.buf.len())];

        match data.channel {
            HCI_CHANNEL_CONTROL => {
                packet::packet_control(tv_ref, cred.as_ref(), index, opcode, pkt_data, pktlen);
            }
            HCI_CHANNEL_MONITOR => {
                // Write to btsnoop file
                if let Ok(mut guard) = BTSNOOP_FILE.lock() {
                    if let Some(ref mut snoop) = *guard {
                        let _ = snoop.write_hci(tv_ref, index, opcode, 0, pkt_data);
                    }
                }
                // Inject to Ellisys
                ellisys::ellisys_inject_hci(tv_ref, index, opcode, pkt_data, pktlen as u16);
                // Dispatch to packet monitor
                packet::packet_monitor(tv_ref, cred.as_ref(), index, opcode, pkt_data, pktlen);
            }
            _ => {}
        }
    }
}

/// Open an HCI socket channel, optionally attach an index filter, and spawn
/// an async reader task.
///
/// Replaces C `open_channel()` (control.c lines 1054-1082).
fn open_channel(channel: u16) -> Result<(), io::Error> {
    let fd = open_socket(channel)?;
    let raw_fd = fd.as_raw_fd();

    let filter_idx = FILTER_INDEX.load(Ordering::Relaxed);
    if filter_idx != HCI_DEV_NONE {
        attach_index_filter(raw_fd, filter_idx);
    }

    let async_fd = AsyncFd::new(fd)?;

    tokio::spawn(async move {
        let inner_fd = async_fd.into_inner();
        let mut data = ControlData { channel, fd: inner_fd, buf: vec![0u8; MAX_PACKET_SIZE] };

        // Re-wrap for async readiness. We need to re-create AsyncFd from the fd.
        // Use a raw fd approach with OwnedFd for the loop.
        let raw = data.fd.as_raw_fd();
        // SAFETY: Duplicating the fd for AsyncFd is safe as we control its lifetime.
        let dup_fd = ffi::raw_owned_fd(ffi::raw_dup(raw));
        let Ok(async_fd2) = AsyncFd::new(dup_fd) else {
            return;
        };

        loop {
            let guard = async_fd2.readable().await;
            match guard {
                Ok(mut ready) => {
                    read_and_dispatch(&mut data);
                    ready.clear_ready();
                }
                Err(_) => break,
            }
        }
    });

    Ok(())
}

// ─── /dev/kmsg Integration ──────────────────────────────────────────────────

/// Open `/dev/kmsg` for reading and spawn a task that tails it for
/// Bluetooth-related kernel messages.
///
/// Replaces C `open_kmsg()` (control.c lines 1124-1138).
fn open_kmsg() -> Result<(), io::Error> {
    // SAFETY: Opening /dev/kmsg read-only. This is a valid kernel interface.
    let fd = ffi::raw_open(c"/dev/kmsg", libc::O_RDONLY | libc::O_NONBLOCK);
    if fd < 0 {
        let err = io::Error::last_os_error();
        warn!("Failed to open /dev/kmsg: {}", err);
        return Err(err);
    }

    // SAFETY: fd is valid from the open() call above.
    let owned_fd = ffi::raw_owned_fd(fd);

    // Seek to end to only get new messages
    // Seek to end to only get new messages.
    ffi::raw_lseek(owned_fd.as_raw_fd(), 0, libc::SEEK_END);

    let async_fd = AsyncFd::new(owned_fd)?;

    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let guard = async_fd.readable().await;
            match guard {
                Ok(mut ready) => {
                    // Read from /dev/kmsg into a stack buffer.
                    let len = ffi::raw_read(async_fd.as_raw_fd(), &mut buf);
                    if len <= 0 {
                        ready.clear_ready();
                        continue;
                    }
                    let len = len as usize;

                    // Check if kernel message is from Bluetooth
                    let msg_str = String::from_utf8_lossy(&buf[..len]);
                    if let Some(pos) = msg_str.to_lowercase().find("bluetooth:") {
                        // Replace "Bluetooth" with "Kernel" prefix (skip "Blu" and place "Kernel")
                        let bt_pos = pos + 3; // skip past "Blu" to "etooth:"
                        let mut output = Vec::with_capacity(len);
                        output.extend_from_slice("Kernel".as_bytes());
                        let remaining_start = bt_pos + "etooth".len();
                        if remaining_start < len {
                            output.extend_from_slice(&buf[remaining_start..len]);
                        }
                        // Remove trailing newline
                        if output.last() == Some(&b'\n') {
                            output.pop();
                        }
                        // Add null terminator as C does
                        if output.last() != Some(&0) {
                            output.push(0);
                        }

                        let mut tv: libc::timeval = ffi::raw_zeroed();
                        // Get current time of day.
                        ffi::raw_gettimeofday(&mut tv);

                        if let Ok(mut guard) = BTSNOOP_FILE.lock() {
                            if let Some(ref mut snoop) = *guard {
                                let _ = snoop.write_hci(
                                    &tv,
                                    HCI_DEV_NONE,
                                    BtSnoopOpcode::SystemNote as u16,
                                    0,
                                    &output,
                                );
                            }
                        }
                        packet::packet_monitor(
                            &tv,
                            None,
                            HCI_DEV_NONE,
                            BtSnoopOpcode::SystemNote as u16,
                            &output,
                            output.len(),
                        );
                    }
                    ready.clear_ready();
                }
                Err(_) => break,
            }
        }
    });

    Ok(())
}

// ─── Unix Domain Server (replaces control_server + server_accept_callback) ──

/// Open a PF_UNIX/SOCK_STREAM server socket at the specified path, accept
/// client connections, and parse MGMT header+payload streams from each client.
///
/// Replaces C `control_server()` (control.c lines 1221-1265) and
/// `server_accept_callback()` (lines 1179-1217) and `client_callback()`
/// (lines 1140-1177).
pub fn control_server(path: &str) {
    {
        let sfd = SERVER_FD.lock().unwrap();
        if *sfd >= 0 {
            return;
        }
    }

    if path.len() > 107 {
        // sizeof(sockaddr_un.sun_path) - 1
        eprintln!("Socket name too long");
        return;
    }

    // Remove any stale socket file
    let _ = std::fs::remove_file(path);

    let path_owned = path.to_owned();

    tokio::spawn(async move {
        let listener = match UnixListener::bind(&path_owned) {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to open server socket: {}", e);
                return;
            }
        };

        {
            // SAFETY: Accessing the raw fd of the tokio UnixListener to store in
            // the global SERVER_FD sentinel.
            let mut sfd = SERVER_FD.lock().unwrap();
            *sfd = listener.as_fd().as_raw_fd();
        }

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    println!("--- New monitor connection ---");

                    tokio::spawn(async move {
                        let mut buf = vec![0u8; MAX_PACKET_SIZE];
                        let mut offset: usize = 0;

                        let fd = stream.into_std().unwrap();
                        fd.set_nonblocking(true).ok();
                        let Ok(async_fd) = AsyncFd::new(fd) else {
                            return;
                        };

                        loop {
                            let guard = async_fd.readable().await;
                            match guard {
                                Ok(mut ready) => {
                                    // Receive data from connected socket.
                                    let len = ffi::raw_recv(async_fd.as_raw_fd(), &mut buf[offset..], libc::MSG_DONTWAIT);
                                    if len <= 0 {
                                        if len == 0 {
                                            break; // Connection closed
                                        }
                                        ready.clear_ready();
                                        continue;
                                    }
                                    offset += len as usize;

                                    // Parse complete MGMT packets (mgmt_hdr: 6 bytes)
                                    debug_assert_eq!(MGMT_HDR_SIZE, mem::size_of::<mgmt_hdr>());
                                    while offset >= MGMT_HDR_SIZE {
                                        let pktlen = u16::from_le_bytes([buf[4], buf[5]]) as usize;

                                        if offset < pktlen + MGMT_HDR_SIZE {
                                            break;
                                        }

                                        let opcode = u16::from_le_bytes([buf[0], buf[1]]);
                                        let index = u16::from_le_bytes([buf[2], buf[3]]);
                                        debug!(
                                            "Server client: opcode 0x{:04x} [{}] index {} len {}",
                                            opcode,
                                            mgmt_opstr(opcode),
                                            index,
                                            pktlen
                                        );

                                        packet::packet_monitor(
                                            &libc::timeval { tv_sec: 0, tv_usec: 0 },
                                            None,
                                            index,
                                            opcode,
                                            &buf[MGMT_HDR_SIZE..MGMT_HDR_SIZE + pktlen],
                                            pktlen,
                                        );

                                        let consumed = pktlen + MGMT_HDR_SIZE;
                                        offset -= consumed;
                                        if offset > 0 {
                                            buf.copy_within(consumed..consumed + offset, 0);
                                        }
                                    }
                                    ready.clear_ready();
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept client socket: {}", e);
                }
            }
        }
    });
}

// ─── TTY Framing (replaces process_data + tty_callback + control_tty) ───────

/// Parse a single drop counter from the extended header data.
fn parse_drops(data: &[u8], pos: &mut usize, total: &mut u32) -> Option<u8> {
    if *pos >= data.len() {
        return None;
    }
    let drops = data[*pos];
    *total += drops as u32;
    *pos += 1;
    Some(drops)
}

/// Parse TTY extended headers, extracting drop counters and timestamps.
///
/// Replaces C `tty_parse_header()` (control.c lines 1281-1352).
fn tty_parse_header(ext_hdr: &[u8], hdr_len: usize) -> (Option<libc::timeval>, u32) {
    let mut tv: Option<libc::timeval> = None;
    let mut cmd: u8 = 0;
    let mut evt: u8 = 0;
    let mut acl_tx: u8 = 0;
    let mut acl_rx: u8 = 0;
    let mut sco_tx: u8 = 0;
    let mut sco_rx: u8 = 0;
    let mut other: u8 = 0;
    let mut total: u32 = 0;
    let mut pos: usize = 0;
    let data = &ext_hdr[..hdr_len.min(ext_hdr.len())];

    while pos < data.len() {
        let type_ = data[pos];
        pos += 1;

        match type_ {
            TTY_EXTHDR_COMMAND_DROPS => {
                if let Some(d) = parse_drops(data, &mut pos, &mut total) {
                    cmd = d;
                } else {
                    break;
                }
            }
            TTY_EXTHDR_EVENT_DROPS => {
                if let Some(d) = parse_drops(data, &mut pos, &mut total) {
                    evt = d;
                } else {
                    break;
                }
            }
            TTY_EXTHDR_ACL_TX_DROPS => {
                if let Some(d) = parse_drops(data, &mut pos, &mut total) {
                    acl_tx = d;
                } else {
                    break;
                }
            }
            TTY_EXTHDR_ACL_RX_DROPS => {
                if let Some(d) = parse_drops(data, &mut pos, &mut total) {
                    acl_rx = d;
                } else {
                    break;
                }
            }
            TTY_EXTHDR_SCO_TX_DROPS => {
                if let Some(d) = parse_drops(data, &mut pos, &mut total) {
                    sco_tx = d;
                } else {
                    break;
                }
            }
            TTY_EXTHDR_SCO_RX_DROPS => {
                if let Some(d) = parse_drops(data, &mut pos, &mut total) {
                    sco_rx = d;
                } else {
                    break;
                }
            }
            TTY_EXTHDR_OTHER_DROPS => {
                if let Some(d) = parse_drops(data, &mut pos, &mut total) {
                    other = d;
                } else {
                    break;
                }
            }
            TTY_EXTHDR_TS32 => {
                if pos + 4 > data.len() {
                    break;
                }
                let ts32 = bt_get_le32(&data[pos..]);
                pos += 4;
                // ts32 is in units of 1/10th of a millisecond
                let ctv = libc::timeval {
                    tv_sec: (ts32 / 10000) as libc::time_t,
                    tv_usec: ((ts32 % 10000) * 100) as libc::suseconds_t,
                };
                tv = Some(ctv);
            }
            _ => {
                println!("Unknown extended header type {}", type_);
                break;
            }
        }
    }

    if total > 0 {
        println!(
            "* Drops: cmd {} evt {} acl_tx {} acl_rx {} sco_tx {} sco_rx {} other {}",
            cmd, evt, acl_tx, acl_rx, sco_tx, sco_rx, other
        );
    }

    (tv, total)
}

/// Process buffered TTY data, extracting complete frames and dispatching them.
///
/// Replaces C `process_data()` (control.c lines 1354-1395).
fn process_tty_data(buf: &mut [u8], offset: &mut usize) {
    while *offset >= TTY_HDR_SIZE {
        // Parse header fields (all little-endian)
        let data_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let opcode = u16::from_le_bytes([buf[2], buf[3]]);
        let _flags = buf[4];
        let hdr_len = buf[5] as usize;

        if *offset < 2 + data_len {
            return;
        }

        if *offset < TTY_HDR_SIZE + hdr_len {
            eprintln!("Received corrupted data from TTY");
            let remove = 2 + data_len;
            if remove <= *offset {
                buf.copy_within(remove..*offset, 0);
                *offset -= remove;
            }
            return;
        }

        // Parse extended header
        let ext_hdr_start = TTY_HDR_SIZE;
        let ext_hdr_end = ext_hdr_start + hdr_len;
        let (tv, drops) = tty_parse_header(&buf[ext_hdr_start..], hdr_len);

        // Payload starts after the extended header
        let payload_start = ext_hdr_end;
        let pktlen = data_len.saturating_sub(4 + hdr_len);
        let payload_end = payload_start + pktlen.min(buf.len().saturating_sub(payload_start));
        let payload = &buf[payload_start..payload_end];

        let default_tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
        let tv_ref = tv.as_ref().unwrap_or(&default_tv);

        // Write to btsnoop
        if let Ok(mut guard) = BTSNOOP_FILE.lock() {
            if let Some(ref mut snoop) = *guard {
                let _ = snoop.write_hci(tv_ref, 0, opcode, drops, payload);
            }
        }

        // Inject to Ellisys
        ellisys::ellisys_inject_hci(tv_ref, 0, opcode, payload, pktlen as u16);

        // Dispatch to packet monitor
        packet::packet_monitor(tv_ref, None, 0, opcode, payload, pktlen);

        // Remove consumed data
        let consumed = 2 + data_len;
        *offset -= consumed;
        if *offset > 0 {
            buf.copy_within(consumed..consumed + *offset, 0);
        }
    }
}

/// Open a serial TTY device in raw mode at the specified baud rate and
/// spawn an async reader task for TTY-framed HCI data.
///
/// Replaces C `control_tty()` (control.c lines 1417-1473).
pub fn control_tty(path: &str, speed: u32) -> Result<(), io::Error> {
    // SAFETY: Opening a TTY device. This is a designated FFI boundary site.
    let cpath = std::ffi::CString::new(path)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))?;
    let fd = ffi::raw_open(&cpath, libc::O_RDWR | libc::O_NOCTTY);
    if fd < 0 {
        let err = io::Error::last_os_error();
        error!("Failed to open serial port: {}", err);
        return Err(err);
    }

    // SAFETY: fd is valid from the open() call above.
    let owned_fd = ffi::raw_owned_fd(fd);

    // Flush serial port
    // Flush pending terminal I/O.
    ffi::raw_tcflush(owned_fd.as_raw_fd(), libc::TCIOFLUSH);

    // Configure raw mode
    let mut ti: libc::termios = ffi::raw_zeroed();
    // SAFETY: cfmakeraw on a valid termios struct.
    ffi::raw_cfmakeraw(&mut ti);
    ti.c_cflag |= libc::CLOCAL | libc::CREAD;
    ti.c_cflag &= !libc::CRTSCTS;

    // Set terminal baud rate.
    ffi::raw_cfsetspeed(&mut ti, speed as libc::speed_t);

    // SAFETY: tcsetattr on a valid tty fd with a valid termios struct.
    let ret = ffi::raw_tcsetattr(owned_fd.as_raw_fd(), libc::TCSANOW, &ti);
    if ret < 0 {
        let err = io::Error::last_os_error();
        error!("Failed to set serial port settings: {}", err);
        return Err(err);
    }

    println!("--- {} opened ---", path);

    let async_fd = AsyncFd::new(owned_fd)?;

    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let mut offset: usize = 0;

        loop {
            let guard = async_fd.readable().await;
            match guard {
                Ok(mut ready) => {
                    // Read from tty fd into buffer.
                    let len = ffi::raw_read(async_fd.as_raw_fd(), &mut buf[offset..]);
                    if len <= 0 {
                        ready.clear_ready();
                        continue;
                    }
                    offset += len as usize;
                    process_tty_data(&mut buf, &mut offset);
                    ready.clear_ready();
                }
                Err(_) => break,
            }
        }
    });

    Ok(())
}

// ─── J-Link RTT (replaces control_rtt + rtt_callback) ───────────────────────

/// Initialize the J-Link RTT backend and spawn a periodic polling task.
///
/// Replaces C `control_rtt()` (control.c lines 1491-1522).
pub fn control_rtt(jlink_cfg: &str, rtt: Option<&str>) -> Result<(), io::Error> {
    jlink::jlink_init()?;
    jlink::jlink_connect(jlink_cfg)?;
    jlink::jlink_start_rtt(rtt)?;

    println!("--- RTT opened ---");

    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let mut offset: usize = 0;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(1));

        loop {
            interval.tick().await;

            loop {
                match jlink::jlink_rtt_read(&mut buf[offset..]) {
                    Ok(n) if n > 0 => {
                        offset += n;
                        process_tty_data(&mut buf, &mut offset);
                    }
                    _ => break,
                }
            }
        }
    });

    Ok(())
}

// ─── Public API Functions ───────────────────────────────────────────────────

/// Open a btsnoop output file for writing captured packets.
///
/// Replaces C `control_writer()` (control.c lines 1524-1529).
pub fn control_writer(path: &str) -> bool {
    match BtSnoop::create(path, 0, 0, BtSnoopFormat::Monitor) {
        Ok(snoop) => {
            let mut guard = BTSNOOP_FILE.lock().unwrap();
            *guard = Some(snoop);
            true
        }
        Err(e) => {
            error!("Failed to create btsnoop file: {}", e);
            false
        }
    }
}

/// Replay a btsnoop capture file, dispatching each record through the
/// packet decoder pipeline.
///
/// Replaces C `control_reader()` (control.c lines 1531-1595).
pub fn control_reader(path: &str, pager: bool) {
    let snoop = match BtSnoop::open(path, BTSNOOP_FLAG_PKLG_SUPPORT) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to open btsnoop file: {}", e);
            return;
        }
    };

    let format = snoop.get_format();

    match format {
        BtSnoopFormat::Hci | BtSnoopFormat::Uart | BtSnoopFormat::Simulator => {
            packet::del_filter(PacketFilter::SHOW_INDEX);
        }
        BtSnoopFormat::Monitor => {
            packet::add_filter(PacketFilter::SHOW_INDEX);
        }
        _ => {}
    }

    if pager {
        display::open_pager();
    }

    // Wrap in mutex since we need mutable access in the loop
    let mut snoop = snoop;

    match format {
        BtSnoopFormat::Hci | BtSnoopFormat::Uart | BtSnoopFormat::Monitor => {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            loop {
                match snoop.read_hci(&mut buf) {
                    Ok(Some(record)) => {
                        if record.opcode == 0xffff {
                            continue;
                        }
                        let data = &buf[..record.size as usize];
                        packet::packet_monitor(
                            &record.tv,
                            None,
                            record.index,
                            record.opcode,
                            data,
                            record.size as usize,
                        );
                        ellisys::ellisys_inject_hci(
                            &record.tv,
                            record.index,
                            record.opcode,
                            data,
                            record.size,
                        );
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
        BtSnoopFormat::Simulator => {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let mut tv: libc::timeval = libc::timeval { tv_sec: 0, tv_usec: 0 };
            let mut frequency: u16 = 0;
            let mut size: u16 = 0;
            while let Ok(true) = snoop.read_phy(&mut tv, &mut frequency, &mut buf, &mut size) {
                packet::packet_simulator(&tv, frequency, &buf[..size as usize], size as usize);
            }
        }
        _ => {}
    }

    if pager {
        display::close_pager();
    }

    // BtSnoop is dropped here, closing the file.
}

/// Open HCI monitor and control channels for live tracing.
///
/// Falls back to the hcidump backend if HCI_CHANNEL_MONITOR is not
/// supported by the kernel (bind returns EINVAL).
///
/// Replaces C `control_tracing()` (control.c lines 1597-1619).
pub fn control_tracing() -> Result<(), io::Error> {
    packet::add_filter(PacketFilter::SHOW_INDEX);

    {
        let sfd = SERVER_FD.lock().unwrap();
        if *sfd >= 0 {
            return Ok(());
        }
    }

    if open_channel(HCI_CHANNEL_MONITOR).is_err() {
        if !HCIDUMP_FALLBACK.load(Ordering::Relaxed) {
            return Err(io::Error::other("Failed to open monitor channel"));
        }
        debug!("Falling back to hcidump tracing");
        // hcidump_tracing is async; spawn it
        tokio::spawn(async move {
            if let Err(e) = hcidump::hcidump_tracing().await {
                error!("hcidump tracing failed: {}", e);
            }
        });
        return Ok(());
    }

    if packet::has_filter(PacketFilter::SHOW_MGMT_SOCKET) {
        let _ = open_channel(HCI_CHANNEL_CONTROL);
    }

    if packet::has_filter(PacketFilter::SHOW_KMSG) {
        let _ = open_kmsg();
    }

    Ok(())
}

/// Disable MGMT event decoding in `control_message`.
///
/// Replaces C `control_disable_decoding()` (control.c line 1621-1624).
pub fn control_disable_decoding() {
    DECODE_CONTROL.store(false, Ordering::Relaxed);
}

/// Set the controller index filter for BPF filtering on HCI sockets.
///
/// Replaces C `control_filter_index()` (control.c lines 1626-1629).
pub fn control_filter_index(index: u16) {
    FILTER_INDEX.store(index, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tty_hdr_size() {
        // TtyHdr should be 6 bytes (matching C struct)
        assert_eq!(mem::size_of::<TtyHdr>(), 6);
    }

    #[test]
    fn test_tty_get_speed() {
        assert_eq!(tty_get_speed(115200), Some(libc::B115200));
        assert_eq!(tty_get_speed(9600), Some(libc::B9600));
        assert_eq!(tty_get_speed(1000000), Some(libc::B1000000));
        assert_eq!(tty_get_speed(12345), None);
    }

    #[test]
    fn test_control_message_unknown() {
        // Should not panic for unknown opcode
        control_message(0xFFFF, &[], 0);
    }

    #[test]
    fn test_control_message_decode_disabled() {
        DECODE_CONTROL.store(false, Ordering::Relaxed);
        // Should return immediately without printing
        control_message(MGMT_EV_INDEX_ADDED, &[0u8; 10], 10);
        DECODE_CONTROL.store(true, Ordering::Relaxed);
    }

    #[test]
    fn test_ba2str_from_slice() {
        let addr = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        assert_eq!(ba2str_from_slice(&addr), "BC:9A:78:56:34:12");
    }

    #[test]
    fn test_tty_parse_header_empty() {
        let (tv, total) = tty_parse_header(&[], 0);
        assert!(tv.is_none());
        assert_eq!(total, 0);
    }

    #[test]
    fn test_tty_parse_header_ts32() {
        // TTY_EXTHDR_TS32 = 8, followed by 4 bytes LE timestamp
        // ts32 = 50000 (5 seconds = 5000ms = 50000 * 0.1ms)
        let data = [
            TTY_EXTHDR_TS32,
            0x50,
            0xC3,
            0x00,
            0x00, // 50000 in LE
        ];
        let (tv, total) = tty_parse_header(&data, data.len());
        assert_eq!(total, 0);
        let tv = tv.unwrap();
        assert_eq!(tv.tv_sec, 5);
        assert_eq!(tv.tv_usec, 0);
    }

    #[test]
    fn test_tty_parse_header_drops() {
        // 3 command drops, 2 event drops
        let data = [TTY_EXTHDR_COMMAND_DROPS, 3, TTY_EXTHDR_EVENT_DROPS, 2];
        let (tv, total) = tty_parse_header(&data, data.len());
        assert!(tv.is_none());
        assert_eq!(total, 5);
    }

    #[test]
    fn test_control_disable_decoding() {
        DECODE_CONTROL.store(true, Ordering::Relaxed);
        control_disable_decoding();
        assert!(!DECODE_CONTROL.load(Ordering::Relaxed));
        DECODE_CONTROL.store(true, Ordering::Relaxed);
    }

    #[test]
    fn test_control_filter_index() {
        control_filter_index(42);
        assert_eq!(FILTER_INDEX.load(Ordering::Relaxed), 42);
        FILTER_INDEX.store(HCI_DEV_NONE, Ordering::Relaxed);
    }

    #[test]
    fn test_settings_str_coverage() {
        // Ensure all settings strings are present
        assert!(SETTINGS_STR.len() >= 18);
        assert_eq!(SETTINGS_STR[0], "powered");
        assert_eq!(SETTINGS_STR[17], "wbs");
    }
}
