// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012-2014 Intel Corporation. All rights reserved.

//! BTSnoop capture file format parser and writer.
//!
//! Complete Rust rewrite of `src/shared/btsnoop.c` and `src/shared/btsnoop.h`.
//! Provides read/write support for BTSnoop packet capture files, Apple
//! PacketLogger (PKLG) format reading, and file rotation for log management.
//! Used primarily by `btmon` for recording and replaying Bluetooth packet
//! traces.
//!
//! # Design Notes
//!
//! - **Zero `unsafe`** — This module uses safe Rust I/O exclusively. The C
//!   implementation uses `read()`/`write()` system calls (not `mmap`), so
//!   memory-mapped file access is not needed.
//! - **RAII resource management** — The underlying file handle is closed
//!   automatically when the [`BtSnoop`] struct is dropped. C's manual
//!   reference counting (`btsnoop_ref`/`btsnoop_unref`) is replaced by
//!   `Arc<BtSnoop>` at call sites.
//! - **Big-endian wire format** — All BTSnoop header and record fields are
//!   stored in big-endian byte order on disk.
//! - **PKLG support** — Apple PacketLogger format files are auto-detected
//!   from their header bytes (big-endian v1 and little-endian v2 variants).
//! - **File rotation** — Write mode supports automatic file rotation based
//!   on configurable maximum file size and file count.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ─── Public Constants ───────────────────────────────────────────────────────

/// Flag to enable Apple PacketLogger (PKLG) format auto-detection in
/// [`BtSnoop::open`]. When set, files that do not begin with the BTSnoop
/// magic number are checked for PKLG format headers.
pub const BTSNOOP_FLAG_PKLG_SUPPORT: u32 = 1 << 0;

/// Maximum Bluetooth packet payload size (1486 + 4 = 1490 bytes).
pub const MAX_PACKET_SIZE: usize = 1486 + 4;

/// HCI adapter type: primary (BR/EDR or LE) controller.
pub const TYPE_PRIMARY: u8 = 0;

/// HCI adapter type: AMP (Alternate MAC/PHY) controller.
pub const TYPE_AMP: u8 = 1;

// ─── BtSnoopFormat ──────────────────────────────────────────────────────────

/// BTSnoop data link type constants (btsnoop.h lines 15-21).
///
/// Identifies the encapsulation format of captured packets in the BTSnoop
/// file. These values correspond to the `type` field in the file header.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtSnoopFormat {
    /// Invalid or unrecognised format.
    Invalid = 0,
    /// Un-encapsulated HCI (H1).
    Hci = 1001,
    /// UART (H4) transport.
    Uart = 1002,
    /// BCSP transport.
    Bcsp = 1003,
    /// Three-Wire (H5) transport.
    ThreeWire = 1004,
    /// BlueZ Monitor protocol.
    Monitor = 2001,
    /// BlueZ Simulator protocol.
    Simulator = 2002,
}

impl From<u32> for BtSnoopFormat {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Invalid,
            1001 => Self::Hci,
            1002 => Self::Uart,
            1003 => Self::Bcsp,
            1004 => Self::ThreeWire,
            2001 => Self::Monitor,
            2002 => Self::Simulator,
            _ => Self::Invalid,
        }
    }
}

// ─── BtSnoopOpcode ──────────────────────────────────────────────────────────

/// BTSnoop monitor opcode values (btsnoop.h lines 25-44).
///
/// Identifies the type of each captured packet record in Monitor format.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtSnoopOpcode {
    /// New HCI index announcement.
    NewIndex = 0,
    /// HCI index removal.
    DelIndex = 1,
    /// HCI command packet.
    CommandPkt = 2,
    /// HCI event packet.
    EventPkt = 3,
    /// ACL data packet (host → controller).
    AclTxPkt = 4,
    /// ACL data packet (controller → host).
    AclRxPkt = 5,
    /// SCO data packet (host → controller).
    ScoTxPkt = 6,
    /// SCO data packet (controller → host).
    ScoRxPkt = 7,
    /// HCI index opened.
    OpenIndex = 8,
    /// HCI index closed.
    CloseIndex = 9,
    /// HCI index information.
    IndexInfo = 10,
    /// Vendor diagnostic data.
    VendorDiag = 11,
    /// System-level note/message.
    SystemNote = 12,
    /// User-level logging message.
    UserLogging = 13,
    /// Control channel opened.
    CtrlOpen = 14,
    /// Control channel closed.
    CtrlClose = 15,
    /// Control channel command.
    CtrlCommand = 16,
    /// Control channel event.
    CtrlEvent = 17,
    /// ISO data packet (host → controller).
    IsoTxPkt = 18,
    /// ISO data packet (controller → host).
    IsoRxPkt = 19,
}

// ─── BtSnoopBus ─────────────────────────────────────────────────────────────

/// HCI transport bus type constants (btsnoop.h lines 51-62).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtSnoopBus {
    /// Virtual (software-emulated) transport.
    Virtual = 0,
    /// USB transport.
    Usb = 1,
    /// PC Card (PCMCIA) transport.
    PcCard = 2,
    /// UART (serial) transport.
    Uart = 3,
    /// RS-232 transport.
    Rs232 = 4,
    /// PCI transport.
    Pci = 5,
    /// SDIO transport.
    Sdio = 6,
    /// SPI transport.
    Spi = 7,
    /// I²C transport.
    I2c = 8,
    /// SMD (Shared Memory Driver) transport.
    Smd = 9,
    /// Virtio transport.
    Virtio = 10,
    /// IPC transport.
    Ipc = 11,
}

// ─── BtSnoopPriority ────────────────────────────────────────────────────────

/// User logging priority levels (btsnoop.h lines 76-83).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtSnoopPriority {
    /// System is unusable.
    Emerg = 0,
    /// Action must be taken immediately.
    Alert = 1,
    /// Critical conditions.
    Crit = 2,
    /// Error conditions.
    Err = 3,
    /// Warning conditions.
    Warning = 4,
    /// Normal but significant condition.
    Notice = 5,
    /// Informational.
    Info = 6,
    /// Debug-level messages.
    Debug = 7,
}

// ─── Wire-Format Packed Structures (internal) ───────────────────────────────

/// BTSnoop file header — exactly 16 bytes on disk (btsnoop.c lines 28-33).
///
/// All multi-byte fields are stored in big-endian byte order.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
struct BtSnoopHdr {
    /// Magic identification pattern: `"btsnoop\0"`.
    id: [u8; 8],
    /// Version number (big-endian, must be 1).
    version: u32,
    /// Data link type (big-endian, one of [`BtSnoopFormat`] values).
    type_: u32,
}

/// BTSnoop packet record header — exactly 24 bytes on disk (btsnoop.c lines
/// 35-43).
///
/// All multi-byte fields are stored in big-endian byte order.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
struct BtSnoopPkt {
    /// Original packet length in bytes (big-endian).
    size: u32,
    /// Included (captured) packet length in bytes (big-endian).
    len: u32,
    /// Packet flags (big-endian). Meaning depends on format.
    flags: u32,
    /// Cumulative dropped packet count (big-endian).
    drops: u32,
    /// Timestamp in microseconds since BTSnoop epoch (big-endian).
    ts: u64,
}

/// Apple PacketLogger record header — exactly 13 bytes on disk (btsnoop.c
/// lines 50-55). Byte order depends on PKLG version (v1 = big-endian,
/// v2 = little-endian).
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Clone, Copy)]
struct PklgPkt {
    /// Record length excluding this field (byte-order varies).
    len: u32,
    /// Timestamp (byte-order varies).
    ts: u64,
    /// Packet type indicator.
    type_: u8,
}

// ─── Public Packed Structures ───────────────────────────────────────────────

/// Payload for [`BtSnoopOpcode::NewIndex`] records (btsnoop.h lines 64-69).
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy, Debug)]
pub struct BtSnoopOpcodeNewIndex {
    /// Controller type ([`TYPE_PRIMARY`] or [`TYPE_AMP`]).
    pub type_: u8,
    /// Transport bus type (one of [`BtSnoopBus`] values).
    pub bus: u8,
    /// Bluetooth device address (6 bytes, little-endian).
    pub bdaddr: [u8; 6],
    /// Controller name (null-padded, up to 8 bytes).
    pub name: [u8; 8],
}

/// Payload for [`BtSnoopOpcode::IndexInfo`] records (btsnoop.h lines 71-74).
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy, Debug)]
pub struct BtSnoopOpcodeIndexInfo {
    /// Bluetooth device address (6 bytes, little-endian).
    pub bdaddr: [u8; 6],
    /// Manufacturer identifier.
    pub manufacturer: u16,
}

/// Payload header for [`BtSnoopOpcode::UserLogging`] records (btsnoop.h
/// lines 85-88).
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy, Debug)]
pub struct BtSnoopOpcodeUserLogging {
    /// Log priority level (one of [`BtSnoopPriority`] values).
    pub priority: u8,
    /// Length of the identifier string that follows this header.
    pub ident_len: u8,
}

// Compile-time size assertions matching C `sizeof()` expectations.
const _: () = assert!(size_of::<BtSnoopHdr>() == 16);
const _: () = assert!(size_of::<BtSnoopPkt>() == 24);
const _: () = assert!(size_of::<PklgPkt>() == 13);
const _: () = assert!(size_of::<BtSnoopOpcodeNewIndex>() == 16);
const _: () = assert!(size_of::<BtSnoopOpcodeIndexInfo>() == 8);
const _: () = assert!(size_of::<BtSnoopOpcodeUserLogging>() == 2);

// ─── Internal Constants ─────────────────────────────────────────────────────

/// BTSnoop file magic: `"btsnoop\0"` (btsnoop.c line 45).
const BTSNOOP_MAGIC: [u8; 8] = [0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00];

/// BTSnoop file format version (must be 1).
const BTSNOOP_VERSION: u32 = 1;

/// BTSnoop header size in bytes.
const BTSNOOP_HDR_SIZE: usize = size_of::<BtSnoopHdr>();

/// BTSnoop packet record header size in bytes.
const BTSNOOP_PKT_SIZE: usize = size_of::<BtSnoopPkt>();

/// BTSnoop epoch offset: microseconds between Unix epoch (1970-01-01) and
/// BTSnoop epoch (2000-01-01 00:00:00 UTC), encoded as the standard constant
/// `0x00E03AB44A676000`.
const BTSNOOP_EPOCH_DELTA: u64 = 0x00E0_3AB4_4A67_6000;

/// Seconds between Unix epoch (1970-01-01) and BTSnoop base date
/// (2000-01-01 00:00:00 UTC).
const EPOCH_OFFSET_SECS: i64 = 946_684_800;

// ─── BtSnoopError ───────────────────────────────────────────────────────────

/// Errors that can occur when operating on BTSnoop capture files.
#[derive(Debug, thiserror::Error)]
pub enum BtSnoopError {
    /// File does not begin with the BTSnoop magic identification bytes.
    #[error("invalid btsnoop magic identification")]
    InvalidMagic,

    /// The BTSnoop file header version field is not the expected value (1).
    #[error("unsupported btsnoop version")]
    UnsupportedVersion,

    /// The data link type in the file header is not a recognised format.
    #[error("invalid btsnoop format")]
    InvalidFormat,

    /// The file was identified as Apple PacketLogger format but PKLG support
    /// was not enabled via [`BTSNOOP_FLAG_PKLG_SUPPORT`].
    #[error("unsupported pklg format")]
    UnsupportedPklg,

    /// A previous read operation encountered a truncated or corrupt record,
    /// and the stream position is no longer valid for further reads.
    #[error("read aborted due to truncated record")]
    Aborted,

    /// An I/O error from the underlying file system.
    #[error(transparent)]
    Io(#[from] io::Error),
}

// ─── HciRecord ──────────────────────────────────────────────────────────────

/// A single HCI packet record returned by [`BtSnoop::read_hci`].
#[derive(Debug, Clone)]
pub struct HciRecord {
    /// Timestamp of the captured packet.
    pub tv: libc::timeval,
    /// HCI adapter index (0xffff for non-adapter-specific records).
    pub index: u16,
    /// Monitor opcode identifying the packet type.
    pub opcode: u16,
    /// Number of payload bytes placed into the caller's buffer.
    pub size: u16,
}

// ─── BtSnoop ────────────────────────────────────────────────────────────────

/// BTSnoop capture file handle for reading and writing Bluetooth packet
/// traces.
///
/// This struct replaces the C `struct btsnoop` (btsnoop.c lines 57-71).
/// Automatic resource cleanup occurs via `Drop`; C-style reference counting
/// (`btsnoop_ref`/`btsnoop_unref`) is replaced by wrapping in `Arc<BtSnoop>`
/// at call sites.
#[derive(Debug)]
pub struct BtSnoop {
    /// Underlying file handle (RAII — closed on drop).
    fd: File,
    /// Data link type identified from the file header.
    format: BtSnoopFormat,
    /// Current HCI adapter index tracked during writes (initialised to
    /// `0xffff`).
    index: u16,
    /// Set to `true` when a read encounters a truncated or corrupt record.
    /// All subsequent reads return `Ok(None)` immediately.
    aborted: bool,
    /// `true` if the file was identified as Apple PacketLogger format.
    pklg_format: bool,
    /// `true` if the PKLG file uses little-endian byte order (v2).
    pklg_v2: bool,
    /// Base file path used for rotation (without `.N` suffix).
    path: Option<String>,
    /// Maximum file size (bytes) before triggering rotation. Zero disables
    /// rotation.
    max_size: usize,
    /// Current file size in bytes.
    cur_size: usize,
    /// Maximum number of rotated files to keep.
    max_count: u32,
    /// Counter for the next rotation file suffix.
    cur_count: u32,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Read exactly `buf.len()` bytes from `reader`, returning `Ok(true)` on
/// success, `Ok(false)` on clean EOF (zero bytes available), and
/// `Err(...)` on partial/short read or I/O error.
fn read_exact_or_eof(reader: &mut File, buf: &mut [u8]) -> Result<bool, io::Error> {
    let mut total = 0usize;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => {
                if total == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short read in btsnoop record",
                ));
            }
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Map a monitor opcode to HCI btsnoop flags for write operations
/// (btsnoop.c lines 299-325).
///
/// Returns `Some(flags)` on success, or `None` if the opcode is not a valid
/// HCI packet type for the basic btsnoop HCI format.
fn get_flags_from_opcode(opcode: u16) -> Option<u32> {
    match opcode {
        x if x == BtSnoopOpcode::CommandPkt as u16 => Some(0x02),
        x if x == BtSnoopOpcode::EventPkt as u16 => Some(0x03),
        x if x == BtSnoopOpcode::AclTxPkt as u16 => Some(0x00),
        x if x == BtSnoopOpcode::AclRxPkt as u16 => Some(0x01),
        _ => None,
    }
}

/// Map HCI packet type + btsnoop flags to a monitor opcode for read
/// operations (btsnoop.c lines 475-513).
///
/// Returns the opcode value, or `0xffff` if the combination is not
/// recognised.
fn get_opcode_from_flags(pkt_type: u8, flags: u32) -> u16 {
    match pkt_type {
        // H4 packet type 0x01 = HCI Command
        0x01 => BtSnoopOpcode::CommandPkt as u16,
        // H4 packet type 0x02 = ACL Data
        0x02 => {
            if flags & 0x01 != 0 {
                BtSnoopOpcode::AclRxPkt as u16
            } else {
                BtSnoopOpcode::AclTxPkt as u16
            }
        }
        // H4 packet type 0x03 = SCO Data
        0x03 => {
            if flags & 0x01 != 0 {
                BtSnoopOpcode::ScoRxPkt as u16
            } else {
                BtSnoopOpcode::ScoTxPkt as u16
            }
        }
        // H4 packet type 0x04 = HCI Event
        0x04 => BtSnoopOpcode::EventPkt as u16,
        // H4 packet type 0x05 = ISO Data
        0x05 => {
            if flags & 0x01 != 0 {
                BtSnoopOpcode::IsoRxPkt as u16
            } else {
                BtSnoopOpcode::IsoTxPkt as u16
            }
        }
        // Type 0xff = infer from btsnoop direction/command flags
        0xff => {
            if flags & 0x02 != 0 {
                // Command/Event based on direction bit
                if flags & 0x01 != 0 {
                    BtSnoopOpcode::EventPkt as u16
                } else {
                    BtSnoopOpcode::CommandPkt as u16
                }
            } else {
                // ACL based on direction bit
                if flags & 0x01 != 0 {
                    BtSnoopOpcode::AclRxPkt as u16
                } else {
                    BtSnoopOpcode::AclTxPkt as u16
                }
            }
        }
        _ => 0xffff,
    }
}

// ─── BtSnoop Implementation ────────────────────────────────────────────────

impl BtSnoop {
    /// Open an existing BTSnoop (or PKLG) capture file for reading.
    ///
    /// Replaces `btsnoop_open()` (btsnoop.c lines 73-135).
    ///
    /// The file is opened read-only. If the file begins with the BTSnoop
    /// magic header, the version and format are validated. If
    /// [`BTSNOOP_FLAG_PKLG_SUPPORT`] is set in `flags` and the file does
    /// not have a BTSnoop header, Apple PacketLogger format detection is
    /// attempted.
    pub fn open(path: &str, flags: u32) -> Result<Self, BtSnoopError> {
        let mut fd = File::open(path)?;

        // Read the 16-byte file header.
        let mut hdr_buf = [0u8; BTSNOOP_HDR_SIZE];
        fd.read_exact(&mut hdr_buf)?;

        let hdr = BtSnoopHdr::read_from_bytes(&hdr_buf)
            .expect("BtSnoopHdr::read_from_bytes on correctly-sized buffer");

        // Check for standard BTSnoop magic.
        if hdr.id == BTSNOOP_MAGIC {
            let version = u32::from_be_bytes(hdr.version.to_ne_bytes());
            if version != BTSNOOP_VERSION {
                return Err(BtSnoopError::UnsupportedVersion);
            }
            let format_val = u32::from_be_bytes(hdr.type_.to_ne_bytes());
            let format = BtSnoopFormat::from(format_val);
            if format == BtSnoopFormat::Invalid {
                return Err(BtSnoopError::InvalidFormat);
            }
            return Ok(Self {
                fd,
                format,
                index: 0xffff,
                aborted: false,
                pklg_format: false,
                pklg_v2: false,
                path: None,
                max_size: 0,
                cur_size: 0,
                max_count: 0,
                cur_count: 0,
            });
        }

        // Not BTSnoop — check if PKLG support is enabled.
        if flags & BTSNOOP_FLAG_PKLG_SUPPORT == 0 {
            return Err(BtSnoopError::UnsupportedPklg);
        }

        // PKLG detection: examine the first 4 bytes for endianness.
        let pklg_v2;
        if hdr_buf[0] == 0x00 && (hdr_buf[1] == 0x00 || hdr_buf[1] == 0x01) {
            // Big-endian PKLG (v1)
            pklg_v2 = false;
        } else if hdr_buf[3] == 0x00 && (hdr_buf[2] == 0x00 || hdr_buf[2] == 0x01) {
            // Little-endian PKLG (v2)
            pklg_v2 = true;
        } else {
            return Err(BtSnoopError::InvalidMagic);
        }

        // PKLG has no file header — seek back to the beginning.
        fd.seek(SeekFrom::Start(0))?;

        Ok(Self {
            fd,
            format: BtSnoopFormat::Monitor,
            index: 0xffff,
            aborted: false,
            pklg_format: true,
            pklg_v2,
            path: None,
            max_size: 0,
            cur_size: 0,
            max_count: 0,
            cur_count: 0,
        })
    }

    /// Create a new BTSnoop capture file for writing.
    ///
    /// Replaces `btsnoop_create()` (btsnoop.c lines 137-188).
    ///
    /// If `max_size` is non-zero, automatic file rotation is enabled: when
    /// the file grows beyond `max_size` bytes a new numbered file is
    /// created. Up to `max_count` rotated files are kept; older files are
    /// deleted. The first file has suffix `.0`, the next `.1`, etc.
    pub fn create(
        path: &str,
        max_size: usize,
        max_count: u32,
        format: BtSnoopFormat,
    ) -> Result<Self, BtSnoopError> {
        // Validate rotation parameters (btsnoop.c line 146).
        if max_size == 0 && max_count > 0 {
            return Err(BtSnoopError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_count requires non-zero max_size",
            )));
        }

        // Determine the actual file path: append ".0" when rotation is
        // enabled.
        let real_path = if max_size > 0 { format!("{path}.0") } else { path.to_owned() };

        let mut fd = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&real_path)?;

        // Write the 16-byte BTSnoop file header.
        let hdr = BtSnoopHdr {
            id: BTSNOOP_MAGIC,
            version: u32::from_ne_bytes(BTSNOOP_VERSION.to_be_bytes()),
            type_: u32::from_ne_bytes((format as u32).to_be_bytes()),
        };
        fd.write_all(hdr.as_bytes())?;

        Ok(Self {
            fd,
            format,
            index: 0xffff,
            aborted: false,
            pklg_format: false,
            pklg_v2: false,
            path: Some(path.to_owned()),
            max_size,
            cur_size: BTSNOOP_HDR_SIZE,
            max_count,
            cur_count: 1,
        })
    }

    /// Return the data link type / encapsulation format of this capture file.
    ///
    /// Replaces `btsnoop_get_format()` (btsnoop.c lines 214-220).
    pub fn get_format(&self) -> BtSnoopFormat {
        self.format
    }

    /// Rotate the capture file when the current file exceeds `max_size`.
    ///
    /// Replaces `btsnoop_rotate()` (btsnoop.c lines 222-256).
    fn rotate(&mut self) -> Result<(), io::Error> {
        // Delete the oldest rotated file if we have exceeded max_count.
        if self.max_count > 0 && self.cur_count >= self.max_count {
            let old_idx = self.cur_count - self.max_count;
            let old_path =
                format!("{}.{}", self.path.as_ref().expect("rotation requires path"), old_idx);
            // Best-effort delete; ignore error if file is already gone.
            let _ = std::fs::remove_file(&old_path);
        }

        // Construct the new file path.
        let new_path =
            format!("{}.{}", self.path.as_ref().expect("rotation requires path"), self.cur_count);
        self.cur_count += 1;

        // Open the new file (old fd is dropped/closed automatically on
        // reassignment).
        let mut new_fd = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&new_path)?;

        // Write the BTSnoop file header.
        let hdr = BtSnoopHdr {
            id: BTSNOOP_MAGIC,
            version: u32::from_ne_bytes(BTSNOOP_VERSION.to_be_bytes()),
            type_: u32::from_ne_bytes((self.format as u32).to_be_bytes()),
        };
        new_fd.write_all(hdr.as_bytes())?;

        self.fd = new_fd;
        self.cur_size = BTSNOOP_HDR_SIZE;
        Ok(())
    }

    /// Write a raw packet record to the capture file.
    ///
    /// Replaces `btsnoop_write()` (btsnoop.c lines 258-297).
    ///
    /// `tv` is the packet timestamp, `flags` and `drops` are stored in the
    /// record header, and `data` is the packet payload.
    pub fn write(
        &mut self,
        tv: &libc::timeval,
        flags: u32,
        drops: u32,
        data: &[u8],
    ) -> Result<(), BtSnoopError> {
        // Check if rotation is needed.
        let record_total = BTSNOOP_PKT_SIZE + data.len();
        if self.max_size > 0 && self.max_size <= self.cur_size + record_total {
            self.rotate()?;
        }

        // Compute BTSnoop timestamp: microseconds since BTSnoop epoch.
        // C code: ts = (tv->tv_sec - 946684800LL) * 1000000LL + tv->tv_usec;
        //         pkt.ts = htobe64(ts + 0x00E03AB44A676000LL);
        let ts_usec = (tv.tv_sec - EPOCH_OFFSET_SECS) * 1_000_000 + tv.tv_usec;
        let ts = (ts_usec as u64).wrapping_add(BTSNOOP_EPOCH_DELTA);

        let data_len = data.len() as u32;
        let pkt = BtSnoopPkt {
            size: u32::from_ne_bytes(data_len.to_be_bytes()),
            len: u32::from_ne_bytes(data_len.to_be_bytes()),
            flags: u32::from_ne_bytes(flags.to_be_bytes()),
            drops: u32::from_ne_bytes(drops.to_be_bytes()),
            ts: u64::from_ne_bytes(ts.to_be_bytes()),
        };

        self.fd.write_all(pkt.as_bytes())?;
        self.fd.write_all(data)?;
        self.cur_size += record_total;

        Ok(())
    }

    /// Write an HCI packet record to the capture file.
    ///
    /// Replaces `btsnoop_write_hci()` (btsnoop.c lines 327-358).
    ///
    /// The `index` and `opcode` values are format-specific; for `Hci`
    /// format the opcode is mapped to btsnoop flags, while for `Monitor`
    /// format the index and opcode are packed into the flags field.
    pub fn write_hci(
        &mut self,
        tv: &libc::timeval,
        index: u16,
        opcode: u16,
        drops: u32,
        data: &[u8],
    ) -> Result<(), BtSnoopError> {
        let flags = match self.format {
            BtSnoopFormat::Hci => {
                if self.index == 0xffff {
                    self.index = index;
                }
                if index != self.index {
                    return Err(BtSnoopError::InvalidFormat);
                }
                match get_flags_from_opcode(opcode) {
                    Some(f) => f,
                    None => return Err(BtSnoopError::InvalidFormat),
                }
            }
            BtSnoopFormat::Monitor => ((index as u32) << 16) | (opcode as u32),
            _ => return Err(BtSnoopError::InvalidFormat),
        };

        self.write(tv, flags, drops, data)
    }

    /// Write a PHY-layer packet record to the capture file.
    ///
    /// Replaces `btsnoop_write_phy()` (btsnoop.c lines 360-378).
    ///
    /// Only valid for [`BtSnoopFormat::Simulator`] files. The `frequency`
    /// is encoded into the record flags.
    pub fn write_phy(
        &mut self,
        tv: &libc::timeval,
        frequency: u16,
        data: &[u8],
    ) -> Result<(), BtSnoopError> {
        let flags = match self.format {
            BtSnoopFormat::Simulator => (1u32 << 16) | (frequency as u32),
            _ => return Err(BtSnoopError::InvalidFormat),
        };

        self.write(tv, flags, 0, data)
    }

    /// Read the next HCI packet record from the capture file.
    ///
    /// Replaces `btsnoop_read_hci()` (btsnoop.c lines 515-589).
    ///
    /// Returns `Ok(Some(record))` with the packet metadata and the payload
    /// written into `buf`, or `Ok(None)` on clean EOF or after a previous
    /// abort. Returns `Err` on I/O errors or corrupt records.
    pub fn read_hci(&mut self, buf: &mut [u8]) -> Result<Option<HciRecord>, BtSnoopError> {
        if self.aborted {
            return Ok(None);
        }

        // Delegate to PKLG reader if in PKLG mode.
        if self.pklg_format {
            return self.pklg_read_hci(buf);
        }

        // Read the 24-byte packet record header.
        let mut pkt_buf = [0u8; BTSNOOP_PKT_SIZE];
        match read_exact_or_eof(&mut self.fd, &mut pkt_buf) {
            Ok(true) => {}
            Ok(false) => return Ok(None), // Clean EOF
            Err(e) => {
                self.aborted = true;
                return Err(BtSnoopError::Io(e));
            }
        }

        let pkt = BtSnoopPkt::read_from_bytes(&pkt_buf)
            .expect("BtSnoopPkt::read_from_bytes on correctly-sized buffer");

        let toread = u32::from_be_bytes(pkt.len.to_ne_bytes()) as usize;
        if toread > MAX_PACKET_SIZE {
            self.aborted = true;
            return Err(BtSnoopError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "btsnoop record exceeds MAX_PACKET_SIZE",
            )));
        }

        let flags = u32::from_be_bytes(pkt.flags.to_ne_bytes());

        // Decode BTSnoop timestamp back to Unix timeval.
        // C code: ts = be64toh(pkt.ts) - 0x00E03AB44A676000LL;
        //         tv->tv_sec  = (ts / 1000000LL) + 946684800LL;
        //         tv->tv_usec = ts % 1000000LL;
        // Note: the subtraction and subsequent division/modulo must use
        // signed arithmetic to correctly handle timestamps before the
        // BTSnoop epoch (Jan 1 2000), matching C's signed int64_t math.
        let raw_ts = u64::from_be_bytes(pkt.ts.to_ne_bytes());
        let ts = raw_ts.wrapping_sub(BTSNOOP_EPOCH_DELTA) as i64;
        let tv = libc::timeval {
            tv_sec: (ts / 1_000_000 + EPOCH_OFFSET_SECS) as libc::time_t,
            tv_usec: (ts % 1_000_000) as libc::suseconds_t,
        };

        // Determine index and opcode based on the file format.
        let (index, opcode, data_offset) = match self.format {
            BtSnoopFormat::Hci => {
                let op = get_opcode_from_flags(0xff, flags);
                (0u16, op, 0usize)
            }
            BtSnoopFormat::Uart => {
                // UART format: first byte is HCI packet type indicator.
                if toread == 0 {
                    self.aborted = true;
                    return Err(BtSnoopError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "uart record with zero length",
                    )));
                }
                let mut type_buf = [0u8; 1];
                match self.fd.read_exact(&mut type_buf) {
                    Ok(()) => {}
                    Err(e) => {
                        self.aborted = true;
                        return Err(BtSnoopError::Io(e));
                    }
                }
                let pkt_type = type_buf[0];
                let op = get_opcode_from_flags(pkt_type, flags);
                // One byte already consumed from the record payload.
                (0u16, op, 1usize)
            }
            BtSnoopFormat::Monitor => {
                let idx = (flags >> 16) as u16;
                let op = (flags & 0xffff) as u16;
                (idx, op, 0usize)
            }
            _ => {
                self.aborted = true;
                return Err(BtSnoopError::InvalidFormat);
            }
        };

        // Read the remaining payload data.
        let remaining = toread - data_offset;
        if remaining > buf.len() {
            self.aborted = true;
            return Err(BtSnoopError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "btsnoop record payload exceeds buffer size",
            )));
        }
        if remaining > 0 {
            match self.fd.read_exact(&mut buf[..remaining]) {
                Ok(()) => {}
                Err(e) => {
                    self.aborted = true;
                    return Err(BtSnoopError::Io(e));
                }
            }
        }

        Ok(Some(HciRecord { tv, index, opcode, size: remaining as u16 }))
    }

    /// Read the next PKLG packet record from the capture file.
    ///
    /// Internal helper called by [`Self::read_hci`] when
    /// [`Self::pklg_format`] is set. Replaces the PKLG path in
    /// `btsnoop_read_hci()` and the dedicated `pklg_read_hci()` helper
    /// (btsnoop.c lines 380-473).
    fn pklg_read_hci(&mut self, buf: &mut [u8]) -> Result<Option<HciRecord>, BtSnoopError> {
        let mut pkt_buf = [0u8; size_of::<PklgPkt>()];
        match read_exact_or_eof(&mut self.fd, &mut pkt_buf) {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(e) => {
                self.aborted = true;
                return Err(BtSnoopError::Io(e));
            }
        }

        let pkt = PklgPkt::read_from_bytes(&pkt_buf)
            .expect("PklgPkt::read_from_bytes on correctly-sized buffer");

        let (toread, tv) = if self.pklg_v2 {
            // Little-endian PKLG (v2).
            let pkt_len = u32::from_le_bytes(pkt.len.to_ne_bytes());
            let ts = u64::from_le_bytes(pkt.ts.to_ne_bytes());
            let data_len = pkt_len.saturating_sub(9) as usize;
            let tv = libc::timeval {
                tv_sec: (ts & 0xffff_ffff) as libc::time_t,
                tv_usec: (ts >> 32) as libc::suseconds_t,
            };
            (data_len, tv)
        } else {
            // Big-endian PKLG (v1).
            let pkt_len = u32::from_be_bytes(pkt.len.to_ne_bytes());
            let ts = u64::from_be_bytes(pkt.ts.to_ne_bytes());
            let data_len = pkt_len.saturating_sub(9) as usize;
            let tv = libc::timeval {
                tv_sec: (ts >> 32) as libc::time_t,
                tv_usec: (ts & 0xffff_ffff) as libc::suseconds_t,
            };
            (data_len, tv)
        };

        if toread > MAX_PACKET_SIZE {
            self.aborted = true;
            return Err(BtSnoopError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "pklg record exceeds MAX_PACKET_SIZE",
            )));
        }

        // Map PKLG packet type to monitor index + opcode
        // (btsnoop.c lines 432-464).
        let pkt_type = pkt.type_;
        let (index, opcode) = match pkt_type {
            0x00 => (0u16, BtSnoopOpcode::CommandPkt as u16),
            0x01 => (0u16, BtSnoopOpcode::EventPkt as u16),
            0x02 => (0u16, BtSnoopOpcode::AclTxPkt as u16),
            0x03 => (0u16, BtSnoopOpcode::AclRxPkt as u16),
            0x08 => (0u16, BtSnoopOpcode::ScoTxPkt as u16),
            0x09 => (0u16, BtSnoopOpcode::ScoRxPkt as u16),
            0x12 => (0u16, BtSnoopOpcode::IsoTxPkt as u16),
            0x13 => (0u16, BtSnoopOpcode::IsoRxPkt as u16),
            0x0b => (0u16, BtSnoopOpcode::VendorDiag as u16),
            0xfc => (0xffffu16, BtSnoopOpcode::SystemNote as u16),
            _ => (0xffffu16, 0xffffu16),
        };

        // Read payload data into the caller's buffer.
        if toread > buf.len() {
            self.aborted = true;
            return Err(BtSnoopError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "pklg record payload exceeds buffer size",
            )));
        }
        if toread > 0 {
            match self.fd.read_exact(&mut buf[..toread]) {
                Ok(()) => {}
                Err(e) => {
                    self.aborted = true;
                    return Err(BtSnoopError::Io(e));
                }
            }
        }

        Ok(Some(HciRecord { tv, index, opcode, size: toread as u16 }))
    }

    /// Read the next PHY-layer packet record from the capture file.
    ///
    /// Replaces `btsnoop_read_phy()` (btsnoop.c lines 591-595).
    ///
    /// **Stub implementation**: always returns `Ok(false)`, matching the C
    /// original which always returns `false`.
    pub fn read_phy(
        &mut self,
        _tv: &mut libc::timeval,
        _frequency: &mut u16,
        _buf: &mut [u8],
        _size: &mut u16,
    ) -> Result<bool, BtSnoopError> {
        Ok(false)
    }
}
