// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012-2014 Intel Corporation. All rights reserved.

//! PCAP capture file format parser.
//!
//! Complete Rust rewrite of `src/shared/pcap.c` and `src/shared/pcap.h`.
//! Provides read-only support for standard PCAP format files with Per-Packet
//! Information (PPI) header parsing. Used by `btmon` for reading captured
//! Bluetooth packet traces.
//!
//! # Design Notes
//!
//! - **Zero `unsafe`** — All file I/O uses safe Rust standard library APIs.
//!   This module has no designated unsafe boundary per AAP Section 0.7.4.
//! - **Native endianness** — PCAP file header fields use native byte order
//!   (determined by the magic number `0xa1b2c3d4`). Only native endian is
//!   supported, matching the C implementation exactly.
//! - **Little-endian PPI fields** — PPI header `len` and `dlt` fields are
//!   always little-endian regardless of host byte order.
//! - **RAII resource management** — The underlying file handle is closed
//!   automatically when the [`Pcap`] struct is dropped. C's manual reference
//!   counting (`pcap_ref`/`pcap_unref`) is replaced by `Arc<Pcap>` at call
//!   sites.
//! - **No write support** — The C implementation is read-only; no
//!   `pcap_write` / `pcap_create` exists.

use std::fs::File;
use std::io::{self, Read};

use zerocopy::{FromBytes, Immutable, KnownLayout};

// ─── Constants ──────────────────────────────────────────────────────────────

/// PCAP native-endian magic number (pcap.c line 77).
///
/// A PCAP file is valid only if its first four bytes match this value in the
/// host's native byte order. The byte-swapped variant (`0xd4c3b2a1`) is NOT
/// supported, matching the C implementation.
pub const PCAP_MAGIC: u32 = 0xa1b2_c3d4;

/// PCAP file format major version number.
pub const PCAP_VERSION_MAJOR: u16 = 2;

/// PCAP file format minor version number.
pub const PCAP_VERSION_MINOR: u16 = 4;

/// Size of the PPI base header in bytes (internal constant).
const PCAP_PPI_SIZE: usize = 8;

// ─── PcapType Enum ──────────────────────────────────────────────────────────

/// PCAP data link type constants (pcap.h lines 15-18).
///
/// Identifies the link-layer header type of captured packets in the PCAP file.
/// These values correspond to the `network` field in the PCAP file header.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapType {
    /// Invalid or unknown link type.
    Invalid = 0,
    /// User-defined link type 0 (`DLT_USER0`, value 147).
    User0 = 147,
    /// Per-Packet Information (PPI) encapsulation (`DLT_PPI`, value 192).
    Ppi = 192,
    /// Bluetooth LE Link Layer (`DLT_BLUETOOTH_LE_LL`, value 251).
    BluetoothLeLl = 251,
}

impl From<u32> for PcapType {
    /// Convert a raw `u32` network/link-type value from the PCAP file header
    /// into a [`PcapType`]. Unknown values map to [`PcapType::Invalid`].
    fn from(value: u32) -> Self {
        match value {
            0 => PcapType::Invalid,
            147 => PcapType::User0,
            192 => PcapType::Ppi,
            251 => PcapType::BluetoothLeLl,
            _ => PcapType::Invalid,
        }
    }
}

// ─── Error Type ─────────────────────────────────────────────────────────────

/// Errors that can occur when opening a PCAP file.
///
/// Replaces the C pattern of returning `NULL` from `pcap_open()` with typed
/// error variants providing detailed failure information.
#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    /// The file does not contain a valid PCAP magic number (`0xa1b2c3d4`).
    #[error("invalid magic number")]
    InvalidMagic,

    /// The PCAP file version is not supported (expected 2.4).
    #[error("unsupported version {major}.{minor}")]
    UnsupportedVersion {
        /// Major version found in the file header.
        major: u16,
        /// Minor version found in the file header.
        minor: u16,
    },

    /// An I/O error occurred during file operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

// ─── Public Record Types ────────────────────────────────────────────────────

/// Result of reading a single PCAP packet record via [`Pcap::read`].
///
/// Contains the packet timestamp and the number of data bytes actually read
/// into the caller's buffer. The actual packet data is written directly into
/// the buffer passed to [`Pcap::read`].
#[derive(Debug, Clone, Copy)]
pub struct PcapRecord {
    /// Timestamp seconds (from the PCAP packet record header).
    pub tv_sec: u32,
    /// Timestamp microseconds (from the PCAP packet record header).
    pub tv_usec: u32,
    /// Number of bytes actually read into the data buffer.
    pub len: u32,
}

/// Result of reading a PPI-encapsulated PCAP packet record via
/// [`Pcap::read_ppi`].
///
/// Contains the packet timestamp, the data link type from the PPI header,
/// the byte offset of the actual payload within the data buffer (past any PPI
/// header extension area), and the payload length.
///
/// The data buffer layout after a successful `read_ppi` call is:
/// ```text
/// [PPI extension data (offset bytes)] [payload (len bytes)]
/// ```
#[derive(Debug, Clone, Copy)]
pub struct PpiRecord {
    /// Timestamp seconds (from the PCAP packet record header).
    pub tv_sec: u32,
    /// Timestamp microseconds (from the PCAP packet record header).
    pub tv_usec: u32,
    /// Data link type from the PPI header (little-endian decoded).
    pub type_: u32,
    /// Byte offset within the data buffer where the payload begins, past the
    /// PPI header extension area (`pph_len - 8`).
    pub offset: u32,
    /// Length of the actual payload data in the buffer (`toread - pph_len`).
    pub len: u32,
}

// ─── Wire-Format Packed Structures (internal) ───────────────────────────────

/// PCAP file header — 24 bytes on disk (pcap.c lines 23-32).
///
/// All fields are in the file's native endianness, which is determined by the
/// magic number. Since we only support native endian (`0xa1b2c3d4`), the
/// fields can be read directly as native integers.
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Clone, Copy)]
struct PcapHdr {
    /// Magic number identifying the file format and byte order.
    magic_number: u32,
    /// Major version number of the file format.
    version_major: u16,
    /// Minor version number of the file format.
    version_minor: u16,
    /// GMT to local time zone correction (typically 0).
    thiszone: i32,
    /// Accuracy of timestamps (typically 0).
    sigfigs: u32,
    /// Maximum length of captured packets, in octets.
    snaplen: u32,
    /// Data link type (network layer protocol).
    network: u32,
}

/// PCAP packet record header — 16 bytes on disk (pcap.c lines 34-40).
///
/// All fields are in native endianness.
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Clone, Copy)]
struct PcapPkt {
    /// Timestamp seconds.
    ts_sec: u32,
    /// Timestamp microseconds.
    ts_usec: u32,
    /// Number of octets of packet data saved in the file.
    incl_len: u32,
    /// Actual length of the packet on the wire.
    orig_len: u32,
}

/// Per-Packet Information (PPI) header — 8 bytes on disk (pcap.c lines 42-48).
///
/// Unlike PCAP headers, PPI `len` and `dlt` fields are always little-endian
/// regardless of host byte order.
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Clone, Copy)]
struct PcapPpi {
    /// PPI version (currently 0).
    version: u8,
    /// PPI flags (must be 0 for valid PPI data).
    flags: u8,
    /// Length of the entire PPI header including extensions (little-endian).
    len: u16,
    /// Data link type of the encapsulated packet (little-endian).
    dlt: u32,
}

// Compile-time size assertions matching C sizeof checks.
const _: () = assert!(std::mem::size_of::<PcapHdr>() == 24);
const _: () = assert!(std::mem::size_of::<PcapPkt>() == 16);
const _: () = assert!(std::mem::size_of::<PcapPpi>() == 8);

// ─── Pcap Reader ────────────────────────────────────────────────────────────

/// Read-only PCAP file reader.
///
/// Replaces the C `struct pcap` with RAII semantics. The underlying file
/// handle is closed automatically when this struct is dropped. C's manual
/// reference counting (`pcap_ref`/`pcap_unref`) is replaced by `Arc<Pcap>`
/// at call sites where shared ownership is needed.
///
/// # Examples
///
/// ```no_run
/// use bluez_shared::capture::pcap::{Pcap, PcapType};
///
/// let mut pcap = Pcap::open("/path/to/capture.pcap").unwrap();
/// assert_eq!(pcap.get_type(), PcapType::BluetoothLeLl);
///
/// let mut buf = vec![0u8; pcap.get_snaplen() as usize];
/// while let Some(record) = pcap.read(&mut buf).unwrap() {
///     println!("ts={}.{} len={}", record.tv_sec, record.tv_usec, record.len);
/// }
/// ```
#[derive(Debug)]
pub struct Pcap {
    /// The open PCAP file handle. Closed automatically on drop.
    fd: File,
    /// Link-layer type parsed from the file header's `network` field.
    type_: PcapType,
    /// Maximum capture length parsed from the file header.
    snaplen: u32,
}

impl Pcap {
    /// Open a PCAP file for reading.
    ///
    /// Validates the magic number (`0xa1b2c3d4`, native endian only) and the
    /// file format version (must be 2.4). Returns an error if the file cannot
    /// be opened, the header cannot be read, the magic number is invalid, or
    /// the version is unsupported.
    ///
    /// Replaces `pcap_open()` (pcap.c lines 57-93).
    pub fn open(path: &str) -> Result<Self, PcapError> {
        let mut file = File::open(path)?;

        // Read the 24-byte file header.
        let mut buf = [0u8; std::mem::size_of::<PcapHdr>()];
        file.read_exact(&mut buf)?;

        // Parse the header via zerocopy — safe zero-copy byte conversion.
        let hdr = PcapHdr::read_from_bytes(&buf).map_err(|_| PcapError::InvalidMagic)?;

        // Validate magic number — native endian only (C line 77).
        // The C code does NOT support the byte-swapped variant (0xd4c3b2a1).
        let magic = hdr.magic_number;
        if magic != PCAP_MAGIC {
            return Err(PcapError::InvalidMagic);
        }

        // Validate version — must be exactly 2.4 (C line 80).
        let major = hdr.version_major;
        let minor = hdr.version_minor;
        if major != PCAP_VERSION_MAJOR || minor != PCAP_VERSION_MINOR {
            return Err(PcapError::UnsupportedVersion { major, minor });
        }

        Ok(Pcap { fd: file, type_: PcapType::from(hdr.network), snaplen: hdr.snaplen })
    }

    /// Returns the link-layer type of this PCAP file.
    ///
    /// Replaces `pcap_get_type()` (pcap.c lines 119-125).
    pub fn get_type(&self) -> PcapType {
        self.type_
    }

    /// Returns the maximum snapshot length of this PCAP file.
    ///
    /// This value indicates the maximum number of bytes captured per packet,
    /// as recorded in the file header.
    ///
    /// Replaces `pcap_get_snaplen()` (pcap.c lines 127-133).
    pub fn get_snaplen(&self) -> u32 {
        self.snaplen
    }

    /// Read the next packet record from the PCAP file.
    ///
    /// Reads the 16-byte packet record header, then reads up to `data.len()`
    /// bytes of packet data into the provided buffer. If the record's included
    /// length (`incl_len`) exceeds the buffer size, the data is silently
    /// truncated to fit the buffer. This matches the C behavior exactly — the
    /// caller must provide a buffer at least as large as `incl_len` to avoid
    /// misaligned subsequent reads.
    ///
    /// Returns `Ok(Some(PcapRecord))` on success with the timestamp and
    /// actual bytes read, `Ok(None)` at end-of-file, or `Err` on I/O error.
    ///
    /// Replaces `pcap_read()` (pcap.c lines 135-167).
    pub fn read(&mut self, data: &mut [u8]) -> Result<Option<PcapRecord>, io::Error> {
        // Read the 16-byte packet record header.
        let mut pkt_buf = [0u8; std::mem::size_of::<PcapPkt>()];
        if !read_exact_or_eof(&mut self.fd, &mut pkt_buf)? {
            return Ok(None);
        }

        // Parse the packet header via zerocopy.
        let pkt = match PcapPkt::read_from_bytes(&pkt_buf) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };

        // Compute bytes to read: min(incl_len, buffer size).
        // Matches C: if (pkt.incl_len > size) toread = size; else toread = pkt.incl_len;
        let incl_len = pkt.incl_len;
        let buf_size = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let toread = core::cmp::min(incl_len, buf_size) as usize;

        // Read packet data into the caller's buffer.
        if toread > 0 {
            self.fd.read_exact(&mut data[..toread])?;
        }

        Ok(Some(PcapRecord { tv_sec: pkt.ts_sec, tv_usec: pkt.ts_usec, len: toread as u32 }))
    }

    /// Read the next PPI-encapsulated packet record from the PCAP file.
    ///
    /// Reads the 16-byte PCAP packet record header, then the 8-byte PPI base
    /// header (consumed separately, not placed in the data buffer), then the
    /// remaining data into the caller's buffer. The PPI `len` and `dlt` fields
    /// are decoded from little-endian byte order.
    ///
    /// The returned [`PpiRecord::offset`] indicates how many bytes of PPI
    /// header extension data precede the actual payload in the buffer, and
    /// [`PpiRecord::len`] gives the payload length.
    ///
    /// Returns `Ok(Some(PpiRecord))` on success, `Ok(None)` at end-of-file
    /// or on invalid PPI data (non-zero flags, `pph_len < 8`), or `Err` on
    /// I/O error.
    ///
    /// Replaces `pcap_read_ppi()` (pcap.c lines 169-221).
    pub fn read_ppi(&mut self, data: &mut [u8]) -> Result<Option<PpiRecord>, io::Error> {
        // Read the 16-byte PCAP packet record header.
        let mut pkt_buf = [0u8; std::mem::size_of::<PcapPkt>()];
        if !read_exact_or_eof(&mut self.fd, &mut pkt_buf)? {
            return Ok(None);
        }

        let pkt = match PcapPkt::read_from_bytes(&pkt_buf) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };

        // Compute total bytes to read for this record: min(incl_len, buffer size).
        let incl_len = pkt.incl_len;
        let buf_size = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let toread = core::cmp::min(incl_len, buf_size) as usize;

        // Read the 8-byte PPI base header (consumed separately from user buffer).
        let mut ppi_buf = [0u8; std::mem::size_of::<PcapPpi>()];
        if !read_exact_or_eof(&mut self.fd, &mut ppi_buf)? {
            return Ok(None);
        }

        let ppi = match PcapPpi::read_from_bytes(&ppi_buf) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };

        // Validate PPI flags — must be zero (C lines 195-196).
        if ppi.flags != 0 {
            return Ok(None);
        }

        // Parse PPI header length — LITTLE-ENDIAN (C uses le16_to_cpu).
        let pph_len = u16::from_le(ppi.len) as usize;

        // Validate PPI header length >= base PPI size (C line 199).
        if pph_len < PCAP_PPI_SIZE {
            return Ok(None);
        }

        // Read remaining data after the PPI base header into the user buffer.
        // Total bytes from file for this record: PPI_SIZE + remaining = toread.
        let remaining = toread.saturating_sub(PCAP_PPI_SIZE);
        if remaining > 0 {
            self.fd.read_exact(&mut data[..remaining])?;
        }

        // Parse PPI data link type — LITTLE-ENDIAN (C uses le32_to_cpu).
        let dlt = u32::from_le(ppi.dlt);

        // Compute offset: bytes of PPI extension data past the base header.
        let offset = (pph_len - PCAP_PPI_SIZE) as u32;

        // Compute payload length: total data minus the full PPI header.
        let len = toread.saturating_sub(pph_len) as u32;

        Ok(Some(PpiRecord { tv_sec: pkt.ts_sec, tv_usec: pkt.ts_usec, type_: dlt, offset, len }))
    }
}

// ─── Helper Functions ───────────────────────────────────────────────────────

/// Read exactly `buf.len()` bytes from the reader, returning `Ok(false)` on
/// a clean end-of-file (zero bytes available) or on a short read (partial
/// data before EOF).
///
/// This matches the C pattern where `read()` returning fewer bytes than the
/// expected struct size causes the caller to return `false` (mapped to
/// `Ok(None)` in the public API). Actual I/O errors (not EOF) propagate as
/// `Err`.
fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> Result<bool, io::Error> {
    let mut offset = 0;
    while offset < buf.len() {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => {
                // EOF reached — either a clean EOF (no bytes read at all) or
                // a partial read followed by EOF. The C code returns false for
                // both cases (bytes_read != expected_size).
                return Ok(false);
            }
            Ok(n) => offset += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_pcap_type_from_known_values() {
        assert_eq!(PcapType::from(0u32), PcapType::Invalid);
        assert_eq!(PcapType::from(147u32), PcapType::User0);
        assert_eq!(PcapType::from(192u32), PcapType::Ppi);
        assert_eq!(PcapType::from(251u32), PcapType::BluetoothLeLl);
    }

    #[test]
    fn test_pcap_type_from_unknown_maps_to_invalid() {
        assert_eq!(PcapType::from(1u32), PcapType::Invalid);
        assert_eq!(PcapType::from(100u32), PcapType::Invalid);
        assert_eq!(PcapType::from(u32::MAX), PcapType::Invalid);
    }

    #[test]
    fn test_pcap_type_discriminant_values() {
        assert_eq!(PcapType::Invalid as u32, 0);
        assert_eq!(PcapType::User0 as u32, 147);
        assert_eq!(PcapType::Ppi as u32, 192);
        assert_eq!(PcapType::BluetoothLeLl as u32, 251);
    }

    #[test]
    fn test_struct_sizes() {
        assert_eq!(std::mem::size_of::<PcapHdr>(), 24);
        assert_eq!(std::mem::size_of::<PcapPkt>(), 16);
        assert_eq!(std::mem::size_of::<PcapPpi>(), 8);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PCAP_MAGIC, 0xa1b2_c3d4);
        assert_eq!(PCAP_VERSION_MAJOR, 2);
        assert_eq!(PCAP_VERSION_MINOR, 4);
    }

    #[test]
    fn test_open_nonexistent_file() {
        let result = Pcap::open("/nonexistent/path/to/file.pcap");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PcapError::Io(_)));
    }

    #[test]
    fn test_open_invalid_magic() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_bad_magic.pcap");
        {
            let mut f = File::create(&path).unwrap();
            // Write an invalid magic number followed by enough zeros for a header.
            f.write_all(&[0x00; 24]).unwrap();
        }
        let result = Pcap::open(path.to_str().unwrap());
        assert!(matches!(result.unwrap_err(), PcapError::InvalidMagic));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_open_unsupported_version() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_bad_version.pcap");
        {
            let mut f = File::create(&path).unwrap();
            // Valid magic, but version 3.0 instead of 2.4.
            f.write_all(&PCAP_MAGIC.to_ne_bytes()).unwrap();
            f.write_all(&3u16.to_ne_bytes()).unwrap(); // major = 3
            f.write_all(&0u16.to_ne_bytes()).unwrap(); // minor = 0
            f.write_all(&[0u8; 16]).unwrap(); // remaining header fields
        }
        let result = Pcap::open(path.to_str().unwrap());
        match result.unwrap_err() {
            PcapError::UnsupportedVersion { major, minor } => {
                assert_eq!(major, 3);
                assert_eq!(minor, 0);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_open_valid_header() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_valid.pcap");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(&PCAP_MAGIC.to_ne_bytes()).unwrap();
            f.write_all(&PCAP_VERSION_MAJOR.to_ne_bytes()).unwrap();
            f.write_all(&PCAP_VERSION_MINOR.to_ne_bytes()).unwrap();
            f.write_all(&0i32.to_ne_bytes()).unwrap(); // thiszone
            f.write_all(&0u32.to_ne_bytes()).unwrap(); // sigfigs
            f.write_all(&65535u32.to_ne_bytes()).unwrap(); // snaplen
            f.write_all(&251u32.to_ne_bytes()).unwrap(); // network = BLE LL
        }
        let pcap = Pcap::open(path.to_str().unwrap()).unwrap();
        assert_eq!(pcap.get_type(), PcapType::BluetoothLeLl);
        assert_eq!(pcap.get_snaplen(), 65535);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_eof_on_empty_body() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_read_eof.pcap");
        {
            let mut f = File::create(&path).unwrap();
            write_valid_header(&mut f, 192); // PPI type
        }
        let mut pcap = Pcap::open(path.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 256];
        let result = pcap.read(&mut buf).unwrap();
        assert!(result.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_single_record() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_read_single.pcap");
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        {
            let mut f = File::create(&path).unwrap();
            write_valid_header(&mut f, 251);
            // Write a packet record header.
            f.write_all(&1000u32.to_ne_bytes()).unwrap(); // ts_sec
            f.write_all(&500u32.to_ne_bytes()).unwrap(); // ts_usec
            f.write_all(&4u32.to_ne_bytes()).unwrap(); // incl_len
            f.write_all(&4u32.to_ne_bytes()).unwrap(); // orig_len
            f.write_all(&payload).unwrap();
        }
        let mut pcap = Pcap::open(path.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 256];
        let record = pcap.read(&mut buf).unwrap().unwrap();
        assert_eq!(record.tv_sec, 1000);
        assert_eq!(record.tv_usec, 500);
        assert_eq!(record.len, 4);
        assert_eq!(&buf[..4], &payload);
        // Next read should be EOF.
        assert!(pcap.read(&mut buf).unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_truncation_when_buffer_small() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_read_trunc.pcap");
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        {
            let mut f = File::create(&path).unwrap();
            write_valid_header(&mut f, 251);
            f.write_all(&100u32.to_ne_bytes()).unwrap(); // ts_sec
            f.write_all(&200u32.to_ne_bytes()).unwrap(); // ts_usec
            f.write_all(&8u32.to_ne_bytes()).unwrap(); // incl_len = 8
            f.write_all(&8u32.to_ne_bytes()).unwrap(); // orig_len
            f.write_all(&payload).unwrap();
        }
        let mut pcap = Pcap::open(path.to_str().unwrap()).unwrap();
        // Buffer smaller than incl_len — read truncates to buffer size.
        let mut buf = [0u8; 4];
        let record = pcap.read(&mut buf).unwrap().unwrap();
        assert_eq!(record.len, 4);
        assert_eq!(&buf[..4], &payload[..4]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_ppi_valid() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_read_ppi.pcap");
        let payload_data = [0x11, 0x22, 0x33, 0x44];
        {
            let mut f = File::create(&path).unwrap();
            write_valid_header(&mut f, 192); // PPI type
            // Packet record header: incl_len = PPI(8) + payload(4) = 12.
            f.write_all(&2000u32.to_ne_bytes()).unwrap(); // ts_sec
            f.write_all(&300u32.to_ne_bytes()).unwrap(); // ts_usec
            f.write_all(&12u32.to_ne_bytes()).unwrap(); // incl_len
            f.write_all(&12u32.to_ne_bytes()).unwrap(); // orig_len
            // PPI header (8 bytes): version=0, flags=0, len=8 (LE), dlt=251 (LE).
            f.write_all(&[0u8]).unwrap(); // version
            f.write_all(&[0u8]).unwrap(); // flags
            f.write_all(&8u16.to_le_bytes()).unwrap(); // len (LE)
            f.write_all(&251u32.to_le_bytes()).unwrap(); // dlt (LE)
            // Payload data.
            f.write_all(&payload_data).unwrap();
        }
        let mut pcap = Pcap::open(path.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 256];
        let ppi = pcap.read_ppi(&mut buf).unwrap().unwrap();
        assert_eq!(ppi.tv_sec, 2000);
        assert_eq!(ppi.tv_usec, 300);
        assert_eq!(ppi.type_, 251);
        assert_eq!(ppi.offset, 0); // pph_len(8) - PPI_SIZE(8) = 0
        assert_eq!(ppi.len, 4); // toread(12) - pph_len(8) = 4
        assert_eq!(&buf[..4], &payload_data);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_ppi_with_extension() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_read_ppi_ext.pcap");
        let ext_data = [0xEE, 0xFF]; // 2 bytes of PPI extension
        let payload_data = [0xAA, 0xBB];
        {
            let mut f = File::create(&path).unwrap();
            write_valid_header(&mut f, 192);
            // incl_len = PPI(8) + ext(2) + payload(2) = 12.
            f.write_all(&3000u32.to_ne_bytes()).unwrap();
            f.write_all(&400u32.to_ne_bytes()).unwrap();
            f.write_all(&12u32.to_ne_bytes()).unwrap();
            f.write_all(&12u32.to_ne_bytes()).unwrap();
            // PPI header: pph_len = 10 (8 base + 2 extension).
            f.write_all(&[0u8]).unwrap(); // version
            f.write_all(&[0u8]).unwrap(); // flags
            f.write_all(&10u16.to_le_bytes()).unwrap(); // len = 10 (LE)
            f.write_all(&147u32.to_le_bytes()).unwrap(); // dlt = User0 (LE)
            // Extension + payload written together.
            f.write_all(&ext_data).unwrap();
            f.write_all(&payload_data).unwrap();
        }
        let mut pcap = Pcap::open(path.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 256];
        let ppi = pcap.read_ppi(&mut buf).unwrap().unwrap();
        assert_eq!(ppi.type_, 147);
        assert_eq!(ppi.offset, 2); // pph_len(10) - PPI_SIZE(8) = 2
        assert_eq!(ppi.len, 2); // toread(12) - pph_len(10) = 2
        // Data buffer: [ext(2), payload(2)]
        assert_eq!(&buf[..2], &ext_data);
        assert_eq!(&buf[2..4], &payload_data);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_ppi_nonzero_flags_returns_none() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_ppi_flags.pcap");
        {
            let mut f = File::create(&path).unwrap();
            write_valid_header(&mut f, 192);
            f.write_all(&0u32.to_ne_bytes()).unwrap(); // ts_sec
            f.write_all(&0u32.to_ne_bytes()).unwrap(); // ts_usec
            f.write_all(&12u32.to_ne_bytes()).unwrap(); // incl_len
            f.write_all(&12u32.to_ne_bytes()).unwrap(); // orig_len
            // PPI with flags = 1 (invalid).
            f.write_all(&[0u8]).unwrap(); // version
            f.write_all(&[1u8]).unwrap(); // flags = 1 (invalid!)
            f.write_all(&8u16.to_le_bytes()).unwrap();
            f.write_all(&251u32.to_le_bytes()).unwrap();
            f.write_all(&[0u8; 4]).unwrap(); // payload
        }
        let mut pcap = Pcap::open(path.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 256];
        let result = pcap.read_ppi(&mut buf).unwrap();
        assert!(result.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_ppi_short_pph_len_returns_none() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_ppi_short_len.pcap");
        {
            let mut f = File::create(&path).unwrap();
            write_valid_header(&mut f, 192);
            f.write_all(&0u32.to_ne_bytes()).unwrap();
            f.write_all(&0u32.to_ne_bytes()).unwrap();
            f.write_all(&12u32.to_ne_bytes()).unwrap();
            f.write_all(&12u32.to_ne_bytes()).unwrap();
            // PPI with pph_len = 4 (less than PPI_SIZE = 8).
            f.write_all(&[0u8]).unwrap(); // version
            f.write_all(&[0u8]).unwrap(); // flags
            f.write_all(&4u16.to_le_bytes()).unwrap(); // len = 4 (too small!)
            f.write_all(&251u32.to_le_bytes()).unwrap();
            f.write_all(&[0u8; 4]).unwrap();
        }
        let mut pcap = Pcap::open(path.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 256];
        let result = pcap.read_ppi(&mut buf).unwrap();
        assert!(result.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_open_truncated_header() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_test_pcap_truncated.pcap");
        {
            let mut f = File::create(&path).unwrap();
            // Only 10 bytes — less than the 24-byte header.
            f.write_all(&[0u8; 10]).unwrap();
        }
        let result = Pcap::open(path.to_str().unwrap());
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_pcap_error_display() {
        let err = PcapError::InvalidMagic;
        assert_eq!(format!("{err}"), "invalid magic number");

        let err = PcapError::UnsupportedVersion { major: 3, minor: 1 };
        assert_eq!(format!("{err}"), "unsupported version 3.1");

        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = PcapError::Io(io_err);
        assert!(format!("{err}").starts_with("I/O error:"));
    }

    /// Helper to write a valid PCAP file header for testing.
    fn write_valid_header(f: &mut File, network: u32) {
        f.write_all(&PCAP_MAGIC.to_ne_bytes()).unwrap();
        f.write_all(&PCAP_VERSION_MAJOR.to_ne_bytes()).unwrap();
        f.write_all(&PCAP_VERSION_MINOR.to_ne_bytes()).unwrap();
        f.write_all(&0i32.to_ne_bytes()).unwrap(); // thiszone
        f.write_all(&0u32.to_ne_bytes()).unwrap(); // sigfigs
        f.write_all(&65535u32.to_ne_bytes()).unwrap(); // snaplen
        f.write_all(&network.to_ne_bytes()).unwrap();
    }
}
