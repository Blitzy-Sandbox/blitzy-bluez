// SPDX-License-Identifier: GPL-2.0-or-later
//
// PCAP capture file format replacing src/shared/pcap.c
//
// Supports reading and writing PCAP packet capture files.
// Used alongside BTSnoop for packet capture functionality.

use std::io::{self, Read, Write};

/// PCAP file magic (little-endian).
pub const PCAP_MAGIC: u32 = 0xA1B2C3D4;
/// PCAP file magic (nanosecond resolution).
pub const PCAP_NSEC_MAGIC: u32 = 0xA1B23C4D;

/// PCAP version.
pub const PCAP_VERSION_MAJOR: u16 = 2;
pub const PCAP_VERSION_MINOR: u16 = 4;

/// PCAP link types for Bluetooth.
pub const PCAP_LINK_TYPE_BLUETOOTH_HCI_H4: u32 = 187;
pub const PCAP_LINK_TYPE_BLUETOOTH_HCI_H4_WITH_PHDR: u32 = 201;
pub const PCAP_LINK_TYPE_BLUETOOTH_LINUX_MONITOR: u32 = 254;

/// PCAP file header (24 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct PcapHeader {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub link_type: u32,
}

/// PCAP packet header (16 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct PcapPacketHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
}

/// A PCAP file writer.
pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    /// Create a new PCAP writer and write the file header.
    pub fn new(mut writer: W, link_type: u32, snaplen: u32) -> io::Result<Self> {
        writer.write_all(&PCAP_MAGIC.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
        writer.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?; // thiszone
        writer.write_all(&0u32.to_le_bytes())?; // sigfigs
        writer.write_all(&snaplen.to_le_bytes())?;
        writer.write_all(&link_type.to_le_bytes())?;
        Ok(Self { writer })
    }

    /// Write a packet record.
    pub fn write_packet(
        &mut self,
        data: &[u8],
        orig_len: u32,
        ts_sec: u32,
        ts_usec: u32,
    ) -> io::Result<()> {
        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&ts_usec.to_le_bytes())?;
        self.writer
            .write_all(&(data.len() as u32).to_le_bytes())?;
        self.writer.write_all(&orig_len.to_le_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// A PCAP file reader.
pub struct PcapReader<R: Read> {
    reader: R,
    /// Whether the file uses nanosecond resolution timestamps.
    pub nanosecond: bool,
    /// The link type from the file header.
    pub link_type: u32,
    /// The snap length from the file header.
    pub snaplen: u32,
}

/// A parsed PCAP packet record.
#[derive(Debug, Clone)]
pub struct PcapPacket {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

impl<R: Read> PcapReader<R> {
    /// Open a PCAP file and read/validate the header.
    pub fn new(mut reader: R) -> io::Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let magic = u32::from_le_bytes(buf);

        let nanosecond = match magic {
            PCAP_MAGIC => false,
            PCAP_NSEC_MAGIC => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "not a PCAP file",
                ))
            }
        };

        let mut buf2 = [0u8; 2];
        reader.read_exact(&mut buf2)?;
        let _major = u16::from_le_bytes(buf2);
        reader.read_exact(&mut buf2)?;
        let _minor = u16::from_le_bytes(buf2);

        reader.read_exact(&mut buf)?;
        let _thiszone = i32::from_le_bytes(buf);
        reader.read_exact(&mut buf)?;
        let _sigfigs = u32::from_le_bytes(buf);
        reader.read_exact(&mut buf)?;
        let snaplen = u32::from_le_bytes(buf);
        reader.read_exact(&mut buf)?;
        let link_type = u32::from_le_bytes(buf);

        Ok(Self {
            reader,
            nanosecond,
            link_type,
            snaplen,
        })
    }

    /// Read the next packet, or None at EOF.
    pub fn read_packet(&mut self) -> io::Result<Option<PcapPacket>> {
        let mut buf = [0u8; 4];
        match self.reader.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let ts_sec = u32::from_le_bytes(buf);

        self.reader.read_exact(&mut buf)?;
        let ts_usec = u32::from_le_bytes(buf);

        self.reader.read_exact(&mut buf)?;
        let incl_len = u32::from_le_bytes(buf);

        self.reader.read_exact(&mut buf)?;
        let orig_len = u32::from_le_bytes(buf);

        let mut data = vec![0u8; incl_len as usize];
        self.reader.read_exact(&mut data)?;

        Ok(Some(PcapPacket {
            ts_sec,
            ts_usec,
            orig_len,
            data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(PCAP_MAGIC, 0xA1B2C3D4);
        assert_eq!(PCAP_LINK_TYPE_BLUETOOTH_HCI_H4, 187);
    }

    #[test]
    fn test_roundtrip() {
        let mut buf = Vec::new();

        {
            let mut writer =
                PcapWriter::new(&mut buf, PCAP_LINK_TYPE_BLUETOOTH_HCI_H4, 65535).unwrap();
            writer.write_packet(&[0x01, 0x02], 2, 1000, 500).unwrap();
            writer.write_packet(&[0x03], 1, 1001, 0).unwrap();
        }

        let mut reader = PcapReader::new(&buf[..]).unwrap();
        assert_eq!(reader.link_type, PCAP_LINK_TYPE_BLUETOOTH_HCI_H4);
        assert!(!reader.nanosecond);

        let pkt1 = reader.read_packet().unwrap().unwrap();
        assert_eq!(pkt1.data, vec![0x01, 0x02]);
        assert_eq!(pkt1.ts_sec, 1000);
        assert_eq!(pkt1.ts_usec, 500);

        let pkt2 = reader.read_packet().unwrap().unwrap();
        assert_eq!(pkt2.data, vec![0x03]);

        assert!(reader.read_packet().unwrap().is_none());
    }

    #[test]
    fn test_invalid_magic() {
        let data = [0u8; 24];
        assert!(PcapReader::new(&data[..]).is_err());
    }

    #[test]
    fn test_header_sizes() {
        assert_eq!(std::mem::size_of::<PcapHeader>(), 24);
        assert_eq!(std::mem::size_of::<PcapPacketHeader>(), 16);
    }
}
