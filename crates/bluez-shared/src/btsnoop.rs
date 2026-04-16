// SPDX-License-Identifier: GPL-2.0-or-later
//
// BTSnoop capture file format replacing src/shared/btsnoop.c
//
// Supports reading and writing BTSnoop packet capture files as defined
// in the Bluetooth specification and used by Android's HCI snoop logging.

use std::io::{self, Read, Write};

/// BTSnoop file magic header.
pub const BTSNOOP_MAGIC: &[u8; 8] = b"btsnoop\0";

/// BTSnoop format version.
pub const BTSNOOP_VERSION: u32 = 1;

/// BTSnoop datalink types.
pub const BTSNOOP_TYPE_HCI_UNENCAP: u32 = 1001;
pub const BTSNOOP_TYPE_HCI_UART: u32 = 1002;
pub const BTSNOOP_TYPE_HCI_BSCP: u32 = 1003;
pub const BTSNOOP_TYPE_HCI_SERIAL: u32 = 1004;
pub const BTSNOOP_TYPE_MONITOR: u32 = 2001;
pub const BTSNOOP_TYPE_SIMULATOR: u32 = 2002;

/// BTSnoop packet flags.
pub const BTSNOOP_FLAG_SENT: u32 = 0;
pub const BTSNOOP_FLAG_RECV: u32 = 1;
pub const BTSNOOP_FLAG_DATA: u32 = 0;
pub const BTSNOOP_FLAG_CMD_EVT: u32 = 2;

/// BTSnoop file header (16 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct BtSnoopHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub datalink_type: u32,
}

/// BTSnoop packet record header (24 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct BtSnoopPacketHeader {
    /// Original length of captured packet.
    pub original_len: u32,
    /// Number of octets captured.
    pub included_len: u32,
    /// Packet flags.
    pub flags: u32,
    /// Cumulative drops.
    pub drops: u32,
    /// Timestamp in microseconds since 2000-01-01 00:00:00 UTC.
    pub timestamp: i64,
}

/// BTSnoop epoch: 2000-01-01 00:00:00 UTC in microseconds since Unix epoch.
/// Matches the Bluetooth specification BTSnoop format.
pub const BTSNOOP_EPOCH_DELTA: i64 = 0x00dcddb30f2f8000;

/// A BTSnoop file writer.
pub struct BtSnoopWriter<W: Write> {
    writer: W,
}

impl<W: Write> BtSnoopWriter<W> {
    /// Create a new BTSnoop writer and write the file header.
    pub fn new(mut writer: W, datalink_type: u32) -> io::Result<Self> {
        writer.write_all(BTSNOOP_MAGIC)?;
        writer.write_all(&BTSNOOP_VERSION.to_be_bytes())?;
        writer.write_all(&datalink_type.to_be_bytes())?;
        Ok(Self { writer })
    }

    /// Write a packet record.
    pub fn write_packet(
        &mut self,
        data: &[u8],
        original_len: u32,
        flags: u32,
        drops: u32,
        timestamp: i64,
    ) -> io::Result<()> {
        self.writer
            .write_all(&original_len.to_be_bytes())?;
        self.writer
            .write_all(&(data.len() as u32).to_be_bytes())?;
        self.writer.write_all(&flags.to_be_bytes())?;
        self.writer.write_all(&drops.to_be_bytes())?;
        self.writer.write_all(&timestamp.to_be_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Get a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }
}

/// A BTSnoop file reader.
pub struct BtSnoopReader<R: Read> {
    reader: R,
    /// Datalink type from the file header.
    pub datalink_type: u32,
}

/// A parsed BTSnoop packet record.
#[derive(Debug, Clone)]
pub struct BtSnoopPacket {
    pub original_len: u32,
    pub flags: u32,
    pub drops: u32,
    pub timestamp: i64,
    pub data: Vec<u8>,
}

impl<R: Read> BtSnoopReader<R> {
    /// Open a BTSnoop file and read/validate the header.
    pub fn new(mut reader: R) -> io::Result<Self> {
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if &magic != BTSNOOP_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a BTSnoop file",
            ));
        }

        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let version = u32::from_be_bytes(buf);
        if version != BTSNOOP_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported BTSnoop version",
            ));
        }

        reader.read_exact(&mut buf)?;
        let datalink_type = u32::from_be_bytes(buf);

        Ok(Self {
            reader,
            datalink_type,
        })
    }

    /// Read the next packet record, or None at EOF.
    pub fn read_packet(&mut self) -> io::Result<Option<BtSnoopPacket>> {
        let mut buf4 = [0u8; 4];
        match self.reader.read_exact(&mut buf4) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let original_len = u32::from_be_bytes(buf4);

        self.reader.read_exact(&mut buf4)?;
        let included_len = u32::from_be_bytes(buf4);

        self.reader.read_exact(&mut buf4)?;
        let flags = u32::from_be_bytes(buf4);

        self.reader.read_exact(&mut buf4)?;
        let drops = u32::from_be_bytes(buf4);

        let mut buf8 = [0u8; 8];
        self.reader.read_exact(&mut buf8)?;
        let timestamp = i64::from_be_bytes(buf8);

        let mut data = vec![0u8; included_len as usize];
        self.reader.read_exact(&mut data)?;

        Ok(Some(BtSnoopPacket {
            original_len,
            flags,
            drops,
            timestamp,
            data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_constants() {
        assert_eq!(BTSNOOP_MAGIC, b"btsnoop\0");
        assert_eq!(BTSNOOP_VERSION, 1);
        assert_eq!(BTSNOOP_TYPE_MONITOR, 2001);
    }

    #[test]
    fn test_roundtrip() {
        let mut buf = Vec::new();

        // Write
        {
            let mut writer =
                BtSnoopWriter::new(&mut buf, BTSNOOP_TYPE_HCI_UART).unwrap();
            writer
                .write_packet(&[0x01, 0x02, 0x03], 3, BTSNOOP_FLAG_SENT, 0, 1000)
                .unwrap();
            writer
                .write_packet(&[0x04, 0x05], 2, BTSNOOP_FLAG_RECV, 0, 2000)
                .unwrap();
        }

        // Read
        let mut reader = BtSnoopReader::new(&buf[..]).unwrap();
        assert_eq!(reader.datalink_type, BTSNOOP_TYPE_HCI_UART);

        let pkt1 = reader.read_packet().unwrap().unwrap();
        assert_eq!(pkt1.data, vec![0x01, 0x02, 0x03]);
        assert_eq!(pkt1.flags, BTSNOOP_FLAG_SENT);
        assert_eq!(pkt1.timestamp, 1000);

        let pkt2 = reader.read_packet().unwrap().unwrap();
        assert_eq!(pkt2.data, vec![0x04, 0x05]);
        assert_eq!(pkt2.flags, BTSNOOP_FLAG_RECV);

        assert!(reader.read_packet().unwrap().is_none());
    }

    #[test]
    fn test_invalid_magic() {
        let data = b"notsnoop________";
        let result = BtSnoopReader::new(&data[..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_header_size() {
        assert_eq!(std::mem::size_of::<BtSnoopPacketHeader>(), 24);
    }

    #[test]
    fn test_file_header_size() {
        assert_eq!(std::mem::size_of::<BtSnoopHeader>(), 16);
    }
}
