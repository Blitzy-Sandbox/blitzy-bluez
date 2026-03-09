// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Rust rewrite

use std::fmt;
use std::str::FromStr;

/// Bluetooth device address (6 bytes, stored in little-endian wire order).
///
/// Corresponds to `bdaddr_t` from `bluetooth.h`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct BdAddr(pub [u8; 6]);

impl BdAddr {
    /// All-zero address (`BDADDR_ANY`).
    pub const ANY: BdAddr = BdAddr([0x00; 6]);

    /// All-ones address (`BDADDR_ALL`).
    pub const ALL: BdAddr = BdAddr([0xff; 6]);

    /// Local address (`BDADDR_LOCAL` = 00:00:00:FF:FF:FF).
    pub const LOCAL: BdAddr = BdAddr([0x00, 0x00, 0x00, 0xff, 0xff, 0xff]);

    /// Returns true if this is the all-zero address.
    pub fn is_any(&self) -> bool {
        *self == Self::ANY
    }

    /// Returns the address bytes in wire (little-endian) order.
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Swap byte order (reverse the 6 bytes). Corresponds to `baswap()`.
    pub fn swap(&self) -> BdAddr {
        let mut out = [0u8; 6];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = self.0[5 - i];
        }
        BdAddr(out)
    }

    /// Extract the OUI (first 3 bytes in display order = last 3 in wire order).
    /// Returns a string like "AB:CD:EF". Corresponds to `ba2oui()`.
    pub fn oui(&self) -> String {
        format!("{:02X}:{:02X}:{:02X}", self.0[5], self.0[4], self.0[3])
    }
}

/// Display as colon-separated uppercase hex: "AA:BB:CC:DD:EE:FF".
///
/// BlueZ stores addresses in little-endian wire order, but displays them
/// in big-endian (most-significant byte first), matching `ba2str()`.
impl fmt::Display for BdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[5], self.0[4], self.0[3], self.0[2], self.0[1], self.0[0]
        )
    }
}

/// Display as lowercase colon-separated hex, matching `ba2strlc()`.
pub fn bd_addr_to_lower(addr: &BdAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr.0[5], addr.0[4], addr.0[3], addr.0[2], addr.0[1], addr.0[0]
    )
}

impl fmt::Debug for BdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BdAddr({})", self)
    }
}

/// Parse error for Bluetooth addresses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid Bluetooth address format")]
pub struct ParseBdAddrError;

/// Parse from "XX:XX:XX:XX:XX:XX" format. Corresponds to `str2ba()`.
impl FromStr for BdAddr {
    type Err = ParseBdAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Validate format matches `bachk()`: exactly 17 chars, colons at positions 2,5,8,11,14
        if s.len() != 17 {
            return Err(ParseBdAddrError);
        }

        let bytes = s.as_bytes();
        for &pos in &[2, 5, 8, 11, 14] {
            if bytes[pos] != b':' {
                return Err(ParseBdAddrError);
            }
        }

        let mut addr = [0u8; 6];
        // Parse in display order (big-endian), store in wire order (little-endian)
        for (i, chunk) in s.split(':').enumerate() {
            if chunk.len() != 2 {
                return Err(ParseBdAddrError);
            }
            addr[5 - i] = u8::from_str_radix(chunk, 16).map_err(|_| ParseBdAddrError)?;
        }

        Ok(BdAddr(addr))
    }
}

/// Bluetooth address type. Corresponds to `BDADDR_BREDR`, `BDADDR_LE_PUBLIC`, `BDADDR_LE_RANDOM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BdAddrType {
    BrEdr = 0x00,
    LePublic = 0x01,
    LeRandom = 0x02,
}

impl BdAddrType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::BrEdr),
            0x01 => Some(Self::LePublic),
            0x02 => Some(Self::LeRandom),
            _ => None,
        }
    }
}

impl fmt::Display for BdAddrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BdAddrType::BrEdr => write!(f, "BR/EDR"),
            BdAddrType::LePublic => write!(f, "LE Public"),
            BdAddrType::LeRandom => write!(f, "LE Random"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_and_parse() {
        let addr = BdAddr([0x78, 0x56, 0x34, 0x12, 0xAB, 0xCD]);
        let s = addr.to_string();
        assert_eq!(s, "CD:AB:12:34:56:78");

        let parsed: BdAddr = s.parse().unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_display_lowercase() {
        let addr = BdAddr([0x78, 0x56, 0x34, 0x12, 0xab, 0xcd]);
        assert_eq!(bd_addr_to_lower(&addr), "cd:ab:12:34:56:78");
    }

    #[test]
    fn test_any_all_local() {
        assert_eq!(BdAddr::ANY.to_string(), "00:00:00:00:00:00");
        assert_eq!(BdAddr::ALL.to_string(), "FF:FF:FF:FF:FF:FF");
        assert_eq!(BdAddr::LOCAL.to_string(), "FF:FF:FF:00:00:00");
        assert!(BdAddr::ANY.is_any());
        assert!(!BdAddr::ALL.is_any());
    }

    #[test]
    fn test_swap() {
        let addr = BdAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let swapped = addr.swap();
        assert_eq!(swapped.0, [0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_oui() {
        let addr: BdAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        assert_eq!(addr.oui(), "AA:BB:CC");
    }

    #[test]
    fn test_parse_errors() {
        assert!("".parse::<BdAddr>().is_err());
        assert!("AA:BB:CC:DD:EE".parse::<BdAddr>().is_err());
        assert!("AA:BB:CC:DD:EE:GG".parse::<BdAddr>().is_err());
        assert!("AA-BB-CC-DD-EE-FF".parse::<BdAddr>().is_err());
        assert!("AABBCCDDEEFF".parse::<BdAddr>().is_err());
    }

    #[test]
    fn test_addr_type() {
        assert_eq!(BdAddrType::from_u8(0x00), Some(BdAddrType::BrEdr));
        assert_eq!(BdAddrType::from_u8(0x01), Some(BdAddrType::LePublic));
        assert_eq!(BdAddrType::from_u8(0x02), Some(BdAddrType::LeRandom));
        assert_eq!(BdAddrType::from_u8(0x03), None);
        assert_eq!(BdAddrType::BrEdr.to_string(), "BR/EDR");
    }

    #[test]
    fn test_default_is_any() {
        assert_eq!(BdAddr::default(), BdAddr::ANY);
    }

    #[test]
    fn test_case_insensitive_parse() {
        let upper: BdAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        let lower: BdAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let mixed: BdAddr = "Aa:Bb:Cc:Dd:Ee:Ff".parse().unwrap();
        assert_eq!(upper, lower);
        assert_eq!(upper, mixed);
    }
}
