// SPDX-License-Identifier: GPL-2.0-or-later
//
// Network profile implementations (~2.3K LOC C).
//
// Covers PAN (Personal Area Network) and BNEP session management.

use bluez_shared::BdAddr;

// ---------------------------------------------------------------------------
// PAN — Personal Area Network
// ---------------------------------------------------------------------------

/// PAN role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanRole {
    /// Network Access Point — bridges to external network.
    Nap,
    /// Group Ad-hoc Network — peer-to-peer networking.
    Gn,
    /// PAN User — client connecting to NAP/GN.
    Panu,
}

/// PAN connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PanState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}


/// PAN profile plugin.
#[derive(Debug)]
pub struct PanProfile {
    pub local_role: PanRole,
    pub remote_role: Option<PanRole>,
    pub state: PanState,
    pub remote_addr: Option<BdAddr>,
    pub interface: Option<String>,
    pub bridge: Option<String>,
}

impl PanProfile {
    pub fn new(role: PanRole) -> Self {
        Self {
            local_role: role,
            remote_role: None,
            state: PanState::default(),
            remote_addr: None,
            interface: None,
            bridge: None,
        }
    }
}

// ---------------------------------------------------------------------------
// BNEP — Bluetooth Network Encapsulation Protocol
// ---------------------------------------------------------------------------

/// BNEP packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BnepPacketType {
    GeneralEthernet = 0x00,
    Control = 0x01,
    CompressedEthernet = 0x02,
    CompressedEthernetSrcOnly = 0x03,
    CompressedEthernetDstOnly = 0x04,
}

impl BnepPacketType {
    pub fn from_byte(b: u8) -> Option<Self> {
        // Mask off the extension bit (bit 7).
        match b & 0x7F {
            0x00 => Some(Self::GeneralEthernet),
            0x01 => Some(Self::Control),
            0x02 => Some(Self::CompressedEthernet),
            0x03 => Some(Self::CompressedEthernetSrcOnly),
            0x04 => Some(Self::CompressedEthernetDstOnly),
            _ => None,
        }
    }
}

/// BNEP control type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BnepControlType {
    CommandNotUnderstood = 0x00,
    SetupConnectionRequest = 0x01,
    SetupConnectionResponse = 0x02,
    FilterNetTypeSet = 0x03,
    FilterNetTypeResponse = 0x04,
    FilterMultiAddrSet = 0x05,
    FilterMultiAddrResponse = 0x06,
}

impl BnepControlType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::CommandNotUnderstood),
            0x01 => Some(Self::SetupConnectionRequest),
            0x02 => Some(Self::SetupConnectionResponse),
            0x03 => Some(Self::FilterNetTypeSet),
            0x04 => Some(Self::FilterNetTypeResponse),
            0x05 => Some(Self::FilterMultiAddrSet),
            0x06 => Some(Self::FilterMultiAddrResponse),
            _ => None,
        }
    }
}

/// A BNEP packet with its type, addresses, protocol, and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BnepPacket {
    pub packet_type: BnepPacketType,
    /// Destination MAC address (present in General and DstOnly).
    pub dst_addr: Option<[u8; 6]>,
    /// Source MAC address (present in General and SrcOnly).
    pub src_addr: Option<[u8; 6]>,
    /// Ethernet protocol type (e.g. 0x0800 for IPv4).
    pub protocol: u16,
    /// Payload data.
    pub payload: Vec<u8>,
}

impl BnepPacket {
    /// Encode a BNEP packet to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.packet_type as u8);

        match self.packet_type {
            BnepPacketType::GeneralEthernet => {
                // dst(6) + src(6) + proto(2) + payload
                buf.extend_from_slice(
                    self.dst_addr.as_ref().unwrap_or(&[0u8; 6]),
                );
                buf.extend_from_slice(
                    self.src_addr.as_ref().unwrap_or(&[0u8; 6]),
                );
                buf.extend_from_slice(&self.protocol.to_be_bytes());
            }
            BnepPacketType::CompressedEthernet => {
                // Just protocol(2) + payload
                buf.extend_from_slice(&self.protocol.to_be_bytes());
            }
            BnepPacketType::CompressedEthernetSrcOnly => {
                // src(6) + proto(2) + payload
                buf.extend_from_slice(
                    self.src_addr.as_ref().unwrap_or(&[0u8; 6]),
                );
                buf.extend_from_slice(&self.protocol.to_be_bytes());
            }
            BnepPacketType::CompressedEthernetDstOnly => {
                // dst(6) + proto(2) + payload
                buf.extend_from_slice(
                    self.dst_addr.as_ref().unwrap_or(&[0u8; 6]),
                );
                buf.extend_from_slice(&self.protocol.to_be_bytes());
            }
            BnepPacketType::Control => {
                // Control packets: payload only (control type + data).
            }
        }

        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a BNEP packet from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let pkt_type = BnepPacketType::from_byte(data[0])?;
        let mut offset = 1;

        match pkt_type {
            BnepPacketType::GeneralEthernet => {
                // Need at least 6+6+2 = 14 bytes after type
                if data.len() < offset + 14 {
                    return None;
                }
                let mut dst = [0u8; 6];
                dst.copy_from_slice(&data[offset..offset + 6]);
                offset += 6;
                let mut src = [0u8; 6];
                src.copy_from_slice(&data[offset..offset + 6]);
                offset += 6;
                let proto =
                    u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                Some(BnepPacket {
                    packet_type: pkt_type,
                    dst_addr: Some(dst),
                    src_addr: Some(src),
                    protocol: proto,
                    payload: data[offset..].to_vec(),
                })
            }
            BnepPacketType::CompressedEthernet => {
                if data.len() < offset + 2 {
                    return None;
                }
                let proto =
                    u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                Some(BnepPacket {
                    packet_type: pkt_type,
                    dst_addr: None,
                    src_addr: None,
                    protocol: proto,
                    payload: data[offset..].to_vec(),
                })
            }
            BnepPacketType::CompressedEthernetSrcOnly => {
                if data.len() < offset + 8 {
                    return None;
                }
                let mut src = [0u8; 6];
                src.copy_from_slice(&data[offset..offset + 6]);
                offset += 6;
                let proto =
                    u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                Some(BnepPacket {
                    packet_type: pkt_type,
                    dst_addr: None,
                    src_addr: Some(src),
                    protocol: proto,
                    payload: data[offset..].to_vec(),
                })
            }
            BnepPacketType::CompressedEthernetDstOnly => {
                if data.len() < offset + 8 {
                    return None;
                }
                let mut dst = [0u8; 6];
                dst.copy_from_slice(&data[offset..offset + 6]);
                offset += 6;
                let proto =
                    u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                Some(BnepPacket {
                    packet_type: pkt_type,
                    dst_addr: Some(dst),
                    src_addr: None,
                    protocol: proto,
                    payload: data[offset..].to_vec(),
                })
            }
            BnepPacketType::Control => {
                Some(BnepPacket {
                    packet_type: pkt_type,
                    dst_addr: None,
                    src_addr: None,
                    protocol: 0,
                    payload: data[offset..].to_vec(),
                })
            }
        }
    }
}

/// BNEP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BnepState {
    #[default]
    Idle,
    SetupPending,
    Connected,
    Closing,
}

/// A BNEP session carrying Ethernet-over-Bluetooth.
#[derive(Debug)]
pub struct BnepSession {
    pub state: BnepState,
    pub remote_addr: BdAddr,
    pub source_uuid: u16,
    pub destination_uuid: u16,
    /// Network protocol type filters.
    pub net_type_filters: Vec<(u16, u16)>,
    /// Multicast address filters.
    pub multicast_filters: Vec<([u8; 6], [u8; 6])>,
}

impl BnepSession {
    pub fn new(remote_addr: BdAddr) -> Self {
        Self {
            state: BnepState::default(),
            remote_addr,
            source_uuid: 0,
            destination_uuid: 0,
            net_type_filters: Vec::new(),
            multicast_filters: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pan_defaults() {
        let pan = PanProfile::new(PanRole::Panu);
        assert_eq!(pan.state, PanState::Disconnected);
        assert_eq!(pan.local_role, PanRole::Panu);
        assert!(pan.interface.is_none());
    }

    #[test]
    fn test_bnep_session() {
        let addr = BdAddr::default();
        let session = BnepSession::new(addr);
        assert_eq!(session.state, BnepState::Idle);
        assert!(session.net_type_filters.is_empty());
    }

    #[test]
    fn test_bnep_general_ethernet_round_trip() {
        let pkt = BnepPacket {
            packet_type: BnepPacketType::GeneralEthernet,
            dst_addr: Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            src_addr: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            protocol: 0x0800, // IPv4
            payload: vec![0xDE, 0xAD],
        };

        let encoded = pkt.encode();
        // Type(1) + dst(6) + src(6) + proto(2) + payload(2) = 17
        assert_eq!(encoded.len(), 17);
        assert_eq!(encoded[0], 0x00); // GeneralEthernet

        let decoded = BnepPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.packet_type, BnepPacketType::GeneralEthernet);
        assert_eq!(decoded.dst_addr, Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
        assert_eq!(decoded.src_addr, Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        assert_eq!(decoded.protocol, 0x0800);
        assert_eq!(decoded.payload, vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_bnep_compressed_round_trip() {
        let pkt = BnepPacket {
            packet_type: BnepPacketType::CompressedEthernet,
            dst_addr: None,
            src_addr: None,
            protocol: 0x86DD, // IPv6
            payload: vec![1, 2, 3],
        };

        let encoded = pkt.encode();
        assert_eq!(encoded[0], 0x02);

        let decoded = BnepPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.packet_type, BnepPacketType::CompressedEthernet);
        assert!(decoded.dst_addr.is_none());
        assert!(decoded.src_addr.is_none());
        assert_eq!(decoded.protocol, 0x86DD);
        assert_eq!(decoded.payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_bnep_control_packet() {
        // Setup Connection Request: control type 0x01, UUID size 2, src UUID, dst UUID
        let pkt = BnepPacket {
            packet_type: BnepPacketType::Control,
            dst_addr: None,
            src_addr: None,
            protocol: 0,
            payload: vec![
                BnepControlType::SetupConnectionRequest as u8,
                0x02, // UUID size = 2
                0x11, 0x15, // PANU UUID
                0x11, 0x16, // NAP UUID
            ],
        };

        let encoded = pkt.encode();
        assert_eq!(encoded[0], 0x01); // Control type

        let decoded = BnepPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.packet_type, BnepPacketType::Control);
        assert_eq!(
            BnepControlType::from_byte(decoded.payload[0]),
            Some(BnepControlType::SetupConnectionRequest)
        );
    }

    #[test]
    fn test_bnep_packet_type_from_byte() {
        assert_eq!(BnepPacketType::from_byte(0x00), Some(BnepPacketType::GeneralEthernet));
        assert_eq!(BnepPacketType::from_byte(0x80), Some(BnepPacketType::GeneralEthernet)); // extension bit
        assert_eq!(BnepPacketType::from_byte(0x04), Some(BnepPacketType::CompressedEthernetDstOnly));
        assert_eq!(BnepPacketType::from_byte(0x05), None); // invalid
    }
}
