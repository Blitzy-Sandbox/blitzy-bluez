// SPDX-License-Identifier: GPL-2.0-or-later
//
// PB-ADV bearer — replaces mesh/pb-adv.c
//
// Provisioning Bearer over Advertising.

/// Generic Provisioning PDU types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpPduType {
    /// Transaction Start.
    TransactionStart = 0x00,
    /// Transaction Acknowledgment.
    TransactionAck = 0x01,
    /// Transaction Continuation.
    TransactionContinuation = 0x02,
    /// Provisioning Bearer Control.
    BearerControl = 0x03,
}

/// Bearer control opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BearerOpcode {
    LinkOpen = 0x00,
    LinkAck = 0x01,
    LinkClose = 0x02,
}

/// Close reasons for PB-ADV links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkCloseReason {
    Success = 0x00,
    Timeout = 0x01,
    Fail = 0x02,
}

/// A Generic Provisioning PDU.
#[derive(Debug, Clone)]
pub struct GenericProvisioningPdu {
    /// Link ID (32-bit).
    pub link_id: u32,
    /// Transaction number.
    pub transaction: u8,
    /// PDU type.
    pub pdu_type: GpPduType,
    /// Payload data.
    pub data: Vec<u8>,
}

impl GenericProvisioningPdu {
    /// Encode the PDU into bytes for transmission.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(6 + self.data.len());
        buf.extend_from_slice(&self.link_id.to_be_bytes());
        buf.push(self.transaction);
        // GPCF is lower 2 bits of first data byte
        let gpcf = self.pdu_type as u8 & 0x03;
        buf.push(gpcf);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode a PDU from received bytes. Returns None if too short.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let link_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let transaction = data[4];
        let gpcf = data[5] & 0x03;
        let pdu_type = match gpcf {
            0 => GpPduType::TransactionStart,
            1 => GpPduType::TransactionAck,
            2 => GpPduType::TransactionContinuation,
            3 => GpPduType::BearerControl,
            _ => return None,
        };
        let payload = data[6..].to_vec();

        Some(Self {
            link_id,
            transaction,
            pdu_type,
            data: payload,
        })
    }
}

/// PB-ADV link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbAdvState {
    Idle,
    LinkOpening,
    LinkOpen,
    LinkClosing,
}

/// PB-ADV bearer instance.
#[derive(Debug)]
pub struct PbAdv {
    pub state: PbAdvState,
    pub link_id: u32,
    pub transaction: u8,
}

impl PbAdv {
    pub fn new() -> Self {
        Self {
            state: PbAdvState::Idle,
            link_id: 0,
            transaction: 0,
        }
    }

    /// Initiate a link open to a device with the given UUID.
    pub fn open_link(&mut self, link_id: u32) {
        self.link_id = link_id;
        self.state = PbAdvState::LinkOpening;
        self.transaction = 0;
    }

    /// Handle a link acknowledgment.
    pub fn link_ack(&mut self) -> Result<(), &'static str> {
        if self.state != PbAdvState::LinkOpening {
            return Err("not opening");
        }
        self.state = PbAdvState::LinkOpen;
        Ok(())
    }

    /// Close the current link.
    pub fn close_link(&mut self, _reason: LinkCloseReason) {
        self.state = PbAdvState::Idle;
        self.link_id = 0;
    }
}

impl Default for PbAdv {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdu_encode_decode() {
        let pdu = GenericProvisioningPdu {
            link_id: 0x12345678,
            transaction: 3,
            pdu_type: GpPduType::BearerControl,
            data: vec![0x00, 0x01, 0x02],
        };

        let encoded = pdu.encode();
        let decoded = GenericProvisioningPdu::decode(&encoded).unwrap();
        assert_eq!(decoded.link_id, 0x12345678);
        assert_eq!(decoded.transaction, 3);
        assert_eq!(decoded.pdu_type, GpPduType::BearerControl);
        assert_eq!(decoded.data, vec![0x00, 0x01, 0x02]);
    }

    #[test]
    fn test_pb_adv_state_flow() {
        let mut pb = PbAdv::new();
        assert_eq!(pb.state, PbAdvState::Idle);

        pb.open_link(42);
        assert_eq!(pb.state, PbAdvState::LinkOpening);

        pb.link_ack().unwrap();
        assert_eq!(pb.state, PbAdvState::LinkOpen);

        pb.close_link(LinkCloseReason::Success);
        assert_eq!(pb.state, PbAdvState::Idle);
    }
}
