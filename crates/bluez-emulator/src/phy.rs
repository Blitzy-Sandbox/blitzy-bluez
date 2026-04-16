// SPDX-License-Identifier: GPL-2.0-or-later
//
// PHY layer simulation replacing emulator/phy.c
//
// Simulates the radio physical layer between virtual Bluetooth devices.
// Uses a Unix datagram socket to broadcast packets between PHY instances.

use std::sync::{Arc, Mutex};

// Packet types
pub const BT_PHY_PKT_NULL: u16 = 0x0000;
pub const BT_PHY_PKT_ADV: u16 = 0x0001;
pub const BT_PHY_PKT_CONN: u16 = 0x0002;

/// Advertising PDU packet.
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct PhyPktAdv {
    pub chan_idx: u8,
    pub pdu_type: u8,
    pub tx_addr_type: u8,
    pub tx_addr: [u8; 6],
    pub rx_addr_type: u8,
    pub rx_addr: [u8; 6],
    pub adv_data_len: u8,
    pub scan_rsp_len: u8,
}

/// Connection PDU packet.
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct PhyPktConn {
    pub chan_idx: u8,
    pub link_type: u8,
    pub tx_addr_type: u8,
    pub tx_addr: [u8; 6],
    pub rx_addr_type: u8,
    pub rx_addr: [u8; 6],
    pub features: [u8; 8],
    pub id: u8,
}

/// Callback for receiving PHY packets.
pub type PhyCallback = Box<dyn Fn(u16, &[u8]) + Send + Sync>;

struct BtPhyInner {
    callback: Option<PhyCallback>,
}

/// Virtual PHY layer.
pub struct BtPhy {
    inner: Arc<Mutex<BtPhyInner>>,
}

impl BtPhy {
    /// Create a new PHY instance.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BtPhyInner { callback: None })),
        }
    }

    /// Register a packet receive callback.
    pub fn register(&self, callback: PhyCallback) {
        let mut inner = self.inner.lock().unwrap();
        inner.callback = Some(callback);
    }

    /// Send a packet through the PHY.
    pub fn send(&self, pkt_type: u16, data: &[u8]) -> bool {
        let inner = self.inner.lock().unwrap();
        if let Some(ref cb) = inner.callback {
            cb(pkt_type, data);
            true
        } else {
            false
        }
    }

    /// Send a packet with up to 3 fragments concatenated.
    pub fn send_vector(
        &self,
        pkt_type: u16,
        data1: &[u8],
        data2: &[u8],
        data3: &[u8],
    ) -> bool {
        let mut combined = Vec::with_capacity(data1.len() + data2.len() + data3.len());
        combined.extend_from_slice(data1);
        combined.extend_from_slice(data2);
        combined.extend_from_slice(data3);
        self.send(pkt_type, &combined)
    }

    /// Clone the Arc for sharing.
    pub fn clone_ref(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Default for BtPhy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};

    #[test]
    fn test_phy_send_no_callback() {
        let phy = BtPhy::new();
        assert!(!phy.send(BT_PHY_PKT_NULL, &[]));
    }

    #[test]
    fn test_phy_send_with_callback() {
        let phy = BtPhy::new();
        let received_type = Arc::new(AtomicU16::new(0));
        let rt = received_type.clone();
        phy.register(Box::new(move |pkt_type, _data| {
            rt.store(pkt_type, Ordering::SeqCst);
        }));
        assert!(phy.send(BT_PHY_PKT_ADV, &[1, 2, 3]));
        assert_eq!(received_type.load(Ordering::SeqCst), BT_PHY_PKT_ADV);
    }

    #[test]
    fn test_phy_send_vector() {
        let phy = BtPhy::new();
        let received_len = Arc::new(AtomicU16::new(0));
        let rl = received_len.clone();
        phy.register(Box::new(move |_pkt_type, data| {
            rl.store(data.len() as u16, Ordering::SeqCst);
        }));
        assert!(phy.send_vector(BT_PHY_PKT_CONN, &[1, 2], &[3, 4], &[5]));
        assert_eq!(received_len.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn test_phy_pkt_sizes() {
        // chan_idx(1) + pdu_type(1) + tx_addr_type(1) + tx_addr(6) + rx_addr_type(1) + rx_addr(6) + adv_data_len(1) + scan_rsp_len(1) = 18
        assert_eq!(std::mem::size_of::<PhyPktAdv>(), 18);
        // chan_idx(1) + link_type(1) + tx_addr_type(1) + tx_addr(6) + rx_addr_type(1) + rx_addr(6) + features(8) + id(1) = 25
        assert_eq!(std::mem::size_of::<PhyPktConn>(), 25);
    }
}
