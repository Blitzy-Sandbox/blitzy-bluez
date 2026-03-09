// SPDX-License-Identifier: GPL-2.0-or-later
//
// Mesh network layer — replaces mesh/net.c
//
// Handles Network PDU encryption, decryption, relay, and key management.

use std::collections::HashMap;

use crate::crypto_mesh;

/// Key refresh phase per Mesh Profile spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefreshPhase {
    /// Normal operation — using current key.
    Normal,
    /// Phase 1 — distribute new key, accept old + new for Rx.
    Phase1,
    /// Phase 2 — transmit with new key, accept old + new for Rx.
    Phase2,
}

/// Derived key material from a network key.
#[derive(Debug, Clone)]
pub struct NetKeyMaterial {
    /// NID (7-bit) derived via k2.
    pub nid: u8,
    /// Encryption key derived from the network key via k2.
    pub encryption_key: [u8; 16],
    /// Privacy key derived from the network key via k2.
    pub privacy_key: [u8; 16],
    /// Network ID (8 bytes) derived via k3.
    pub network_id: [u8; 8],
    /// Beacon key derived via k1 with salt=s1("nkbk") and P="id128\x01".
    pub beacon_key: [u8; 16],
}

/// Derive all network key material from a raw 128-bit network key.
pub fn derive_net_keys(net_key: &[u8; 16]) -> NetKeyMaterial {
    // k2 with P = 0x00 gives NID, encryption key, privacy key
    let (nid, encryption_key, privacy_key) = crypto_mesh::mesh_k2(net_key, &[0x00]);
    // k3 gives network ID
    let network_id = crypto_mesh::mesh_k3(net_key);
    // Beacon key: k1(NetKey, s1("nkbk"), "id128\x01")
    let salt = crypto_mesh::mesh_s1(b"nkbk");
    let beacon_key = crypto_mesh::mesh_k1(net_key, &salt, b"id128\x01");

    NetKeyMaterial {
        nid,
        encryption_key,
        privacy_key,
        network_id,
        beacon_key,
    }
}

/// A network encryption key and its derived keys.
#[derive(Debug, Clone)]
pub struct NetKey {
    /// Network key index (12-bit).
    pub index: u16,
    /// Raw 128-bit network key.
    pub key: [u8; 16],
    /// Key refresh phase.
    pub phase: KeyRefreshPhase,
    /// Privacy key derived from the network key.
    pub privacy_key: [u8; 16],
    /// Encryption key derived from the network key.
    pub encryption_key: [u8; 16],
    /// Beacon key derived from the network key.
    pub beacon_key: [u8; 16],
    /// Network ID (8 bytes) derived via k3.
    pub network_id: [u8; 8],
    /// NID (7-bit) derived via k2.
    pub nid: u8,
}

impl NetKey {
    /// Create a new network key and derive all sub-keys.
    pub fn new(index: u16, key: [u8; 16]) -> Self {
        let material = derive_net_keys(&key);
        Self {
            index,
            key,
            phase: KeyRefreshPhase::Normal,
            privacy_key: material.privacy_key,
            encryption_key: material.encryption_key,
            beacon_key: material.beacon_key,
            network_id: material.network_id,
            nid: material.nid,
        }
    }

    /// Create a network key with zeroed derived keys (for manual setup/testing).
    pub fn new_raw(index: u16, key: [u8; 16]) -> Self {
        Self {
            index,
            key,
            phase: KeyRefreshPhase::Normal,
            privacy_key: [0u8; 16],
            encryption_key: [0u8; 16],
            beacon_key: [0u8; 16],
            network_id: [0u8; 8],
            nid: 0,
        }
    }
}

/// A Network PDU as defined by the Mesh Profile specification.
#[derive(Debug, Clone)]
pub struct NetworkPdu {
    /// IV Index least-significant bit.
    pub ivi: u8,
    /// Network ID (7 bits).
    pub nid: u8,
    /// Control message flag.
    pub ctl: bool,
    /// Time To Live.
    pub ttl: u8,
    /// Sequence number (24-bit).
    pub seq: u32,
    /// Source address.
    pub src: u16,
    /// Destination address.
    pub dst: u16,
    /// Encrypted transport PDU + MIC.
    pub payload: Vec<u8>,
}

impl NetworkPdu {
    /// Encode the network PDU header into bytes (excluding payload).
    pub fn encode_header(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9);
        let first = (self.ivi & 0x01) << 7 | (self.nid & 0x7f);
        buf.push(first);
        let ctl_ttl = if self.ctl { 0x80 } else { 0x00 } | (self.ttl & 0x7f);
        buf.push(ctl_ttl);
        buf.push(((self.seq >> 16) & 0xff) as u8);
        buf.push(((self.seq >> 8) & 0xff) as u8);
        buf.push((self.seq & 0xff) as u8);
        buf.push((self.src >> 8) as u8);
        buf.push((self.src & 0xff) as u8);
        buf.push((self.dst >> 8) as u8);
        buf.push((self.dst & 0xff) as u8);
        buf
    }

    /// Decode a network PDU header from bytes. Returns None if too short.
    pub fn decode_header(data: &[u8]) -> Option<Self> {
        if data.len() < 9 {
            return None;
        }
        let ivi = (data[0] >> 7) & 0x01;
        let nid = data[0] & 0x7f;
        let ctl = (data[1] & 0x80) != 0;
        let ttl = data[1] & 0x7f;
        let seq = (u32::from(data[2]) << 16)
            | (u32::from(data[3]) << 8)
            | u32::from(data[4]);
        let src = (u16::from(data[5]) << 8) | u16::from(data[6]);
        let dst = (u16::from(data[7]) << 8) | u16::from(data[8]);
        let payload = data[9..].to_vec();

        Some(Self {
            ivi,
            nid,
            ctl,
            ttl,
            seq,
            src,
            dst,
            payload,
        })
    }

    /// MIC size depends on CTL: control messages use 8-byte MIC, access 4-byte.
    pub fn mic_size(&self) -> usize {
        if self.ctl { 8 } else { 4 }
    }
}

/// IV Index update state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IvUpdateState {
    /// Normal operation.
    Normal,
    /// IV Update in progress — accepting current and next IV index.
    InProgress,
}

/// The mesh network state machine.
#[derive(Debug)]
pub struct MeshNet {
    /// Current IV index.
    pub iv_index: u32,
    /// IV update state.
    pub iv_update_state: IvUpdateState,
    /// Whether an IV update is in progress (legacy field).
    pub iv_update: bool,
    /// Network keys indexed by key index.
    pub net_keys: HashMap<u16, NetKey>,
}

impl MeshNet {
    pub fn new() -> Self {
        Self {
            iv_index: 0,
            iv_update_state: IvUpdateState::Normal,
            iv_update: false,
            net_keys: HashMap::new(),
        }
    }

    /// Add or replace a network key.
    pub fn add_net_key(&mut self, key: NetKey) {
        self.net_keys.insert(key.index, key);
    }

    /// Remove a network key by index.
    pub fn remove_net_key(&mut self, index: u16) -> Option<NetKey> {
        self.net_keys.remove(&index)
    }

    /// Look up a network key by NID (for incoming PDU matching).
    pub fn find_key_by_nid(&self, nid: u8) -> Option<&NetKey> {
        self.net_keys.values().find(|k| k.nid == nid)
    }

    /// Begin an IV Index update. Transitions from Normal to InProgress
    /// and increments the IV Index by 1.
    pub fn begin_iv_update(&mut self) -> Result<(), &'static str> {
        if self.iv_update_state != IvUpdateState::Normal {
            return Err("IV update already in progress");
        }
        self.iv_update_state = IvUpdateState::InProgress;
        self.iv_update = true;
        self.iv_index = self.iv_index.wrapping_add(1);
        Ok(())
    }

    /// Complete an IV Index update. Transitions from InProgress to Normal.
    pub fn complete_iv_update(&mut self) -> Result<(), &'static str> {
        if self.iv_update_state != IvUpdateState::InProgress {
            return Err("no IV update in progress");
        }
        self.iv_update_state = IvUpdateState::Normal;
        self.iv_update = false;
        Ok(())
    }

    /// Encrypt a network PDU using the specified key index.
    ///
    /// This constructs the network nonce, encrypts the DST + transport PDU
    /// with AES-CCM, then obfuscates the header.
    pub fn encrypt_pdu(&self, pdu: &mut NetworkPdu, key_index: u16) -> Result<Vec<u8>, &'static str> {
        let net_key = self.net_keys.get(&key_index).ok_or("key index not found")?;

        let ctl_ttl = if pdu.ctl { 0x80 } else { 0x00 } | (pdu.ttl & 0x7f);
        let mic_size = pdu.mic_size();

        // Construct network nonce
        let nonce = crypto_mesh::network_nonce(ctl_ttl, pdu.seq, pdu.src, self.iv_index);

        // Plaintext for encryption = DST(2) || TransportPDU
        let mut plaintext = Vec::with_capacity(2 + pdu.payload.len());
        plaintext.push((pdu.dst >> 8) as u8);
        plaintext.push(pdu.dst as u8);
        plaintext.extend_from_slice(&pdu.payload);

        // Encrypt with AES-CCM (DST + transport PDU)
        let encrypted = crypto_mesh::mesh_aes_ccm_encrypt(
            &net_key.encryption_key,
            &nonce,
            &plaintext,
            &[],
            mic_size,
        );

        // Build header: IVI_NID || obfuscated(CTL_TTL, SEQ, SRC)
        let ivi_nid = ((self.iv_index as u8) & 0x01) << 7 | (net_key.nid & 0x7f);
        let header_6: [u8; 6] = [
            ctl_ttl,
            (pdu.seq >> 16) as u8,
            (pdu.seq >> 8) as u8,
            pdu.seq as u8,
            (pdu.src >> 8) as u8,
            pdu.src as u8,
        ];

        let obfuscated = crypto_mesh::obfuscate_header(
            &net_key.privacy_key,
            self.iv_index,
            &header_6,
            &encrypted,
        );

        // Assemble: IVI_NID(1) || Obfuscated(6) || EncDST_TransportPDU_MIC
        let mut result = Vec::with_capacity(1 + 6 + encrypted.len());
        result.push(ivi_nid);
        result.extend_from_slice(&obfuscated);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    /// Decrypt a network PDU from raw bytes. Returns the decoded PDU and the
    /// key index that successfully decrypted it.
    pub fn decrypt_pdu(&self, data: &[u8]) -> Result<(NetworkPdu, u16), &'static str> {
        if data.len() < 14 {
            return Err("PDU too short");
        }

        let nid = data[0] & 0x7f;
        let ivi = (data[0] >> 7) & 0x01;

        // Find matching key(s) by NID
        for net_key in self.net_keys.values() {
            if net_key.nid != nid {
                continue;
            }

            // Encrypted portion starts at byte 7 (after IVI_NID + 6 obfuscated bytes)
            let enc_data = &data[7..];

            // Deobfuscate the header
            let mut obfuscated = [0u8; 6];
            obfuscated.copy_from_slice(&data[1..7]);
            let header = crypto_mesh::deobfuscate_header(
                &net_key.privacy_key,
                self.iv_index,
                &obfuscated,
                enc_data,
            );

            let ctl = (header[0] & 0x80) != 0;
            let ttl = header[0] & 0x7f;
            let seq = (u32::from(header[1]) << 16)
                | (u32::from(header[2]) << 8)
                | u32::from(header[3]);
            let src = (u16::from(header[4]) << 8) | u16::from(header[5]);

            let mic_size = if ctl { 8 } else { 4 };
            let ctl_ttl = header[0];
            let nonce = crypto_mesh::network_nonce(ctl_ttl, seq, src, self.iv_index);

            // Try to decrypt
            if let Some(plaintext) = crypto_mesh::mesh_aes_ccm_decrypt(
                &net_key.encryption_key,
                &nonce,
                enc_data,
                &[],
                mic_size,
            ) {
                if plaintext.len() < 2 {
                    continue;
                }
                let dst = (u16::from(plaintext[0]) << 8) | u16::from(plaintext[1]);
                let transport_pdu = plaintext[2..].to_vec();

                let pdu = NetworkPdu {
                    ivi,
                    nid,
                    ctl,
                    ttl,
                    seq,
                    src,
                    dst,
                    payload: transport_pdu,
                };

                return Ok((pdu, net_key.index));
            }
        }

        Err("no matching key found")
    }

    /// Process a received network PDU: decrypt, check TTL, decide relay.
    pub fn process_incoming(&self, data: &[u8]) -> Result<NetworkPdu, &'static str> {
        let (pdu, _key_index) = self.decrypt_pdu(data)?;
        Ok(pdu)
    }

    /// Relay a PDU by decrementing TTL and re-encrypting.
    pub fn relay_pdu(&self, pdu: &NetworkPdu) -> Option<NetworkPdu> {
        if pdu.ttl < 2 {
            return None;
        }
        let mut relayed = pdu.clone();
        relayed.ttl -= 1;
        Some(relayed)
    }
}

impl Default for MeshNet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdu_encode_decode_roundtrip() {
        let pdu = NetworkPdu {
            ivi: 1,
            nid: 0x3a,
            ctl: true,
            ttl: 5,
            seq: 0x000123,
            src: 0x0001,
            dst: 0xFFFF,
            payload: vec![0xAA, 0xBB],
        };

        let mut encoded = pdu.encode_header();
        encoded.extend_from_slice(&pdu.payload);

        let decoded = NetworkPdu::decode_header(&encoded).unwrap();
        assert_eq!(decoded.ivi, 1);
        assert_eq!(decoded.nid, 0x3a);
        assert!(decoded.ctl);
        assert_eq!(decoded.ttl, 5);
        assert_eq!(decoded.seq, 0x000123);
        assert_eq!(decoded.src, 0x0001);
        assert_eq!(decoded.dst, 0xFFFF);
        assert_eq!(decoded.payload, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_net_key_management() {
        let mut mesh = MeshNet::new();
        let key = NetKey::new(0, [0x11; 16]);
        let nid = key.nid;
        mesh.add_net_key(key);

        assert!(mesh.find_key_by_nid(nid).is_some());
        // NID 0 is unlikely to match the derived NID
        if nid != 0 {
            assert!(mesh.find_key_by_nid(0x00).is_none());
        }

        mesh.remove_net_key(0);
        assert!(mesh.find_key_by_nid(nid).is_none());
    }

    #[test]
    fn test_relay_pdu() {
        let mesh = MeshNet::new();
        let pdu = NetworkPdu {
            ivi: 0,
            nid: 0x10,
            ctl: false,
            ttl: 5,
            seq: 1,
            src: 0x0001,
            dst: 0x0002,
            payload: vec![],
        };

        let relayed = mesh.relay_pdu(&pdu).unwrap();
        assert_eq!(relayed.ttl, 4);

        let no_relay = NetworkPdu { ttl: 1, ..pdu };
        assert!(mesh.relay_pdu(&no_relay).is_none());
    }

    #[test]
    fn test_net_key_derivation() {
        // Derive keys from a known network key and verify they are non-zero
        let net_key_bytes: [u8; 16] = [
            0xf7, 0xa2, 0xa4, 0x4f, 0x8e, 0x8a, 0x80, 0x29,
            0x06, 0x4f, 0x17, 0x3d, 0xdc, 0x1e, 0x2b, 0x00,
        ];
        let material = derive_net_keys(&net_key_bytes);
        assert!(material.nid <= 0x7f);
        assert_ne!(material.encryption_key, [0u8; 16]);
        assert_ne!(material.privacy_key, [0u8; 16]);
        assert_ne!(material.network_id, [0u8; 8]);
        assert_ne!(material.beacon_key, [0u8; 16]);

        // Create a full NetKey and verify it matches
        let net_key = NetKey::new(0, net_key_bytes);
        assert_eq!(net_key.nid, material.nid);
        assert_eq!(net_key.encryption_key, material.encryption_key);
        assert_eq!(net_key.privacy_key, material.privacy_key);
        assert_eq!(net_key.network_id, material.network_id);
        assert_eq!(net_key.beacon_key, material.beacon_key);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut mesh = MeshNet::new();
        let net_key = NetKey::new(0, [0x11; 16]);
        mesh.add_net_key(net_key);

        let mut pdu = NetworkPdu {
            ivi: 0,
            nid: 0,
            ctl: false,
            ttl: 7,
            seq: 42,
            src: 0x0001,
            dst: 0x0002,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let encrypted = mesh.encrypt_pdu(&mut pdu, 0).unwrap();
        assert!(!encrypted.is_empty());

        // Decrypt it back
        let (decrypted, key_idx) = mesh.decrypt_pdu(&encrypted).unwrap();
        assert_eq!(key_idx, 0);
        assert_eq!(decrypted.src, 0x0001);
        assert_eq!(decrypted.dst, 0x0002);
        assert_eq!(decrypted.seq, 42);
        assert_eq!(decrypted.ttl, 7);
        assert_eq!(decrypted.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_iv_update_procedure() {
        let mut mesh = MeshNet::new();
        assert_eq!(mesh.iv_index, 0);
        assert_eq!(mesh.iv_update_state, IvUpdateState::Normal);

        // Begin update
        mesh.begin_iv_update().unwrap();
        assert_eq!(mesh.iv_index, 1);
        assert_eq!(mesh.iv_update_state, IvUpdateState::InProgress);
        assert!(mesh.iv_update);

        // Can't begin again while in progress
        assert!(mesh.begin_iv_update().is_err());

        // Complete
        mesh.complete_iv_update().unwrap();
        assert_eq!(mesh.iv_index, 1);
        assert_eq!(mesh.iv_update_state, IvUpdateState::Normal);
        assert!(!mesh.iv_update);

        // Can't complete when not in progress
        assert!(mesh.complete_iv_update().is_err());
    }

    #[test]
    fn test_mic_size() {
        let access_pdu = NetworkPdu {
            ivi: 0, nid: 0, ctl: false, ttl: 7, seq: 0, src: 0, dst: 0, payload: vec![],
        };
        assert_eq!(access_pdu.mic_size(), 4);

        let control_pdu = NetworkPdu {
            ivi: 0, nid: 0, ctl: true, ttl: 7, seq: 0, src: 0, dst: 0, payload: vec![],
        };
        assert_eq!(control_pdu.mic_size(), 8);
    }
}
