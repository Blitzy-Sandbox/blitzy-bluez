// SPDX-License-Identifier: GPL-2.0-or-later
//
// Provisioning — replaces mesh/provision.c + mesh/prov.h
//
// Implements the provisioning protocol state machine.

use crate::crypto_mesh;

/// Provisioning state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionState {
    Idle,
    BeaconSent,
    LinkOpened,
    InviteSent,
    CapabilitiesReceived,
    PublicKeySent,
    AuthValueInput,
    ConfirmationSent,
    RandomSent,
    DataSent,
    Complete,
    Failed,
}

/// Provisioning capabilities advertised by a device.
#[derive(Debug, Clone)]
pub struct ProvisioningCapabilities {
    pub num_elements: u8,
    pub algorithms: u16,
    pub public_key_type: u8,
    pub static_oob_type: u8,
    pub output_oob_size: u8,
    pub output_oob_action: u16,
    pub input_oob_size: u8,
    pub input_oob_action: u16,
}

impl Default for ProvisioningCapabilities {
    fn default() -> Self {
        Self {
            num_elements: 1,
            algorithms: 0x0001, // FIPS P-256
            public_key_type: 0,
            static_oob_type: 0,
            output_oob_size: 0,
            output_oob_action: 0,
            input_oob_size: 0,
            input_oob_action: 0,
        }
    }
}

/// OOB authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OobMethod {
    None,
    Static,
    Output,
    Input,
}

/// Provisioning Data — the data sent to the device during provisioning.
#[derive(Debug, Clone)]
pub struct ProvisioningData {
    /// Network key (128-bit).
    pub net_key: [u8; 16],
    /// Network key index (12-bit).
    pub key_index: u16,
    /// Flags (key refresh, IV update).
    pub flags: u8,
    /// Current IV index.
    pub iv_index: u32,
    /// Unicast address assigned to the device.
    pub unicast_addr: u16,
}

impl ProvisioningData {
    /// Encode provisioning data into 25 bytes per spec.
    pub fn encode(&self) -> [u8; 25] {
        let mut buf = [0u8; 25];
        buf[0..16].copy_from_slice(&self.net_key);
        buf[16] = (self.key_index >> 8) as u8;
        buf[17] = self.key_index as u8;
        buf[18] = self.flags;
        buf[19] = (self.iv_index >> 24) as u8;
        buf[20] = (self.iv_index >> 16) as u8;
        buf[21] = (self.iv_index >> 8) as u8;
        buf[22] = self.iv_index as u8;
        buf[23] = (self.unicast_addr >> 8) as u8;
        buf[24] = self.unicast_addr as u8;
        buf
    }

    /// Decode provisioning data from 25 bytes. Returns None if too short.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 25 {
            return None;
        }
        let mut net_key = [0u8; 16];
        net_key.copy_from_slice(&data[0..16]);
        let key_index = (u16::from(data[16]) << 8) | u16::from(data[17]);
        let flags = data[18];
        let iv_index = (u32::from(data[19]) << 24)
            | (u32::from(data[20]) << 16)
            | (u32::from(data[21]) << 8)
            | u32::from(data[22]);
        let unicast_addr = (u16::from(data[23]) << 8) | u16::from(data[24]);

        Some(Self {
            net_key,
            key_index,
            flags,
            iv_index,
            unicast_addr,
        })
    }
}

/// Calculate the provisioning confirmation value.
///
/// Confirmation = AES-CMAC(ConfirmationKey, Random || AuthValue)
///
/// where ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, "prck")
///
/// This function takes pre-computed confirmation salt and key for flexibility.
/// `conf_key` is the confirmation key derived from the ECDH secret.
/// `random` is the 16-byte provisioner or device random.
/// `auth_value` is the 16-byte authentication value.
pub fn calculate_confirmation(
    conf_key: &[u8; 16],
    random: &[u8; 16],
    auth_value: &[u8; 16],
) -> [u8; 16] {
    let mut input = Vec::with_capacity(32);
    input.extend_from_slice(random);
    input.extend_from_slice(auth_value);
    crypto_mesh::mesh_k1(&input, conf_key, &[])
}

/// Derive the confirmation key from ECDH secret and confirmation salt.
///
/// ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, "prck")
pub fn derive_confirmation_key(ecdh_secret: &[u8], conf_salt: &[u8; 16]) -> [u8; 16] {
    crypto_mesh::mesh_k1(ecdh_secret, conf_salt, b"prck")
}

/// Derive the confirmation salt from provisioning inputs.
///
/// ConfirmationSalt = s1(ConfirmationInputs)
/// where ConfirmationInputs = ProvisioningInvitePDU || ProvisioningCapabilitiesPDU ||
///                            ProvisioningStartPDU || PublicKeyProvisioner || PublicKeyDevice
pub fn derive_confirmation_salt(conf_inputs: &[u8]) -> [u8; 16] {
    crypto_mesh::mesh_s1(conf_inputs)
}

/// Calculate session key, session nonce, and device key from the ECDH shared
/// secret and the provisioning salt.
///
/// ProvisioningSalt = s1(ConfirmationSalt || ProvisionerRandom || DeviceRandom)
/// SessionKey = k1(ECDHSecret, ProvisioningSalt, "prsk")
/// SessionNonce = k1(ECDHSecret, ProvisioningSalt, "prsn")[3..16] (13 bytes -> take last 13)
/// DeviceKey = k1(ECDHSecret, ProvisioningSalt, "prdk")
///
/// Returns (session_key, session_nonce_13, device_key).
pub fn calculate_session_keys(
    ecdh_secret: &[u8],
    prov_salt: &[u8; 16],
) -> ([u8; 16], [u8; 13], [u8; 16]) {
    let session_key = crypto_mesh::mesh_k1(ecdh_secret, prov_salt, b"prsk");

    let nonce_full = crypto_mesh::mesh_k1(ecdh_secret, prov_salt, b"prsn");
    let mut session_nonce = [0u8; 13];
    session_nonce.copy_from_slice(&nonce_full[3..16]);

    let device_key = crypto_mesh::mesh_k1(ecdh_secret, prov_salt, b"prdk");

    (session_key, session_nonce, device_key)
}

/// Derive the provisioning salt from confirmation salt and randoms.
///
/// ProvisioningSalt = s1(ConfirmationSalt || ProvisionerRandom || DeviceRandom)
pub fn derive_provisioning_salt(
    conf_salt: &[u8; 16],
    prov_random: &[u8; 16],
    dev_random: &[u8; 16],
) -> [u8; 16] {
    let mut input = Vec::with_capacity(48);
    input.extend_from_slice(conf_salt);
    input.extend_from_slice(prov_random);
    input.extend_from_slice(dev_random);
    crypto_mesh::mesh_s1(&input)
}

/// The provisioner state machine.
#[derive(Debug)]
pub struct Provisioner {
    /// Current state.
    pub state: ProvisionState,
    /// Link ID for PB-ADV.
    pub link_id: u32,
    /// Transaction number.
    pub transaction: u8,
    /// Remote device capabilities (once received).
    pub capabilities: Option<ProvisioningCapabilities>,
    /// Selected OOB method.
    pub oob_method: OobMethod,
    /// Provisioning random (16 bytes).
    pub random: [u8; 16],
    /// Provisioning confirmation (16 bytes).
    pub confirmation: [u8; 16],
    /// Auth value.
    pub auth_value: [u8; 16],
    /// Allocated unicast address for the device being provisioned.
    pub unicast_addr: u16,
    /// Network key index to provision with.
    pub net_key_index: u16,
}

impl Provisioner {
    /// Create a new provisioner in the Idle state.
    pub fn new() -> Self {
        Self {
            state: ProvisionState::Idle,
            link_id: 0,
            transaction: 0,
            capabilities: None,
            oob_method: OobMethod::None,
            random: [0u8; 16],
            confirmation: [0u8; 16],
            auth_value: [0u8; 16],
            unicast_addr: 0,
            net_key_index: 0,
        }
    }

    /// Start provisioning a device.
    pub fn start_provisioning(
        &mut self,
        link_id: u32,
        unicast_addr: u16,
        net_key_index: u16,
    ) -> Result<(), &'static str> {
        if self.state != ProvisionState::Idle {
            return Err("provisioner not idle");
        }
        self.link_id = link_id;
        self.unicast_addr = unicast_addr;
        self.net_key_index = net_key_index;
        self.state = ProvisionState::BeaconSent;
        Ok(())
    }

    /// Send an invite and transition state.
    pub fn send_invite(&mut self, attention_duration: u8) -> Result<Vec<u8>, &'static str> {
        if self.state != ProvisionState::LinkOpened {
            return Err("link not open");
        }
        let pdu = vec![0x00, attention_duration]; // Provisioning Invite PDU
        self.state = ProvisionState::InviteSent;
        Ok(pdu)
    }

    /// Process received capabilities from the device.
    pub fn process_capabilities(
        &mut self,
        caps: ProvisioningCapabilities,
    ) -> Result<(), &'static str> {
        if self.state != ProvisionState::InviteSent {
            return Err("not expecting capabilities");
        }
        if caps.num_elements == 0 {
            self.state = ProvisionState::Failed;
            return Err("device has zero elements");
        }
        self.capabilities = Some(caps);
        self.state = ProvisionState::CapabilitiesReceived;
        Ok(())
    }

    /// Simulate public key exchange step.
    pub fn exchange_keys(&mut self) -> Result<(), &'static str> {
        if self.state != ProvisionState::CapabilitiesReceived {
            return Err("capabilities not received");
        }
        // TODO: ECDH P-256 key exchange
        self.state = ProvisionState::PublicKeySent;
        Ok(())
    }

    /// Mark provisioning as complete.
    pub fn complete(&mut self) {
        self.state = ProvisionState::Complete;
    }

    /// Mark provisioning as failed.
    pub fn fail(&mut self) {
        self.state = ProvisionState::Failed;
    }

    /// Simulate opening a link (called when PB-ADV link is established).
    pub fn link_opened(&mut self) -> Result<(), &'static str> {
        if self.state != ProvisionState::BeaconSent {
            return Err("beacon not sent");
        }
        self.state = ProvisionState::LinkOpened;
        Ok(())
    }
}

impl Default for Provisioner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provisioning_state_flow() {
        let mut prov = Provisioner::new();
        assert_eq!(prov.state, ProvisionState::Idle);

        prov.start_provisioning(1, 0x0100, 0).unwrap();
        assert_eq!(prov.state, ProvisionState::BeaconSent);

        prov.link_opened().unwrap();
        assert_eq!(prov.state, ProvisionState::LinkOpened);

        let invite = prov.send_invite(5).unwrap();
        assert_eq!(invite, vec![0x00, 5]);
        assert_eq!(prov.state, ProvisionState::InviteSent);

        let caps = ProvisioningCapabilities::default();
        prov.process_capabilities(caps).unwrap();
        assert_eq!(prov.state, ProvisionState::CapabilitiesReceived);

        prov.exchange_keys().unwrap();
        assert_eq!(prov.state, ProvisionState::PublicKeySent);
    }

    #[test]
    fn test_provisioning_zero_elements_fails() {
        let mut prov = Provisioner::new();
        prov.start_provisioning(1, 0x0100, 0).unwrap();
        prov.link_opened().unwrap();
        prov.send_invite(0).unwrap();

        let mut caps = ProvisioningCapabilities::default();
        caps.num_elements = 0;
        assert!(prov.process_capabilities(caps).is_err());
        assert_eq!(prov.state, ProvisionState::Failed);
    }

    #[test]
    fn test_provisioning_wrong_state() {
        let mut prov = Provisioner::new();
        // Can't send invite without starting
        assert!(prov.send_invite(0).is_err());
        // Can't start twice
        prov.start_provisioning(1, 0x0100, 0).unwrap();
        assert!(prov.start_provisioning(2, 0x0200, 0).is_err());
    }

    #[test]
    fn test_provisioning_confirmation() {
        // Test that confirmation calculation is deterministic and non-zero
        let conf_key = [0x11u8; 16];
        let random = [0x22u8; 16];
        let auth_value = [0x00u8; 16];

        let conf1 = calculate_confirmation(&conf_key, &random, &auth_value);
        let conf2 = calculate_confirmation(&conf_key, &random, &auth_value);

        assert_eq!(conf1, conf2);
        assert_ne!(conf1, [0u8; 16]);

        // Different random should give different confirmation
        let random2 = [0x33u8; 16];
        let conf3 = calculate_confirmation(&conf_key, &random2, &auth_value);
        assert_ne!(conf1, conf3);
    }

    #[test]
    fn test_session_key_derivation() {
        let ecdh_secret = [0x42u8; 32];
        let prov_salt = crypto_mesh::mesh_s1(b"test_prov_salt");

        let (session_key, session_nonce, device_key) =
            calculate_session_keys(&ecdh_secret, &prov_salt);

        assert_ne!(session_key, [0u8; 16]);
        assert_ne!(session_nonce, [0u8; 13]);
        assert_ne!(device_key, [0u8; 16]);

        // Session key and device key should differ
        assert_ne!(session_key, device_key);

        // Reproducible
        let (sk2, sn2, dk2) = calculate_session_keys(&ecdh_secret, &prov_salt);
        assert_eq!(session_key, sk2);
        assert_eq!(session_nonce, sn2);
        assert_eq!(device_key, dk2);
    }

    #[test]
    fn test_provisioning_data_encode_decode() {
        let data = ProvisioningData {
            net_key: [0xAA; 16],
            key_index: 0x0123,
            flags: 0x01,
            iv_index: 0xDEADBEEF,
            unicast_addr: 0x0100,
        };

        let encoded = data.encode();
        assert_eq!(encoded.len(), 25);

        let decoded = ProvisioningData::decode(&encoded).unwrap();
        assert_eq!(decoded.net_key, data.net_key);
        assert_eq!(decoded.key_index, data.key_index);
        assert_eq!(decoded.flags, data.flags);
        assert_eq!(decoded.iv_index, data.iv_index);
        assert_eq!(decoded.unicast_addr, data.unicast_addr);
    }

    #[test]
    fn test_provisioning_salt_derivation() {
        let conf_salt = [0x11u8; 16];
        let prov_random = [0x22u8; 16];
        let dev_random = [0x33u8; 16];

        let salt = derive_provisioning_salt(&conf_salt, &prov_random, &dev_random);
        assert_ne!(salt, [0u8; 16]);

        // Reproducible
        let salt2 = derive_provisioning_salt(&conf_salt, &prov_random, &dev_random);
        assert_eq!(salt, salt2);
    }
}
