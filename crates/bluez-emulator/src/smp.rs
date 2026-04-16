// SPDX-License-Identifier: GPL-2.0-or-later
//
// SMP (Security Manager Protocol) emulation replacing emulator/smp.c
//
// Implements SMP pairing state machine for virtual Bluetooth connections.
// Used by bthost for LE and BR/EDR security.

use bluez_shared::crypto;

// SMP opcodes
pub const SMP_CMD_PAIRING_REQUEST: u8 = 0x01;
pub const SMP_CMD_PAIRING_RESPONSE: u8 = 0x02;
pub const SMP_CMD_PAIRING_CONFIRM: u8 = 0x03;
pub const SMP_CMD_PAIRING_RANDOM: u8 = 0x04;
pub const SMP_CMD_PAIRING_FAILED: u8 = 0x05;
pub const SMP_CMD_ENCRYPT_INFO: u8 = 0x06;
pub const SMP_CMD_CENTRAL_IDENT: u8 = 0x07;
pub const SMP_CMD_IDENT_INFO: u8 = 0x08;
pub const SMP_CMD_IDENT_ADDR_INFO: u8 = 0x09;
pub const SMP_CMD_SIGNING_INFO: u8 = 0x0a;
pub const SMP_CMD_SECURITY_REQ: u8 = 0x0b;
pub const SMP_CMD_PUBLIC_KEY: u8 = 0x0c;
pub const SMP_CMD_DHKEY_CHECK: u8 = 0x0d;

// SMP error codes
pub const SMP_ERR_PASSKEY_ENTRY_FAILED: u8 = 0x01;
pub const SMP_ERR_OOB_NOT_AVAIL: u8 = 0x02;
pub const SMP_ERR_AUTH_REQUIREMENTS: u8 = 0x03;
pub const SMP_ERR_CONFIRM_VALUE_FAILED: u8 = 0x04;
pub const SMP_ERR_PAIRING_NOTSUPP: u8 = 0x05;
pub const SMP_ERR_ENC_KEY_SIZE: u8 = 0x06;
pub const SMP_ERR_CMD_NOTSUPP: u8 = 0x07;
pub const SMP_ERR_UNSPECIFIED: u8 = 0x08;

// IO Capabilities
pub const SMP_IO_DISPLAY_ONLY: u8 = 0x00;
pub const SMP_IO_DISPLAY_YESNO: u8 = 0x01;
pub const SMP_IO_KEYBOARD_ONLY: u8 = 0x02;
pub const SMP_IO_NO_INPUT_OUTPUT: u8 = 0x03;
pub const SMP_IO_KEYBOARD_DISPLAY: u8 = 0x04;

// Auth requirements
pub const SMP_AUTH_BONDING: u8 = 0x01;
pub const SMP_AUTH_MITM: u8 = 0x04;
pub const SMP_AUTH_SC: u8 = 0x08;

// Key distribution
pub const SMP_DIST_ENC_KEY: u8 = 0x01;
pub const SMP_DIST_ID_KEY: u8 = 0x02;
pub const SMP_DIST_SIGN: u8 = 0x04;

/// Pairing parameters (from request/response).
#[derive(Debug, Clone, Copy)]
pub struct PairingParams {
    pub io_capability: u8,
    pub oob_data: u8,
    pub auth_req: u8,
    pub max_key_size: u8,
    pub init_key_dist: u8,
    pub resp_key_dist: u8,
}

impl PairingParams {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        Some(Self {
            io_capability: data[0],
            oob_data: data[1],
            auth_req: data[2],
            max_key_size: data[3],
            init_key_dist: data[4],
            resp_key_dist: data[5],
        })
    }

    pub fn to_bytes(&self) -> [u8; 6] {
        [
            self.io_capability,
            self.oob_data,
            self.auth_req,
            self.max_key_size,
            self.init_key_dist,
            self.resp_key_dist,
        ]
    }
}

/// SMP pairing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpState {
    Idle,
    WaitingResponse,
    WaitingConfirm,
    WaitingRandom,
    WaitingPublicKey,
    WaitingDhkeyCheck,
    KeyDistribution,
    Complete,
    Failed,
}

/// SMP connection context for one LE link.
pub struct SmpConn {
    pub handle: u16,
    pub ia: [u8; 6],
    pub ia_type: u8,
    pub ra: [u8; 6],
    pub ra_type: u8,
    pub initiator: bool,
    pub state: SmpState,
    pub local_params: Option<PairingParams>,
    pub remote_params: Option<PairingParams>,
    pub preq: [u8; 7],
    pub pres: [u8; 7],
    pub tk: [u8; 16],
    pub local_random: [u8; 16],
    pub remote_random: [u8; 16],
    pub local_confirm: [u8; 16],
    pub ltk: [u8; 16],
    pub rand_val: u64,
    pub ediv: u16,
    pub encrypted: bool,
    pub sc: bool,
}

impl SmpConn {
    pub fn new(
        handle: u16,
        ia: &[u8; 6],
        ia_type: u8,
        ra: &[u8; 6],
        ra_type: u8,
        initiator: bool,
    ) -> Self {
        Self {
            handle,
            ia: *ia,
            ia_type,
            ra: *ra,
            ra_type,
            initiator,
            state: SmpState::Idle,
            local_params: None,
            remote_params: None,
            preq: [0; 7],
            pres: [0; 7],
            tk: [0; 16],
            local_random: [0; 16],
            remote_random: [0; 16],
            local_confirm: [0; 16],
            ltk: [0; 16],
            rand_val: 0,
            ediv: 0,
            encrypted: false,
            sc: false,
        }
    }

    /// Generate a pairing confirm value using SMP c1.
    pub fn compute_confirm(&self) -> Option<[u8; 16]> {
        let mut res = [0u8; 16];
        if crypto::bt_crypto_c1(
            &self.tk,
            &self.local_random,
            &self.preq,
            &self.pres,
            self.ia_type,
            &self.ia,
            self.ra_type,
            &self.ra,
            &mut res,
        ) {
            Some(res)
        } else {
            None
        }
    }

    /// Verify the remote confirm value.
    pub fn verify_confirm(&self) -> bool {
        let mut computed = [0u8; 16];
        if crypto::bt_crypto_c1(
            &self.tk,
            &self.remote_random,
            &self.preq,
            &self.pres,
            self.ia_type,
            &self.ia,
            self.ra_type,
            &self.ra,
            &mut computed,
        ) {
            computed == self.local_confirm
        } else {
            false
        }
    }

    /// Generate STK from confirmed random values.
    pub fn compute_stk(&self) -> Option<[u8; 16]> {
        let (r1, r2) = if self.initiator {
            (&self.local_random, &self.remote_random)
        } else {
            (&self.remote_random, &self.local_random)
        };
        let mut res = [0u8; 16];
        if crypto::bt_crypto_s1(&self.tk, r1, r2, &mut res) {
            Some(res)
        } else {
            None
        }
    }

    /// Set encryption state.
    pub fn set_encrypted(&mut self, encrypted: bool) {
        self.encrypted = encrypted;
        if encrypted && self.state == SmpState::WaitingRandom {
            self.state = SmpState::KeyDistribution;
        }
    }
}

/// SMP context managing all connections.
pub struct Smp {
    connections: Vec<SmpConn>,
    io_capability: u8,
    auth_req: u8,
}

impl Smp {
    /// Create SMP context.
    pub fn new() -> Self {
        Self {
            connections: Vec::new(),
            io_capability: SMP_IO_NO_INPUT_OUTPUT,
            auth_req: SMP_AUTH_BONDING,
        }
    }

    /// Set pairing IO capability.
    pub fn set_io_capability(&mut self, io_cap: u8) {
        self.io_capability = io_cap;
    }

    /// Set auth requirements.
    pub fn set_auth_req(&mut self, auth_req: u8) {
        self.auth_req = auth_req;
    }

    /// Add a new connection for SMP tracking.
    pub fn conn_add(
        &mut self,
        handle: u16,
        ia: &[u8; 6],
        ia_type: u8,
        ra: &[u8; 6],
        ra_type: u8,
        initiator: bool,
    ) -> usize {
        let conn = SmpConn::new(handle, ia, ia_type, ra, ra_type, initiator);
        self.connections.push(conn);
        self.connections.len() - 1
    }

    /// Remove a connection.
    pub fn conn_del(&mut self, handle: u16) {
        self.connections.retain(|c| c.handle != handle);
    }

    /// Get a connection by handle.
    pub fn conn_get(&self, handle: u16) -> Option<&SmpConn> {
        self.connections.iter().find(|c| c.handle == handle)
    }

    /// Get a mutable connection by handle.
    pub fn conn_get_mut(&mut self, handle: u16) -> Option<&mut SmpConn> {
        self.connections.iter_mut().find(|c| c.handle == handle)
    }

    /// Set encryption state for a connection.
    pub fn conn_encrypted(&mut self, handle: u16, encrypted: bool) {
        if let Some(conn) = self.conn_get_mut(handle) {
            conn.set_encrypted(encrypted);
        }
    }

    /// Build a pairing request/response PDU.
    pub fn build_pairing_pdu(&self, opcode: u8) -> Vec<u8> {
        let mut pdu = vec![opcode];
        pdu.push(self.io_capability);
        pdu.push(0x00); // OOB not available
        pdu.push(self.auth_req);
        pdu.push(16); // max key size
        pdu.push(SMP_DIST_ENC_KEY | SMP_DIST_ID_KEY); // init key dist
        pdu.push(SMP_DIST_ENC_KEY | SMP_DIST_ID_KEY); // resp key dist
        pdu
    }

    /// Look up LTK by rand and ediv.
    pub fn get_ltk(&self, rand_val: u64, ediv: u16) -> Option<&[u8; 16]> {
        self.connections
            .iter()
            .find(|c| c.rand_val == rand_val && c.ediv == ediv)
            .map(|c| &c.ltk)
    }

    /// Initiate pairing on a connection.
    pub fn pair(&mut self, handle: u16) -> Option<Vec<u8>> {
        let pdu = self.build_pairing_pdu(SMP_CMD_PAIRING_REQUEST);
        if let Some(conn) = self.conn_get_mut(handle) {
            conn.state = SmpState::WaitingResponse;
            conn.preq.copy_from_slice(&pdu);
            Some(pdu)
        } else {
            None
        }
    }

    /// Process incoming SMP data for a connection.
    pub fn process_data(&mut self, handle: u16, data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }

        let opcode = data[0];
        match opcode {
            SMP_CMD_PAIRING_REQUEST => self.handle_pairing_request(handle, data),
            SMP_CMD_PAIRING_RESPONSE => self.handle_pairing_response(handle, data),
            SMP_CMD_PAIRING_CONFIRM => self.handle_confirm(handle, data),
            SMP_CMD_PAIRING_RANDOM => self.handle_random(handle, data),
            _ => None,
        }
    }

    fn handle_pairing_request(&mut self, handle: u16, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 7 {
            return None;
        }
        let params = PairingParams::from_bytes(&data[1..])?;
        let conn = self.conn_get_mut(handle)?;
        conn.remote_params = Some(params);
        conn.preq.copy_from_slice(&data[..7]);
        conn.state = SmpState::WaitingConfirm;

        // Build response
        let pdu = vec![
            SMP_CMD_PAIRING_RESPONSE,
            self.io_capability,
            0x00,
            self.auth_req,
            16,
            SMP_DIST_ENC_KEY | SMP_DIST_ID_KEY,
            SMP_DIST_ENC_KEY | SMP_DIST_ID_KEY,
        ];
        // Save our response for confirm computation
        let conn = self.conn_get_mut(handle)?;
        conn.pres.copy_from_slice(&pdu);
        conn.local_params = Some(PairingParams::from_bytes(&pdu[1..])?);
        Some(pdu)
    }

    fn handle_pairing_response(&mut self, handle: u16, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 7 {
            return None;
        }
        let params = PairingParams::from_bytes(&data[1..])?;
        let conn = self.conn_get_mut(handle)?;
        conn.remote_params = Some(params);
        conn.pres.copy_from_slice(&data[..7]);
        conn.state = SmpState::WaitingConfirm;

        // Generate random and compute confirm
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.fill(&mut conn.local_random);

        let confirm = conn.compute_confirm()?;
        conn.local_confirm = confirm;

        let mut pdu = vec![SMP_CMD_PAIRING_CONFIRM];
        pdu.extend_from_slice(&confirm);
        Some(pdu)
    }

    fn handle_confirm(&mut self, handle: u16, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 17 {
            return None;
        }
        let conn = self.conn_get_mut(handle)?;

        if conn.initiator {
            // Store remote confirm, send our random
            let mut pdu = vec![SMP_CMD_PAIRING_RANDOM];
            pdu.extend_from_slice(&conn.local_random);
            conn.state = SmpState::WaitingRandom;
            Some(pdu)
        } else {
            // Non-initiator: generate random, compute confirm, send confirm
            use rand::Rng;
            let mut rng = rand::thread_rng();
            rng.fill(&mut conn.local_random);

            let confirm = conn.compute_confirm()?;
            conn.local_confirm = confirm;

            let mut pdu = vec![SMP_CMD_PAIRING_CONFIRM];
            pdu.extend_from_slice(&confirm);
            conn.state = SmpState::WaitingRandom;
            Some(pdu)
        }
    }

    fn handle_random(&mut self, handle: u16, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 17 {
            return None;
        }
        let conn = self.conn_get_mut(handle)?;
        conn.remote_random.copy_from_slice(&data[1..17]);

        if conn.initiator {
            // Verify remote confirm, compute STK
            if let Some(stk) = conn.compute_stk() {
                conn.ltk = stk;
                conn.state = SmpState::KeyDistribution;
            } else {
                conn.state = SmpState::Failed;
            }
            None
        } else {
            // Send our random
            let mut pdu = vec![SMP_CMD_PAIRING_RANDOM];
            pdu.extend_from_slice(&conn.local_random);

            if let Some(stk) = conn.compute_stk() {
                conn.ltk = stk;
                conn.state = SmpState::KeyDistribution;
            } else {
                conn.state = SmpState::Failed;
            }
            Some(pdu)
        }
    }
}

impl Default for Smp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing_params() {
        let params = PairingParams {
            io_capability: SMP_IO_NO_INPUT_OUTPUT,
            oob_data: 0,
            auth_req: SMP_AUTH_BONDING,
            max_key_size: 16,
            init_key_dist: SMP_DIST_ENC_KEY,
            resp_key_dist: SMP_DIST_ENC_KEY,
        };
        let bytes = params.to_bytes();
        let parsed = PairingParams::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.io_capability, SMP_IO_NO_INPUT_OUTPUT);
        assert_eq!(parsed.max_key_size, 16);
    }

    #[test]
    fn test_smp_conn_lifecycle() {
        let mut smp = Smp::new();
        let ia = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let ra = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

        smp.conn_add(0x0040, &ia, 0, &ra, 1, true);
        assert!(smp.conn_get(0x0040).is_some());
        assert!(smp.conn_get(0x0041).is_none());

        smp.conn_encrypted(0x0040, true);
        assert!(smp.conn_get(0x0040).unwrap().encrypted);

        smp.conn_del(0x0040);
        assert!(smp.conn_get(0x0040).is_none());
    }

    #[test]
    fn test_smp_pair_initiate() {
        let mut smp = Smp::new();
        let ia = [0x01; 6];
        let ra = [0x02; 6];
        smp.conn_add(0x0040, &ia, 0, &ra, 1, true);

        let pdu = smp.pair(0x0040).unwrap();
        assert_eq!(pdu[0], SMP_CMD_PAIRING_REQUEST);
        assert_eq!(pdu.len(), 7);

        let conn = smp.conn_get(0x0040).unwrap();
        assert_eq!(conn.state, SmpState::WaitingResponse);
    }

    #[test]
    fn test_smp_build_pdu() {
        let smp = Smp::new();
        let pdu = smp.build_pairing_pdu(SMP_CMD_PAIRING_REQUEST);
        assert_eq!(pdu[0], SMP_CMD_PAIRING_REQUEST);
        assert_eq!(pdu[1], SMP_IO_NO_INPUT_OUTPUT);
        assert_eq!(pdu.len(), 7);
    }

    #[test]
    fn test_smp_state_default() {
        let conn = SmpConn::new(0x0040, &[0; 6], 0, &[0; 6], 1, false);
        assert_eq!(conn.state, SmpState::Idle);
        assert!(!conn.encrypted);
        assert!(!conn.initiator);
    }
}
