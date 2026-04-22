// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/bluez-emulator/src/smp.rs — Security Manager Protocol emulation
//
// Complete Rust rewrite of BlueZ emulator/smp.c (923 lines).
// Implements the SMP state machine for LE and BR/EDR fixed-channel pairing.
// Supports legacy pairing (c1/s1 functions) and Secure Connections pairing
// (ECC key generation, ECDH, f4/f5/f6 crypto functions).
//
// Architecture note: Because SmpManager is a trait object owned by BtHost,
// the SMP cannot hold a back-reference to BtHost.  Instead, output actions
// (send packets, start encryption) are buffered in `actions: Vec<SmpAction>`
// and drained by BtHost after each SmpManager method call.  Configuration
// values (io_capability, auth_req, bredr_capable, fixed_chan bitmaps) are
// stored locally in the Smp struct and updated by BtHost via trait methods.

use std::collections::HashMap;

use thiserror::Error;

use bluez_shared::crypto::aes_cmac::{
    bt_crypto_c1, bt_crypto_f4, bt_crypto_f5, bt_crypto_f6, bt_crypto_s1, random_bytes,
};
use bluez_shared::crypto::ecc::{ecc_make_key, ecdh_shared_secret};
use bluez_shared::sys::bluetooth::{BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, bt_put_le32};
use bluez_shared::sys::hci::{LE_PUBLIC_ADDRESS, LE_RANDOM_ADDRESS};

// ---------------------------------------------------------------------------
// SMP Error Type
// ---------------------------------------------------------------------------

/// Errors from the SMP subsystem.
#[derive(Debug, Error)]
pub enum SmpError {
    /// No LTK has been negotiated yet (equivalent to C `-ENOENT`).
    #[error("No LTK available")]
    NoLtk,

    /// Cryptographic operation failed during SMP processing.
    #[error("Crypto error: {0}")]
    Crypto(String),
}

// ---------------------------------------------------------------------------
// SMP Output Actions
// ---------------------------------------------------------------------------

/// Actions buffered by the SMP state machine for execution by BtHost.
/// After each SmpManager method call, BtHost must drain these via
/// `take_actions()` and execute them.
#[derive(Debug)]
pub enum SmpAction {
    /// Send data on a specific L2CAP CID.
    SendCidV {
        /// ACL connection handle.
        handle: u16,
        /// L2CAP channel identifier.
        cid: u16,
        /// Payload data to send.
        data: Vec<u8>,
    },
    /// Initiate LE encryption with the given LTK.
    LeStartEncrypt {
        /// ACL connection handle.
        handle: u16,
        /// Long Term Key for encryption.
        ltk: [u8; 16],
    },
}

// ---------------------------------------------------------------------------
// L2CAP CID Constants
// ---------------------------------------------------------------------------

/// L2CAP fixed channel CID for SMP over LE.
const SMP_CID: u16 = 0x0006;

/// L2CAP fixed channel CID for SMP over BR/EDR.
const SMP_BREDR_CID: u16 = 0x0007;

/// Fixed channel bit for SMP over BR/EDR in L2CAP info response.
const L2CAP_FC_SMP_BREDR: u64 = 0x80;

// ---------------------------------------------------------------------------
// SMP Error Codes (sent in Pairing Failed PDU)
// ---------------------------------------------------------------------------

const SMP_CONFIRM_FAILED: u8 = 0x04;
const SMP_UNSPECIFIED: u8 = 0x08;
const SMP_DHKEY_CHECK_FAILED: u8 = 0x0b;

// ---------------------------------------------------------------------------
// Key Distribution Flags
// ---------------------------------------------------------------------------

/// Distribute Encryption Key (LTK + Rand + EDIV).
const DIST_ENC_KEY: u8 = 0x01;

/// Distribute Identity Key (IRK + Identity Address).
const DIST_ID_KEY: u8 = 0x02;

/// Distribute Signing Key (CSRK).
const DIST_SIGN: u8 = 0x04;

/// Distribute Link Key (for cross-transport pairing).
const DIST_LINK_KEY: u8 = 0x08;

/// Keys NOT distributed in Secure Connections mode.
const SC_NO_DIST: u8 = DIST_ENC_KEY | DIST_LINK_KEY;

// ---------------------------------------------------------------------------
// IO Capability and Auth Constants
// ---------------------------------------------------------------------------

/// Maximum valid IO capability value.
const MAX_IO_CAP: u8 = 0x04;

/// Auth requirement: Secure Connections flag.
const SMP_AUTH_SC: u8 = 0x08;

/// Auth requirement: MITM flag.
const SMP_AUTH_MITM: u8 = 0x04;

// ---------------------------------------------------------------------------
// SMP PDU Opcode Constants (from monitor/bt.h)
// ---------------------------------------------------------------------------

const BT_L2CAP_SMP_PAIRING_REQUEST: u8 = 0x01;
const BT_L2CAP_SMP_PAIRING_RESPONSE: u8 = 0x02;
const BT_L2CAP_SMP_PAIRING_CONFIRM: u8 = 0x03;
const BT_L2CAP_SMP_PAIRING_RANDOM: u8 = 0x04;
const BT_L2CAP_SMP_PAIRING_FAILED: u8 = 0x05;
const BT_L2CAP_SMP_ENCRYPT_INFO: u8 = 0x06;
const BT_L2CAP_SMP_CENTRAL_IDENT: u8 = 0x07;
const BT_L2CAP_SMP_IDENT_INFO: u8 = 0x08;
const BT_L2CAP_SMP_IDENT_ADDR_INFO: u8 = 0x09;
const BT_L2CAP_SMP_SIGNING_INFO: u8 = 0x0a;
const BT_L2CAP_SMP_PUBLIC_KEY: u8 = 0x0c;
const BT_L2CAP_SMP_DHKEY_CHECK: u8 = 0x0d;

// ---------------------------------------------------------------------------
// Pairing Method Enum and Lookup Tables
// ---------------------------------------------------------------------------

/// Pairing authentication method selected based on IO capabilities.
///
/// All methods from the SMP specification are included, including `ReqOob`
/// which is not used in the current pairing table entries but is mandated
/// by the Bluetooth SMP specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingMethod {
    /// Just Works: no user interaction required.
    JustWorks,
    /// Just Confirm: user confirms numeric comparison.
    JustCfm,
    /// Request Passkey: user enters passkey on local device.
    ReqPasskey,
    /// Confirm Passkey: user confirms displayed passkey.
    CfmPasskey,
    /// Request OOB: Out-of-Band data used for pairing.
    ReqOob,
    /// Display Passkey: passkey displayed for entry on remote.
    DspPasskey,
    /// Overlap: both devices have keyboard+display.
    Overlap,
}

use PairingMethod::*;

/// Legacy pairing method matrix, indexed by [remote_io][local_io].
/// Matches the C `gen_method` array (smp.c lines 116-122) exactly.
#[rustfmt::skip]
const GEN_METHOD: [[PairingMethod; 5]; 5] = [
    [JustWorks,  JustCfm,    ReqPasskey, JustWorks, ReqPasskey],
    [JustWorks,  JustCfm,    ReqPasskey, JustWorks, ReqPasskey],
    [CfmPasskey, CfmPasskey, ReqPasskey, JustWorks, CfmPasskey],
    [JustWorks,  JustCfm,    JustWorks,  JustWorks, JustCfm   ],
    [CfmPasskey, CfmPasskey, ReqPasskey, JustWorks, Overlap    ],
];

/// Secure Connections pairing method matrix, indexed by [remote_io][local_io].
/// Matches the C `sc_method` array (smp.c lines 124-130) exactly.
#[rustfmt::skip]
const SC_METHOD: [[PairingMethod; 5]; 5] = [
    [JustWorks,  JustCfm,    ReqPasskey, JustWorks, ReqPasskey],
    [JustWorks,  CfmPasskey, ReqPasskey, JustWorks, CfmPasskey],
    [DspPasskey, DspPasskey, ReqPasskey, JustWorks, DspPasskey],
    [JustWorks,  JustCfm,    JustWorks,  JustWorks, JustCfm   ],
    [DspPasskey, CfmPasskey, ReqPasskey, JustWorks, CfmPasskey],
];

// ---------------------------------------------------------------------------
// SMP Structs
// ---------------------------------------------------------------------------

/// Top-level SMP context implementing the pairing state machine.
/// Replaces `struct smp` from smp.c lines 68-72.
///
/// Output actions are buffered in `actions` and must be drained by the caller
/// (BtHost) after each SmpManager method call via `take_actions()`.
pub struct Smp {
    /// Per-connection SMP state, keyed by ACL handle.
    connections: HashMap<u16, SmpConn>,
    /// Buffered output actions for the caller to execute.
    actions: Vec<SmpAction>,
    /// Current IO capability of the host (mirrored from BtHost).
    io_capability: u8,
    /// Current auth requirements of the host (mirrored from BtHost).
    auth_req: u8,
    /// Whether the host supports BR/EDR (mirrored from BtHost).
    bredr_capable: bool,
    /// Per-connection fixed channel bitmaps (mirrored from BtHost).
    conn_fixed_chans: HashMap<u16, u64>,
}

/// Per-connection SMP pairing state machine.
/// Replaces `struct smp_conn` from smp.c lines 74-104.
pub struct SmpConn {
    /// ACL connection handle.
    handle: u16,
    /// Address type of the local side (BDADDR_BREDR, BDADDR_LE_PUBLIC, etc.).
    addr_type: u8,
    /// `true` if this side initiated the pairing (initiator role).
    out: bool,
    /// `true` if Secure Connections mode is active.
    sc: bool,
    /// Same as `out` (preserved for behavioral parity with C code).
    initiator: bool,
    /// Selected pairing authentication method.
    method: PairingMethod,
    /// Local key distribution flags.
    local_key_dist: u8,
    /// Remote key distribution flags.
    remote_key_dist: u8,
    /// Initiator Bluetooth address (6 bytes).
    ia: [u8; 6],
    /// Initiator address type in HCI format.
    ia_type: u8,
    /// Responder Bluetooth address (6 bytes).
    ra: [u8; 6],
    /// Responder address type in HCI format.
    ra_type: u8,
    /// Temporary Key (legacy pairing).
    tk: [u8; 16],
    /// Local random nonce.
    prnd: [u8; 16],
    /// Remote random nonce.
    rrnd: [u8; 16],
    /// Received pairing confirm value.
    pcnf: [u8; 16],
    /// Pairing Request PDU (opcode + 6 bytes).
    preq: [u8; 7],
    /// Pairing Response PDU (opcode + 6 bytes).
    prsp: [u8; 7],
    /// Long-Term Key.
    ltk: [u8; 16],
    /// Local secret key for Secure Connections (32 bytes).
    local_sk: [u8; 32],
    /// Local public key for Secure Connections (64 bytes).
    local_pk: [u8; 64],
    /// Remote public key for Secure Connections (64 bytes).
    remote_pk: [u8; 64],
    /// Diffie-Hellman shared secret (32 bytes).
    dhkey: [u8; 32],
    /// MAC key derived from f5 (16 bytes).
    mackey: [u8; 16],
    /// Passkey value for passkey-entry authentication.
    passkey_notify: u8,
    /// Current passkey round counter (0-19 for SC passkey entry).
    passkey_round: u8,
}

// ---------------------------------------------------------------------------
// Helper: Address Type Conversion
// ---------------------------------------------------------------------------

/// Convert BlueZ address type to HCI address type.
/// Replaces `type2hci()` from smp.c lines 840-851.
fn type2hci(addr_type: u8) -> u8 {
    match addr_type {
        BDADDR_BREDR | BDADDR_LE_PUBLIC => LE_PUBLIC_ADDRESS,
        BDADDR_LE_RANDOM => LE_RANDOM_ADDRESS,
        _ => 0x00,
    }
}

// ---------------------------------------------------------------------------
// Helper: Pairing Method Selection
// ---------------------------------------------------------------------------

/// Look up the pairing method from IO capability matrices.
/// Replaces `get_auth_method()` from smp.c lines 132-145.
fn get_auth_method(sc: bool, local_io: u8, remote_io: u8) -> PairingMethod {
    if local_io > MAX_IO_CAP || remote_io > MAX_IO_CAP {
        return JustCfm;
    }
    let li = local_io as usize;
    let ri = remote_io as usize;
    if sc { SC_METHOD[ri][li] } else { GEN_METHOD[ri][li] }
}

/// Select the SC pairing method from the pairing PDUs.
/// Replaces `sc_select_method()` from smp.c lines 147-179.
fn sc_select_method(conn: &SmpConn) -> PairingMethod {
    let (local_pdu, remote_pdu) = if conn.out {
        (&conn.preq[1..], &conn.prsp[1..])
    } else {
        (&conn.prsp[1..], &conn.preq[1..])
    };

    let local_io = local_pdu[0];
    let remote_io = remote_pdu[0];
    let local_mitm = local_pdu[2] & SMP_AUTH_MITM;
    let remote_mitm = remote_pdu[2] & SMP_AUTH_MITM;

    let method = if local_mitm != 0 || remote_mitm != 0 {
        get_auth_method(conn.sc, local_io, remote_io)
    } else {
        JustWorks
    };

    if method == JustCfm && conn.initiator { JustWorks } else { method }
}

/// Compute key distribution flags based on host capabilities.
/// Replaces `key_dist()` from smp.c lines 181-187.
fn key_dist(bredr_capable: bool) -> u8 {
    if !bredr_capable {
        DIST_ENC_KEY | DIST_ID_KEY | DIST_SIGN
    } else {
        DIST_ENC_KEY | DIST_ID_KEY | DIST_SIGN | DIST_LINK_KEY
    }
}

// ---------------------------------------------------------------------------
// SmpConn: Internal Helper Methods
// ---------------------------------------------------------------------------

impl SmpConn {
    /// Send an SMP PDU (opcode + payload) on the appropriate CID.
    /// Replaces `smp_send()` from smp.c lines 189-207.
    /// Buffers the output into the actions vec for BtHost to execute.
    fn smp_send(&self, actions: &mut Vec<SmpAction>, smp_cmd: u8, data: &[u8]) {
        let cid = if self.addr_type == BDADDR_BREDR { SMP_BREDR_CID } else { SMP_CID };
        let mut pdu = Vec::with_capacity(1 + data.len());
        pdu.push(smp_cmd);
        pdu.extend_from_slice(data);
        actions.push(SmpAction::SendCidV { handle: self.handle, cid, data: pdu });
    }

    /// Generate and send our SC public key.
    /// Replaces `send_public_key()` from smp.c lines 209-217.
    fn send_public_key(&mut self, actions: &mut Vec<SmpAction>) -> bool {
        match ecc_make_key() {
            Ok((pk, sk)) => {
                self.local_pk = pk;
                self.local_sk = sk;
                let pk_copy = self.local_pk;
                self.smp_send(actions, BT_L2CAP_SMP_PUBLIC_KEY, &pk_copy);
                true
            }
            Err(_) => false,
        }
    }

    /// Derive MacKey and LTK from ECDH shared secret.
    /// Replaces `sc_mackey_and_ltk()` from smp.c lines 247-266.
    fn sc_mackey_and_ltk(&mut self) {
        let (na, nb) = if self.out { (&self.prnd, &self.rrnd) } else { (&self.rrnd, &self.prnd) };

        let mut a = [0u8; 7];
        let mut b = [0u8; 7];
        a[..6].copy_from_slice(&self.ia);
        a[6] = self.ia_type;
        b[..6].copy_from_slice(&self.ra);
        b[6] = self.ra_type;

        if let Ok((mackey, ltk)) = bt_crypto_f5(&self.dhkey, na, nb, &a, &b) {
            self.mackey = mackey;
            self.ltk = ltk;
        }
    }

    /// Compute and send a DHKey Check value.
    /// Replaces `sc_dhkey_check()` from smp.c lines 219-245.
    fn sc_dhkey_check(&self, actions: &mut Vec<SmpAction>) {
        let mut a = [0u8; 7];
        let mut b = [0u8; 7];
        a[..6].copy_from_slice(&self.ia);
        a[6] = self.ia_type;
        b[..6].copy_from_slice(&self.ra);
        b[6] = self.ra_type;

        let (local_addr, remote_addr, io_cap_src) =
            if self.out { (&a, &b, &self.preq[1..4]) } else { (&b, &a, &self.prsp[1..4]) };

        let mut io_cap = [0u8; 3];
        io_cap.copy_from_slice(io_cap_src);

        let r = [0u8; 16];

        if let Ok(check_e) =
            bt_crypto_f6(&self.mackey, &self.prnd, &self.rrnd, &r, &io_cap, local_addr, remote_addr)
        {
            self.smp_send(actions, BT_L2CAP_SMP_DHKEY_CHECK, &check_e);
        }
    }

    /// Send an SC passkey confirm value for the current round.
    /// Replaces `sc_passkey_send_confirm()` from smp.c lines 268-283.
    fn sc_passkey_send_confirm(&self, actions: &mut Vec<SmpAction>) -> u8 {
        let mut r = (self.passkey_notify >> self.passkey_round) & 0x01;
        r |= 0x80;

        let mut local_pk_x = [0u8; 32];
        let mut remote_pk_x = [0u8; 32];
        local_pk_x.copy_from_slice(&self.local_pk[..32]);
        remote_pk_x.copy_from_slice(&self.remote_pk[..32]);

        match bt_crypto_f4(&local_pk_x, &remote_pk_x, &self.prnd, r) {
            Ok(cfm) => {
                self.smp_send(actions, BT_L2CAP_SMP_PAIRING_CONFIRM, &cfm);
                0
            }
            Err(_) => SMP_UNSPECIFIED,
        }
    }

    /// Execute one round of the SC passkey authentication protocol.
    /// Replaces `sc_passkey_round()` from smp.c lines 285-349.
    fn sc_passkey_round(&mut self, actions: &mut Vec<SmpAction>, smp_op: u8) -> u8 {
        if self.passkey_round >= 20 {
            return 0;
        }

        match smp_op {
            BT_L2CAP_SMP_PAIRING_RANDOM => {
                let mut r = (self.passkey_notify >> self.passkey_round) & 0x01;
                r |= 0x80;

                let mut remote_pk_x = [0u8; 32];
                let mut local_pk_x = [0u8; 32];
                remote_pk_x.copy_from_slice(&self.remote_pk[..32]);
                local_pk_x.copy_from_slice(&self.local_pk[..32]);

                let cfm = match bt_crypto_f4(&remote_pk_x, &local_pk_x, &self.rrnd, r) {
                    Ok(c) => c,
                    Err(_) => return SMP_UNSPECIFIED,
                };

                if self.pcnf != cfm {
                    return SMP_CONFIRM_FAILED;
                }

                self.passkey_round += 1;

                if self.passkey_round == 20 {
                    self.sc_mackey_and_ltk();
                }

                if !self.out {
                    let prnd = self.prnd;
                    self.smp_send(actions, BT_L2CAP_SMP_PAIRING_RANDOM, &prnd);
                    return 0;
                }

                if self.passkey_round != 20 {
                    return self.sc_passkey_round(actions, 0);
                }

                self.sc_dhkey_check(actions);
                0
            }
            BT_L2CAP_SMP_PAIRING_CONFIRM => {
                if self.out {
                    let prnd = self.prnd;
                    self.smp_send(actions, BT_L2CAP_SMP_PAIRING_RANDOM, &prnd);
                    return 0;
                }
                self.sc_passkey_send_confirm(actions)
            }
            _ => {
                if !self.out {
                    return 0;
                }
                self.sc_passkey_send_confirm(actions)
            }
        }
    }

    /// Verify received random value in legacy pairing.
    /// Replaces `verify_random()` from smp.c lines 351-377.
    fn verify_random(&mut self, actions: &mut Vec<SmpAction>) -> bool {
        let confirm = match bt_crypto_c1(
            &self.tk,
            &self.rrnd,
            &self.prsp,
            &self.preq,
            self.ia_type,
            &self.ia,
            self.ra_type,
            &self.ra,
        ) {
            Ok(c) => c,
            Err(_) => return false,
        };

        if self.pcnf != confirm {
            return false;
        }

        if self.out {
            if let Ok(ltk) = bt_crypto_s1(&self.tk, &self.rrnd, &self.prnd) {
                self.ltk = ltk;
            }
            let ltk = self.ltk;
            actions.push(SmpAction::LeStartEncrypt { handle: self.handle, ltk });
        } else if let Ok(ltk) = bt_crypto_s1(&self.tk, &self.prnd, &self.rrnd) {
            self.ltk = ltk;
        }

        true
    }

    /// Distribute keys after pairing completes.
    /// Replaces `distribute_keys()` from smp.c lines 379-410.
    fn distribute_keys(&self, actions: &mut Vec<SmpAction>) {
        if self.local_key_dist & DIST_ENC_KEY != 0 {
            let buf = [0u8; 16];
            self.smp_send(actions, BT_L2CAP_SMP_ENCRYPT_INFO, &buf);
            let buf10 = [0u8; 10];
            self.smp_send(actions, BT_L2CAP_SMP_CENTRAL_IDENT, &buf10);
        }

        if self.local_key_dist & DIST_ID_KEY != 0 {
            let buf = [0u8; 16];
            self.smp_send(actions, BT_L2CAP_SMP_IDENT_INFO, &buf);

            let mut id_buf = [0u8; 7];
            if self.out {
                id_buf[0] = self.ia_type;
                id_buf[1..7].copy_from_slice(&self.ia);
            } else {
                id_buf[0] = self.ra_type;
                id_buf[1..7].copy_from_slice(&self.ra);
            }
            self.smp_send(actions, BT_L2CAP_SMP_IDENT_ADDR_INFO, &id_buf);
        }

        if self.local_key_dist & DIST_SIGN != 0 {
            let buf = [0u8; 16];
            self.smp_send(actions, BT_L2CAP_SMP_SIGNING_INFO, &buf);
        }
    }

    /// Handle SC confirm check logic.
    /// Replaces `sc_check_confirm()` from smp.c lines 487-497.
    fn sc_check_confirm(&mut self, actions: &mut Vec<SmpAction>) {
        if self.method == ReqPasskey || self.method == DspPasskey {
            self.sc_passkey_round(actions, BT_L2CAP_SMP_PAIRING_CONFIRM);
            return;
        }

        if self.out {
            let prnd = self.prnd;
            self.smp_send(actions, BT_L2CAP_SMP_PAIRING_RANDOM, &prnd);
        }
    }

    /// Handle SC random value processing.
    /// Replaces `sc_random()` from smp.c lines 522-546.
    fn sc_random(&mut self, actions: &mut Vec<SmpAction>) -> u8 {
        if self.method == ReqPasskey || self.method == DspPasskey {
            return self.sc_passkey_round(actions, BT_L2CAP_SMP_PAIRING_RANDOM);
        }

        if self.out {
            let mut remote_pk_x = [0u8; 32];
            let mut local_pk_x = [0u8; 32];
            remote_pk_x.copy_from_slice(&self.remote_pk[..32]);
            local_pk_x.copy_from_slice(&self.local_pk[..32]);

            if let Ok(cfm) = bt_crypto_f4(&remote_pk_x, &local_pk_x, &self.rrnd, 0) {
                if self.pcnf != cfm {
                    return SMP_CONFIRM_FAILED;
                }
            }
        } else {
            let prnd = self.prnd;
            self.smp_send(actions, BT_L2CAP_SMP_PAIRING_RANDOM, &prnd);
        }

        self.sc_mackey_and_ltk();

        if self.out {
            self.sc_dhkey_check(actions);
        }

        0
    }
}

// ---------------------------------------------------------------------------
// SMP PDU Handlers
// ---------------------------------------------------------------------------

impl SmpConn {
    /// Handle Pairing Request PDU.
    /// Replaces `pairing_req()` from smp.c lines 412-450.
    fn pairing_req(
        &mut self,
        actions: &mut Vec<SmpAction>,
        data: &[u8],
        io_capability: u8,
        auth_req_val: u8,
        bredr_capable: bool,
    ) {
        let copy_len = data.len().min(7);
        self.preq[..copy_len].copy_from_slice(&data[..copy_len]);

        let (io_capa, oob_data, auth_r) = if self.addr_type == BDADDR_BREDR {
            (0x00u8, 0x00u8, 0x00u8)
        } else {
            (io_capability, 0x00u8, auth_req_val)
        };

        let dist = key_dist(bredr_capable);
        let init_key_dist = self.preq[5] & dist;
        let resp_key_dist = self.preq[6] & dist;

        let rsp = [io_capa, oob_data, auth_r, 0x10, init_key_dist, resp_key_dist];

        self.prsp[0] = BT_L2CAP_SMP_PAIRING_RESPONSE;
        self.prsp[1..7].copy_from_slice(&rsp);

        self.local_key_dist = resp_key_dist;
        self.remote_key_dist = init_key_dist;

        if ((self.prsp[3] & SMP_AUTH_SC) != 0 && (self.preq[3] & SMP_AUTH_SC) != 0)
            || self.addr_type == BDADDR_BREDR
        {
            self.sc = true;
            self.local_key_dist &= !SC_NO_DIST;
            self.remote_key_dist &= !SC_NO_DIST;
        }

        self.smp_send(actions, BT_L2CAP_SMP_PAIRING_RESPONSE, &rsp);

        if self.addr_type == BDADDR_BREDR {
            self.distribute_keys(actions);
        }
    }

    /// Handle Pairing Response PDU.
    /// Replaces `pairing_rsp()` from smp.c lines 452-486.
    fn pairing_rsp(&mut self, actions: &mut Vec<SmpAction>, data: &[u8]) {
        let copy_len = data.len().min(7);
        self.prsp[..copy_len].copy_from_slice(&data[..copy_len]);

        self.local_key_dist = self.prsp[5];
        self.remote_key_dist = self.prsp[6];

        if self.addr_type == BDADDR_BREDR {
            self.local_key_dist &= !SC_NO_DIST;
            self.remote_key_dist &= !SC_NO_DIST;
            self.distribute_keys(actions);
            return;
        }

        if ((self.prsp[3] & SMP_AUTH_SC) != 0 && (self.preq[3] & SMP_AUTH_SC) != 0)
            || self.addr_type == BDADDR_BREDR
        {
            self.sc = true;
            self.local_key_dist &= !SC_NO_DIST;
            self.remote_key_dist &= !SC_NO_DIST;
            if self.addr_type == BDADDR_BREDR {
                self.distribute_keys(actions);
            } else {
                self.send_public_key(actions);
            }
            return;
        }

        // Legacy pairing: compute c1 confirm and send
        if let Ok(cfm) = bt_crypto_c1(
            &self.tk,
            &self.prnd,
            &self.prsp,
            &self.preq,
            self.ia_type,
            &self.ia,
            self.ra_type,
            &self.ra,
        ) {
            self.smp_send(actions, BT_L2CAP_SMP_PAIRING_CONFIRM, &cfm);
        }
    }

    /// Handle Pairing Confirm PDU.
    /// Replaces `pairing_cfm()` from smp.c lines 499-520.
    fn pairing_cfm(&mut self, actions: &mut Vec<SmpAction>, data: &[u8]) {
        if data.len() > 1 {
            let copy_len = (data.len() - 1).min(16);
            self.pcnf[..copy_len].copy_from_slice(&data[1..1 + copy_len]);
        }

        if self.sc {
            self.sc_check_confirm(actions);
            return;
        }

        if self.out {
            let prnd = self.prnd;
            self.smp_send(actions, BT_L2CAP_SMP_PAIRING_RANDOM, &prnd);
        } else if let Ok(rsp) = bt_crypto_c1(
            &self.tk,
            &self.prnd,
            &self.prsp,
            &self.preq,
            self.ia_type,
            &self.ia,
            self.ra_type,
            &self.ra,
        ) {
            self.smp_send(actions, BT_L2CAP_SMP_PAIRING_CONFIRM, &rsp);
        }
    }

    /// Handle Pairing Random PDU.
    /// Replaces `pairing_rnd()` from smp.c lines 548-568.
    fn pairing_rnd(&mut self, actions: &mut Vec<SmpAction>, data: &[u8]) {
        if data.len() > 1 {
            let copy_len = (data.len() - 1).min(16);
            self.rrnd[..copy_len].copy_from_slice(&data[1..1 + copy_len]);
        }

        if self.sc {
            let reason = self.sc_random(actions);
            if reason != 0 {
                self.smp_send(actions, BT_L2CAP_SMP_PAIRING_FAILED, &[reason]);
            }
            return;
        }

        if !self.verify_random(actions) {
            return;
        }

        if self.out {
            return;
        }

        let prnd = self.prnd;
        self.smp_send(actions, BT_L2CAP_SMP_PAIRING_RANDOM, &prnd);
    }

    /// Handle received Public Key PDU (SC only).
    /// Replaces `public_key()` from smp.c lines 603-633.
    fn public_key_handler(&mut self, actions: &mut Vec<SmpAction>, data: &[u8]) {
        if data.len() > 1 {
            let copy_len = (data.len() - 1).min(64);
            self.remote_pk[..copy_len].copy_from_slice(&data[1..1 + copy_len]);
        }

        if !self.out && !self.send_public_key(actions) {
            return;
        }

        if ecdh_shared_secret(&self.remote_pk, &self.local_sk)
            .map(|dhkey| self.dhkey = dhkey)
            .is_err()
        {
            return;
        }

        self.method = sc_select_method(self);

        if self.method == DspPasskey || self.method == ReqPasskey {
            self.sc_passkey_round(actions, BT_L2CAP_SMP_PUBLIC_KEY);
            return;
        }

        if self.out {
            return;
        }

        let mut local_pk_x = [0u8; 32];
        let mut remote_pk_x = [0u8; 32];
        local_pk_x.copy_from_slice(&self.local_pk[..32]);
        remote_pk_x.copy_from_slice(&self.remote_pk[..32]);

        if let Ok(buf) = bt_crypto_f4(&local_pk_x, &remote_pk_x, &self.prnd, 0) {
            self.smp_send(actions, BT_L2CAP_SMP_PAIRING_CONFIRM, &buf);
        }
    }

    /// Handle received DHKey Check PDU (SC only).
    /// Replaces `dhkey_check()` from smp.c lines 635-676.
    fn dhkey_check_handler(&mut self, actions: &mut Vec<SmpAction>, data: &[u8]) {
        let mut cmd_e = [0u8; 16];
        if data.len() > 1 {
            let copy_len = (data.len() - 1).min(16);
            cmd_e[..copy_len].copy_from_slice(&data[1..1 + copy_len]);
        }

        let mut a = [0u8; 7];
        let mut b = [0u8; 7];
        a[..6].copy_from_slice(&self.ia);
        a[6] = self.ia_type;
        b[..6].copy_from_slice(&self.ra);
        b[6] = self.ra_type;

        let (local_addr, remote_addr, io_cap_src) =
            if self.out { (&a, &b, &self.prsp[1..4]) } else { (&b, &a, &self.preq[1..4]) };

        let mut io_cap = [0u8; 3];
        io_cap.copy_from_slice(io_cap_src);

        let mut r = [0u8; 16];
        if self.method == ReqPasskey || self.method == DspPasskey {
            bt_put_le32(self.passkey_notify as u32, &mut r);
        }

        let e = match bt_crypto_f6(
            &self.mackey,
            &self.rrnd,
            &self.prnd,
            &r,
            &io_cap,
            remote_addr,
            local_addr,
        ) {
            Ok(v) => v,
            Err(_) => return,
        };

        if cmd_e != e {
            let reason = SMP_DHKEY_CHECK_FAILED;
            self.smp_send(actions, BT_L2CAP_SMP_PAIRING_FAILED, &[reason]);
        }

        if self.out {
            let ltk = self.ltk;
            actions.push(SmpAction::LeStartEncrypt { handle: self.handle, ltk });
        } else {
            self.sc_dhkey_check(actions);
        }
    }

    /// Handle Encrypt Info PDU (no-op in emulator).
    /// Replaces `encrypt_info()` from smp.c lines 570-572.
    fn encrypt_info_handler(&mut self, _data: &[u8]) {
        // No processing needed
    }

    /// Handle Central Ident PDU (clears ENC_KEY dist flag).
    /// Replaces `central_ident()` from smp.c lines 574-580.
    fn central_ident_handler(&mut self, actions: &mut Vec<SmpAction>, _data: &[u8]) {
        self.remote_key_dist &= !DIST_ENC_KEY;
        if self.out && self.remote_key_dist == 0 {
            self.distribute_keys(actions);
        }
    }

    /// Handle Identity Info PDU (clears ID_KEY dist flag).
    /// Replaces `ident_info()` from smp.c lines 587-593.
    fn ident_info_handler(&mut self, actions: &mut Vec<SmpAction>, _data: &[u8]) {
        self.remote_key_dist &= !DIST_ID_KEY;
        if self.out && self.remote_key_dist == 0 {
            self.distribute_keys(actions);
        }
    }

    /// Handle Identity Address Info PDU (no-op in emulator).
    /// Replaces `ident_addr_info()` from smp.c lines 582-585.
    fn ident_addr_info_handler(&mut self, _data: &[u8]) {
        // No processing needed
    }

    /// Handle Signing Info PDU (clears SIGN dist flag).
    /// Replaces `signing_info()` from smp.c lines 595-601.
    fn signing_info_handler(&mut self, actions: &mut Vec<SmpAction>, _data: &[u8]) {
        self.remote_key_dist &= !DIST_SIGN;
        if self.out && self.remote_key_dist == 0 {
            self.distribute_keys(actions);
        }
    }

    /// Handle BR/EDR encryption event — trigger SMP over BR/EDR.
    /// Replaces `smp_conn_bredr()` from smp.c lines 796-820.
    fn smp_conn_bredr(
        &mut self,
        actions: &mut Vec<SmpAction>,
        encrypt: u8,
        bredr_capable: bool,
        fixed_chan: u64,
    ) {
        if encrypt != 0x02 {
            return;
        }

        self.sc = true;

        if !self.out {
            return;
        }

        if !bredr_capable {
            return;
        }

        if fixed_chan & L2CAP_FC_SMP_BREDR == 0 {
            return;
        }

        let dist = key_dist(bredr_capable);
        let req = [0x00u8, 0x00, 0x00, 0x10, dist, dist];

        self.preq[0] = BT_L2CAP_SMP_PAIRING_REQUEST;
        self.preq[1..7].copy_from_slice(&req);

        self.smp_send(actions, BT_L2CAP_SMP_PAIRING_REQUEST, &req);
    }
}

// ---------------------------------------------------------------------------
// Implementation: Smp Public API
// ---------------------------------------------------------------------------

impl Smp {
    /// Create a new SMP context.
    /// Replaces `smp_start()` from smp.c lines 895-914.
    pub fn start() -> Result<Self, SmpError> {
        Ok(Smp {
            connections: HashMap::new(),
            actions: Vec::new(),
            io_capability: 0x03, // NoInputNoOutput default
            auth_req: 0x00,
            bredr_capable: false,
            conn_fixed_chans: HashMap::new(),
        })
    }

    /// Shut down the SMP context, releasing all resources.
    /// Replaces `smp_stop()` from smp.c lines 916-923.
    pub fn stop(&mut self) {
        self.connections.clear();
        self.actions.clear();
        self.conn_fixed_chans.clear();
    }

    /// Drain all buffered output actions.
    /// BtHost must call this after each SmpManager method invocation
    /// and execute the returned actions.
    pub fn take_actions(&mut self) -> Vec<SmpAction> {
        std::mem::take(&mut self.actions)
    }

    /// Update the IO capability setting (mirrored from BtHost).
    pub fn set_io_capability(&mut self, cap: u8) {
        self.io_capability = cap;
    }

    /// Update the auth requirement setting (mirrored from BtHost).
    pub fn set_auth_req(&mut self, req: u8) {
        self.auth_req = req;
    }

    /// Update the BR/EDR capable flag (mirrored from BtHost).
    pub fn set_bredr_capable(&mut self, capable: bool) {
        self.bredr_capable = capable;
    }

    /// Update the fixed channel bitmap for a connection.
    pub fn set_conn_fixed_chan(&mut self, handle: u16, fixed_chan: u64) {
        self.conn_fixed_chans.insert(handle, fixed_chan);
    }
}

// ---------------------------------------------------------------------------
// SmpManager Trait Implementation
// ---------------------------------------------------------------------------

impl crate::bthost::SmpManager for Smp {
    /// Add a new SMP connection for the given ACL handle.
    /// Replaces `smp_conn_add()` from smp.c lines 853-886.
    fn conn_add(
        &mut self,
        handle: u16,
        ia: &[u8; 6],
        ia_type: u8,
        ra: &[u8; 6],
        ra_type: u8,
        smp_over_bredr: bool,
    ) {
        let addr_type = if smp_over_bredr { BDADDR_BREDR } else { ia_type };

        // For BR/EDR, we are always the initiator (bthost only triggers
        // SMP-over-BR/EDR from the initiating side).
        // For LE, default to false; pair() sets out=true when initiating.
        let out = smp_over_bredr;

        let mut prnd = [0u8; 16];
        let _ = random_bytes(&mut prnd);

        let conn = SmpConn {
            handle,
            addr_type,
            out,
            sc: false,
            initiator: out,
            method: JustWorks,
            local_key_dist: 0,
            remote_key_dist: 0,
            ia: *ia,
            ia_type: type2hci(ia_type),
            ra: *ra,
            ra_type: type2hci(ra_type),
            tk: [0u8; 16],
            prnd,
            rrnd: [0u8; 16],
            pcnf: [0u8; 16],
            preq: [0u8; 7],
            prsp: [0u8; 7],
            ltk: [0u8; 16],
            local_sk: [0u8; 32],
            local_pk: [0u8; 64],
            remote_pk: [0u8; 64],
            dhkey: [0u8; 32],
            mackey: [0u8; 16],
            passkey_notify: 0,
            passkey_round: 0,
        };

        self.connections.insert(handle, conn);
    }

    /// Remove the SMP connection for the given ACL handle.
    /// Replaces `smp_conn_del()` from smp.c lines 888-893.
    fn conn_del(&mut self, handle: u16) {
        self.connections.remove(&handle);
        self.conn_fixed_chans.remove(&handle);
    }

    /// Notify the SMP layer that the connection is now encrypted.
    /// Replaces `smp_conn_encrypted()` from smp.c lines 822-838.
    fn conn_encrypted(&mut self, handle: u16, encrypt: u8) {
        if encrypt == 0 {
            return;
        }

        let bredr_capable = self.bredr_capable;
        let fixed_chan = self.conn_fixed_chans.get(&handle).copied().unwrap_or(0);

        if let Some(conn) = self.connections.get_mut(&handle) {
            if conn.addr_type == BDADDR_BREDR {
                conn.smp_conn_bredr(&mut self.actions, encrypt, bredr_capable, fixed_chan);
                return;
            }

            if conn.out && conn.remote_key_dist != 0 {
                return;
            }

            conn.distribute_keys(&mut self.actions);
        }
    }

    /// Process incoming SMP data on the LE SMP channel.
    /// Replaces `smp_data()` from smp.c lines 696-751.
    fn data(&mut self, handle: u16, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if let Some(conn) = self.connections.get(&handle) {
            if conn.addr_type == BDADDR_BREDR {
                return;
            }
        } else {
            return;
        }

        let opcode = data[0];
        let io_cap = self.io_capability;
        let auth = self.auth_req;
        let bredr_cap = self.bredr_capable;

        if let Some(conn) = self.connections.get_mut(&handle) {
            match opcode {
                BT_L2CAP_SMP_PAIRING_REQUEST => {
                    conn.pairing_req(&mut self.actions, data, io_cap, auth, bredr_cap);
                }
                BT_L2CAP_SMP_PAIRING_RESPONSE => {
                    conn.pairing_rsp(&mut self.actions, data);
                }
                BT_L2CAP_SMP_PAIRING_CONFIRM => {
                    conn.pairing_cfm(&mut self.actions, data);
                }
                BT_L2CAP_SMP_PAIRING_RANDOM => {
                    conn.pairing_rnd(&mut self.actions, data);
                }
                BT_L2CAP_SMP_ENCRYPT_INFO => {
                    conn.encrypt_info_handler(data);
                }
                BT_L2CAP_SMP_CENTRAL_IDENT => {
                    conn.central_ident_handler(&mut self.actions, data);
                }
                BT_L2CAP_SMP_IDENT_ADDR_INFO => {
                    conn.ident_addr_info_handler(data);
                }
                BT_L2CAP_SMP_IDENT_INFO => {
                    conn.ident_info_handler(&mut self.actions, data);
                }
                BT_L2CAP_SMP_SIGNING_INFO => {
                    conn.signing_info_handler(&mut self.actions, data);
                }
                BT_L2CAP_SMP_PUBLIC_KEY => {
                    conn.public_key_handler(&mut self.actions, data);
                }
                BT_L2CAP_SMP_DHKEY_CHECK => {
                    conn.dhkey_check_handler(&mut self.actions, data);
                }
                _ => {} // Unknown opcode — silently ignore
            }
        }
    }

    /// Process incoming SMP data on the BR/EDR SMP channel.
    /// Replaces `smp_bredr_data()` from smp.c lines 753-781.
    fn bredr_data(&mut self, handle: u16, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if let Some(conn) = self.connections.get(&handle) {
            if conn.addr_type != BDADDR_BREDR {
                return;
            }
        } else {
            return;
        }

        let opcode = data[0];
        let io_cap = self.io_capability;
        let auth = self.auth_req;
        let bredr_cap = self.bredr_capable;

        if let Some(conn) = self.connections.get_mut(&handle) {
            match opcode {
                BT_L2CAP_SMP_PAIRING_REQUEST => {
                    conn.pairing_req(&mut self.actions, data, io_cap, auth, bredr_cap);
                }
                BT_L2CAP_SMP_PAIRING_RESPONSE => {
                    conn.pairing_rsp(&mut self.actions, data);
                }
                _ => {} // Other opcodes not handled for BR/EDR
            }
        }
    }

    /// Retrieve the negotiated LTK for a connection.
    /// Replaces `smp_get_ltk()` from smp.c lines 783-794.
    fn get_ltk(&self, handle: u16) -> Option<[u8; 16]> {
        let conn = self.connections.get(&handle)?;
        let no_ltk = [0u8; 16];
        if conn.ltk == no_ltk { None } else { Some(conn.ltk) }
    }

    /// Initiate SMP pairing for a connection.
    /// Replaces `smp_pair()` from smp.c lines 678-694.
    fn pair(&mut self, handle: u16, io_cap: u8, auth_req_val: u8) {
        let bredr_cap = self.bredr_capable;

        if let Some(conn) = self.connections.get_mut(&handle) {
            // Mark as initiator
            conn.out = true;
            conn.initiator = true;

            let dist = key_dist(bredr_cap);
            let req = [io_cap, 0x00, auth_req_val, 0x10, dist, dist];

            conn.preq[0] = BT_L2CAP_SMP_PAIRING_REQUEST;
            conn.preq[1..7].copy_from_slice(&req);

            conn.smp_send(&mut self.actions, BT_L2CAP_SMP_PAIRING_REQUEST, &req);
        }
    }

    fn take_actions(&mut self) -> Vec<SmpAction> {
        std::mem::take(&mut self.actions)
    }

    fn set_io_capability(&mut self, cap: u8) {
        self.io_capability = cap;
    }

    fn set_auth_req(&mut self, req: u8) {
        self.auth_req = req;
    }

    fn set_bredr_capable(&mut self, capable: bool) {
        self.bredr_capable = capable;
    }

    fn set_conn_fixed_chan(&mut self, handle: u16, fixed_chan: u64) {
        self.conn_fixed_chans.insert(handle, fixed_chan);
    }
}

// ---------------------------------------------------------------------------
// SmpConn Public API (standalone convenience methods)
// ---------------------------------------------------------------------------

impl SmpConn {
    /// Create a new SmpConn. Exposed for testing.
    pub fn add(
        handle: u16,
        ia: &[u8; 6],
        ia_type: u8,
        ra: &[u8; 6],
        ra_type: u8,
        conn_init: bool,
    ) -> Self {
        let addr_type = if conn_init { ia_type } else { ra_type };
        let mut prnd = [0u8; 16];
        let _ = random_bytes(&mut prnd);

        SmpConn {
            handle,
            addr_type,
            out: conn_init,
            sc: false,
            initiator: conn_init,
            method: JustWorks,
            local_key_dist: 0,
            remote_key_dist: 0,
            ia: *ia,
            ia_type: type2hci(ia_type),
            ra: *ra,
            ra_type: type2hci(ra_type),
            tk: [0u8; 16],
            prnd,
            rrnd: [0u8; 16],
            pcnf: [0u8; 16],
            preq: [0u8; 7],
            prsp: [0u8; 7],
            ltk: [0u8; 16],
            local_sk: [0u8; 32],
            local_pk: [0u8; 64],
            remote_pk: [0u8; 64],
            dhkey: [0u8; 32],
            mackey: [0u8; 16],
            passkey_notify: 0,
            passkey_round: 0,
        }
    }

    /// Delete / drop this SmpConn. In Rust, this is handled by Drop.
    pub fn del(self) {
        // Dropping self is sufficient
    }

    /// Initiate pairing from this connection.
    pub fn pair(
        &mut self,
        actions: &mut Vec<SmpAction>,
        io_cap: u8,
        auth_req_val: u8,
        bredr_capable: bool,
    ) {
        self.out = true;
        self.initiator = true;
        let dist = key_dist(bredr_capable);
        let req = [io_cap, 0x00, auth_req_val, 0x10, dist, dist];
        self.preq[0] = BT_L2CAP_SMP_PAIRING_REQUEST;
        self.preq[1..7].copy_from_slice(&req);
        self.smp_send(actions, BT_L2CAP_SMP_PAIRING_REQUEST, &req);
    }

    /// Process incoming SMP data on the LE channel.
    pub fn data(
        &mut self,
        actions: &mut Vec<SmpAction>,
        data: &[u8],
        io_capability: u8,
        auth_req_val: u8,
        bredr_capable: bool,
    ) {
        if data.is_empty() || self.addr_type == BDADDR_BREDR {
            return;
        }

        let opcode = data[0];
        match opcode {
            BT_L2CAP_SMP_PAIRING_REQUEST => {
                self.pairing_req(actions, data, io_capability, auth_req_val, bredr_capable);
            }
            BT_L2CAP_SMP_PAIRING_RESPONSE => self.pairing_rsp(actions, data),
            BT_L2CAP_SMP_PAIRING_CONFIRM => self.pairing_cfm(actions, data),
            BT_L2CAP_SMP_PAIRING_RANDOM => self.pairing_rnd(actions, data),
            BT_L2CAP_SMP_ENCRYPT_INFO => self.encrypt_info_handler(data),
            BT_L2CAP_SMP_CENTRAL_IDENT => self.central_ident_handler(actions, data),
            BT_L2CAP_SMP_IDENT_ADDR_INFO => self.ident_addr_info_handler(data),
            BT_L2CAP_SMP_IDENT_INFO => self.ident_info_handler(actions, data),
            BT_L2CAP_SMP_SIGNING_INFO => self.signing_info_handler(actions, data),
            BT_L2CAP_SMP_PUBLIC_KEY => self.public_key_handler(actions, data),
            BT_L2CAP_SMP_DHKEY_CHECK => self.dhkey_check_handler(actions, data),
            _ => {}
        }
    }

    /// Process incoming SMP data on the BR/EDR channel.
    pub fn bredr_data(
        &mut self,
        actions: &mut Vec<SmpAction>,
        data: &[u8],
        io_capability: u8,
        auth_req_val: u8,
        bredr_capable: bool,
    ) {
        if data.is_empty() || self.addr_type != BDADDR_BREDR {
            return;
        }

        let opcode = data[0];
        match opcode {
            BT_L2CAP_SMP_PAIRING_REQUEST => {
                self.pairing_req(actions, data, io_capability, auth_req_val, bredr_capable);
            }
            BT_L2CAP_SMP_PAIRING_RESPONSE => self.pairing_rsp(actions, data),
            _ => {}
        }
    }

    /// Get the LTK for this connection, if one has been negotiated.
    pub fn get_ltk(&self) -> Result<[u8; 16], SmpError> {
        let no_ltk = [0u8; 16];
        if self.ltk == no_ltk { Err(SmpError::NoLtk) } else { Ok(self.ltk) }
    }

    /// Notify SMP that the connection is now encrypted.
    pub fn conn_encrypted(
        &mut self,
        actions: &mut Vec<SmpAction>,
        encrypt: u8,
        bredr_capable: bool,
        fixed_chan: u64,
    ) {
        if encrypt == 0 {
            return;
        }

        if self.addr_type == BDADDR_BREDR {
            self.smp_conn_bredr(actions, encrypt, bredr_capable, fixed_chan);
            return;
        }

        if self.out && self.remote_key_dist != 0 {
            return;
        }

        self.distribute_keys(actions);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type2hci_conversion() {
        assert_eq!(type2hci(BDADDR_BREDR), LE_PUBLIC_ADDRESS);
        assert_eq!(type2hci(BDADDR_LE_PUBLIC), LE_PUBLIC_ADDRESS);
        assert_eq!(type2hci(BDADDR_LE_RANDOM), LE_RANDOM_ADDRESS);
        assert_eq!(type2hci(0xFF), 0x00);
    }

    #[test]
    fn test_pairing_method_tables() {
        assert_eq!(GEN_METHOD[0][0], JustWorks);
        assert_eq!(GEN_METHOD[0][1], JustCfm);
        assert_eq!(GEN_METHOD[2][2], ReqPasskey);
        assert_eq!(GEN_METHOD[4][4], Overlap);
        assert_eq!(SC_METHOD[1][1], CfmPasskey);
        assert_eq!(SC_METHOD[2][0], DspPasskey);
        assert_eq!(SC_METHOD[4][4], CfmPasskey);
    }

    #[test]
    fn test_get_auth_method_unknown_io() {
        assert_eq!(get_auth_method(false, 0x05, 0x00), JustCfm);
        assert_eq!(get_auth_method(true, 0x00, 0x05), JustCfm);
        assert_eq!(get_auth_method(false, 0xFF, 0xFF), JustCfm);
    }

    #[test]
    fn test_get_auth_method_legacy() {
        assert_eq!(get_auth_method(false, 0, 0), JustWorks);
        assert_eq!(get_auth_method(false, 4, 4), Overlap);
    }

    #[test]
    fn test_get_auth_method_sc() {
        assert_eq!(get_auth_method(true, 0, 0), JustWorks);
        assert_eq!(get_auth_method(true, 1, 1), CfmPasskey);
    }

    #[test]
    fn test_smp_conn_add_creates_valid_state() {
        let ia = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let ra = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

        let conn = SmpConn::add(0x0040, &ia, BDADDR_LE_PUBLIC, &ra, BDADDR_LE_RANDOM, true);

        assert_eq!(conn.handle, 0x0040);
        assert_eq!(conn.addr_type, BDADDR_LE_PUBLIC);
        assert!(conn.out);
        assert!(conn.initiator);
        assert!(!conn.sc);
        assert_eq!(conn.method, JustWorks);
        assert_eq!(conn.ia, ia);
        assert_eq!(conn.ra, ra);
        assert_eq!(conn.ia_type, LE_PUBLIC_ADDRESS);
        assert_eq!(conn.ra_type, LE_RANDOM_ADDRESS);
    }

    #[test]
    fn test_smp_conn_add_responder() {
        let ia = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let ra = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

        let conn = SmpConn::add(0x0041, &ia, BDADDR_LE_PUBLIC, &ra, BDADDR_LE_RANDOM, false);

        assert_eq!(conn.handle, 0x0041);
        assert_eq!(conn.addr_type, BDADDR_LE_RANDOM);
        assert!(!conn.out);
        assert!(!conn.initiator);
    }

    #[test]
    fn test_get_ltk_no_ltk() {
        let conn = SmpConn::add(0x0042, &[0; 6], BDADDR_LE_PUBLIC, &[0; 6], BDADDR_LE_PUBLIC, true);
        assert!(conn.get_ltk().is_err());
    }

    #[test]
    fn test_sc_no_dist_mask() {
        assert_eq!(SC_NO_DIST, DIST_ENC_KEY | DIST_LINK_KEY);
        assert_eq!(SC_NO_DIST, 0x09);
    }

    #[test]
    fn test_smp_opcode_constants() {
        assert_eq!(BT_L2CAP_SMP_PAIRING_REQUEST, 0x01);
        assert_eq!(BT_L2CAP_SMP_PAIRING_RESPONSE, 0x02);
        assert_eq!(BT_L2CAP_SMP_PAIRING_CONFIRM, 0x03);
        assert_eq!(BT_L2CAP_SMP_PAIRING_RANDOM, 0x04);
        assert_eq!(BT_L2CAP_SMP_PAIRING_FAILED, 0x05);
        assert_eq!(BT_L2CAP_SMP_ENCRYPT_INFO, 0x06);
        assert_eq!(BT_L2CAP_SMP_CENTRAL_IDENT, 0x07);
        assert_eq!(BT_L2CAP_SMP_IDENT_INFO, 0x08);
        assert_eq!(BT_L2CAP_SMP_IDENT_ADDR_INFO, 0x09);
        assert_eq!(BT_L2CAP_SMP_SIGNING_INFO, 0x0a);
        assert_eq!(BT_L2CAP_SMP_PUBLIC_KEY, 0x0c);
        assert_eq!(BT_L2CAP_SMP_DHKEY_CHECK, 0x0d);
    }

    #[test]
    fn test_smp_cid_constants() {
        assert_eq!(SMP_CID, 0x0006);
        assert_eq!(SMP_BREDR_CID, 0x0007);
        assert_eq!(L2CAP_FC_SMP_BREDR, 0x80);
    }

    #[test]
    fn test_smp_start_stop() {
        let mut smp = Smp::start().unwrap();
        assert!(smp.connections.is_empty());
        assert!(smp.actions.is_empty());
        smp.stop();
        assert!(smp.connections.is_empty());
    }

    #[test]
    fn test_key_dist_flags() {
        // Without BR/EDR
        assert_eq!(key_dist(false), DIST_ENC_KEY | DIST_ID_KEY | DIST_SIGN);
        // With BR/EDR
        assert_eq!(key_dist(true), DIST_ENC_KEY | DIST_ID_KEY | DIST_SIGN | DIST_LINK_KEY);
    }

    #[test]
    fn test_smp_send_le() {
        let conn = SmpConn::add(0x0040, &[0; 6], BDADDR_LE_PUBLIC, &[0; 6], BDADDR_LE_PUBLIC, true);
        let mut actions = Vec::new();
        conn.smp_send(
            &mut actions,
            BT_L2CAP_SMP_PAIRING_REQUEST,
            &[0x03, 0x00, 0x01, 0x10, 0x07, 0x07],
        );
        assert_eq!(actions.len(), 1);
        if let SmpAction::SendCidV { handle, cid, data } = &actions[0] {
            assert_eq!(*handle, 0x0040);
            assert_eq!(*cid, SMP_CID);
            assert_eq!(data[0], BT_L2CAP_SMP_PAIRING_REQUEST);
        } else {
            panic!("Expected SendCidV action");
        }
    }

    #[test]
    fn test_smp_send_bredr() {
        let conn = SmpConn::add(0x0040, &[0; 6], BDADDR_BREDR, &[0; 6], BDADDR_BREDR, true);
        let mut actions = Vec::new();
        conn.smp_send(&mut actions, BT_L2CAP_SMP_PAIRING_REQUEST, &[0x00]);
        assert_eq!(actions.len(), 1);
        if let SmpAction::SendCidV { cid, .. } = &actions[0] {
            assert_eq!(*cid, SMP_BREDR_CID);
        } else {
            panic!("Expected SendCidV action");
        }
    }

    #[test]
    fn test_smp_pair_via_manager() {
        use crate::bthost::SmpManager;
        let mut smp = Smp::start().unwrap();
        smp.conn_add(0x0040, &[1; 6], BDADDR_LE_PUBLIC, &[2; 6], BDADDR_LE_RANDOM, false);
        smp.pair(0x0040, 0x03, 0x01);
        let actions = smp.take_actions();
        assert_eq!(actions.len(), 1);
        if let SmpAction::SendCidV { handle, cid, data } = &actions[0] {
            assert_eq!(*handle, 0x0040);
            assert_eq!(*cid, SMP_CID);
            assert_eq!(data[0], BT_L2CAP_SMP_PAIRING_REQUEST);
        } else {
            panic!("Expected SendCidV action");
        }
    }

    #[test]
    fn test_smp_get_ltk_via_manager() {
        use crate::bthost::SmpManager;
        let mut smp = Smp::start().unwrap();
        smp.conn_add(0x0040, &[1; 6], BDADDR_LE_PUBLIC, &[2; 6], BDADDR_LE_RANDOM, false);
        // No LTK yet
        assert!(smp.get_ltk(0x0040).is_none());
        // Unknown handle
        assert!(smp.get_ltk(0xFFFF).is_none());
    }

    #[test]
    fn test_smp_conn_del_via_manager() {
        use crate::bthost::SmpManager;
        let mut smp = Smp::start().unwrap();
        smp.conn_add(0x0040, &[1; 6], BDADDR_LE_PUBLIC, &[2; 6], BDADDR_LE_RANDOM, false);
        assert!(smp.connections.contains_key(&0x0040));
        smp.conn_del(0x0040);
        assert!(!smp.connections.contains_key(&0x0040));
    }
}
