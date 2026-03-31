// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2018-2019 Intel Corporation. All rights reserved.
//
// Rust rewrite of mesh/prov-acceptor.c (821 lines).
// Implements the provisioning **acceptor** (device being provisioned)
// state machine: ECDH key exchange, confirmation/random exchange,
// OOB authentication (all four methods), agent-driven callbacks,
// provisioning data decryption, and unprovisioned device beacon
// management.

use std::collections::VecDeque;
use std::sync::Arc;

use rand::RngCore;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error};

use crate::agent::{
    MeshAgent, MeshAgentProvCaps, mesh_agent_display_number, mesh_agent_display_string,
    mesh_agent_get_caps, mesh_agent_prompt_alpha, mesh_agent_prompt_number,
    mesh_agent_request_private_key, mesh_agent_request_static,
};
use crate::crypto;
use crate::mesh::{self, BEACON_TYPE_UNPROVISIONED, BT_AD_MESH_PROV};
use crate::models::register_nppi_acceptor;
use crate::provisioning::pb_adv;
use crate::provisioning::{
    AUTH_METHOD_INPUT, AUTH_METHOD_NO_OOB, AUTH_METHOD_OUTPUT, AUTH_METHOD_STATIC, ConfInput,
    EXPECTED_PDU_SIZE, MeshNetProvCaps, MeshProvNodeInfo, OOB_IN_ACTION_ALPHA, OOB_INFO_URI_HASH,
    OOB_OUT_ACTION_ALPHA, PROV_CAPS, PROV_COMPLETE, PROV_CONFIRM, PROV_DATA,
    PROV_ERR_CONFIRM_FAILED, PROV_ERR_DECRYPT_FAILED, PROV_ERR_INVALID_FORMAT,
    PROV_ERR_PROHIBITED_PDU, PROV_ERR_SUCCESS, PROV_ERR_TIMEOUT, PROV_ERR_UNEXPECTED_ERR,
    PROV_ERR_UNEXPECTED_PDU, PROV_FAILED, PROV_INP_CMPLT, PROV_INVITE, PROV_NONE, PROV_PUB_KEY,
    PROV_RANDOM, PROV_START, ProvAckCb, ProvCloseCb, ProvData, ProvOpenCb, ProvRxCb, ProvStart,
    ProvTransTx, TRANSPORT_NPPI, TRANSPORT_PB_ADV, digit_mod, swap_u256_bytes,
};
use crate::util;
use bluez_shared::crypto::ecc::{ecc_make_key, ecc_make_public_key, ecdh_shared_secret};

// ---------------------------------------------------------------------------
// Constants — from prov-acceptor.c lines 40-56
// ---------------------------------------------------------------------------

/// AD type for mesh beacon advertisements.
const BT_AD_MESH_BEACON: u8 = 0x2B;

/// Filter for mesh provisioning packets (single byte).
const PKT_FILTER: u8 = BT_AD_MESH_PROV;

/// Filter for unprovisioned device beacons (2 bytes: AD type + beacon type).
const BEC_FILTER: [u8; 2] = [BT_AD_MESH_BEACON, BEACON_TYPE_UNPROVISIONED];

/// Material bitmask: remote (provisioner) public key received.
const MAT_REMOTE_PUBLIC: u8 = 0x01;
/// Material bitmask: local (device) private key available.
const MAT_LOCAL_PRIVATE: u8 = 0x02;
/// Material bitmask: random / authentication value ready.
const MAT_RAND_AUTH: u8 = 0x04;
/// Combined bitmask indicating both ECDH keys are available (secret can be
/// computed).
const MAT_SECRET: u8 = MAT_REMOTE_PUBLIC | MAT_LOCAL_PRIVATE;

/// Returns `true` when the given `auth_action` value corresponds to the output
/// OOB alphanumeric action (bitmask `OOB_OUT_ACTION_ALPHA`).
#[inline]
fn is_output_alpha_action(auth_action: u8) -> bool {
    (1u16 << auth_action) & OOB_OUT_ACTION_ALPHA != 0
}

/// Returns `true` when the given `auth_action` value corresponds to the input
/// OOB alphanumeric action (bitmask `OOB_IN_ACTION_ALPHA`).
#[inline]
fn is_input_alpha_action(auth_action: u8) -> bool {
    (1u16 << auth_action) & OOB_IN_ACTION_ALPHA != 0
}

// ---------------------------------------------------------------------------
// Deferred command queue entry
// ---------------------------------------------------------------------------

/// A provisioning message queued for transmission when the bearer is busy.
/// Mirrors C `struct deferred_cmd` from prov-acceptor.c lines 47-50.
struct DeferredCmd {
    data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Acceptor state
// ---------------------------------------------------------------------------

/// Provisioning acceptor state machine.
///
/// Mirrors C `struct mesh_prov_acceptor` from prov-acceptor.c lines 58-85.
/// Only one acceptor session is active at a time (singleton).
struct MeshProvAcceptor {
    /// Completion callback invoked when provisioning succeeds or fails.
    cmplt: Option<Box<dyn FnOnce(usize, u8, Option<MeshProvNodeInfo>) + Send>>,
    /// Bearer transmit function — sends a PDU over the provisioning bearer.
    trans_tx: Option<ProvTransTx>,
    /// Handle to the bearer transport data (opaque integer token).
    trans_data: usize,
    /// FIFO queue of outbound messages waiting for ACK.
    ob: VecDeque<DeferredCmd>,
    /// Reference to the mesh agent providing OOB capabilities.
    agent: Option<Arc<MeshAgent>>,
    /// Opaque caller data token passed through to the completion callback.
    caller_data: usize,
    /// Async timeout task handle; `None` when no timeout is active.
    timeout: Option<JoinHandle<()>>,
    /// Timeout duration in seconds (as configured by the caller).
    to_secs: u32,
    /// Opcode of the message currently in-flight to the bearer, or
    /// `PROV_NONE` if the bearer is idle and can accept new messages.
    out_opcode: u8,
    /// Transport type (PB-ADV / NPPI).
    transport: u8,
    /// Bitmask tracking which crypto materials are ready.
    material: u8,
    /// Expected next PDU opcode from the provisioner.
    expected: u8,
    /// Opcode of the previously received PDU (`-1` initially — stored as `i8`
    /// to allow sentinel value).
    previous: i8,
    /// Set when a failure PDU has been sent.
    failed: bool,
    /// Concatenated confirmation inputs (invite + caps + start + both keys).
    conf_inputs: ConfInput,
    /// Derived confirmation key (16 bytes).
    calc_key: [u8; 16],
    /// Current salt value (evolves through the protocol).
    salt: [u8; 16],
    /// Stored remote (provisioner) confirmation value for later comparison.
    confirm: [u8; 16],
    /// Derived session encryption key (16 bytes).
    s_key: [u8; 16],
    /// Derived session nonce (13 bytes).
    s_nonce: [u8; 13],
    /// Local ECDH private key (32 bytes, ECC byte order).
    private_key: [u8; 32],
    /// ECDH shared secret (32 bytes, mesh byte order).
    secret: [u8; 32],
    /// Workspace for random value and authentication data.
    ///
    /// Layout:
    ///   `[0..16]`  — our random value
    ///   `[16..32]` — their random value (or copy of auth)
    ///   `[28..32]` — BE32 numeric OOB (overlaps workspace)
    ///   `[32..48]` — auth value (static OOB / numeric OOB)
    ///   `[44..48]` — BE32 numeric OOB second copy (overlaps workspace)
    rand_auth_workspace: [u8; 48],
}

// ---------------------------------------------------------------------------
// Module-level singleton
// ---------------------------------------------------------------------------

/// Global singleton acceptor state, guarded by an async mutex.
/// Only one provisioning acceptor session is active at a time.
static PROV: Mutex<Option<MeshProvAcceptor>> = Mutex::const_new(None);

// ---------------------------------------------------------------------------
// Lifecycle functions
// ---------------------------------------------------------------------------

/// Release all resources associated with the current acceptor session.
///
/// Mirrors C `acceptor_free()` from prov-acceptor.c lines 91-106.
fn acceptor_free_inner(prov: &mut Option<MeshProvAcceptor>) {
    if let Some(p) = prov.take() {
        // Cancel the timeout task if active.
        if let Some(handle) = p.timeout {
            handle.abort();
        }
        // Cancel outstanding beacon and provisioning transmissions.
        mesh::mesh_send_cancel(&BEC_FILTER);
        mesh::mesh_send_cancel(&[PKT_FILTER]);
        // Unregister from the PB-ADV bearer.
        pb_adv::pb_adv_unreg(0);
        // Deferred queue and remaining state are dropped automatically.
    }
}

/// Handle bearer-level close from PB-ADV.
///
/// Mirrors C `acp_prov_close()` from prov-acceptor.c lines 108-123.
/// Called by the bearer when the provisioning link closes unexpectedly.
fn acp_prov_close_inner(prov_state: &mut Option<MeshProvAcceptor>, reason: u8) {
    let effective_reason =
        if reason == PROV_ERR_SUCCESS { PROV_ERR_UNEXPECTED_ERR } else { reason };

    if let Some(p) = prov_state.as_mut() {
        if let Some(cb) = p.cmplt.take() {
            cb(p.caller_data, effective_reason, None);
        }
    }

    acceptor_free_inner(prov_state);
}

// ---------------------------------------------------------------------------
// Message sending with deferred queue
// ---------------------------------------------------------------------------

/// Send a provisioning PDU, or enqueue it if the bearer is busy.
///
/// Mirrors C `prov_send()` from prov-acceptor.c lines 125-138.
///
/// The deferred queue ensures messages are sent in order.  When the
/// bearer signals ACK (`acp_prov_ack`), the next queued message is sent.
fn prov_send(p: &mut MeshProvAcceptor, data: &[u8]) {
    if p.out_opcode == PROV_NONE {
        // Bearer is idle — send directly.
        p.out_opcode = data[0];
        if let Some(ref mut tx) = p.trans_tx {
            tx(data);
        }
    } else {
        // Bearer is busy — queue the message.
        p.ob.push_back(DeferredCmd { data: data.to_vec() });
    }
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// Compute the ECDH shared secret from a mesh-order public key and an
/// ECC-order private key, returning the result in mesh byte order.
///
/// Mirrors C `prov_calc_secret()` from prov-acceptor.c lines 194-210.
fn prov_calc_secret(pub_key: &[u8; 64], priv_key: &[u8; 32], secret: &mut [u8; 32]) -> bool {
    // Convert public key from mesh byte order to ECC byte order.
    let mut tmp = [0u8; 64];
    tmp.copy_from_slice(pub_key);
    let (x, y) = tmp.split_at_mut(32);
    let x: &mut [u8; 32] = x.try_into().unwrap();
    let y: &mut [u8; 32] = y.try_into().unwrap();
    swap_u256_bytes(x);
    swap_u256_bytes(y);

    match ecdh_shared_secret(&tmp, priv_key) {
        Ok(s) => {
            secret.copy_from_slice(&s);
            // Convert shared secret from ECC byte order to mesh byte order.
            swap_u256_bytes(secret);
            true
        }
        Err(e) => {
            error!("ECDH shared secret computation failed: {:?}", e);
            false
        }
    }
}

/// Derive confirmation key and salt from the confirmation inputs and
/// the ECDH shared secret.  Also generates the local random value.
///
/// Mirrors C `acp_credentials()` from prov-acceptor.c lines 212-246.
fn acp_credentials(p: &mut MeshProvAcceptor) -> bool {
    // Disallow matching public keys (trivial reflection).
    if p.conf_inputs.prv_pub_key == p.conf_inputs.dev_pub_key {
        return false;
    }

    // Compute ECDH shared secret using the provisioner's public key
    // and our private key.
    let mut secret = [0u8; 32];
    if !prov_calc_secret(&p.conf_inputs.prv_pub_key, &p.private_key, &mut secret) {
        return false;
    }
    p.secret = secret;

    // Compute confirmation salt: S1(ConfirmationInputs).
    let conf_bytes = p.conf_inputs.as_bytes();
    let salt = match crypto::mesh_crypto_s1(&conf_bytes) {
        Some(s) => s,
        None => return false,
    };
    p.salt = salt;

    // Derive confirmation key.
    let calc_key = match crypto::mesh_crypto_prov_conf_key(&p.secret, &p.salt) {
        Some(k) => k,
        None => return false,
    };
    p.calc_key = calc_key;

    // Generate 16 random bytes for our local confirmation random.
    rand::rngs::OsRng.fill_bytes(&mut p.rand_auth_workspace[0..16]);

    // Debug output matching the C implementation.
    util::print_packet("PublicKeyProv", &p.conf_inputs.prv_pub_key);
    util::print_packet("PublicKeyDev", &p.conf_inputs.dev_pub_key);

    // Normalize private key for debug output (no longer needed for
    // calculations after this point).
    let mut priv_debug = p.private_key;
    swap_u256_bytes(&mut priv_debug);
    util::print_packet("PrivateKeyLocal", &priv_debug);

    util::print_packet("ConfirmationInputs", &conf_bytes);
    util::print_packet("ECDHSecret", &p.secret);
    util::print_packet("LocalRandom", &p.rand_auth_workspace[0..16]);
    util::print_packet("ConfirmationSalt", &p.salt);
    util::print_packet("ConfirmationKey", &p.calc_key);
    true
}

// ---------------------------------------------------------------------------
// Protocol message builders
// ---------------------------------------------------------------------------

/// Build and send a PROV_CAPS response containing our device capabilities.
///
/// Mirrors C `send_caps()` from prov-acceptor.c lines 342-352.
fn send_caps(p: &mut MeshProvAcceptor) {
    let caps_bytes = p.conf_inputs.caps.to_bytes();
    let mut msg = Vec::with_capacity(12);
    msg.push(PROV_CAPS);
    msg.extend_from_slice(&caps_bytes);
    p.expected = PROV_START;
    prov_send(p, &msg);
}

/// Build and send a PROV_PUB_KEY message containing our device public key.
///
/// Mirrors C `send_pub_key()` from prov-acceptor.c lines 354-361.
fn send_pub_key(p: &mut MeshProvAcceptor) {
    let mut msg = Vec::with_capacity(65);
    msg.push(PROV_PUB_KEY);
    msg.extend_from_slice(&p.conf_inputs.dev_pub_key);
    prov_send(p, &msg);
}

/// Compute AES-CMAC confirmation and send a PROV_CONFIRM message.
///
/// Returns `false` if the computed confirmation matches the stored remote
/// confirmation (reflection attack prevention).
///
/// Mirrors C `send_conf()` from prov-acceptor.c lines 363-377.
fn send_conf(p: &mut MeshProvAcceptor) -> bool {
    let mut conf = [0u8; 16];
    // AES-CMAC(calc_key, rand_auth_workspace[0..32]) → confirmation.
    crypto::mesh_crypto_aes_cmac(&p.calc_key, &p.rand_auth_workspace[0..32], &mut conf);

    // Reflection attack check: fail if our confirmation matches theirs.
    if conf == p.confirm {
        return false;
    }

    let mut msg = Vec::with_capacity(17);
    msg.push(PROV_CONFIRM);
    msg.extend_from_slice(&conf);
    prov_send(p, &msg);
    true
}

/// Build and send a PROV_RANDOM message containing our random value.
///
/// Mirrors C `send_rand()` from prov-acceptor.c lines 379-386.
fn send_rand(p: &mut MeshProvAcceptor) {
    let mut msg = Vec::with_capacity(17);
    msg.push(PROV_RANDOM);
    msg.extend_from_slice(&p.rand_auth_workspace[0..16]);
    prov_send(p, &msg);
}

// ---------------------------------------------------------------------------
// PROV_START validation
// ---------------------------------------------------------------------------

/// Validate the provisioner's selected start parameters against our
/// announced capabilities.
///
/// Mirrors C `prov_start_check()` from prov-acceptor.c lines 388-429.
fn prov_start_check(start: &ProvStart, caps: &MeshNetProvCaps) -> bool {
    // Algorithm must be 0 (P-256 FIPS).  Public key must be 0 or 1.
    // Auth method must be 0..3.
    if start.algorithm != 0 || start.pub_key > 1 || start.auth_method > 3 {
        return false;
    }

    // If OOB public key requested, we must support it.
    if start.pub_key != 0 && caps.pub_type == 0 {
        return false;
    }

    match start.auth_method {
        0 => {
            // No OOB — action and size must both be zero.
            if start.auth_action != 0 || start.auth_size != 0 {
                return false;
            }
        }
        1 => {
            // Static OOB — we must support it; action and size must be zero.
            if caps.static_type == 0 || start.auth_action != 0 || start.auth_size != 0 {
                return false;
            }
        }
        2 => {
            // Output OOB — the selected action bit must be set in our
            // output_action capability, and auth_size must be nonzero.
            if (caps.output_action & (1 << start.auth_action)) == 0 || start.auth_size == 0 {
                return false;
            }
        }
        3 => {
            // Input OOB — the selected action bit must be set in our
            // input_action capability, and auth_size must be nonzero.
            if (caps.input_action & (1 << start.auth_action)) == 0 || start.auth_size == 0 {
                return false;
            }
        }
        _ => return false,
    }

    true
}

// ---------------------------------------------------------------------------
// PDU receive state machine
// ---------------------------------------------------------------------------

/// Process a received provisioning PDU.
///
/// This is the core state machine for the acceptor side of the provisioning
/// protocol.  It handles all PDU opcodes from PROV_INVITE through
/// PROV_FAILED, performing ECDH key exchange, authentication, confirmation
/// verification, and provisioning data decryption.
///
/// Mirrors C `acp_prov_rx()` from prov-acceptor.c lines 431-708.
fn acp_prov_rx_inner(p: &mut MeshProvAcceptor, data: &[u8]) -> RxAction {
    if data.is_empty() || p.trans_tx.is_none() {
        return RxAction::None;
    }

    let pdu_type = data[0];
    let len = data.len() as u16;

    debug!("Provisioning packet received type: 0x{:02x} ({} octets)", pdu_type, len);

    // Validate opcode range — an out-of-range PDU type is a prohibited PDU.
    if pdu_type as usize >= EXPECTED_PDU_SIZE.len() {
        error!("Unknown PDU type: 0x{:02x}", pdu_type);
        return RxAction::Fail(PROV_ERR_PROHIBITED_PDU);
    }

    // Ignore repeated packets.
    if pdu_type as i8 == p.previous {
        error!("Ignore repeated 0x{:02x} packet", pdu_type);
        return RxAction::None;
    }

    // Check for out-of-order or unexpected PDUs.
    if p.failed || pdu_type > p.expected || (p.previous >= 0 && (pdu_type as i8) < p.previous) {
        error!("Expected 0x{:02x}, Got: 0x{:02x}", p.expected, pdu_type);
        return RxAction::Fail(PROV_ERR_UNEXPECTED_PDU);
    }

    // Validate PDU size.
    if len != EXPECTED_PDU_SIZE[pdu_type as usize] {
        error!(
            "Expected PDU size {}, Got {} (type: 0x{:02x})",
            EXPECTED_PDU_SIZE[pdu_type as usize], len, pdu_type
        );
        return RxAction::Fail(PROV_ERR_INVALID_FORMAT);
    }

    let payload = &data[1..];

    match pdu_type {
        PROV_INVITE => {
            p.conf_inputs.invite.attention = payload[0];
            send_caps(p);
        }

        PROV_START => {
            let start = match ProvStart::from_bytes(payload) {
                Some(s) => s,
                None => return RxAction::Fail(PROV_ERR_INVALID_FORMAT),
            };

            if !prov_start_check(&start, &p.conf_inputs.caps) {
                return RxAction::Fail(PROV_ERR_INVALID_FORMAT);
            }

            p.conf_inputs.start = start;

            if start.pub_key != 0 {
                // OOB public key — request private key from agent.
                return RxAction::RequestPrivateKey;
            }
            // Ephemeral key pair.
            match ecc_make_key() {
                Ok((pub_key, priv_key)) => {
                    let mut dev_pub = [0u8; 64];
                    dev_pub.copy_from_slice(&pub_key);
                    // Convert public key from ECC byte order to mesh byte order.
                    let (x, y) = dev_pub.split_at_mut(32);
                    let x: &mut [u8; 32] = x.try_into().unwrap();
                    let y: &mut [u8; 32] = y.try_into().unwrap();
                    swap_u256_bytes(x);
                    swap_u256_bytes(y);
                    p.conf_inputs.dev_pub_key = dev_pub;
                    p.private_key = priv_key;
                    p.material |= MAT_LOCAL_PRIVATE;
                }
                Err(e) => {
                    error!("ECC key generation failed: {:?}", e);
                    return RxAction::Fail(PROV_ERR_UNEXPECTED_ERR);
                }
            }

            p.expected = PROV_PUB_KEY;
        }

        PROV_PUB_KEY => {
            // Save the provisioner's public key.
            p.conf_inputs.prv_pub_key.copy_from_slice(&payload[..64]);
            p.material |= MAT_REMOTE_PUBLIC;
            p.expected = PROV_CONFIRM;

            if (p.material & MAT_SECRET) != MAT_SECRET {
                // Still waiting for our private key — stop processing
                // until priv_key_cb fires.
                p.previous = pdu_type as i8;
                return RxAction::None;
            }

            if !acp_credentials(p) {
                return RxAction::Fail(PROV_ERR_UNEXPECTED_ERR);
            }

            // Send our public key if NOT using OOB public key.
            if p.conf_inputs.start.pub_key == 0 {
                send_pub_key(p);
            }

            // Dispatch auth method (Step 3).
            match p.conf_inputs.start.auth_method {
                AUTH_METHOD_NO_OOB => {
                    // No OOB — auth bytes stay zero.
                    p.material |= MAT_RAND_AUTH;
                }
                AUTH_METHOD_STATIC => {
                    // Static OOB — request from agent.
                    return RxAction::RequestStatic;
                }
                AUTH_METHOD_OUTPUT => {
                    // Output OOB — generate random key and display.
                    return RxAction::OutputOob;
                }
                AUTH_METHOD_INPUT => {
                    // Input OOB — prompt agent.
                    return RxAction::InputOob;
                }
                _ => {
                    return RxAction::Fail(PROV_ERR_UNEXPECTED_ERR);
                }
            }

            p.expected = PROV_CONFIRM;
        }

        PROV_CONFIRM => {
            // Save provisioner's confirmation for later comparison.
            p.confirm.copy_from_slice(&payload[..16]);
            p.expected = PROV_RANDOM;

            if !send_conf(p) {
                return RxAction::Fail(PROV_ERR_INVALID_FORMAT);
            }
        }

        PROV_RANDOM => {
            // Disallow matching random values (reflection attack).
            if p.rand_auth_workspace[..16] == payload[..16] {
                return RxAction::Fail(PROV_ERR_INVALID_FORMAT);
            }

            // Compute provisioning salt.
            // ACCEPTOR order: prov_prov_salt(conf_salt, REMOTE_random, LOCAL_random).
            let remote_rand: &[u8; 16] = payload[..16].try_into().unwrap();
            let local_rand: [u8; 16] = {
                let mut lr = [0u8; 16];
                lr.copy_from_slice(&p.rand_auth_workspace[..16]);
                lr
            };

            match crypto::mesh_crypto_prov_prov_salt(&p.salt, remote_rand, &local_rand) {
                Some(new_salt) => p.salt = new_salt,
                None => return RxAction::Fail(PROV_ERR_UNEXPECTED_ERR),
            }

            // Derive session key and nonce.
            match crypto::mesh_crypto_session_key(&p.secret, &p.salt) {
                Some(k) => p.s_key = k,
                None => return RxAction::Fail(PROV_ERR_UNEXPECTED_ERR),
            }
            match crypto::mesh_crypto_nonce(&p.secret, &p.salt) {
                Some(n) => p.s_nonce = n,
                None => return RxAction::Fail(PROV_ERR_UNEXPECTED_ERR),
            }

            // Verify remote confirmation value.
            // Copy remote random into workspace[16..32] for CMAC computation.
            p.rand_auth_workspace[16..32].copy_from_slice(&payload[..16]);
            let mut expected_confirm = [0u8; 16];
            crypto::mesh_crypto_aes_cmac(
                &p.calc_key,
                &p.rand_auth_workspace[16..48],
                &mut expected_confirm,
            );

            if expected_confirm != p.confirm {
                return RxAction::Fail(PROV_ERR_CONFIRM_FAILED);
            }

            // Send our random value.
            send_rand(p);
            p.expected = PROV_DATA;
        }

        PROV_DATA => {
            // Derive device key.
            let dev_key = match crypto::mesh_crypto_device_key(&p.secret, &p.salt) {
                Some(k) => k,
                None => return RxAction::Fail(PROV_ERR_UNEXPECTED_ERR),
            };
            p.calc_key = dev_key;

            // Decrypt provisioning data.
            // payload = data[1..] which is 33 bytes (25 encrypted + 8 MIC).
            let enc_data = payload;
            let enc_len = enc_data.len(); // Should be 33 bytes.
            let data_len = enc_len.saturating_sub(8);
            let mut decrypted = vec![0u8; data_len];
            let mut decode_mic = vec![0u8; 8];

            let decrypt_ok = crypto::mesh_crypto_aes_ccm_decrypt(
                &p.s_nonce,
                &p.s_key,
                None,
                enc_data,
                &mut decrypted,
                &mut decode_mic,
                8,
            );

            if !decrypt_ok {
                error!("Provisioning data decryption failed");
                return RxAction::Fail(PROV_ERR_DECRYPT_FAILED);
            }

            // Validate MIC: compare computed MIC with the MIC from the wire.
            let wire_mic = &enc_data[data_len..];
            if decode_mic != wire_mic {
                error!("Provisioning Failed-MIC compare");
                return RxAction::Fail(PROV_ERR_DECRYPT_FAILED);
            }

            // Parse the decrypted provisioning data (25 bytes).
            let prov_data = match ProvData::from_bytes(&decrypted) {
                Some(pd) => pd,
                None => return RxAction::Fail(PROV_ERR_UNEXPECTED_ERR),
            };

            // Build node info.
            let info = MeshProvNodeInfo {
                device_key: p.calc_key,
                net_key: prov_data.net_key,
                net_index: prov_data.net_idx,
                flags: prov_data.flags,
                iv_index: prov_data.iv_index,
                unicast: prov_data.primary,
                num_ele: p.conf_inputs.caps.num_ele,
            };

            // Send PROV_COMPLETE directly through the bearer.
            if let Some(ref mut tx) = p.trans_tx {
                tx(&[PROV_COMPLETE]);
            }

            // Invoke completion callback with success.
            if let Some(cb) = p.cmplt.take() {
                cb(p.caller_data, PROV_ERR_SUCCESS, Some(info));
            }

            debug!("PROV_COMPLETE");
            return RxAction::Cleanup;
        }

        PROV_FAILED => {
            let err_code = if !payload.is_empty() && payload[0] != 0 {
                payload[0]
            } else {
                PROV_ERR_UNEXPECTED_ERR
            };
            if let Some(cb) = p.cmplt.take() {
                cb(p.caller_data, err_code, None);
            }
            return RxAction::Cleanup;
        }

        _ => {
            return RxAction::Fail(PROV_ERR_UNEXPECTED_PDU);
        }
    }

    p.previous = pdu_type as i8;
    RxAction::None
}

/// Internal action returned by `acp_prov_rx_inner` to direct async
/// processing in the caller context.
enum RxAction {
    /// No further action needed — PDU handled synchronously.
    None,
    /// Send PROV_FAILED with the given error code and enter cleanup.
    Fail(u8),
    /// Enter the 5-second cleanup timeout.
    Cleanup,
    /// Request the agent's OOB private key (PROV_START with pub_key=1).
    RequestPrivateKey,
    /// Request static OOB data from the agent.
    RequestStatic,
    /// Generate and display an output OOB value.
    OutputOob,
    /// Prompt the agent for input OOB.
    InputOob,
}

// ---------------------------------------------------------------------------
// ACK handler
// ---------------------------------------------------------------------------

/// Handle bearer acknowledgment of a previously sent message.
///
/// Pops the next deferred command (if any) and sends it.
///
/// Mirrors C `acp_prov_ack()` from prov-acceptor.c lines 710-729.
fn acp_prov_ack_inner(p: &mut MeshProvAcceptor) {
    if p.out_opcode == PROV_NONE {
        return;
    }

    p.out_opcode = PROV_NONE;

    if let Some(deferred) = p.ob.pop_front() {
        prov_send(p, &deferred.data);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Start an unprovisioned device beacon and register for provisioning.
///
/// This is the entry point for a device that wants to join a mesh network.
/// It begins broadcasting an unprovisioned device beacon and registers
/// callbacks for the PB-ADV bearer.
///
/// # Arguments
///
/// * `num_ele` — Number of elements on this device.
/// * `uuid` — Device UUID (16 bytes), or `None` for Device Key Refresh.
/// * `algorithms` — Supported algorithm bitmask.
/// * `timeout` — Provisioning timeout in seconds.
/// * `agent` — Reference to the mesh provisioning agent.
/// * `complete_cb` — Callback invoked on provisioning completion.
/// * `caller_data` — Opaque token passed through to `complete_cb`.
///
/// Returns `true` if the acceptor session was started successfully, `false`
/// if another session is already active or registration failed.
///
/// Mirrors C `acceptor_start()` from prov-acceptor.c lines 733-816.
pub async fn acceptor_start(
    num_ele: u8,
    uuid: Option<&[u8; 16]>,
    algorithms: u16,
    timeout: u32,
    agent: Arc<MeshAgent>,
    complete_cb: impl FnOnce(usize, u8, Option<MeshProvNodeInfo>) + Send + 'static,
    caller_data: usize,
) -> bool {
    let mut guard = PROV.lock().await;

    // Only one provisioning session at a time.
    if guard.is_some() {
        return false;
    }

    let caps_from_agent: Option<MeshAgentProvCaps> = {
        let agent_caps = mesh_agent_get_caps(&agent);
        Some(agent_caps.clone())
    };

    let mut acceptor = MeshProvAcceptor {
        cmplt: Some(Box::new(complete_cb)),
        trans_tx: None,
        trans_data: 0,
        ob: VecDeque::new(),
        agent: Some(agent.clone()),
        caller_data,
        timeout: None,
        to_secs: timeout,
        out_opcode: PROV_NONE,
        transport: TRANSPORT_PB_ADV,
        material: 0,
        expected: PROV_INVITE,
        previous: -1,
        failed: false,
        conf_inputs: ConfInput::default(),
        calc_key: [0u8; 16],
        salt: [0u8; 16],
        confirm: [0u8; 16],
        s_key: [0u8; 16],
        s_nonce: [0u8; 13],
        private_key: [0u8; 32],
        secret: [0u8; 32],
        rand_auth_workspace: [0u8; 48],
    };

    // Populate capabilities.
    acceptor.conf_inputs.caps.num_ele = num_ele;
    acceptor.conf_inputs.caps.algorithms = algorithms;

    if let Some(ref caps) = caps_from_agent {
        acceptor.conf_inputs.caps.pub_type = caps.pub_type;
        acceptor.conf_inputs.caps.static_type = caps.static_type;
        acceptor.conf_inputs.caps.output_size = caps.output_size;
        acceptor.conf_inputs.caps.input_size = caps.input_size;
        acceptor.conf_inputs.caps.output_action = caps.output_action;
        acceptor.conf_inputs.caps.input_action = caps.input_action;
    }

    if let Some(uuid_bytes) = uuid {
        // Compose unprovisioned device beacon.
        // Layout: [BT_AD_MESH_BEACON, BEACON_TYPE_UNPROVISIONED, uuid(16),
        //          oob_info_be16(2), optional uri_hash_be32(4)]
        let mut beacon = Vec::with_capacity(24);
        beacon.push(BT_AD_MESH_BEACON);
        beacon.push(BEACON_TYPE_UNPROVISIONED);
        beacon.extend_from_slice(uuid_bytes);

        let oob_info: u16 = caps_from_agent.as_ref().map(|c| c.oob_info).unwrap_or(0);
        beacon.extend_from_slice(&oob_info.to_be_bytes());

        if oob_info & OOB_INFO_URI_HASH != 0 {
            let uri_hash: u32 = caps_from_agent.as_ref().map(|c| c.uri_hash).unwrap_or(0);
            beacon.extend_from_slice(&uri_hash.to_be_bytes());
        }

        // Beacon indefinitely (count=0) every 500ms.
        if !mesh::mesh_send_pkt(0, 500, &beacon) {
            acceptor_free_inner(&mut Some(acceptor));
            return false;
        }

        // Register with PB-ADV bearer.
        // We use handle 0 since there's only one acceptor at a time.
        let uuid_copy = *uuid_bytes;
        if !register_pb_adv_acceptor(&uuid_copy) {
            // Clean up if registration fails.
            mesh::mesh_send_cancel(&BEC_FILTER);
            mesh::mesh_send_cancel(&[PKT_FILTER]);
            return false;
        }
    } else {
        // Device Key Refresh procedure — NPPI transport (TRANSPORT_NPPI).
        //
        // When no UUID is supplied the provisioning session is a device-key
        // refresh via NPPI (Node Provisioning Protocol Interface).  The
        // acceptor registers its open/close/rx/ack callbacks with the
        // Remote Provisioning Server which will relay PDUs over the mesh
        // network instead of a PB-ADV bearer.
        //
        // Mirrors C prov-acceptor.c lines 810-815:
        //   prov->transport = TRANSPORT_NPPI;
        //   if (!register_nppi_acceptor(open, close, rx, ack, prov))
        //       return false;
        acceptor.transport = TRANSPORT_NPPI;

        if !register_nppi_prov_acceptor() {
            acceptor_free_inner(&mut Some(acceptor));
            return false;
        }
    }

    *guard = Some(acceptor);
    true
}

/// Cancel an active acceptor provisioning session.
///
/// Mirrors C `acceptor_cancel()` from prov-acceptor.c lines 818-821.
pub async fn acceptor_cancel(_caller_data: usize) {
    let mut guard = PROV.lock().await;
    acceptor_free_inner(&mut guard);
}

// ---------------------------------------------------------------------------
// PB-ADV callback registration
// ---------------------------------------------------------------------------

/// Register the acceptor's PB-ADV callbacks.
///
/// This wires up the open/close/rx/ack callbacks to the PB-ADV bearer,
/// delegating each event to the singleton `PROV` state.
fn register_pb_adv_acceptor(uuid: &[u8; 16]) -> bool {
    // Construct the callback closures that bridge from the PB-ADV bearer
    // into our async acceptor state machine.
    let open_cb: ProvOpenCb =
        Box::new(|_user_data: usize, trans_tx: ProvTransTx, trans_data: usize, transport: u8| {
            let rt = tokio::runtime::Handle::current();
            rt.spawn(async move {
                handle_prov_open(trans_tx, trans_data, transport).await;
            });
        });

    let close_cb: ProvCloseCb = Box::new(|_user_data: usize, reason: u8| {
        let rt = tokio::runtime::Handle::current();
        rt.spawn(async move {
            handle_prov_close(reason).await;
        });
    });

    let rx_cb: ProvRxCb = Box::new(|_user_data: usize, data: &[u8]| {
        let data_owned = data.to_vec();
        let rt = tokio::runtime::Handle::current();
        rt.spawn(async move {
            handle_prov_rx(&data_owned).await;
        });
    });

    let ack_cb: ProvAckCb = Box::new(|_user_data: usize, msg_num: u8| {
        let rt = tokio::runtime::Handle::current();
        rt.spawn(async move {
            handle_prov_ack(msg_num).await;
        });
    });

    pb_adv::pb_adv_reg(false, open_cb, close_cb, rx_cb, ack_cb, uuid, 0)
}

// ---------------------------------------------------------------------------
// NPPI callback registration
// ---------------------------------------------------------------------------

/// Register the acceptor's callbacks with the Remote Provisioning Server
/// for an NPPI (Node Provisioning Protocol Interface) session.
///
/// This mirrors the PB-ADV registration pattern: four callback closures
/// (open/close/rx/ack) are constructed that bridge bearer events into the
/// async acceptor state machine, then handed to the Remote Provisioning
/// Server via [`register_nppi_acceptor`].
///
/// Mirrors C prov-acceptor.c lines 810-815:
///   `register_nppi_acceptor(acp_prov_open, acp_prov_close, acp_prov_rx, acp_prov_ack, prov)`
fn register_nppi_prov_acceptor() -> bool {
    // Construct the callback closures that bridge from the Remote
    // Provisioning Server into our async acceptor state machine.
    // Identical signatures to the PB-ADV callbacks.
    let open_cb: ProvOpenCb =
        Box::new(|_user_data: usize, trans_tx: ProvTransTx, trans_data: usize, transport: u8| {
            let rt = tokio::runtime::Handle::current();
            rt.spawn(async move {
                handle_prov_open(trans_tx, trans_data, transport).await;
            });
        });

    let close_cb: ProvCloseCb = Box::new(|_user_data: usize, reason: u8| {
        let rt = tokio::runtime::Handle::current();
        rt.spawn(async move {
            handle_prov_close(reason).await;
        });
    });

    let rx_cb: ProvRxCb = Box::new(|_user_data: usize, data: &[u8]| {
        let data_owned = data.to_vec();
        let rt = tokio::runtime::Handle::current();
        rt.spawn(async move {
            handle_prov_rx(&data_owned).await;
        });
    });

    let ack_cb: ProvAckCb = Box::new(|_user_data: usize, msg_num: u8| {
        let rt = tokio::runtime::Handle::current();
        rt.spawn(async move {
            handle_prov_ack(msg_num).await;
        });
    });

    // The user_data value 0 is used since there is only one acceptor at
    // a time (same convention as the PB-ADV registration).
    register_nppi_acceptor(open_cb, close_cb, rx_cb, ack_cb, 0)
}

/// Called by the PB-ADV bearer when the provisioning link is opened.
///
/// This function is invoked from the bearer context and must update
/// the singleton acceptor state.
pub async fn handle_prov_open(trans_tx: ProvTransTx, trans_data: usize, transport: u8) {
    let mut guard = PROV.lock().await;
    if let Some(ref mut p) = *guard {
        // Reject if a different transport is already connected.
        if p.trans_tx.is_some() && p.transport != transport {
            return;
        }

        p.trans_tx = Some(trans_tx);
        p.transport = transport;
        p.trans_data = trans_data;

        // Start the provisioning timeout.
        let to_secs = p.to_secs;
        let timeout_handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(u64::from(to_secs))).await;
            handle_prov_timeout().await;
        });
        p.timeout = Some(timeout_handle);
        p.expected = PROV_INVITE;
        p.previous = -1;
    }
}

/// Called by the PB-ADV bearer when the provisioning link is closed.
pub async fn handle_prov_close(reason: u8) {
    let mut guard = PROV.lock().await;
    acp_prov_close_inner(&mut guard, reason);
}

/// Called by the PB-ADV bearer when a provisioning PDU is received.
pub async fn handle_prov_rx(data: &[u8]) {
    let action = {
        let mut guard = PROV.lock().await;
        match guard.as_mut() {
            Some(p) => acp_prov_rx_inner(p, data),
            None => return,
        }
    };

    // Process actions that require async operations outside the lock.
    match action {
        RxAction::None => {}
        RxAction::Fail(reason) => {
            handle_failure(reason).await;
        }
        RxAction::Cleanup => {
            handle_cleanup().await;
        }
        RxAction::RequestPrivateKey => {
            handle_request_private_key().await;
        }
        RxAction::RequestStatic => {
            handle_request_static().await;
        }
        RxAction::OutputOob => {
            handle_output_oob().await;
        }
        RxAction::InputOob => {
            handle_input_oob().await;
        }
    }
}

/// Called by the PB-ADV bearer when an outbound message is acknowledged.
pub async fn handle_prov_ack(_msg_num: u8) {
    let mut guard = PROV.lock().await;
    if let Some(ref mut p) = *guard {
        acp_prov_ack_inner(p);
    }
}

// ---------------------------------------------------------------------------
// Async action handlers (invoked outside the mutex lock)
// ---------------------------------------------------------------------------

/// Handle a protocol failure: send PROV_FAILED, notify completion callback,
/// and start a cleanup timeout.
async fn handle_failure(reason: u8) {
    let mut guard = PROV.lock().await;
    if let Some(ref mut p) = *guard {
        let fail_msg = [PROV_FAILED, reason];
        prov_send(p, &fail_msg);
        p.failed = true;
        p.previous = -1;

        if let Some(cb) = p.cmplt.take() {
            cb(p.caller_data, reason, None);
        }

        // Cancel the existing timeout and start a 5-second cleanup timeout.
        if let Some(h) = p.timeout.take() {
            h.abort();
        }
        let timeout_handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            handle_prov_timeout().await;
        });
        p.timeout = Some(timeout_handle);
    }
}

/// Handle cleanup after a successful or failed provisioning sequence.
async fn handle_cleanup() {
    let mut guard = PROV.lock().await;
    if let Some(ref mut p) = *guard {
        // Cancel the existing timeout and start a 5-second cleanup timeout.
        if let Some(h) = p.timeout.take() {
            h.abort();
        }
        let timeout_handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            handle_prov_timeout().await;
        });
        p.timeout = Some(timeout_handle);
    }
}

/// Handle provisioning timeout.
///
/// Mirrors C `prov_to()` from prov-acceptor.c lines 140-160.
///
/// On first timeout: sends PROV_FAILED + PROV_ERR_UNEXPECTED_ERR, calls
/// the completion callback with PROV_ERR_TIMEOUT, and starts a 1-second
/// follow-up timeout.  On second timeout (trans_tx already cleared or
/// cmplt already consumed): calls `acceptor_free`.
async fn handle_prov_timeout() {
    let needs_followup = {
        let mut guard = PROV.lock().await;
        if let Some(ref mut p) = *guard {
            // Clear the timeout handle since we're in the timeout callback.
            p.timeout = None;

            if p.cmplt.is_some() && p.trans_tx.is_some() {
                // First timeout — notify caller and send failure PDU.
                if let Some(cb) = p.cmplt.take() {
                    cb(p.caller_data, PROV_ERR_TIMEOUT, None);
                }
                let fail_msg = [PROV_FAILED, PROV_ERR_UNEXPECTED_ERR];
                prov_send(p, &fail_msg);
                true
            } else {
                // Second timeout — clean up.
                acceptor_free_inner(&mut guard);
                false
            }
        } else {
            false
        }
    };

    if needs_followup {
        // Start a 1-second follow-up timeout (non-recursive: spawns
        // a fresh task calling prov_timeout_followup).
        let timeout_handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            prov_timeout_followup().await;
        });
        let mut guard = PROV.lock().await;
        if let Some(ref mut p) = *guard {
            p.timeout = Some(timeout_handle);
        }
    }
}

/// Second-phase timeout handler: simply frees the acceptor session.
///
/// This avoids async recursion in `handle_prov_timeout`.
async fn prov_timeout_followup() {
    let mut guard = PROV.lock().await;
    acceptor_free_inner(&mut guard);
}

/// Handle the agent's response to a private key request.
///
/// Mirrors C `priv_key_cb()` from prov-acceptor.c lines 307-340.
async fn handle_request_private_key() {
    let agent_arc = {
        let guard = PROV.lock().await;
        match guard.as_ref() {
            Some(p) => p.agent.clone(),
            None => return,
        }
    };

    let agent = match agent_arc {
        Some(ref a) => a,
        None => return,
    };

    let result = mesh_agent_request_private_key(agent).await;

    let mut guard = PROV.lock().await;
    let p = match guard.as_mut() {
        Some(p) => p,
        None => return,
    };

    match result {
        Ok(key_data) if key_data.len() == 32 => {
            // API delivers mesh byte order — swap to ECC (little-endian).
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_data);
            swap_u256_bytes(&mut key);
            p.private_key = key;

            // Derive public key from private key.
            match ecc_make_public_key(&p.private_key) {
                Ok(pub_key) => {
                    p.conf_inputs.dev_pub_key.copy_from_slice(&pub_key);
                    // Convert public key to mesh byte order.
                    let (x, y) = p.conf_inputs.dev_pub_key.split_at_mut(32);
                    let x: &mut [u8; 32] = x.try_into().unwrap();
                    let y: &mut [u8; 32] = y.try_into().unwrap();
                    swap_u256_bytes(x);
                    swap_u256_bytes(y);
                }
                Err(e) => {
                    error!("ECC public key derivation failed: {:?}", e);
                    let fail_msg = [PROV_FAILED, PROV_ERR_UNEXPECTED_ERR];
                    prov_send(p, &fail_msg);
                    return;
                }
            }

            p.material |= MAT_LOCAL_PRIVATE;

            if (p.material & MAT_SECRET) == MAT_SECRET && !acp_credentials(p) {
                let fail_msg = [PROV_FAILED, PROV_ERR_UNEXPECTED_ERR];
                prov_send(p, &fail_msg);
            }

            p.expected = PROV_PUB_KEY;
        }
        _ => {
            error!("Private key request failed or returned invalid data");
            let fail_msg = [PROV_FAILED, PROV_ERR_UNEXPECTED_ERR];
            prov_send(p, &fail_msg);
        }
    }
}

/// Handle the agent's response to a static OOB data request.
///
/// Mirrors C `static_cb()` from prov-acceptor.c lines 281-305
/// and the PROV_PUB_KEY auth_method==1 path.
async fn handle_request_static() {
    let agent_arc = {
        let guard = PROV.lock().await;
        match guard.as_ref() {
            Some(p) => p.agent.clone(),
            None => return,
        }
    };

    let agent = match agent_arc {
        Some(ref a) => a,
        None => return,
    };

    let result = mesh_agent_request_static(agent).await;

    let mut guard = PROV.lock().await;
    let p = match guard.as_mut() {
        Some(p) => p,
        None => return,
    };

    match result {
        Ok(key_data) if key_data.len() == 16 => {
            // Save two copies of the static OOB key.
            p.rand_auth_workspace[16..32].copy_from_slice(&key_data);
            p.rand_auth_workspace[32..48].copy_from_slice(&key_data);
            p.material |= MAT_RAND_AUTH;

            // If all material ready, send confirmation.
            if p.material == (MAT_SECRET | MAT_RAND_AUTH) && !send_conf(p) {
                let fail_msg = [PROV_FAILED, PROV_ERR_INVALID_FORMAT];
                prov_send(p, &fail_msg);
            }
        }
        _ => {
            error!("Static OOB request failed or returned invalid data");
            let fail_msg = [PROV_FAILED, PROV_ERR_UNEXPECTED_ERR];
            prov_send(p, &fail_msg);
        }
    }
}

/// Handle output OOB authentication: generate random key and display.
///
/// Mirrors C PROV_PUB_KEY auth_method==2 path from prov-acceptor.c
/// lines 538-563.
async fn handle_output_oob() {
    // Generate a random u32 and reduce it modulo the OOB digit count.
    let (oob_key, auth_action) = {
        let mut guard = PROV.lock().await;
        let p = match guard.as_mut() {
            Some(p) => p,
            None => return,
        };

        let mut rand_bytes = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
        let raw_key = u32::from_ne_bytes(rand_bytes);
        let oob_key = raw_key % digit_mod(p.conf_inputs.start.auth_size);

        // Save two copies of the numeric OOB value.
        p.rand_auth_workspace[28..32].copy_from_slice(&oob_key.to_be_bytes());
        p.rand_auth_workspace[44..48].copy_from_slice(&oob_key.to_be_bytes());
        p.material |= MAT_RAND_AUTH;

        let action = p.conf_inputs.start.auth_action;
        (oob_key, action)
    };

    // Display the OOB value via the agent (async D-Bus call).
    let agent_arc = {
        let guard = PROV.lock().await;
        match guard.as_ref() {
            Some(p) => p.agent.clone(),
            None => return,
        }
    };

    let agent = match agent_arc {
        Some(ref a) => a,
        None => return,
    };

    let display_result = if is_output_alpha_action(auth_action) {
        // Alphanumeric output — display as string.
        mesh_agent_display_string(agent, "").await
    } else {
        // Numeric output — display the number.
        mesh_agent_display_number(agent, false, auth_action, oob_key).await
    };

    if display_result.is_err() {
        let mut guard = PROV.lock().await;
        if let Some(ref mut p) = *guard {
            let fail_msg = [PROV_FAILED, PROV_ERR_UNEXPECTED_ERR];
            prov_send(p, &fail_msg);
        }
    }
}

/// Handle input OOB authentication: prompt the agent for input.
///
/// Mirrors C PROV_PUB_KEY auth_method==3 path from prov-acceptor.c
/// lines 566-584.
async fn handle_input_oob() {
    let auth_action = {
        let guard = PROV.lock().await;
        match guard.as_ref() {
            Some(p) => p.conf_inputs.start.auth_action,
            None => return,
        }
    };

    let agent_arc = {
        let guard = PROV.lock().await;
        match guard.as_ref() {
            Some(p) => p.agent.clone(),
            None => return,
        }
    };

    let agent = match agent_arc {
        Some(ref a) => a,
        None => return,
    };

    if is_input_alpha_action(auth_action) {
        // Alphanumeric input — prompt for static data.
        let result = mesh_agent_prompt_alpha(agent, false).await;
        let mut guard = PROV.lock().await;
        let p = match guard.as_mut() {
            Some(p) => p,
            None => return,
        };

        match result {
            Ok(key_data) => {
                let copy_len = key_data.len().min(16);
                p.rand_auth_workspace[16..16 + copy_len].copy_from_slice(&key_data[..copy_len]);
                p.rand_auth_workspace[32..32 + copy_len].copy_from_slice(&key_data[..copy_len]);
                p.material |= MAT_RAND_AUTH;

                // Send input complete notification.
                prov_send(p, &[PROV_INP_CMPLT]);
            }
            Err(_) => {
                let fail_msg = [PROV_FAILED, PROV_ERR_UNEXPECTED_ERR];
                prov_send(p, &fail_msg);
            }
        }
    } else {
        // Numeric input — prompt for a number.
        let result = mesh_agent_prompt_number(agent, false, auth_action).await;
        let mut guard = PROV.lock().await;
        let p = match guard.as_mut() {
            Some(p) => p,
            None => return,
        };

        match result {
            Ok(number) => {
                // Save two copies.
                p.rand_auth_workspace[28..32].copy_from_slice(&number.to_be_bytes());
                p.rand_auth_workspace[44..48].copy_from_slice(&number.to_be_bytes());
                p.material |= MAT_RAND_AUTH;

                // Send input complete notification.
                prov_send(p, &[PROV_INP_CMPLT]);
            }
            Err(_) => {
                let fail_msg = [PROV_FAILED, PROV_ERR_UNEXPECTED_ERR];
                prov_send(p, &fail_msg);
            }
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// When no Remote Provisioning session is active (the global `RPB_PROV`
    /// is `None`), `register_nppi_prov_acceptor()` must return `false`
    /// because the RP server has no state to store the callbacks.
    #[test]
    fn nppi_registration_fails_without_rp_session() {
        // No setup required — RPB_PROV defaults to None in test context.
        let result = register_nppi_prov_acceptor();
        assert!(
            !result,
            "register_nppi_prov_acceptor must return false when no RP session is active"
        );
    }

    /// Verify that the transport type constant used by the NPPI path is
    /// correct and distinct from the PB-ADV constant.
    #[test]
    fn transport_nppi_constant() {
        assert_ne!(
            TRANSPORT_NPPI, TRANSPORT_PB_ADV,
            "NPPI and PB-ADV transport constants must differ"
        );
    }

    /// Verify that the `MeshProvAcceptor` struct can be created with the
    /// NPPI transport type, matching the NPPI branch in `acceptor_start`.
    #[test]
    fn acceptor_nppi_transport_field() {
        let acceptor = MeshProvAcceptor {
            cmplt: None,
            trans_tx: None,
            trans_data: 0,
            ob: VecDeque::new(),
            agent: None,
            caller_data: 0,
            timeout: None,
            to_secs: 60,
            out_opcode: PROV_NONE,
            transport: TRANSPORT_NPPI,
            material: 0,
            expected: PROV_INVITE,
            previous: -1,
            failed: false,
            conf_inputs: ConfInput::default(),
            calc_key: [0u8; 16],
            salt: [0u8; 16],
            confirm: [0u8; 16],
            s_key: [0u8; 16],
            s_nonce: [0u8; 13],
            private_key: [0u8; 32],
            secret: [0u8; 32],
            rand_auth_workspace: [0u8; 48],
        };
        assert_eq!(acceptor.transport, TRANSPORT_NPPI);
    }

    /// Verify `acceptor_free_inner` safely handles an already-empty state.
    #[test]
    fn acceptor_free_inner_noop_on_none() {
        let mut state: Option<MeshProvAcceptor> = None;
        acceptor_free_inner(&mut state);
        assert!(state.is_none());
    }

    /// `acceptor_free_inner` should clear the session and cancel the
    /// timeout when called on a populated `Some` value.
    #[test]
    fn acceptor_free_inner_clears_session() {
        let acceptor = MeshProvAcceptor {
            cmplt: None,
            trans_tx: None,
            trans_data: 0,
            ob: VecDeque::new(),
            agent: None,
            caller_data: 0,
            timeout: None,
            to_secs: 30,
            out_opcode: PROV_NONE,
            transport: TRANSPORT_PB_ADV,
            material: 0,
            expected: PROV_INVITE,
            previous: -1,
            failed: false,
            conf_inputs: ConfInput::default(),
            calc_key: [0u8; 16],
            salt: [0u8; 16],
            confirm: [0u8; 16],
            s_key: [0u8; 16],
            s_nonce: [0u8; 13],
            private_key: [0u8; 32],
            secret: [0u8; 32],
            rand_auth_workspace: [0u8; 48],
        };
        let mut state = Some(acceptor);
        acceptor_free_inner(&mut state);
        assert!(state.is_none(), "acceptor_free_inner must clear the session");
    }
}
