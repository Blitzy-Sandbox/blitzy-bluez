// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/bluetooth-meshd/src/provisioning/initiator.rs
//
// Complete Rust rewrite of mesh/prov-initiator.c (1162 lines).
// Implements the provisioning **initiator** (provisioner) state machine:
// ECDH key exchange, confirmation/random exchange, OOB authentication,
// agent prompts, provisioning data encryption and delivery, scan
// registration for unprovisioned device beacons, and Remote Provisioning
// (RPR) client model integration.

use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use bluez_shared::crypto::aes_cmac::random_bytes;
use bluez_shared::crypto::ecc::{ecc_make_key, ecdh_shared_secret};

use crate::agent::{
    MeshAgent, MeshAgentProvCaps, mesh_agent_get_caps, mesh_agent_request_public_key,
};
use crate::crypto;
use crate::keyring;
use crate::mesh::{self, BT_AD_MESH_PROV, KEY_REFRESH_PHASE_TWO, PROV_FLAG_IVU, PROV_FLAG_KR};
use crate::model::{
    MeshModelOps, MeshModelPub, mesh_model_opcode_get, mesh_model_opcode_set, mesh_model_register,
    mesh_model_send,
};
use crate::models::remote_prov::{
    OP_REM_PROV_EXT_SCAN_REPORT, OP_REM_PROV_LINK_CLOSE, OP_REM_PROV_LINK_OPEN,
    OP_REM_PROV_LINK_REPORT, OP_REM_PROV_LINK_STATUS, OP_REM_PROV_PDU_OB_REPORT,
    OP_REM_PROV_PDU_REPORT, OP_REM_PROV_PDU_SEND, OP_REM_PROV_SCAN_CAP_STATUS,
    OP_REM_PROV_SCAN_REPORT, OP_REM_PROV_SCAN_STATUS, PB_REM_ERR_SUCCESS, PB_REMOTE_STATE_IDLE,
    PB_REMOTE_STATE_LINK_ACTIVE, PB_REMOTE_STATE_LINK_OPENING, REM_PROV_CLI_MODEL,
};
use crate::node::MeshNode;
use crate::provisioning::pb_adv::{pb_adv_reg, pb_adv_unreg};
use crate::provisioning::{
    ALG_FIPS_256_ECC, AUTH_METHOD_INPUT, AUTH_METHOD_NO_OOB, AUTH_METHOD_OUTPUT,
    AUTH_METHOD_STATIC, ConfInput, EXPECTED_PDU_SIZE, MeshNetProvCaps, MeshProvNodeInfo,
    OOB_IN_ACTION_ALPHA, OOB_IN_ACTION_NUMBER, OOB_IN_ACTION_PUSH, OOB_OUT_ACTION_ALPHA,
    OOB_OUT_ACTION_BLINK, OOB_OUT_ACTION_NUMBER, PROV_CAPS, PROV_COMPLETE, PROV_CONFIRM, PROV_DATA,
    PROV_ERR_CANT_ASSIGN_ADDR, PROV_ERR_CONFIRM_FAILED, PROV_ERR_INVALID_FORMAT, PROV_ERR_SUCCESS,
    PROV_ERR_TIMEOUT, PROV_ERR_UNEXPECTED_ERR, PROV_ERR_UNEXPECTED_PDU, PROV_FAILED,
    PROV_INP_CMPLT, PROV_INVITE, PROV_NONE, PROV_NUM_OPCODES, PROV_PUB_KEY, PROV_RANDOM,
    PROV_START, ProvAckCb, ProvCloseCb, ProvData, ProvOpenCb, ProvRxCb, ProvStart, ProvTransTx,
};
use crate::util::print_packet;

// =========================================================================
// Constants
// =========================================================================

/// AD type filter for PB-ADV provisioning packets.
const PKT_FILTER: u8 = BT_AD_MESH_PROV;

/// Material tracking bitmask: remote device public key received.
const MAT_REMOTE_PUBLIC: u8 = 0x01;
/// Material tracking bitmask: local private key generated.
const MAT_LOCAL_PRIVATE: u8 = 0x02;
/// Material tracking bitmask: random + auth value ready.
const MAT_RAND_AUTH: u8 = 0x04;
/// Combined mask: both keys available for ECDH.
const MAT_SECRET: u8 = MAT_REMOTE_PUBLIC | MAT_LOCAL_PRIVATE;

/// Provisioning action index: Output OOB alpha (C: PROV_ACTION_OUT_ALPHA).
const PROV_ACTION_OUT_ALPHA: u8 = 4;
/// Provisioning action index: Input OOB alpha (C: PROV_ACTION_IN_ALPHA).
const PROV_ACTION_IN_ALPHA: u8 = 3;

/// PB-NPPI transport sub-type 0 (C: PB_NPPI_00).
const PB_NPPI_00: u8 = 0x00;
/// PB-NPPI transport sub-type 2 (C: PB_NPPI_02).
const PB_NPPI_02: u8 = 0x02;

// =========================================================================
// State Machine Enum
// =========================================================================

/// Internal provisioning state (maps to C enum int_state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum IntState {
    Idle = 0,
    InviteSent,
    InviteAcked,
    StartSent,
    StartAcked,
    KeySent,
    KeyAcked,
    ConfSent,
    ConfAcked,
    RandSent,
    RandAcked,
    DataSent,
    DataAcked,
}

// =========================================================================
// Core Structures
// =========================================================================

/// Provisioning initiator session state.
///
/// Mirrors C `struct mesh_prov_initiator` from prov-initiator.c lines 78-110.
struct MeshProvInitiator {
    /// Callback invoked when provisioning session starts (success/failure).
    start_cb: Option<Box<dyn FnOnce(i32) + Send>>,
    /// Callback invoked when provisioning is complete.
    complete_cb: Option<Box<dyn FnOnce(u8, Option<MeshProvNodeInfo>) -> bool + Send>>,
    /// Callback invoked when provisioning data is needed from the manager.
    data_req_cb: Option<Box<dyn FnOnce(u8) -> bool + Send>>,
    /// Transport transmit function for sending PDUs.
    trans_tx: Option<ProvTransTx>,
    /// Mesh agent for OOB authentication interaction.
    agent: Option<Arc<MeshAgent>>,
    /// Opaque caller handle.
    caller_data: usize,
    /// Opaque transport handle.
    trans_data: usize,
    /// Mesh node reference.
    node: Option<Arc<MeshNode>>,
    /// Timeout task handle for session timeout cancellation.
    timeout: Option<JoinHandle<()>>,
    /// Timeout duration in seconds.
    to_secs: u32,
    /// Current state in the provisioning state machine.
    state: IntState,
    /// Network key index for provisioning data.
    net_idx: u16,
    /// Server network index for remote provisioning.
    svr_idx: u16,
    /// Unicast address assigned to provisioned device.
    unicast: u16,
    /// Remote provisioning server address (0 = local PB-ADV).
    server: u16,
    /// Transport type (TRANSPORT_PB_ADV or TRANSPORT_NPPI).
    transport: u8,
    /// Material tracking bitmask (MAT_* flags).
    material: u8,
    /// Expected next opcode.
    expected: u8,
    /// Previous received opcode (-1 = none).
    previous: i8,
    /// Number of output OOB digits for numeric display.
    out_num: u8,
    /// Remote provisioning link state.
    rpr_state: u8,
    /// Confirmation inputs (145 bytes: invite + caps + start + pub keys).
    conf_inputs: ConfInput,
    /// Derived confirmation key or device key.
    calc_key: [u8; 16],
    /// Confirmation salt.
    salt: [u8; 16],
    /// Remote device confirmation value.
    confirm: [u8; 16],
    /// Session encryption key.
    s_key: [u8; 16],
    /// Session nonce (13 bytes).
    s_nonce: [u8; 13],
    /// Local private key (32 bytes).
    private_key: [u8; 32],
    /// ECDH shared secret (32 bytes).
    secret: [u8; 32],
    /// Workspace for [local_random(16) | remote_random(16) | auth_value(16)].
    rand_auth_workspace: [u8; 48],
    /// Device UUID being provisioned.
    uuid: [u8; 16],
}

/// Scan registration request for unprovisioned device beacons.
///
/// Mirrors C `struct scan_req` from prov-initiator.c lines 112-116.
struct ScanReq {
    /// Callback invoked when a scan result is received.
    scan_result: Box<dyn Fn(i32, &[u8]) + Send>,
    /// Mesh node reference.
    node: Arc<MeshNode>,
}

// =========================================================================
// Module-Level Singleton State
// =========================================================================

/// Singleton provisioning session — only one active at a time.
static PROV: Mutex<Option<MeshProvInitiator>> = Mutex::const_new(None);

/// Queue of scan registrations.
static SCANS: Mutex<Vec<ScanReq>> = Mutex::const_new(Vec::new());

// =========================================================================
// Lifecycle Functions
// =========================================================================

/// Free and clean up the provisioning session (synchronous version).
///
/// Mirrors C `initiator_free()` (prov-initiator.c lines 121-134).
fn initiator_free_inner(p: &mut MeshProvInitiator) {
    // Cancel timeout task
    if let Some(handle) = p.timeout.take() {
        handle.abort();
    }

    // Cancel pending mesh advertising if local PB-ADV
    if p.server == 0 {
        mesh::mesh_send_cancel(&[PKT_FILTER]);
    }

    // Unregister PB-ADV session
    pb_adv_unreg(p.caller_data);
}

/// Close the provisioning session with a given reason code.
///
/// On success: populates MeshProvNodeInfo and invokes complete_cb.
/// On failure: invokes complete_cb with the error reason.
/// For remote provisioning: sends OP_REM_PROV_LINK_CLOSE to server.
///
/// Mirrors C `int_prov_close()` (prov-initiator.c lines 136-174).
fn int_prov_close(prov: &mut Option<MeshProvInitiator>, reason: u8) {
    let p = match prov.as_mut() {
        Some(p) => p,
        None => return,
    };

    // If remote provisioning, send link close to remote server
    if p.server != 0 {
        if let Some(ref node) = p.node {
            let mut msg = [0u8; 10];
            let n = mesh_model_opcode_set(OP_REM_PROV_LINK_CLOSE, &mut msg);
            msg[n] = reason;
            mesh_model_send(
                node,
                0,
                p.server,
                mesh::APP_IDX_DEV_REMOTE,
                p.svr_idx,
                mesh::DEFAULT_TTL,
                true,
                &msg[..n + 1],
            );
        }
    }

    if reason != PROV_ERR_SUCCESS {
        // Failure: notify via complete_cb and free
        if let Some(cb) = p.complete_cb.take() {
            cb(reason, None);
        }
        initiator_free_inner(p);
        *prov = None;
        return;
    }

    // Success: build node info and notify
    let node_info = MeshProvNodeInfo {
        device_key: p.calc_key,
        net_key: p.s_key,
        net_index: p.net_idx,
        flags: 0,
        iv_index: 0,
        unicast: p.unicast,
        num_ele: p.conf_inputs.caps.num_ele,
    };

    if let Some(cb) = p.complete_cb.take() {
        cb(PROV_ERR_SUCCESS, Some(node_info));
    }

    initiator_free_inner(p);
    *prov = None;
}

// =========================================================================
// ECDH / Crypto Helpers
// =========================================================================

/// Compute the ECDH shared secret from our private key and the peer's
/// public key.
///
/// Mirrors C `prov_calc_secret()` (prov-initiator.c lines 226-248).
fn prov_calc_secret(priv_key: &[u8; 32], peer_pub: &[u8; 64]) -> Option<[u8; 32]> {
    match ecdh_shared_secret(peer_pub, priv_key) {
        Ok(secret) => Some(secret),
        Err(e) => {
            error!("ECDH shared secret computation failed: {e}");
            None
        }
    }
}

/// Return the bit position of the highest set bit in a u16.
///
/// Returns 0..=15 for the highest bit, or -1 if value is zero.
/// Mirrors C `u16_high_bit()` (prov-initiator.c lines 285-295).
fn u16_high_bit(val: u16) -> i8 {
    if val == 0 {
        return -1;
    }
    15 - val.leading_zeros() as i8
}

/// Compute credentials: ECDH secret, confirmation salt, and confirmation key.
///
/// Mirrors C `int_credentials()` (prov-initiator.c lines 250-280).
fn int_credentials(p: &mut MeshProvInitiator) -> bool {
    // Compare public keys — they must differ
    if p.conf_inputs.prv_pub_key == p.conf_inputs.dev_pub_key {
        error!("Public keys are identical — possible reflection attack");
        return false;
    }

    // Compute ECDH shared secret
    let secret = match prov_calc_secret(&p.private_key, &p.conf_inputs.dev_pub_key) {
        Some(s) => s,
        None => return false,
    };
    p.secret = secret;
    print_packet("ECDH Secret", &p.secret);

    // Compute confirmation salt: S1(conf_inputs_bytes)
    let conf_input_bytes = p.conf_inputs.as_bytes();
    let conf_salt = match crypto::mesh_crypto_s1(&conf_input_bytes) {
        Some(s) => s,
        None => {
            error!("S1 computation failed");
            return false;
        }
    };
    p.salt = conf_salt;
    print_packet("ConfirmationSalt", &p.salt);

    // Derive confirmation key from secret and salt
    let conf_key = match crypto::mesh_crypto_prov_conf_key(&p.secret, &p.salt) {
        Some(k) => k,
        None => {
            error!("Confirmation key derivation failed");
            return false;
        }
    };
    p.calc_key = conf_key;
    print_packet("ConfirmationKey", &p.calc_key);

    // Generate local random nonce (16 bytes)
    if random_bytes(&mut p.rand_auth_workspace[0..16]).is_err() {
        error!("Random generation failed");
        return false;
    }
    print_packet("LocalRandom", &p.rand_auth_workspace[0..16]);

    true
}

/// Derive session material: prov_salt, session key, session nonce.
///
/// Mirrors C `calc_local_material()` (prov-initiator.c lines 282-300).
fn calc_local_material(p: &mut MeshProvInitiator) -> bool {
    let mut dev_rand = [0u8; 16];
    dev_rand.copy_from_slice(&p.rand_auth_workspace[16..32]);
    let mut local_rand = [0u8; 16];
    local_rand.copy_from_slice(&p.rand_auth_workspace[0..16]);

    let prov_salt = match crypto::mesh_crypto_prov_prov_salt(&p.salt, &dev_rand, &local_rand) {
        Some(s) => s,
        None => {
            error!("Provisioning salt derivation failed");
            return false;
        }
    };
    print_packet("ProvisioningSalt", &prov_salt);

    // Session key
    let s_key = match crypto::mesh_crypto_session_key(&p.secret, &prov_salt) {
        Some(k) => k,
        None => {
            error!("Session key derivation failed");
            return false;
        }
    };
    p.s_key = s_key;
    print_packet("SessionKey", &p.s_key);

    // Session nonce (13 bytes)
    let s_nonce = match crypto::mesh_crypto_nonce(&p.secret, &prov_salt) {
        Some(n) => n,
        None => {
            error!("Session nonce derivation failed");
            return false;
        }
    };
    p.s_nonce = s_nonce;
    print_packet("SessionNonce", &p.s_nonce);

    // Store salt for device key derivation
    p.salt = prov_salt;
    true
}

// =========================================================================
// Confirmation and Random PDU helpers
// =========================================================================

/// Build and send the PROV_CONFIRM PDU.
///
/// Mirrors C `send_confirm()` (prov-initiator.c lines 322-365).
fn send_confirm(p: &mut MeshProvInitiator) {
    // confirmation = AES-CMAC(calc_key, rand_auth_workspace[0..32])
    let mut confirmation = [0u8; 16];
    if !crypto::mesh_crypto_aes_cmac(&p.calc_key, &p.rand_auth_workspace[0..32], &mut confirmation)
    {
        error!("Confirmation computation failed");
        return;
    }
    p.confirm = confirmation;
    print_packet("LocalConfirmation", &p.confirm);

    // Build PROV_CONFIRM message: [opcode, confirmation(16)]
    let mut msg = [0u8; 17];
    msg[0] = PROV_CONFIRM;
    msg[1..17].copy_from_slice(&p.confirm);

    p.expected = PROV_CONFIRM;
    p.state = IntState::ConfSent;

    if let Some(ref mut tx) = p.trans_tx {
        tx(&msg);
    }
}

/// Build and send the PROV_RANDOM PDU.
///
/// Mirrors C `send_random()` (prov-initiator.c lines 447-460).
fn send_random(p: &mut MeshProvInitiator) {
    let mut msg = [0u8; 17];
    msg[0] = PROV_RANDOM;
    msg[1..17].copy_from_slice(&p.rand_auth_workspace[0..16]);

    p.expected = PROV_RANDOM;
    p.state = IntState::RandSent;

    if let Some(ref mut tx) = p.trans_tx {
        tx(&msg);
    }
}

/// Build and send the PROV_PUB_KEY PDU.
///
/// Mirrors C `send_pub_key()` (prov-initiator.c lines 407-420).
fn send_pub_key(p: &mut MeshProvInitiator) {
    let mut msg = [0u8; 65];
    msg[0] = PROV_PUB_KEY;
    msg[1..65].copy_from_slice(&p.conf_inputs.prv_pub_key);

    p.state = IntState::KeySent;
    p.expected = PROV_PUB_KEY;

    if let Some(ref mut tx) = p.trans_tx {
        tx(&msg);
    }
}

// =========================================================================
// OOB Callback Helpers
// =========================================================================

/// Agent callback for numeric OOB input result.
///
/// Mirrors C `number_cb()` (prov-initiator.c lines 367-385).
fn number_cb(p: &mut MeshProvInitiator, result: u32) {
    p.rand_auth_workspace[44..48].copy_from_slice(&result.to_be_bytes());
    p.material |= MAT_RAND_AUTH;

    if p.material == (MAT_SECRET | MAT_RAND_AUTH) && int_credentials(p) {
        send_confirm(p);
    }
}

/// Agent callback for static OOB key result.
///
/// Mirrors C `static_cb()` (prov-initiator.c lines 387-405).
fn static_cb(p: &mut MeshProvInitiator, data: &[u8]) {
    let len = data.len().min(16);
    p.rand_auth_workspace[32..48].fill(0);
    p.rand_auth_workspace[32..32 + len].copy_from_slice(&data[..len]);
    p.material |= MAT_RAND_AUTH;

    if p.material == (MAT_SECRET | MAT_RAND_AUTH) && int_credentials(p) {
        send_confirm(p);
    }
}

/// Agent callback for OOB public key result.
///
/// Mirrors C `pub_key_cb()` (prov-initiator.c lines 422-445).
fn pub_key_cb(p: &mut MeshProvInitiator, key_data: &[u8]) {
    if key_data.len() < 64 {
        error!("OOB public key too short: {}", key_data.len());
        return;
    }
    p.conf_inputs.dev_pub_key[..64].copy_from_slice(&key_data[..64]);
    p.material |= MAT_REMOTE_PUBLIC;

    if p.material & MAT_SECRET == MAT_SECRET {
        int_credentials(p);
    }
}

// =========================================================================
// OOB Random Key Generation
// =========================================================================

/// Generate a random key for output OOB authentication.
///
/// Mirrors C `get_random_key()` (prov-initiator.c lines 532-576).
fn get_random_key(p: &mut MeshProvInitiator) {
    let mut random = [0u8; 16];
    if random_bytes(&mut random).is_err() {
        error!("Random key generation failed");
        return;
    }
    p.rand_auth_workspace[32..48].fill(0);
    p.rand_auth_workspace[32..48].copy_from_slice(&random);
}

// =========================================================================
// OOB Authentication
// =========================================================================

/// Dispatch OOB authentication based on the selected method.
///
/// For agent-interactive methods (Static, Output OOB, Input OOB), spawns
/// an async task that calls the agent and then invokes the appropriate
/// callback (`static_cb`, `number_cb`) with the result. The async task
/// runs after the current mutex guard is released.
///
/// Mirrors C `int_prov_auth()` (prov-initiator.c lines 531-615).
fn int_prov_auth(p: &mut MeshProvInitiator) {
    let auth_method = p.conf_inputs.start.auth_method;
    let auth_action = p.conf_inputs.start.auth_action;
    let auth_size = p.conf_inputs.start.auth_size;

    p.state = IntState::KeyAcked;
    debug!("auth_method: {auth_method}");
    p.rand_auth_workspace[16..48].fill(0);

    match auth_method {
        AUTH_METHOD_NO_OOB => {
            // Auth Type 3c — No OOB: zero auth value, ready immediately
            p.material |= MAT_RAND_AUTH;
        }
        AUTH_METHOD_STATIC => {
            // Auth Type 3c — Static OOB: ask agent for static key
            debug!("Requesting static OOB from agent");
            if let Some(ref agent) = p.agent {
                let agent = Arc::clone(agent);
                tokio::spawn(async move {
                    let result = crate::agent::mesh_agent_request_static(&agent).await;
                    let mut guard = PROV.lock().await;
                    match result {
                        Ok(key) => {
                            if let Some(p) = guard.as_mut() {
                                static_cb(p, &key);
                            }
                        }
                        Err(_) => {
                            error!("Static OOB request failed");
                            int_prov_close(&mut guard, PROV_ERR_UNEXPECTED_ERR);
                        }
                    }
                });
            }
            return; // Don't check MAT_RAND_AUTH below — async completes later
        }
        AUTH_METHOD_OUTPUT => {
            // Auth Type 3a — Output OOB: device outputs, provisioner prompts
            debug!("Prompting agent for output OOB");
            if let Some(ref agent) = p.agent {
                let agent = Arc::clone(agent);
                if auth_action == PROV_ACTION_OUT_ALPHA {
                    tokio::spawn(async move {
                        let result = crate::agent::mesh_agent_prompt_alpha(&agent, true).await;
                        let mut guard = PROV.lock().await;
                        match result {
                            Ok(key) => {
                                if let Some(p) = guard.as_mut() {
                                    static_cb(p, &key);
                                }
                            }
                            Err(_) => {
                                error!("Output OOB alpha prompt failed");
                                int_prov_close(&mut guard, PROV_ERR_UNEXPECTED_ERR);
                            }
                        }
                    });
                } else {
                    tokio::spawn(async move {
                        let result =
                            crate::agent::mesh_agent_prompt_number(&agent, true, auth_action).await;
                        let mut guard = PROV.lock().await;
                        match result {
                            Ok(number) => {
                                if let Some(p) = guard.as_mut() {
                                    number_cb(p, number);
                                }
                            }
                            Err(_) => {
                                error!("Output OOB number prompt failed");
                                int_prov_close(&mut guard, PROV_ERR_UNEXPECTED_ERR);
                            }
                        }
                    });
                }
            }
            return; // Async completes later
        }
        AUTH_METHOD_INPUT => {
            // Auth Type 3b — Input OOB: provisioner outputs, device inputs
            get_random_key(p);
            p.out_num = auth_size;
            p.material |= MAT_RAND_AUTH;

            let oob_key = u32::from_be_bytes([
                p.rand_auth_workspace[28],
                p.rand_auth_workspace[29],
                p.rand_auth_workspace[30],
                p.rand_auth_workspace[31],
            ]);

            if let Some(ref agent) = p.agent {
                let agent = Arc::clone(agent);
                if auth_action == PROV_ACTION_IN_ALPHA {
                    // Display alpha string from rand_auth_workspace[16..32]
                    let display_str = String::from_utf8_lossy(
                        &p.rand_auth_workspace[16..16 + auth_size as usize],
                    )
                    .to_string();
                    tokio::spawn(async move {
                        if let Err(e) =
                            crate::agent::mesh_agent_display_string(&agent, &display_str).await
                        {
                            error!("Display string failed: {e:?}");
                        }
                    });
                } else {
                    tokio::spawn(async move {
                        if let Err(e) = crate::agent::mesh_agent_display_number(
                            &agent,
                            true,
                            auth_action,
                            oob_key,
                        )
                        .await
                        {
                            error!("Display number failed: {e:?}");
                        }
                    });
                }
            }
        }
        _ => {
            error!("Unknown auth method: {auth_method}");
        }
    }

    // If material is ready after synchronous path, send confirmation
    if p.material & MAT_RAND_AUTH != 0 && int_credentials(p) {
        send_confirm(p);
    }
}

// =========================================================================
// Authentication Method Negotiation
// =========================================================================

/// Negotiate the authentication method from both provisioner and device
/// capabilities.
///
/// Mirrors C `int_prov_start_auth()` (prov-initiator.c lines 652-740).
fn int_prov_start_auth(p: &mut MeshProvInitiator) {
    let caps = &p.conf_inputs.caps;
    let agent_caps: &MeshAgentProvCaps =
        mesh_agent_get_caps(p.agent.as_ref().expect("Agent must be set"));

    let mut start = ProvStart {
        algorithm: 0, // FIPS P-256
        ..ProvStart::default()
    };

    // Public key type: use OOB if both sides support it
    if caps.pub_type != 0 && agent_caps.pub_type != 0 {
        start.pub_key = 0x01;
        // Request public key from agent asynchronously.
        // pub_key_cb will be applied when the result arrives.
        if let Some(agent) = p.agent.clone() {
            tokio::spawn(async move {
                match mesh_agent_request_public_key(&agent).await {
                    Ok(key_data) => {
                        let mut guard = PROV.lock().await;
                        if let Some(prov) = guard.as_mut() {
                            pub_key_cb(prov, &key_data);
                        }
                    }
                    Err(e) => {
                        error!("OOB public key request failed: {e:?}");
                        let mut guard = PROV.lock().await;
                        int_prov_close(&mut guard, PROV_ERR_UNEXPECTED_ERR);
                    }
                }
            });
        }
    }

    let mut auth_method = AUTH_METHOD_NO_OOB;
    let mut auth_action: u8 = 0;
    let mut auth_size: u8 = 0;

    // Preference order: Static → Output → Input → No OOB
    if caps.static_type != 0 && agent_caps.static_type != 0 {
        auth_method = AUTH_METHOD_STATIC;
    } else if caps.output_action != 0 && caps.output_size != 0 {
        // Output OOB: device outputs, provisioner inputs
        if (caps.output_action & OOB_OUT_ACTION_ALPHA) != 0
            && (agent_caps.input_action & OOB_IN_ACTION_ALPHA) != 0
        {
            let bit = u16_high_bit(caps.output_action & OOB_OUT_ACTION_ALPHA);
            if bit >= 0 {
                auth_method = AUTH_METHOD_OUTPUT;
                auth_action = bit as u8;
                auth_size = caps.output_size;
            }
        } else if (caps.output_action & OOB_OUT_ACTION_NUMBER) != 0
            && (agent_caps.input_action & OOB_IN_ACTION_NUMBER) != 0
        {
            let bit = u16_high_bit(caps.output_action & OOB_OUT_ACTION_NUMBER);
            if bit >= 0 {
                auth_method = AUTH_METHOD_OUTPUT;
                auth_action = bit as u8;
                auth_size = caps.output_size;
            }
        } else if (caps.output_action & OOB_OUT_ACTION_BLINK) != 0
            && (agent_caps.input_action & OOB_IN_ACTION_PUSH) != 0
        {
            let bit = u16_high_bit(caps.output_action & OOB_OUT_ACTION_BLINK);
            if bit >= 0 {
                auth_method = AUTH_METHOD_OUTPUT;
                auth_action = bit as u8;
                auth_size = caps.output_size;
            }
        }
    } else if caps.input_action != 0 && caps.input_size != 0 {
        // Input OOB: provisioner outputs, device inputs
        if (caps.input_action & OOB_IN_ACTION_ALPHA) != 0
            && (agent_caps.output_action & OOB_OUT_ACTION_ALPHA) != 0
        {
            let bit = u16_high_bit(caps.input_action & OOB_IN_ACTION_ALPHA);
            if bit >= 0 {
                auth_method = AUTH_METHOD_INPUT;
                auth_action = bit as u8;
                auth_size = caps.input_size;
            }
        } else if (caps.input_action & OOB_IN_ACTION_NUMBER) != 0
            && (agent_caps.output_action & OOB_OUT_ACTION_NUMBER) != 0
        {
            let bit = u16_high_bit(caps.input_action & OOB_IN_ACTION_NUMBER);
            if bit >= 0 {
                auth_method = AUTH_METHOD_INPUT;
                auth_action = bit as u8;
                auth_size = caps.input_size;
            }
        } else if (caps.input_action & OOB_IN_ACTION_PUSH) != 0
            && (agent_caps.output_action & OOB_OUT_ACTION_BLINK) != 0
        {
            let bit = u16_high_bit(caps.input_action & OOB_IN_ACTION_PUSH);
            if bit >= 0 {
                auth_method = AUTH_METHOD_INPUT;
                auth_action = bit as u8;
                auth_size = caps.input_size;
            }
        }
    }

    start.auth_method = auth_method;
    start.auth_action = auth_action;
    start.auth_size = auth_size;

    p.conf_inputs.start = start;

    debug!(
        "ProvStart: algo={}, pub_key={}, auth_method={}, auth_action={}, auth_size={}",
        start.algorithm, start.pub_key, start.auth_method, start.auth_action, start.auth_size
    );
}

// =========================================================================
// Transport Open Callback
// =========================================================================

/// Bearer open callback — generates ECDH keypair and sends PROV_INVITE.
///
/// Mirrors C `int_prov_open()` (prov-initiator.c lines 176-212).
fn int_prov_open(p: &mut MeshProvInitiator) {
    // Generate ephemeral ECDH key pair
    match ecc_make_key() {
        Ok((pub_key, priv_key)) => {
            p.conf_inputs.prv_pub_key = pub_key;
            p.private_key = priv_key;
            p.material |= MAT_LOCAL_PRIVATE;
            print_packet("LocalPublicKey", &p.conf_inputs.prv_pub_key);
        }
        Err(e) => {
            error!("ECDH key generation failed: {e}");
            if let Some(cb) = p.start_cb.take() {
                cb(-1);
            }
            return;
        }
    }

    // Build PROV_INVITE: [opcode, attention_duration=30]
    let invite_msg = [PROV_INVITE, 30u8];
    p.conf_inputs.invite.attention = 30;

    p.expected = PROV_CAPS;
    p.previous = -1;
    p.state = IntState::InviteSent;

    if let Some(ref mut tx) = p.trans_tx {
        tx(&invite_msg);
    }

    // Notify caller of success
    if let Some(cb) = p.start_cb.take() {
        cb(0);
    }
}

// =========================================================================
// Receive State Machine
// =========================================================================

/// Main provisioning PDU receive handler.
///
/// Dispatches on opcode (data[0]) with ordering enforcement via
/// expected/previous fields.
///
/// Mirrors C `int_prov_rx()` (prov-initiator.c lines 742-920).
fn int_prov_rx(prov: &mut Option<MeshProvInitiator>, data: &[u8]) {
    if prov.is_none() {
        return;
    }

    if data.is_empty() {
        return;
    }

    let opcode = data[0];
    print_packet("ProvRx", data);

    // Validate opcode is in known range
    if (opcode as usize) >= PROV_NUM_OPCODES {
        error!("Unknown provisioning opcode: {opcode}");
        int_prov_close(prov, PROV_ERR_INVALID_FORMAT);
        return;
    }

    // Validate PDU size
    let expected_len = EXPECTED_PDU_SIZE[opcode as usize] as usize;
    if expected_len != 0 && data.len() != expected_len {
        error!("PDU size mismatch: opcode={opcode}, expected={expected_len}, got={}", data.len());
        int_prov_close(prov, PROV_ERR_INVALID_FORMAT);
        return;
    }

    // Validate PDU ordering
    {
        let ordering_fail = {
            let p = match prov.as_ref() {
                Some(p) => p,
                None => return,
            };
            p.expected != PROV_NONE && opcode != p.expected && opcode != PROV_FAILED
        };
        if ordering_fail {
            error!("Unexpected PDU: got opcode={opcode}");
            int_prov_close(prov, PROV_ERR_UNEXPECTED_PDU);
            return;
        }
    }

    // Verify prov is still active before dispatch
    if prov.is_none() {
        return;
    }

    match opcode {
        PROV_CAPS => {
            if data.len() < 12 {
                error!("PROV_CAPS too short");
                int_prov_close(prov, PROV_ERR_INVALID_FORMAT);
                return;
            }

            let p = prov.as_mut().unwrap();
            match MeshNetProvCaps::from_bytes(&data[1..12]) {
                Some(caps) => {
                    debug!(
                        "Caps: num_ele={}, algorithms={:#06x}, pub_type={}, \
                         static_type={}, output_action={:#06x}, output_size={}, \
                         input_action={:#06x}, input_size={}",
                        caps.num_ele,
                        caps.algorithms,
                        caps.pub_type,
                        caps.static_type,
                        caps.output_action,
                        caps.output_size,
                        caps.input_action,
                        caps.input_size,
                    );
                    p.conf_inputs.caps = caps;
                }
                None => {
                    error!("Failed to parse capabilities");
                    int_prov_close(prov, PROV_ERR_INVALID_FORMAT);
                    return;
                }
            }

            let p = prov.as_mut().unwrap();

            // Check algorithm support
            if (p.conf_inputs.caps.algorithms & ALG_FIPS_256_ECC) == 0 {
                error!("Device does not support FIPS P-256");
                int_prov_close(prov, PROV_ERR_INVALID_FORMAT);
                return;
            }

            let p = prov.as_mut().unwrap();

            // Negotiate authentication method
            int_prov_start_auth(p);

            // Build and send PROV_START
            let start_bytes = p.conf_inputs.start.to_bytes();
            let mut msg = [0u8; 6];
            msg[0] = PROV_START;
            msg[1..6].copy_from_slice(&start_bytes);

            p.expected = PROV_PUB_KEY;
            p.state = IntState::StartSent;

            if let Some(ref mut tx) = p.trans_tx {
                tx(&msg);
            }
        }

        PROV_PUB_KEY => {
            if data.len() < 65 {
                error!("PROV_PUB_KEY too short: {}", data.len());
                int_prov_close(prov, PROV_ERR_INVALID_FORMAT);
                return;
            }

            let p = prov.as_mut().unwrap();
            p.conf_inputs.dev_pub_key[..64].copy_from_slice(&data[1..65]);
            p.material |= MAT_REMOTE_PUBLIC;
            print_packet("RemotePublicKey", &p.conf_inputs.dev_pub_key);

            // If both keys available, compute credentials
            if p.material & MAT_SECRET == MAT_SECRET && !int_credentials(p) {
                int_prov_close(prov, PROV_ERR_UNEXPECTED_ERR);
                return;
            }

            let p = prov.as_mut().unwrap();

            // Begin OOB authentication
            int_prov_auth(p);

            // For input OOB, wait for INPUT COMPLETE from device
            if p.conf_inputs.start.auth_method == AUTH_METHOD_INPUT {
                p.expected = PROV_INP_CMPLT;
            } else {
                p.expected = PROV_NONE;
            }
        }

        PROV_INP_CMPLT => {
            debug!("Input complete received");
            let p = prov.as_mut().unwrap();
            p.expected = PROV_NONE;
            send_confirm(p);
        }

        PROV_CONFIRM => {
            if data.len() < 17 {
                error!("PROV_CONFIRM too short");
                int_prov_close(prov, PROV_ERR_INVALID_FORMAT);
                return;
            }

            let p = prov.as_mut().unwrap();

            // Echo check: remote confirm must differ from ours
            if p.confirm == data[1..17] {
                error!("Remote confirmation matches local — echo attack");
                int_prov_close(prov, PROV_ERR_CONFIRM_FAILED);
                return;
            }

            let p = prov.as_mut().unwrap();

            // Store remote confirmation
            p.confirm.copy_from_slice(&data[1..17]);
            print_packet("RemoteConfirm", &p.confirm);

            // Send our random
            send_random(p);
        }

        PROV_RANDOM => {
            if data.len() < 17 {
                error!("PROV_RANDOM too short");
                int_prov_close(prov, PROV_ERR_INVALID_FORMAT);
                return;
            }

            let p = prov.as_mut().unwrap();

            // Store remote random
            p.rand_auth_workspace[16..32].copy_from_slice(&data[1..17]);
            print_packet("RemoteRandom", &prov.as_ref().unwrap().rand_auth_workspace[16..32]);

            // Verify remote confirmation:
            // recomputed = AES-CMAC(conf_key, remote_random || auth_value)
            let p = prov.as_mut().unwrap();
            let mut check_input = [0u8; 32];
            check_input[0..16].copy_from_slice(&p.rand_auth_workspace[16..32]);
            check_input[16..32].copy_from_slice(&p.rand_auth_workspace[32..48]);

            let mut recomputed = [0u8; 16];
            if !crypto::mesh_crypto_aes_cmac(&p.calc_key, &check_input, &mut recomputed) {
                error!("Confirmation recomputation failed");
                int_prov_close(prov, PROV_ERR_UNEXPECTED_ERR);
                return;
            }

            let p = prov.as_mut().unwrap();

            if recomputed != p.confirm {
                error!("Confirmation verification failed");
                let mut fail_msg = [0u8; 2];
                fail_msg[0] = PROV_FAILED;
                fail_msg[1] = PROV_ERR_CONFIRM_FAILED;
                if let Some(ref mut tx) = p.trans_tx {
                    tx(&fail_msg);
                }
                int_prov_close(prov, PROV_ERR_CONFIRM_FAILED);
                return;
            }

            let p = prov.as_mut().unwrap();

            debug!("Confirmation verified successfully");

            // Calculate session material
            if !calc_local_material(p) {
                int_prov_close(prov, PROV_ERR_UNEXPECTED_ERR);
                return;
            }

            let p = prov.as_mut().unwrap();
            p.expected = PROV_COMPLETE;

            // For NPPI transports (PB_NPPI_00 or PB_NPPI_02), call
            // initiator_prov_data directly. Otherwise, request data
            // from the manager via the callback (C lines 809-819).
            if p.transport == PB_NPPI_00 || p.transport == PB_NPPI_02 {
                let svr_idx = p.svr_idx;
                let server = p.server;
                let caller_data = p.caller_data;
                debug!("NPPI transport: calling prov_data directly");
                tokio::spawn(async move {
                    initiator_prov_data(svr_idx, server, caller_data).await;
                });
            } else if let Some(cb) = prov.as_mut().and_then(|p| p.data_req_cb.take()) {
                let num_ele = prov.as_ref().map_or(0, |p| p.conf_inputs.caps.num_ele);
                cb(num_ele);
            } else {
                error!("No data request callback available");
                int_prov_close(prov, PROV_ERR_CANT_ASSIGN_ADDR);
                return;
            }
        }

        PROV_COMPLETE => {
            debug!("Provisioning complete");
            int_prov_close(prov, PROV_ERR_SUCCESS);
        }

        PROV_FAILED => {
            let reason = if data.len() > 1 { data[1] } else { PROV_ERR_UNEXPECTED_ERR };
            error!("Provisioning failed: reason={reason}");
            int_prov_close(prov, reason);
        }

        _ => {
            error!("Unhandled provisioning opcode: {opcode}");
            int_prov_close(prov, PROV_ERR_INVALID_FORMAT);
        }
    }

    // Update previous opcode tracking
    if let Some(p) = prov {
        p.previous = opcode as i8;
    }
}

// =========================================================================
// ACK Handler
// =========================================================================

/// ACK-driven state transitions.
///
/// Mirrors C `int_prov_ack()` (prov-initiator.c lines 926-970).
fn int_prov_ack(p: &mut MeshProvInitiator, _msg_num: u8) {
    match p.state {
        IntState::InviteSent => {
            p.state = IntState::InviteAcked;
        }
        IntState::StartSent => {
            p.state = IntState::StartAcked;
            // After START acked, send public key (unless OOB pub key)
            if p.conf_inputs.start.pub_key == 0 {
                send_pub_key(p);
            }
        }
        IntState::StartAcked => {
            // Public key send already triggered
        }
        IntState::KeySent => {
            p.state = IntState::KeyAcked;
            // If OOB pub key, start auth now
            if p.conf_inputs.start.pub_key != 0 {
                int_prov_auth(p);
            }
        }
        IntState::ConfSent => {
            p.state = IntState::ConfAcked;
        }
        IntState::RandSent => {
            p.state = IntState::RandAcked;
        }
        IntState::DataSent => {
            p.state = IntState::DataAcked;
        }
        _ => {
            debug!("ACK in unexpected state: {:?}", p.state);
        }
    }
}

// =========================================================================
// Initiator Open Callback (branching on local vs remote)
// =========================================================================

/// Called to initiate the provisioning session.
/// For local PB-ADV: registers with pb_adv transport.
/// For remote provisioning: sends OP_REM_PROV_LINK_OPEN.
///
/// Mirrors C `initiator_open_cb()` (prov-initiator.c lines 972-1010).
fn initiator_open_cb(p: &mut MeshProvInitiator) {
    if p.server != 0 {
        // Remote provisioning: send LINK_OPEN to remote server
        let mut msg = [0u8; 40];
        let n = mesh_model_opcode_set(OP_REM_PROV_LINK_OPEN, &mut msg);

        // For NPPI transport types (<= PB_NPPI_02), send transport byte;
        // otherwise send full UUID (C lines 905-910).
        let msg_len = if p.transport <= PB_NPPI_02 {
            msg[n] = p.transport;
            n + 1
        } else {
            msg[n..n + 16].copy_from_slice(&p.uuid);
            n + 16
        };

        if let Some(ref node) = p.node {
            mesh_model_send(
                node,
                0,
                p.server,
                mesh::APP_IDX_DEV_REMOTE,
                p.svr_idx,
                mesh::DEFAULT_TTL,
                true,
                &msg[..msg_len],
            );
        }

        p.rpr_state = PB_REMOTE_STATE_LINK_OPENING;
        debug!("RPR: Sent LINK_OPEN to server {}", p.server);
    } else {
        // Local PB-ADV provisioning
        let prov_handle = 1usize; // Singleton handle

        let open_cb: ProvOpenCb = Box::new(move |_user_data, trans_tx, trans_data, _transport| {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let mut guard = PROV.lock().await;
                    if let Some(ref mut p) = *guard {
                        p.trans_tx = Some(trans_tx);
                        p.trans_data = trans_data;
                        int_prov_open(p);
                    }
                });
            }
        });

        let close_cb: ProvCloseCb = Box::new(move |_user_data, reason| {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let mut guard = PROV.lock().await;
                    int_prov_close(&mut guard, reason);
                });
            }
        });

        let rx_cb: ProvRxCb = Box::new(move |_user_data, data| {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let data_owned = data.to_vec();
                handle.spawn(async move {
                    let mut guard = PROV.lock().await;
                    int_prov_rx(&mut guard, &data_owned);
                });
            }
        });

        let ack_cb: ProvAckCb = Box::new(move |_user_data, msg_num| {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let mut guard = PROV.lock().await;
                    if let Some(ref mut p) = *guard {
                        int_prov_ack(p, msg_num);
                    }
                });
            }
        });

        pb_adv_reg(true, open_cb, close_cb, rx_cb, ack_cb, &p.uuid, prov_handle);
    }
}

// =========================================================================
// Timeout Handler
// =========================================================================

/// Timeout handler — closes provisioning with PROV_ERR_TIMEOUT.
///
/// Mirrors C `initiate_to()` (prov-initiator.c lines 1012-1020).
async fn initiate_to() {
    info!("Provisioning timeout");
    let mut guard = PROV.lock().await;
    int_prov_close(&mut guard, PROV_ERR_TIMEOUT);
}

// =========================================================================
// PUBLIC API: initiator_start
// =========================================================================

/// Start a provisioning session as initiator (provisioner).
///
/// Returns `true` if the session was successfully started.
///
/// Mirrors C `initiator_start()` (prov-initiator.c lines 1022-1070).
pub async fn initiator_start(
    transport: u8,
    server: u16,
    svr_idx: u16,
    uuid: [u8; 16],
    _max_ele: u16,
    timeout: u32,
    agent: Arc<MeshAgent>,
    start_cb: Box<dyn FnOnce(i32) + Send>,
    data_req_cb: Box<dyn FnOnce(u8) -> bool + Send>,
    complete_cb: Box<dyn FnOnce(u8, Option<MeshProvNodeInfo>) -> bool + Send>,
    node: Arc<MeshNode>,
    caller_data: usize,
) -> bool {
    let mut guard = PROV.lock().await;

    // Only one provisioning session at a time
    if guard.is_some() {
        error!("Provisioning session already active");
        return false;
    }

    let to_secs = if timeout > 0 { timeout } else { 60 };

    let mut prov = MeshProvInitiator {
        start_cb: Some(start_cb),
        complete_cb: Some(complete_cb),
        data_req_cb: Some(data_req_cb),
        trans_tx: None,
        agent: Some(agent),
        caller_data,
        trans_data: 0,
        node: Some(node),
        timeout: None,
        to_secs,
        state: IntState::Idle,
        net_idx: svr_idx,
        svr_idx,
        unicast: 0,
        server,
        transport,
        material: 0,
        expected: PROV_NONE,
        previous: -1,
        out_num: 0,
        rpr_state: PB_REMOTE_STATE_IDLE,
        conf_inputs: ConfInput::default(),
        calc_key: [0u8; 16],
        salt: [0u8; 16],
        confirm: [0u8; 16],
        s_key: [0u8; 16],
        s_nonce: [0u8; 13],
        private_key: [0u8; 32],
        secret: [0u8; 32],
        rand_auth_workspace: [0u8; 48],
        uuid,
    };

    // Create timeout task using the stored to_secs value from prov struct
    let prov_to_secs = prov.to_secs;
    let timeout_handle = tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(u64::from(prov_to_secs))).await;
        initiate_to().await;
    });
    prov.timeout = Some(timeout_handle);

    // Initiate the provisioning session
    initiator_open_cb(&mut prov);

    *guard = Some(prov);
    true
}

// =========================================================================
// PUBLIC API: initiator_cancel
// =========================================================================

/// Cancel an active provisioning session.
///
/// Mirrors C `initiator_cancel()` (prov-initiator.c lines 1072-1085).
pub async fn initiator_cancel(caller_data: usize) {
    let mut guard = PROV.lock().await;

    let should_free = match guard.as_ref() {
        Some(p) => p.caller_data == caller_data,
        None => false,
    };

    if should_free {
        int_prov_close(&mut guard, PROV_ERR_UNEXPECTED_ERR);
    }
}

// =========================================================================
// PUBLIC API: initiator_prov_data
// =========================================================================

/// Encrypt and send provisioning data to the device.
///
/// Called by the provisioning manager after the data request callback
/// has provided the unicast address. Fetches the net key from keyring,
/// constructs the ProvData PDU, encrypts with AES-CCM, and derives device key.
///
/// Mirrors C `initiator_prov_data()` (prov-initiator.c lines 462-530).
pub async fn initiator_prov_data(net_idx: u16, primary: u16, _caller_data: usize) {
    let mut guard = PROV.lock().await;

    let p = match guard.as_mut() {
        Some(p) => p,
        None => {
            error!("No active provisioning session for prov_data");
            return;
        }
    };

    let node = match p.node.as_ref() {
        Some(n) => n.clone(),
        None => {
            error!("No node reference in provisioning session");
            return;
        }
    };

    // Fetch network key from keyring
    let storage_dir = node.get_storage_dir();
    let net_key_data = match keyring::keyring_get_net_key(&storage_dir, net_idx) {
        Some(k) => k,
        None => {
            error!("Failed to get net key for index {net_idx}");
            int_prov_close(&mut guard, PROV_ERR_CANT_ASSIGN_ADDR);
            return;
        }
    };

    let p = match guard.as_mut() {
        Some(p) => p,
        None => return,
    };

    // Determine which key to use based on Key Refresh phase
    let net = node.get_net();
    let kr_phase = net.key_refresh_phase_get(net_idx);
    let net_key =
        if kr_phase == KEY_REFRESH_PHASE_TWO { net_key_data.new_key } else { net_key_data.old_key };

    // Get IV index and flags
    let (iv_index, iv_update) = net.get_iv_index();
    let mut flags: u8 = 0;
    if kr_phase == KEY_REFRESH_PHASE_TWO {
        flags |= PROV_FLAG_KR;
    }
    if iv_update {
        flags |= PROV_FLAG_IVU;
    }

    // Build ProvData struct
    let prov_data = ProvData { net_key, net_idx, flags, iv_index, primary };

    let prov_data_bytes = prov_data.to_bytes();
    print_packet("ProvData", &prov_data_bytes);

    // Calculate session material
    if !calc_local_material(p) {
        error!("Failed to calculate session material");
        int_prov_close(&mut guard, PROV_ERR_UNEXPECTED_ERR);
        return;
    }

    let p = match guard.as_mut() {
        Some(p) => p,
        None => return,
    };

    // Encrypt: 25 bytes data + 8 byte MIC = 33 bytes
    let mut encrypted = [0u8; 33];
    if !crypto::mesh_crypto_aes_ccm_encrypt(
        &p.s_nonce,
        &p.s_key,
        None,
        &prov_data_bytes,
        &mut encrypted,
        8,
    ) {
        error!("AES-CCM encryption of provisioning data failed");
        int_prov_close(&mut guard, PROV_ERR_UNEXPECTED_ERR);
        return;
    }

    let p = match guard.as_mut() {
        Some(p) => p,
        None => return,
    };

    print_packet("EncryptedProvData", &encrypted);

    // Build PROV_DATA message: [opcode, encrypted(33)]
    let mut msg = [0u8; 34];
    msg[0] = PROV_DATA;
    msg[1..34].copy_from_slice(&encrypted);

    p.expected = PROV_COMPLETE;
    p.state = IntState::DataSent;
    p.unicast = primary;
    p.net_idx = net_idx;

    if let Some(ref mut tx) = p.trans_tx {
        tx(&msg);
    }

    // Derive device key
    let device_key = match crypto::mesh_crypto_device_key(&p.secret, &p.salt) {
        Some(k) => k,
        None => {
            error!("Device key derivation failed");
            int_prov_close(&mut guard, PROV_ERR_UNEXPECTED_ERR);
            return;
        }
    };

    if let Some(ref mut p) = *guard {
        p.calc_key = device_key;
        print_packet("DeviceKey", &p.calc_key);
    }
}

// =========================================================================
// Remote Provisioning Client
// =========================================================================

/// Stateless RPR PDU send used as `ProvTransTx` closure target.
///
/// Called from closures created in `remprv_cli_pkt` when the RPR link
/// becomes active. Takes pre-extracted node/server/index info.
fn rpr_tx_send(
    node: &Option<Arc<MeshNode>>,
    server: u16,
    _net_idx: u16,
    svr_idx: u16,
    data: &[u8],
) -> bool {
    let mut msg = [0u8; 80];
    let n = mesh_model_opcode_set(OP_REM_PROV_PDU_SEND, &mut msg);

    if n + 1 + data.len() > msg.len() {
        error!("RPR PDU too large for rpr_tx_send");
        return false;
    }

    msg[n] = 0; // outbound PDU number
    msg[n + 1..n + 1 + data.len()].copy_from_slice(data);

    if let Some(node) = node {
        mesh_model_send(
            node,
            0,
            server,
            mesh::APP_IDX_DEV_REMOTE,
            svr_idx,
            mesh::DEFAULT_TTL,
            true,
            &msg[..n + 1 + data.len()],
        )
    } else {
        false
    }
}

/// Handle incoming Remote Provisioning client model messages.
///
/// Dispatches on RPR opcode: LINK_STATUS, LINK_REPORT, PDU_REPORT,
/// PDU_OB_REPORT, SCAN_CAP_STATUS, SCAN_STATUS, SCAN_REPORT.
///
/// Mirrors C `remprv_cli_pkt()` (prov-initiator.c lines 1102-1140).
fn remprv_cli_pkt(prov: &mut Option<MeshProvInitiator>, _src: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let (opcode, consumed) = match mesh_model_opcode_get(data) {
        Some(v) => v,
        None => {
            error!("Failed to decode RPR opcode");
            return;
        }
    };

    let payload = &data[consumed..];

    if opcode == OP_REM_PROV_LINK_STATUS {
        if payload.len() < 2 {
            return;
        }
        let status = payload[0];
        let state = payload[1];
        debug!("RPR LINK_STATUS: status={status}, state={state}");

        if status != PB_REM_ERR_SUCCESS {
            error!("RPR link open failed: status={status}");
            int_prov_close(prov, PROV_ERR_UNEXPECTED_ERR);
            return;
        }

        if let Some(p) = prov {
            p.rpr_state = state;
        }

        if state == PB_REMOTE_STATE_LINK_ACTIVE {
            // Set trans_tx to rpr_tx closure for remote provisioning PDU send
            if let Some(p) = prov {
                let node_clone = p.node.clone();
                let server = p.server;
                let net_idx = p.net_idx;
                let svr_idx = p.svr_idx;
                p.trans_tx = Some(Box::new(move |data: &[u8]| -> bool {
                    rpr_tx_send(&node_clone, server, net_idx, svr_idx, data)
                }));
                int_prov_open(p);
            }
        }
    } else if opcode == OP_REM_PROV_LINK_REPORT {
        if payload.len() < 2 {
            return;
        }
        let status = payload[0];
        let state = payload[1];
        debug!("RPR LINK_REPORT: status={status}, state={state}");

        if let Some(p) = prov {
            p.rpr_state = state;
        }

        if state == PB_REMOTE_STATE_IDLE {
            let reason = if status == PB_REM_ERR_SUCCESS {
                PROV_ERR_SUCCESS
            } else {
                PROV_ERR_UNEXPECTED_ERR
            };
            int_prov_close(prov, reason);
        } else if state == PB_REMOTE_STATE_LINK_ACTIVE {
            if let Some(p) = prov {
                let node_clone = p.node.clone();
                let server = p.server;
                let net_idx = p.net_idx;
                let svr_idx = p.svr_idx;
                p.trans_tx = Some(Box::new(move |data: &[u8]| -> bool {
                    rpr_tx_send(&node_clone, server, net_idx, svr_idx, data)
                }));
                int_prov_open(p);
            }
        }
    } else if opcode == OP_REM_PROV_PDU_REPORT {
        if payload.len() < 2 {
            return;
        }
        let _pdu_num = payload[0];
        let pdu_data = &payload[1..];
        debug!("RPR PDU_REPORT: len={}", pdu_data.len());
        int_prov_rx(prov, pdu_data);
    } else if opcode == OP_REM_PROV_PDU_OB_REPORT {
        if payload.is_empty() {
            return;
        }
        let ob_num = payload[0];
        debug!("RPR PDU_OB_REPORT: ob_num={ob_num}");
        if let Some(p) = prov {
            int_prov_ack(p, ob_num);
        }
    } else if opcode == OP_REM_PROV_SCAN_CAP_STATUS {
        debug!("RPR SCAN_CAP_STATUS received");
    } else if opcode == OP_REM_PROV_SCAN_STATUS {
        debug!("RPR SCAN_STATUS received");
    } else if opcode == OP_REM_PROV_SCAN_REPORT {
        debug!("RPR SCAN_REPORT: len={}", payload.len());
        // Forward scan report to registered scan callbacks
        let report_data = payload.to_vec();
        tokio::spawn(async move {
            let scans = SCANS.lock().await;
            for scan in scans.iter() {
                (scan.scan_result)(0, &report_data);
            }
        });
    } else if opcode == OP_REM_PROV_EXT_SCAN_REPORT {
        debug!("RPR EXT_SCAN_REPORT: len={}", payload.len());
    } else {
        debug!("RPR unhandled opcode: {opcode:#06x}");
    }
}

// =========================================================================
// PUBLIC API: initiator_scan_reg / initiator_scan_unreg
// =========================================================================

/// Register a scan callback for unprovisioned device beacons.
///
/// Mirrors C `initiator_scan_reg()` (prov-initiator.c lines 1142-1155).
pub async fn initiator_scan_reg(scan_result: Box<dyn Fn(i32, &[u8]) + Send>, node: Arc<MeshNode>) {
    let mut scans = SCANS.lock().await;
    scans.push(ScanReq { scan_result, node });
    debug!("Scan registration added, total: {}", scans.len());
}

/// Unregister a scan callback by removing entries matching the given node.
///
/// Mirrors C `initiator_scan_unreg()` (prov-initiator.c lines 1157-1168).
pub async fn initiator_scan_unreg(node: &Arc<MeshNode>) {
    let mut scans = SCANS.lock().await;
    let before = scans.len();
    scans.retain(|s| !Arc::ptr_eq(&s.node, node));
    if scans.len() < before {
        debug!("Scan registration(s) removed");
    }
}

// =========================================================================
// Remote Provisioning Client Model Ops
// =========================================================================

/// Remote Provisioning Client model operations implementation.
struct RemProvCliOps;

impl MeshModelOps for RemProvCliOps {
    fn unregister(&self) {
        debug!("RemProvCli model unregistered");
    }

    fn recv(&self, src: u16, _unicast: u16, _app_idx: u16, _net_idx: u16, data: &[u8]) -> bool {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let data_owned = data.to_vec();
            handle.spawn(async move {
                let mut guard = PROV.lock().await;
                remprv_cli_pkt(&mut guard, src, &data_owned);
            });
        }
        true
    }

    fn bind(&self, _app_idx: u16, _action: u8) -> i32 {
        0
    }

    fn publish(&self, _pub_state: &MeshModelPub) -> i32 {
        0
    }

    fn subscribe(&self, _sub_addr: u16, _action: u8) -> i32 {
        0
    }
}

// =========================================================================
// PUBLIC API: remote_prov_client_init
// =========================================================================

/// Register the Remote Provisioning Client model.
///
/// Mirrors C `remote_prov_client_init()` (prov-initiator.c lines 1170-1180).
pub fn remote_prov_client_init(node: &MeshNode) -> bool {
    let ops = Box::new(RemProvCliOps);
    mesh_model_register(node, 0, REM_PROV_CLI_MODEL, ops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provisioning::{digit_mod, swap_u256_bytes};

    #[test]
    fn test_int_state_values() {
        assert_eq!(IntState::Idle as u8, 0);
        assert_eq!(IntState::InviteSent as u8, 1);
        assert_eq!(IntState::InviteAcked as u8, 2);
        assert_eq!(IntState::StartSent as u8, 3);
        assert_eq!(IntState::StartAcked as u8, 4);
        assert_eq!(IntState::KeySent as u8, 5);
        assert_eq!(IntState::KeyAcked as u8, 6);
        assert_eq!(IntState::ConfSent as u8, 7);
        assert_eq!(IntState::ConfAcked as u8, 8);
        assert_eq!(IntState::RandSent as u8, 9);
        assert_eq!(IntState::RandAcked as u8, 10);
        assert_eq!(IntState::DataSent as u8, 11);
        assert_eq!(IntState::DataAcked as u8, 12);
    }

    #[test]
    fn test_int_state_count() {
        let states = [
            IntState::Idle,
            IntState::InviteSent,
            IntState::InviteAcked,
            IntState::StartSent,
            IntState::StartAcked,
            IntState::KeySent,
            IntState::KeyAcked,
            IntState::ConfSent,
            IntState::ConfAcked,
            IntState::RandSent,
            IntState::RandAcked,
            IntState::DataSent,
            IntState::DataAcked,
        ];
        assert_eq!(states.len(), 13);
    }

    #[test]
    fn test_material_constants() {
        assert_eq!(MAT_REMOTE_PUBLIC, 0x01);
        assert_eq!(MAT_LOCAL_PRIVATE, 0x02);
        assert_eq!(MAT_RAND_AUTH, 0x04);
        assert_eq!(MAT_SECRET, MAT_REMOTE_PUBLIC | MAT_LOCAL_PRIVATE);
        assert_eq!(MAT_SECRET, 0x03);
    }

    #[test]
    fn test_nppi_constants() {
        assert_eq!(PB_NPPI_00, 0x00);
        assert_eq!(PB_NPPI_02, 0x02);
    }

    #[test]
    fn test_action_constants() {
        assert_eq!(PROV_ACTION_OUT_ALPHA, 4);
        assert_eq!(PROV_ACTION_IN_ALPHA, 3);
    }

    #[test]
    fn test_swap_u256_bytes() {
        let mut buf = [0u8; 32];
        for i in 0..32u8 {
            buf[i as usize] = i;
        }
        swap_u256_bytes(&mut buf);
        for i in 0..32u8 {
            assert_eq!(buf[i as usize], 31 - i);
        }
        swap_u256_bytes(&mut buf);
        for i in 0..32u8 {
            assert_eq!(buf[i as usize], i);
        }
    }

    #[test]
    fn test_digit_mod() {
        // digit_mod(power) returns 10^power
        assert_eq!(digit_mod(1), 10);
        assert_eq!(digit_mod(2), 100);
        assert_eq!(digit_mod(3), 1000);
        assert_eq!(digit_mod(8), 100_000_000);
    }

    #[test]
    fn test_u16_high_bit() {
        assert_eq!(u16_high_bit(0), -1);
        assert_eq!(u16_high_bit(1), 0);
        assert_eq!(u16_high_bit(2), 1);
        assert_eq!(u16_high_bit(3), 1);
        assert_eq!(u16_high_bit(0x8000), 15);
        assert_eq!(u16_high_bit(0x0010), 4);
    }

    #[test]
    fn test_prov_calc_secret_with_zeros() {
        let priv_key = [0u8; 32];
        let pub_key = [0u8; 64];
        let _result = prov_calc_secret(&priv_key, &pub_key);
    }

    #[tokio::test]
    async fn test_initiator_cancel_no_session() {
        initiator_cancel(42).await;
    }

    #[tokio::test]
    async fn test_initiator_scan_unreg_no_scans() {
        let node = Arc::new(MeshNode::default());
        initiator_scan_unreg(&node).await;
    }
}
