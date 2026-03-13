// SPDX-License-Identifier: LGPL-2.1-or-later
//
// crates/bluetooth-meshd/src/net_keys.rs
//
// Bluetooth Mesh network key management: derives and stores NetKey material
// (K2/K3, beacon/private keys), performs network PDU encode/decode,
// authenticates SNB/MPB (Secure Network Beacon / Mesh Private Beacon),
// and schedules beacon transmission through mesh I/O.
//
// Complete Rust rewrite of mesh/net-keys.c (~800 lines) and mesh/net-keys.h
// from BlueZ v5.86.

use std::sync::Mutex;

use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error};

use crate::crypto::{
    mesh_crypto_aes_ccm_decrypt, mesh_crypto_aes_ccm_encrypt, mesh_crypto_beacon_cmac,
    mesh_crypto_k2, mesh_crypto_k3, mesh_crypto_nkbk, mesh_crypto_nkpk, mesh_crypto_packet_decode,
    mesh_crypto_packet_encode, mesh_crypto_packet_label,
};
use crate::io::{BT_AD_MESH_BEACON, MeshIoSendInfo, mesh_io_send};
use crate::mesh::MESH_NET_MAX_PDU_LEN;
use crate::util::{get_timestamp_secs, print_packet};
use bluez_shared::crypto::aes_cmac::random_bytes;

// ===========================================================================
// Public Constants (from net-keys.h lines 11-18)
// ===========================================================================

/// Secure Network Beacon type identifier.
pub const BEACON_TYPE_SNB: u8 = 0x01;

/// Mesh Private Beacon type identifier.
pub const BEACON_TYPE_MPB: u8 = 0x02;

/// Length of a Secure Network Beacon in bytes (AD type + data).
pub const BEACON_LEN_SNB: usize = 23;

/// Length of a Mesh Private Beacon in bytes (AD type + data).
pub const BEACON_LEN_MPB: usize = 28;

/// Maximum beacon length (equals `BEACON_LEN_MPB`).
pub const BEACON_LEN_MAX: usize = BEACON_LEN_MPB;

/// Key Refresh flag bit in beacon flags byte.
pub const KEY_REFRESH: u8 = 0x01;

/// IV Index Update flag bit in beacon flags byte.
pub const IV_INDEX_UPDATE: u8 = 0x02;

/// Default MPB refresh interval in 10-second steps (60 → 600 seconds).
pub const NET_MPB_REFRESH_DEFAULT: u32 = 60;

// ===========================================================================
// Internal Constants (from net-keys.c lines 28-32)
// ===========================================================================

/// Minimum beaconing interval in seconds (per mesh spec).
const BEACON_INTERVAL_MIN: u32 = 10;

/// Maximum beaconing interval in seconds (per mesh spec).
const BEACON_INTERVAL_MAX: u32 = 600;

/// Maximum number of recently-seen beacons to cache, allowing the daemon
/// to skip re-decrypting identical beacons.
const BEACON_CACHE_MAX: usize = 10;

/// Default minimum advertising delay (milliseconds).
const DEFAULT_MIN_DELAY: u8 = 0;

/// Default maximum advertising delay (milliseconds).
const DEFAULT_MAX_DELAY: u8 = 25;

// ===========================================================================
// Internal Structures
// ===========================================================================

/// Cached received beacon for deduplication.
struct BeaconRx {
    /// Beacon data (excluding the leading AD type byte).
    data: [u8; BEACON_LEN_MAX],
    /// Internal key ID that authenticated this beacon.
    id: u32,
    /// IV Index extracted from the beacon.
    ivi: u32,
    /// Key Refresh flag.
    kr: bool,
    /// IV Update flag.
    ivu: bool,
}

/// Beacon observation tracking for adaptive beaconing interval.
#[derive(Default)]
struct BeaconObserve {
    /// Handle to the periodic beacon timeout task.
    timeout: Option<JoinHandle<()>>,
    /// Timestamp of last beacon observation.
    ts: u32,
    /// Current observation period in seconds.
    period: u16,
    /// Number of beacons seen in current period.
    seen: u16,
    /// Expected number of beacons in current period.
    expected: u16,
    /// Whether we are in the first or second half of the observation period.
    half_period: bool,
}

/// Internal network key material with all derived cryptographic keys.
struct NetKey {
    /// Internal key identifier (monotonically increasing).
    id: u32,
    /// Handle to the MPB refresh periodic timeout task.
    mpb_to: Option<JoinHandle<()>>,
    /// Composed MPB beacon data (allocated when MPB is enabled).
    mpb: Option<Vec<u8>>,
    /// Composed SNB beacon data (allocated when SNB is enabled).
    snb: Option<Vec<u8>>,
    /// Beacon observation tracking state.
    observe: BeaconObserve,
    /// Current IV Index cached for beacon refresh.
    ivi: u32,
    /// Reference count for this key.
    ref_cnt: u16,
    /// Number of nodes that have enabled MPB for this key.
    mpb_enables: u16,
    /// Number of nodes that have enabled SNB for this key.
    snb_enables: u16,
    /// MPB refresh interval in 10-second steps.
    mpb_refresh: u8,
    /// Whether this is a friendship-derived key.
    friend_key: bool,
    /// Network ID derived via K2 (7-bit, stored in low 7 bits).
    nid: u8,
    /// The flooding (network) key value.
    flooding: [u8; 16],
    /// Encryption key derived via K2.
    enc_key: [u8; 16],
    /// Privacy key derived via K2.
    prv_key: [u8; 16],
    /// Secure Network Beacon key derived via nkbk.
    snb_key: [u8; 16],
    /// Private Beacon key derived via nkpk.
    pvt_key: [u8; 16],
    /// 8-byte Network ID derived via K3.
    net_id: [u8; 8],
    /// Key Refresh state.
    kr: bool,
    /// IV Update state.
    ivu: bool,
}

/// Global state for the net_keys module, protected by a mutex.
struct NetKeyState {
    /// List of recently received beacons for deduplication.
    beacons: Vec<BeaconRx>,
    /// List of all known network keys.
    keys: Vec<NetKey>,
    /// Monotonically increasing ID counter for new keys.
    last_flooding_id: u32,
    /// Cached encrypted packet for avoiding redundant decryption.
    cache_pkt: [u8; MESH_NET_MAX_PDU_LEN],
    /// Cached decrypted (plain) packet.
    cache_plain: [u8; MESH_NET_MAX_PDU_LEN],
    /// Length of the cached encrypted packet.
    cache_len: usize,
    /// Length of the cached plain packet.
    cache_plainlen: usize,
    /// Key ID that successfully decrypted the cached packet.
    cache_id: u32,
    /// IV Index used when decrypting the cached packet.
    cache_iv_index: u32,
}

impl Default for NetKeyState {
    fn default() -> Self {
        Self {
            beacons: Vec::new(),
            keys: Vec::new(),
            last_flooding_id: 0,
            cache_pkt: [0u8; MESH_NET_MAX_PDU_LEN],
            cache_plain: [0u8; MESH_NET_MAX_PDU_LEN],
            cache_len: 0,
            cache_plainlen: 0,
            cache_id: 0,
            cache_iv_index: 0,
        }
    }
}

/// Global singleton state for the net_keys module.
///
/// Uses `std::sync::Mutex` because `bluetooth-meshd` runs on a
/// single-threaded tokio runtime (`new_current_thread`), so lock
/// contention is minimal.
static STATE: Mutex<Option<NetKeyState>> = Mutex::new(None);

/// Access the global state, lazily initializing if needed.
fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut NetKeyState) -> R,
{
    let mut guard = STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = guard.get_or_insert_with(NetKeyState::default);
    f(state)
}

// ===========================================================================
// Key Add / Remove
// ===========================================================================

/// Add a new network key or increment the reference count of an existing one.
///
/// Derives all cryptographic material (K2 → nid/enc_key/prv_key, K3 → net_id,
/// nkbk → snb_key, nkpk → pvt_key). Returns the internal key ID on success,
/// or 0 on failure.
pub fn net_key_add(flooding: &[u8; 16]) -> u32 {
    with_state(|state| {
        // Check if key already exists
        if let Some(existing) = state.keys.iter_mut().find(|k| k.flooding == *flooding) {
            existing.ref_cnt += 1;
            return existing.id;
        }

        // Derive all key material
        let p: [u8; 1] = [0x00];
        let Some((nid, enc_key, prv_key)) = mesh_crypto_k2(flooding, &p) else {
            return 0;
        };

        let Some(net_id) = mesh_crypto_k3(flooding) else {
            return 0;
        };

        let Some(snb_key) = mesh_crypto_nkbk(flooding) else {
            return 0;
        };

        let Some(pvt_key) = mesh_crypto_nkpk(flooding) else {
            return 0;
        };

        state.last_flooding_id += 1;
        let id = state.last_flooding_id;

        let key = NetKey {
            id,
            mpb_to: None,
            mpb: None,
            snb: None,
            observe: BeaconObserve::default(),
            ivi: 0,
            ref_cnt: 1,
            mpb_enables: 0,
            snb_enables: 0,
            mpb_refresh: NET_MPB_REFRESH_DEFAULT as u8,
            friend_key: false,
            nid,
            flooding: *flooding,
            enc_key,
            prv_key,
            snb_key,
            pvt_key,
            net_id,
            kr: false,
            ivu: false,
        };

        state.keys.push(key);
        id
    })
}

/// Add a friendship-derived network key.
///
/// Derives a new key using the K2 function with friendship parameters
/// (LPN address, Friend address, LPN counter, Friend counter) prepended
/// with 0x01 as the `p` parameter. Returns the internal key ID on success,
/// or 0 on failure.
pub fn net_key_frnd_add(flooding_id: u32, lpn: u16, frnd: u16, lp_cnt: u16, fn_cnt: u16) -> u32 {
    with_state(|state| {
        // Find the parent key
        let parent_idx = match state.keys.iter().position(|k| k.id == flooding_id) {
            Some(idx) => idx,
            None => return 0,
        };

        // Parent must not be a friendship key itself
        if state.keys[parent_idx].friend_key {
            return 0;
        }

        // Build the P parameter: 0x01 || LPN || Frnd || LPNCounter || FrndCounter
        let mut p = [0u8; 9];
        p[0] = 0x01;
        p[1..3].copy_from_slice(&lpn.to_be_bytes());
        p[3..5].copy_from_slice(&frnd.to_be_bytes());
        p[5..7].copy_from_slice(&lp_cnt.to_be_bytes());
        p[7..9].copy_from_slice(&fn_cnt.to_be_bytes());

        let parent_flooding = state.keys[parent_idx].flooding;

        let Some((nid, enc_key, prv_key)) = mesh_crypto_k2(&parent_flooding, &p) else {
            return 0;
        };

        state.last_flooding_id += 1;
        let id = state.last_flooding_id;

        let frnd_key = NetKey {
            id,
            mpb_to: None,
            mpb: None,
            snb: None,
            observe: BeaconObserve::default(),
            ivi: 0,
            ref_cnt: 1,
            mpb_enables: 0,
            snb_enables: 0,
            mpb_refresh: NET_MPB_REFRESH_DEFAULT as u8,
            friend_key: true,
            nid,
            flooding: [0u8; 16], // Friendship keys don't carry flooding key
            enc_key,
            prv_key,
            snb_key: [0u8; 16],
            pvt_key: [0u8; 16],
            net_id: [0u8; 8],
            kr: false,
            ivu: false,
        };

        // Push to front (head) like the C version
        state.keys.insert(0, frnd_key);
        id
    })
}

/// Decrease the reference count of a key and remove it when the count
/// reaches zero.
pub fn net_key_unref(id: u32) {
    with_state(|state| {
        let Some(idx) = state.keys.iter().position(|k| k.id == id) else {
            return;
        };

        if state.keys[idx].ref_cnt == 0 {
            return;
        }

        state.keys[idx].ref_cnt -= 1;

        if state.keys[idx].ref_cnt == 0 {
            // Cancel the observe timeout
            if let Some(handle) = state.keys[idx].observe.timeout.take() {
                handle.abort();
            }
            // Cancel the MPB timeout
            if let Some(handle) = state.keys[idx].mpb_to.take() {
                handle.abort();
            }
            state.keys.remove(idx);
        }
    });
}

/// Remove all keys and beacons, resetting the module to its initial state.
pub fn net_key_cleanup() {
    let mut guard = STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(state) = guard.as_mut() {
        // Abort all running timers
        for key in &mut state.keys {
            if let Some(handle) = key.mpb_to.take() {
                handle.abort();
            }
            if let Some(handle) = key.observe.timeout.take() {
                handle.abort();
            }
        }
        state.keys.clear();
        state.beacons.clear();
    }
    *guard = None;
}

// ===========================================================================
// Key Retrieval
// ===========================================================================

/// Verify that the key identified by `id` matches the given flooding key.
pub fn net_key_confirm(id: u32, flooding: &[u8; 16]) -> bool {
    with_state(|state| {
        state.keys.iter().find(|k| k.id == id).is_some_and(|k| k.flooding == *flooding)
    })
}

/// Retrieve the flooding key for the given internal key ID.
///
/// Returns `Some(flooding_key)` on success, `None` if not found.
pub fn net_key_retrieve(id: u32) -> Option<[u8; 16]> {
    with_state(|state| state.keys.iter().find(|k| k.id == id).map(|k| k.flooding))
}

// ===========================================================================
// Network PDU Encrypt / Decrypt
// ===========================================================================

/// Encrypt a network PDU using the key material identified by `id`.
///
/// Applies encryption and privacy obfuscation, then sets the IVI/NID
/// header byte. The packet is modified in place. Returns `true` on success.
pub fn net_key_encrypt(id: u32, iv_index: u32, pkt: &mut [u8]) -> bool {
    with_state(|state| {
        let Some(key) = state.keys.iter().find(|k| k.id == id) else {
            return false;
        };

        let enc_key = key.enc_key;
        let prv_key = key.prv_key;
        let nid = key.nid;

        if !mesh_crypto_packet_encode(pkt, iv_index, &enc_key, &prv_key) {
            return false;
        }

        // The iv_index is cast to u16 for the label function (only IVI bit used)
        mesh_crypto_packet_label(pkt, iv_index as u16, nid)
    })
}

/// Attempt to decrypt a network PDU using all known keys.
///
/// Uses a single-packet cache to avoid redundant decryption when multiple
/// nodes process the same incoming packet. Tries each key whose NID matches
/// the packet's NID field. Returns `Some((key_id, plaintext))` on success.
pub fn net_key_decrypt(iv_index: u32, pkt: &[u8]) -> Option<(u32, Vec<u8>)> {
    with_state(|state| {
        let len = pkt.len();
        if len == 0 || len > MESH_NET_MAX_PDU_LEN {
            return None;
        }

        // Check cache: if we already decrypted this exact packet, reuse result
        if state.cache_id != 0 && state.cache_len == len && state.cache_pkt[..len] == *pkt {
            // IV Index must match what was used to decrypt
            if state.cache_iv_index != iv_index {
                return None;
            }
            let plain = state.cache_plain[..state.cache_plainlen].to_vec();
            return Some((state.cache_id, plain));
        }

        // Populate cache with new packet
        state.cache_id = 0;
        state.cache_pkt[..len].copy_from_slice(pkt);
        state.cache_len = len;
        state.cache_iv_index = iv_index;

        // Try all network keys
        let pkt_nid = pkt[0] & 0x7f;

        for key in &state.keys {
            if state.cache_id != 0 {
                break;
            }
            if key.ref_cnt == 0 || pkt_nid != key.nid {
                continue;
            }

            let mut plain = [0u8; MESH_NET_MAX_PDU_LEN];
            let result = mesh_crypto_packet_decode(
                &state.cache_pkt[..len],
                false,
                &mut plain,
                iv_index,
                &key.enc_key,
                &key.prv_key,
            );

            if result {
                state.cache_id = key.id;
                state.cache_plainlen = len;
                state.cache_plain[..len].copy_from_slice(&plain[..len]);
            }
        }

        if state.cache_id != 0 {
            let plain = state.cache_plain[..state.cache_plainlen].to_vec();
            Some((state.cache_id, plain))
        } else {
            None
        }
    })
}

// ===========================================================================
// Beacon Authentication
// ===========================================================================

/// Authenticate an incoming beacon, trying all known keys.
///
/// For SNB beacons: looks up key by network ID, verifies CMAC.
/// For MPB beacons: tries AES-CCM decryption with each key's private beacon key.
///
/// Returns `Some((key_id, iv_index, ivu, kr))` on success.
pub fn net_key_beacon(data: &[u8]) -> Option<(u32, u32, bool, bool)> {
    if data.len() < 2 {
        return None;
    }

    let beacon_type = data[1];

    // Validate length
    if beacon_type == BEACON_TYPE_SNB && data.len() != BEACON_LEN_SNB {
        return None;
    }
    if beacon_type == BEACON_TYPE_MPB && data.len() != BEACON_LEN_MPB {
        return None;
    }

    with_state(|state| {
        let beacon_data = &data[1..]; // Skip the AD type byte

        // Check if we've already seen this beacon
        let cached_idx = state.beacons.iter().position(|b| {
            if beacon_data[0] == BEACON_TYPE_MPB {
                b.data[..BEACON_LEN_MPB - 1] == beacon_data[..BEACON_LEN_MPB - 1]
            } else if beacon_data[0] == BEACON_TYPE_SNB {
                b.data[..BEACON_LEN_SNB - 1] == beacon_data[..BEACON_LEN_SNB - 1]
            } else {
                false
            }
        });

        if let Some(idx) = cached_idx {
            let beacon = state.beacons.remove(idx);
            let result = (beacon.id, beacon.ivi, beacon.ivu, beacon.kr);
            // Re-insert at front
            state.beacons.insert(
                0,
                BeaconRx {
                    data: beacon.data,
                    id: beacon.id,
                    ivi: beacon.ivi,
                    kr: beacon.kr,
                    ivu: beacon.ivu,
                },
            );
            return Some(result);
        }

        // Validate beacon data
        let (b_id, b_ivi, b_ivu, b_kr) = if beacon_type == BEACON_TYPE_SNB {
            // Find key by network ID (data bytes 3..11 relative to original,
            // which is beacon_data[1..9] after removing the AD type byte but
            // keeping the beacon type byte).
            // In the C code: data[3] is network ID start (data includes AD type).
            // So beacon_data[2..10] is the network ID (beacon_data starts after AD type).
            let net_id_start = 2; // beacon_type(1) + flags(1) = offset 2
            let net_id_end = net_id_start + 8;
            if beacon_data.len() < net_id_end + 4 + 8 {
                return None;
            }

            let mut net_id = [0u8; 8];
            net_id.copy_from_slice(&beacon_data[net_id_start..net_id_end]);

            let key_id = state.keys.iter().find(|k| k.net_id == net_id).map(|k| k.id)?;

            let flags = beacon_data[1]; // flags byte
            let b_ivu = (flags & 0x02) != 0;
            let b_kr = (flags & 0x01) != 0;

            // IV Index is at beacon_data[10..14]
            let b_ivi = u32::from_be_bytes([
                beacon_data[10],
                beacon_data[11],
                beacon_data[12],
                beacon_data[13],
            ]);

            // CMAC is at beacon_data[14..22]
            let cmac = u64::from_be_bytes([
                beacon_data[14],
                beacon_data[15],
                beacon_data[16],
                beacon_data[17],
                beacon_data[18],
                beacon_data[19],
                beacon_data[20],
                beacon_data[21],
            ]);

            if !snb_check_internal(state, key_id, b_ivi, b_kr, b_ivu, cmac) {
                return None;
            }

            (key_id, b_ivi, b_ivu, b_kr)
        } else if beacon_type == BEACON_TYPE_MPB {
            // Try all keys for private beacon decryption
            private_beacon_check(state, beacon_data)?
        } else {
            return None;
        };

        // Cache the validated beacon
        let mut beacon =
            BeaconRx { data: [0u8; BEACON_LEN_MAX], id: b_id, ivi: b_ivi, kr: b_kr, ivu: b_ivu };
        let copy_len = beacon_data.len().min(BEACON_LEN_MAX);
        beacon.data[..copy_len].copy_from_slice(&beacon_data[..copy_len]);

        // Maintain cache size limit
        if state.beacons.len() >= BEACON_CACHE_MAX {
            state.beacons.pop();
        }
        state.beacons.insert(0, beacon);

        Some((b_id, b_ivi, b_ivu, b_kr))
    })
}

/// Verify the CMAC of a Secure Network Beacon.
pub fn net_key_snb_check(id: u32, iv_index: u32, kr: bool, ivu: bool, cmac: u64) -> bool {
    with_state(|state| snb_check_internal(state, id, iv_index, kr, ivu, cmac))
}

/// Internal SNB CMAC verification (callable within `with_state`).
fn snb_check_internal(
    state: &NetKeyState,
    id: u32,
    iv_index: u32,
    kr: bool,
    ivu: bool,
    cmac: u64,
) -> bool {
    let Some(key) = state.keys.iter().find(|k| k.id == id) else {
        return false;
    };

    let Some(cmac_check) = mesh_crypto_beacon_cmac(&key.snb_key, &key.net_id, iv_index, kr, ivu)
    else {
        error!("mesh_crypto_beacon_cmac failed");
        return false;
    };

    if cmac != cmac_check {
        error!("cmac compare failed 0x{:016x} != 0x{:016x}", cmac, cmac_check);
        return false;
    }

    true
}

/// Try all keys to authenticate a Mesh Private Beacon via AES-CCM decryption.
///
/// Returns `Some((key_id, iv_index, ivu, kr))` on success.
fn private_beacon_check(state: &NetKeyState, beacon_data: &[u8]) -> Option<(u32, u32, bool, bool)> {
    // beacon_data[0] = beacon type (MPB)
    // beacon_data[1..14] = random nonce (13 bytes)
    // beacon_data[14..27] = encrypted data + MIC (5 bytes plain + 8 bytes MIC = 13 bytes)
    if beacon_data.len() < BEACON_LEN_MPB - 1 {
        return None;
    }

    for key in &state.keys {
        let mut out = [0u8; 5];
        let mut mic = [0u8; 8];

        // nonce = beacon_data[1..14] (13 bytes)
        let mut nonce = [0u8; 13];
        nonce.copy_from_slice(&beacon_data[1..14]);

        // encrypted = beacon_data[14..27] (13 bytes = 5 plaintext + 8 MIC)
        let encrypted = &beacon_data[14..27];

        if mesh_crypto_aes_ccm_decrypt(&nonce, &key.pvt_key, None, encrypted, &mut out, &mut mic, 8)
        {
            let b_ivi = u32::from_be_bytes([out[1], out[2], out[3], out[4]]);
            let b_ivu = (out[0] & 0x02) != 0;
            let b_kr = (out[0] & 0x01) != 0;
            return Some((key.id, b_ivi, b_ivu, b_kr));
        }
    }

    None
}

/// Look up a key by its 8-byte Network Identity.
///
/// Returns the internal key ID, or `None` if no key matches.
pub fn net_key_network_id(network_id: &[u8; 8]) -> Option<u32> {
    with_state(|state| state.keys.iter().find(|k| k.net_id == *network_id).map(|k| k.id))
}

// ===========================================================================
// Beacon Composition (internal)
// ===========================================================================

/// Compose a Mesh Private Beacon into the key's MPB buffer.
fn mpb_compose(key: &mut NetKey, ivi: u32, kr: bool, ivu: bool) -> bool {
    let mpb = match key.mpb.as_mut() {
        Some(buf) => buf,
        None => return false,
    };

    // Build plaintext: flags || iv_index_be32
    let mut b_data = [0u8; 13]; // 5 bytes plaintext + 8 bytes MIC output space
    b_data[0] = 0;
    b_data[1..5].copy_from_slice(&ivi.to_be_bytes());

    if kr {
        b_data[0] |= KEY_REFRESH;
    }
    if ivu {
        b_data[0] |= IV_INDEX_UPDATE;
    }

    // Generate 13 random bytes for nonce
    let mut random = [0u8; 13];
    if random_bytes(&mut random).is_err() {
        return false;
    }

    // AES-CCM encrypt: nonce=random, key=pvt_key, plaintext=b_data[0..5], MIC=8
    // Output goes back into b_data (5 bytes ciphertext + 8 bytes MIC = 13)
    let pvt_key = key.pvt_key;
    if !mesh_crypto_aes_ccm_encrypt(
        &random,
        &pvt_key,
        None,
        &b_data[..5].to_vec().clone(),
        &mut b_data,
        8,
    ) {
        return false;
    }

    mpb[0] = BT_AD_MESH_BEACON;
    mpb[1] = BEACON_TYPE_MPB;
    mpb[2..15].copy_from_slice(&random);
    mpb[15..28].copy_from_slice(&b_data);

    true
}

/// Compose a Secure Network Beacon into the key's SNB buffer.
fn snb_compose(key: &mut NetKey, ivi: u32, kr: bool, ivu: bool) -> bool {
    let snb_key = key.snb_key;
    let net_id = key.net_id;

    let Some(cmac) = mesh_crypto_beacon_cmac(&snb_key, &net_id, ivi, kr, ivu) else {
        error!("mesh_crypto_beacon_cmac failed");
        return false;
    };

    let snb = match key.snb.as_mut() {
        Some(buf) => buf,
        None => return false,
    };

    snb[0] = BT_AD_MESH_BEACON;
    snb[1] = BEACON_TYPE_SNB;
    snb[2] = 0;

    if kr {
        snb[2] |= KEY_REFRESH;
    }
    if ivu {
        snb[2] |= IV_INDEX_UPDATE;
    }

    snb[3..11].copy_from_slice(&net_id);
    snb[11..15].copy_from_slice(&ivi.to_be_bytes());
    snb[15..23].copy_from_slice(&cmac.to_be_bytes());

    true
}

// ===========================================================================
// Beacon Scheduling
// ===========================================================================

/// Send the network beacon(s) for a given key via mesh I/O.
fn send_network_beacon(key: &mut NetKey) {
    let info = MeshIoSendInfo::General {
        interval: 100,
        cnt: 1,
        min_delay: DEFAULT_MIN_DELAY,
        max_delay: DEFAULT_MAX_DELAY,
    };

    if key.mpb_enables > 0 {
        // If Interval steps == 0, refresh key every time
        if key.mpb_refresh == 0
            || key.mpb.is_none()
            || key.mpb.as_ref().is_none_or(|b| b.is_empty() || b[0] == 0)
        {
            let ivi = key.ivi;
            let kr = key.kr;
            let ivu = key.ivu;
            beacon_refresh_internal(key, ivi, kr, ivu, true);
        }

        if let Some(mpb) = &key.mpb {
            mesh_io_send(&info, mpb);
        }
    }

    if key.snb_enables > 0 {
        if key.snb.is_none() || key.snb.as_ref().is_none_or(|b| b.is_empty() || b[0] == 0) {
            let ivi = key.ivi;
            let kr = key.kr;
            let ivu = key.ivu;
            beacon_refresh_internal(key, ivi, kr, ivu, true);
        }

        if let Some(snb) = &key.snb {
            mesh_io_send(&info, snb);
        }
    }
}

/// Record that a beacon was observed for the given key.
pub fn net_key_beacon_seen(id: u32) {
    with_state(|state| {
        if let Some(key) = state.keys.iter_mut().find(|k| k.id == id) {
            key.observe.seen += 1;
            key.observe.ts = get_timestamp_secs();
        }
    });
}

/// Return the timestamp of the last beacon observation for the given key.
pub fn net_key_beacon_last_seen(id: u32) -> u32 {
    with_state(|state| state.keys.iter().find(|k| k.id == id).map_or(0, |k| k.observe.ts))
}

/// Internal beacon refresh logic (operates on a mutable key reference).
fn beacon_refresh_internal(key: &mut NetKey, ivi: u32, kr: bool, ivu: bool, force: bool) -> bool {
    let mut refresh = force;

    if key.snb_enables > 0 && key.snb.is_none() {
        key.snb = Some(vec![0u8; BEACON_LEN_SNB]);
        refresh = true;
    }

    if key.mpb_enables > 0 && key.mpb.is_none() {
        key.mpb = Some(vec![0u8; BEACON_LEN_MPB]);
        refresh = true;
    }

    if key.ivi != ivi || key.ivu != ivu || key.kr != kr {
        refresh = true;
    }

    if !refresh {
        return true;
    }

    if key.mpb.is_some() {
        if !mpb_compose(key, ivi, kr, ivu) {
            return false;
        }
        if let Some(mpb) = &key.mpb {
            print_packet("Set MPB to", mpb);
        }
    }

    if key.snb.is_some() {
        if !snb_compose(key, ivi, kr, ivu) {
            return false;
        }
        if let Some(snb) = &key.snb {
            print_packet("Set SNB to", snb);
        }
    }

    debug!("Set Beacon: IVI: {:08x}, IVU: {}, KR: {}", ivi, ivu as u8, kr as u8);

    key.ivi = ivi;
    key.ivu = ivu;
    key.kr = kr;

    true
}

/// Refresh the beacon data for the key identified by `id`.
///
/// Recomposes the SNB and/or MPB beacon data if any state has changed
/// (IV Index, IV Update flag, Key Refresh flag) or if `force` is true.
/// After composing, propagates changes to local nodes and schedules a
/// beacon transmission with a randomized delay.
///
/// Returns `true` on success, `false` if the key is not found or
/// beacon composition fails.
pub fn net_key_beacon_refresh(id: u32, iv_index: u32, kr: bool, ivu: bool, force: bool) -> bool {
    with_state(|state| {
        let Some(key) = state.keys.iter_mut().find(|k| k.id == id) else {
            return false;
        };

        if !beacon_refresh_internal(key, iv_index, kr, ivu, force) {
            return false;
        }

        // Note: net_local_beacon(id, ivi, ivu, kr) call is handled by the
        // net module which orchestrates beacon propagation to all local nodes.
        // In the C code this was a direct call; in the Rust architecture the
        // net module registers for beacon updates.

        // Send one new beacon soon, after all nodes have seen it
        let mut rand_buf = [0u8; 4];
        if random_bytes(&mut rand_buf).is_err() {
            return true; // Still succeeded at composing, just can't randomize
        }
        let rand_ms = u32::from_ne_bytes(rand_buf) % 1000;
        key.observe.expected += 1;

        // Cancel existing timeout and schedule a new one
        if let Some(handle) = key.observe.timeout.take() {
            handle.abort();
        }

        let delay_ms = 500 + rand_ms;
        let key_id = key.id;
        key.observe.timeout = Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay_ms as u64)).await;
            beacon_timeout_fire(key_id);
        }));

        true
    })
}

/// Enable beacon transmission for the key identified by `id`.
///
/// If `mpb` is true, enables MPB beaconing with the given refresh count.
/// Otherwise, enables SNB beaconing. When the first beacon type is enabled,
/// starts the periodic beacon observation timer.
pub fn net_key_beacon_enable(id: u32, mpb: bool, refresh_count: u8) {
    with_state(|state| {
        let Some(key) = state.keys.iter_mut().find(|k| k.id == id) else {
            return;
        };

        let already_enabled = key.snb_enables > 0 || key.mpb_enables > 0;

        if mpb {
            key.mpb_enables += 1;
            key.mpb_refresh = refresh_count;

            // Cancel existing MPB refresh timer
            if let Some(handle) = key.mpb_to.take() {
                handle.abort();
            }

            if refresh_count > 0 {
                let interval_secs = u64::from(refresh_count) * 10;
                let key_id = key.id;
                key.mpb_to = Some(tokio::spawn(async move {
                    // First interval
                    tokio::time::sleep(Duration::from_secs(interval_secs)).await;
                    mpb_timeout_fire(key_id);
                }));
            }
        } else {
            key.snb_enables += 1;
        }

        // If already enabled, do nothing more
        if already_enabled {
            return;
        }

        // Randomize first timeout to avoid bursts of beacons
        let mut rand_buf = [0u8; 4];
        let rand_ms = if random_bytes(&mut rand_buf).is_ok() {
            u32::from_ne_bytes(rand_buf) % (BEACON_INTERVAL_MIN * 1000) + 1
        } else {
            500
        };

        // Enable periodic beaconing on this key
        key.observe.period = (BEACON_INTERVAL_MIN * 2) as u16;
        key.observe.expected = 2;
        key.observe.seen = 0;
        key.observe.half_period = true;

        if let Some(handle) = key.observe.timeout.take() {
            handle.abort();
        }

        let key_id = key.id;
        key.observe.timeout = Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(rand_ms as u64)).await;
            beacon_timeout_fire(key_id);
        }));
    });
}

/// Disable beacon transmission for the key identified by `id`.
///
/// If `mpb` is true, decrements the MPB enable count and frees the MPB
/// buffer when no more nodes need it. Otherwise, decrements the SNB enable
/// count similarly. When both enable counts reach zero, cancels the
/// periodic observation timer.
pub fn net_key_beacon_disable(id: u32, mpb: bool) {
    with_state(|state| {
        let Some(key) = state.keys.iter_mut().find(|k| k.id == id) else {
            return;
        };

        if mpb {
            if key.mpb_enables == 0 {
                return;
            }

            key.mpb_enables -= 1;

            if key.mpb_enables == 0 {
                key.mpb = None;
                if let Some(handle) = key.mpb_to.take() {
                    handle.abort();
                }
            }
        } else {
            if key.snb_enables == 0 {
                return;
            }

            key.snb_enables -= 1;

            if key.snb_enables == 0 {
                key.snb = None;
            }
        }

        if key.snb_enables > 0 || key.mpb_enables > 0 {
            return;
        }

        // Disable periodic beaconing on this key
        if let Some(handle) = key.observe.timeout.take() {
            handle.abort();
        }
    });
}

// ===========================================================================
// Timer Callbacks (spawned as tokio tasks)
// ===========================================================================

/// Fired when the beacon observation timer expires.
///
/// Sends beacon(s), updates observation statistics, and reschedules
/// the timer with an adaptive interval based on the observation period.
fn beacon_timeout_fire(key_id: u32) {
    with_state(|state| {
        let Some(key) = state.keys.iter_mut().find(|k| k.id == key_id) else {
            return;
        };

        // Always send at least one beacon
        send_network_beacon(key);

        // Count our own beacons towards the vicinity total
        key.observe.seen += 1;

        if !key.observe.half_period {
            debug!(
                "beacon {} for {} nodes, period {}, obs {}, exp {}",
                key.id,
                key.snb_enables + key.mpb_enables,
                key.observe.period,
                key.observe.seen,
                key.observe.expected,
            );

            let period = key.observe.period as u32;
            let seen = key.observe.seen as u32;
            let expected = key.observe.expected as u32;

            let mut interval = if expected > 0 { (period * seen) / expected } else { period };

            // Limit increases and decreases by 10 seconds up and
            // 20 seconds down each step, to avoid going nearly silent
            // in highly populated environments.
            if interval > period + 10 {
                interval = period + 10;
            } else if interval + 20 < period {
                interval = period - 20;
            }

            // Beaconing must be no slower than once every 10 minutes,
            // and no faster than once every 10 seconds, per spec.
            // Observation period is twice beaconing period.
            interval = interval.clamp(BEACON_INTERVAL_MIN * 2, BEACON_INTERVAL_MAX * 2);

            key.observe.period = interval as u16;
            key.observe.seen = 0;

            // To prevent "over slowing" of the beaconing frequency,
            // require more significant "over observing" the slower
            // our own beaconing frequency.
            key.observe.expected = (interval / 10) as u16;
            let scale_factor = interval / 60;
            key.observe.expected += (scale_factor * 3) as u16;
        }

        let interval_secs = key.observe.period as u64 / 2;
        key.observe.half_period = !key.observe.half_period;

        if key.mpb_enables > 0 || key.snb_enables > 0 {
            // Reschedule the timer
            let next_key_id = key.id;
            if let Some(handle) = key.observe.timeout.take() {
                handle.abort();
            }
            key.observe.timeout = Some(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
                beacon_timeout_fire(next_key_id);
            }));
        } else {
            // No beacons enabled, cancel
            if let Some(handle) = key.observe.timeout.take() {
                handle.abort();
            }
        }
    });
}

/// Fired when the MPB refresh timer expires.
///
/// Re-composes the MPB beacon data and reschedules the timer.
fn mpb_timeout_fire(key_id: u32) {
    with_state(|state| {
        let Some(key) = state.keys.iter_mut().find(|k| k.id == key_id) else {
            return;
        };

        if key.mpb_refresh > 0 {
            let interval_secs = u64::from(key.mpb_refresh) * 10;
            debug!("Refresh in {} seconds", key.mpb_refresh as u32 * 10);

            let next_key_id = key.id;
            if let Some(handle) = key.mpb_to.take() {
                handle.abort();
            }
            key.mpb_to = Some(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
                mpb_timeout_fire(next_key_id);
            }));
        }

        let ivi = key.ivi;
        let kr = key.kr;
        let ivu = key.ivu;
        beacon_refresh_internal(key, ivi, kr, ivu, true);
    });
}
