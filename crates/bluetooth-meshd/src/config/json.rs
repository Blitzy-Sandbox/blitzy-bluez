// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Copyright (C) 2018-2019 Intel Corporation. All rights reserved.
//
// JSON-backed mesh configuration persistence backend.
//
// Complete Rust rewrite of `mesh/mesh-config-json.c` (2718 lines of C).
// Persists Bluetooth Mesh node configuration as `node.json` files using
// `serde_json::Value` as the in-memory representation (replacing json-c).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{Map, Value, json};
use tracing::{debug, error, info, warn};

use super::{
    KEY_REFRESH_PHASE_NONE, KEY_REFRESH_PHASE_ONE, KEY_REFRESH_PHASE_TWO, MIN_COMP_SIZE,
    MeshConfig, MeshConfigAppKey, MeshConfigCompPage, MeshConfigElement, MeshConfigError,
    MeshConfigModel, MeshConfigModes, MeshConfigNetKey, MeshConfigNode, MeshConfigNodeFn,
    MeshConfigPub, MeshConfigStatusFn, MeshConfigSub, MeshConfigTransmit,
};
use crate::util;

// ============================================================================
// Constants
// ============================================================================

/// Name of the JSON configuration file within each node directory.
const CFGNODE_NAME: &str = "/node.json";

/// Backup file extension.
const BAK_EXT: &str = ".bak";

/// Temporary file extension for atomic writes.
const TMP_EXT: &str = ".tmp";

/// Minimum difference between current seq and cached seq that triggers a cache update.
const MIN_SEQ_CACHE_TRIGGER: u32 = 32;

/// Minimum look-ahead value for sequence number caching.
const MIN_SEQ_CACHE_VALUE: u32 = 64;

/// Minimum time window (in seconds) for sequence number caching extrapolation.
const MIN_SEQ_CACHE_TIME: u64 = 300;

/// Maximum valid sequence number (24-bit).
const SEQ_MASK: u32 = 0x00FF_FFFF;

/// Maximum valid TTL (7-bit).
const TTL_MASK: u8 = 0x7F;

/// Maximum valid key index value.
const MAX_KEY_INDEX: u16 = 4095;

// JSON key name constants (matching C string constants exactly).
const KEY_UNICAST_ADDRESS: &str = "unicastAddress";
const KEY_DEVICE_CAN: &str = "deviceCan";
const KEY_DEVICE_KEY: &str = "deviceKey";
const KEY_DEFAULT_TTL: &str = "defaultTTL";
const KEY_SEQUENCE_NUMBER: &str = "sequenceNumber";
const KEY_NET_KEYS: &str = "netKeys";
const KEY_APP_KEYS: &str = "appKeys";
const KEY_ELEMENTS: &str = "elements";
const KEY_MODELS: &str = "models";
const KEY_MODEL_ID: &str = "modelId";
const KEY_ADDRESS: &str = "address";
const KEY_BIND: &str = "bind";
const KEY_PUBLISH: &str = "publish";
const KEY_SUBSCRIBE: &str = "subscribe";
const KEY_BOUND_NET_KEY: &str = "boundNetKey";
const KEY_KEY_REFRESH: &str = "keyRefresh";
const KEY_SUB_ENABLED: &str = "subEnabled";
const KEY_PUB_ENABLED: &str = "pubEnabled";
const KEY_RETRANSMIT: &str = "retransmit";
const KEY_PUB_DISABLED: &str = "pubDisabled";

// Mode string constants.
const MODE_ENABLED: &str = "enabled";
const MODE_DISABLED: &str = "disabled";
const MODE_UNSUPPORTED: &str = "unsupported";

// Mesh mode numeric values matching C MESH_MODE_* defines.
const MESH_MODE_DISABLED: u8 = 0;
const MESH_MODE_ENABLED: u8 = 1;
const MESH_MODE_UNSUPPORTED: u8 = 2;

// ============================================================================
// MeshConfigJson struct
// ============================================================================

/// JSON-backed implementation of the [`MeshConfig`] trait.
///
/// Persists mesh node configuration as `node.json` files within a directory
/// hierarchy organized by node UUID. This is the concrete implementation
/// replacing the C `mesh-config-json.c` module (2718 lines).
///
/// The in-memory representation uses `serde_json::Value` (matching C's
/// `json_object` usage), preserving the exact JSON manipulation patterns
/// from the C code where individual fields are updated in-place.
pub struct MeshConfigJson {
    /// In-memory JSON representation of node configuration.
    node_data: serde_json::Value,
    /// Filesystem path to the node.json file.
    node_dir_path: PathBuf,
    /// 16-byte UUID of the node.
    uuid: [u8; 16],
    /// Last written sequence number (for caching).
    write_seq: u32,
    /// Timestamp of last write (monotonic).
    write_time: Instant,
}

// ============================================================================
// Hex Encoding/Decoding Helpers
// ============================================================================

/// Hex-encode a 16-byte key to a 32-character lowercase hex string.
fn encode_key_hex(key: &[u8; 16]) -> String {
    util::hex2str(key)
}

/// Hex-encode an 8-byte token to a 16-character lowercase hex string.
fn encode_u64_hex(val: &[u8; 8]) -> String {
    util::hex2str(val)
}

/// Format a u16 as a 4-character lowercase hex string.
fn encode_u16_hex(val: u16) -> String {
    format!("{val:04x}")
}

/// Format a u32 as an 8-character lowercase hex string.
fn encode_u32_hex(val: u32) -> String {
    format!("{val:08x}")
}

/// Convert a mode value to its string representation.
fn mode_to_string(mode: u8) -> &'static str {
    match mode {
        MESH_MODE_DISABLED => MODE_DISABLED,
        MESH_MODE_ENABLED => MODE_ENABLED,
        _ => MODE_UNSUPPORTED,
    }
}

/// Parse a mode string to its numeric value. Case-insensitive.
/// Returns `None` for unrecognized strings.
fn parse_mode_string(s: &str) -> Option<u8> {
    let lower = s.to_ascii_lowercase();
    if lower.starts_with(MODE_DISABLED) {
        Some(MESH_MODE_DISABLED)
    } else if lower.starts_with(MODE_ENABLED) {
        Some(MESH_MODE_ENABLED)
    } else if lower.starts_with(MODE_UNSUPPORTED) {
        Some(MESH_MODE_UNSUPPORTED)
    } else {
        None
    }
}

// ============================================================================
// JSON Value Helpers
// ============================================================================

/// Get an integer value from a JSON object by key.
fn get_int(jobj: &Value, key: &str) -> Option<i64> {
    jobj.get(key).and_then(|v| v.as_i64())
}

/// Get a string value from a JSON object by key.
fn get_str<'a>(jobj: &'a Value, key: &str) -> Option<&'a str> {
    jobj.get(key).and_then(|v| v.as_str())
}

/// Get a key index (0..=4095) from a JSON object field.
fn get_key_index(jobj: &Value, key: &str) -> Option<u16> {
    let val = get_int(jobj, key)?;
    if val < 0 || val > MAX_KEY_INDEX as i64 {
        return None;
    }
    Some(val as u16)
}

/// Set an integer field in a JSON object (create or overwrite).
fn write_int_field(jobj: &mut Value, key: &str, val: i64) -> bool {
    if let Some(obj) = jobj.as_object_mut() {
        obj.insert(key.to_string(), json!(val));
        true
    } else {
        false
    }
}

/// Set a string field in a JSON object (create or overwrite).
fn write_str_field(jobj: &mut Value, key: &str, val: &str) -> bool {
    if let Some(obj) = jobj.as_object_mut() {
        obj.insert(key.to_string(), json!(val));
        true
    } else {
        false
    }
}

/// Remove a field from a JSON object.
fn del_field(jobj: &mut Value, key: &str) {
    if let Some(obj) = jobj.as_object_mut() {
        obj.remove(key);
    }
}

/// Write a 16-byte key as a 32-char hex string to a JSON object field.
fn add_key_value(jobj: &mut Value, key: &str, key_bytes: &[u8; 16]) -> bool {
    write_str_field(jobj, key, &encode_key_hex(key_bytes))
}

/// Write an 8-byte value as a 16-char hex string to a JSON object field.
fn add_u64_value(jobj: &mut Value, key: &str, val: &[u8; 8]) -> bool {
    write_str_field(jobj, key, &encode_u64_hex(val))
}

/// Write a u16 as a 4-char hex string to a JSON object field.
fn write_uint16_hex(jobj: &mut Value, key: &str, val: u16) -> bool {
    write_str_field(jobj, key, &encode_u16_hex(val))
}

/// Write a u32 as an 8-char hex string to a JSON object field.
fn write_uint32_hex(jobj: &mut Value, key: &str, val: u32) -> bool {
    write_str_field(jobj, key, &encode_u32_hex(val))
}

/// Write a mode string to a JSON object field.
fn write_mode_field(jobj: &mut Value, key: &str, mode: u8) -> bool {
    write_str_field(jobj, key, mode_to_string(mode))
}

// ============================================================================
// JSON Array Helpers
// ============================================================================

/// Check if a JSON array contains a string starting with `prefix`.
fn jarray_has_string(jarray: &Value, prefix: &str) -> bool {
    if let Some(arr) = jarray.as_array() {
        for entry in arr {
            if let Some(s) = entry.as_str() {
                if s.starts_with(prefix) {
                    return true;
                }
            }
        }
    }
    false
}

/// Remove the first string from a JSON array that starts with `prefix`.
fn jarray_string_del(jarray: &mut Value, prefix: &str) {
    if let Some(arr) = jarray.as_array_mut() {
        if let Some(pos) =
            arr.iter().position(|e| e.as_str().is_some_and(|s| s.starts_with(prefix)))
        {
            arr.remove(pos);
        }
    }
}

/// Find a key object in a JSON array by its "index" field.
fn get_key_object_index(jarray: &Value, idx: u16) -> Option<usize> {
    let arr = jarray.as_array()?;
    arr.iter().position(|entry| get_key_index(entry, "index") == Some(idx))
}

/// Find a key object in a JSON array by its "index" field (immutable ref).
fn get_key_object(jarray: &Value, idx: u16) -> Option<&Value> {
    let pos = get_key_object_index(jarray, idx)?;
    jarray.as_array()?.get(pos)
}

/// Remove a key object from a JSON array by its "index" field.
fn jarray_key_del(jarray: &mut Value, idx: u16) {
    if let Some(arr) = jarray.as_array_mut() {
        if let Some(pos) = arr.iter().position(|entry| get_key_index(entry, "index") == Some(idx)) {
            arr.remove(pos);
        }
    }
}

// ============================================================================
// JSON Navigation Helpers
// ============================================================================

/// Compute element index from unicast address.
/// Returns `None` if the address is out of range.
fn get_element_index(jnode: &Value, ele_addr: u16) -> Option<usize> {
    let addr_str = get_str(jnode, KEY_UNICAST_ADDRESS)?;
    let addr = u16::from_str_radix(addr_str, 16).ok()?;
    let jelements = jnode.get(KEY_ELEMENTS)?.as_array()?;
    let num_ele = jelements.len() as u16;

    if ele_addr < addr || ele_addr >= addr + num_ele {
        return None;
    }
    Some((ele_addr - addr) as usize)
}

/// Find a model JSON object within an element by model ID.
/// Returns the index into the models array.
fn find_element_model_index(
    jnode: &Value,
    ele_idx: usize,
    mod_id: u32,
    vendor: bool,
) -> Option<usize> {
    let jelements = jnode.get(KEY_ELEMENTS)?.as_array()?;
    let jelement = jelements.get(ele_idx)?;
    let jmodels = jelement.get(KEY_MODELS)?.as_array()?;

    let target = if vendor { encode_u32_hex(mod_id) } else { encode_u16_hex(mod_id as u16) };

    jmodels.iter().position(|jmodel| {
        jmodel.get(KEY_MODEL_ID).and_then(|v| v.as_str()).is_some_and(|s| s == target)
    })
}

// ============================================================================
// Parsing Functions (Loading node.json)
// ============================================================================

/// Read IV index and IV update flag from JSON.
fn read_iv_index(jobj: &Value, node: &mut MeshConfigNode) -> bool {
    let iv_index = match get_int(jobj, "IVindex") {
        Some(v) => v as u32,
        None => return false,
    };
    let iv_update = match get_int(jobj, "IVupdate") {
        Some(v) => v != 0,
        None => return false,
    };
    node.iv_index = iv_index;
    node.iv_update = iv_update;
    true
}

/// Read the 8-byte token from JSON.
fn read_token(jobj: &Value, token: &mut [u8; 8]) -> bool {
    let s = match get_str(jobj, "token") {
        Some(v) => v,
        None => return false,
    };
    util::str2hex(s, token)
}

/// Read the 16-byte device key from JSON.
fn read_device_key(jobj: &Value, key: &mut [u8; 16]) -> bool {
    let s = match get_str(jobj, KEY_DEVICE_KEY) {
        Some(v) => v,
        None => return false,
    };
    util::str2hex(s, key)
}

/// Read an optional 16-byte candidate device key from JSON.
fn read_candidate_key(jobj: &Value) -> Option<[u8; 16]> {
    let s = get_str(jobj, KEY_DEVICE_CAN)?;
    let mut key = [0u8; 16];
    if util::str2hex(s, &mut key) { Some(key) } else { None }
}

/// Read the unicast address from JSON.
fn read_unicast_address(jobj: &Value, unicast: &mut u16) -> bool {
    let s = match get_str(jobj, KEY_UNICAST_ADDRESS) {
        Some(v) => v,
        None => return false,
    };
    match u16::from_str_radix(s, 16) {
        Ok(v) => {
            *unicast = v;
            true
        }
        Err(_) => false,
    }
}

/// Read the default TTL (optional). Returns true on success, including when field is absent.
fn read_default_ttl(jobj: &Value, ttl: &mut u8) -> bool {
    let val = match jobj.get(KEY_DEFAULT_TTL) {
        None => return true, // optional field
        Some(v) => match v.as_i64() {
            Some(i) => i,
            None => return false,
        },
    };
    if val < 0 || val == 1 || val > TTL_MASK as i64 {
        return false;
    }
    *ttl = val as u8;
    true
}

/// Read the sequence number (optional). Returns true on success.
fn read_seq_number(jobj: &Value, seq: &mut u32) -> bool {
    let val = match jobj.get(KEY_SEQUENCE_NUMBER) {
        None => return true, // optional field
        Some(v) => match v.as_i64() {
            Some(i) => i,
            None => return false,
        },
    };
    if val < 0 || val > (SEQ_MASK as i64) + 1 {
        return false;
    }
    *seq = val as u32;
    true
}

/// Parse composition data (cid, pid, vid, crpl) from JSON.
fn parse_composition(jobj: &Value, node: &mut MeshConfigNode) -> bool {
    // Parse cid
    let s = match get_str(jobj, "cid") {
        Some(v) => v,
        None => return false,
    };
    node.cid = match u16::from_str_radix(s, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Parse pid
    let s = match get_str(jobj, "pid") {
        Some(v) => v,
        None => return false,
    };
    node.pid = match u16::from_str_radix(s, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Parse vid
    let s = match get_str(jobj, "vid") {
        Some(v) => v,
        None => return false,
    };
    node.vid = match u16::from_str_radix(s, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Parse crpl
    let s = match get_str(jobj, "crpl") {
        Some(v) => v,
        None => return false,
    };
    node.crpl = match u16::from_str_radix(s, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };

    true
}

/// Parse feature modes from JSON.
fn parse_features(jobj: &Value, node: &mut MeshConfigNode) {
    // proxy
    if let Some(jval) = jobj.get("proxy") {
        if let Some(s) = jval.as_str() {
            if let Some(m) = parse_mode_string(s) {
                if m <= MESH_MODE_UNSUPPORTED {
                    node.modes.proxy = m;
                }
            }
        }
    }
    // friend
    if let Some(jval) = jobj.get("friend") {
        if let Some(s) = jval.as_str() {
            if let Some(m) = parse_mode_string(s) {
                if m <= MESH_MODE_UNSUPPORTED {
                    node.modes.friend = m;
                }
            }
        }
    }
    // lowPower
    if let Some(jval) = jobj.get("lowPower") {
        if let Some(s) = jval.as_str() {
            if let Some(m) = parse_mode_string(s) {
                if m <= MESH_MODE_UNSUPPORTED {
                    node.modes.lpn = m;
                }
            }
        }
    }
    // beacon
    if let Some(jval) = jobj.get("beacon") {
        if let Some(s) = jval.as_str() {
            if let Some(m) = parse_mode_string(s) {
                if m <= MESH_MODE_UNSUPPORTED {
                    node.modes.beacon = m;
                }
            }
        }
    }
    // mpb
    if let Some(jval) = jobj.get("mpb") {
        if let Some(s) = jval.as_str() {
            if let Some(m) = parse_mode_string(s) {
                if m <= MESH_MODE_UNSUPPORTED {
                    node.modes.mpb = m;
                }
                if node.modes.mpb == MESH_MODE_ENABLED {
                    if let Some(period) = get_int(jobj, "mpbPeriod") {
                        node.modes.mpb_period = period as u8;
                    }
                }
            }
        }
    }
    // relay (nested object)
    if let Some(jrelay) = jobj.get("relay") {
        if let Some(jmode) = jrelay.get("mode") {
            if let Some(s) = jmode.as_str() {
                if let Some(m) = parse_mode_string(s) {
                    if m <= MESH_MODE_UNSUPPORTED {
                        node.modes.relay = m;
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            return;
        }

        if let Some(cnt) = get_int(jrelay, "count") {
            node.modes.relay_cnt = cnt as u16;
        } else {
            return;
        }

        if let Some(interval) = get_int(jrelay, "interval") {
            node.modes.relay_interval = interval as u16;
        }
    }
}

/// Read network transmit parameters (optional).
fn read_net_transmit(jobj: &Value, node: &mut MeshConfigNode) -> bool {
    let jrtx = match jobj.get(KEY_RETRANSMIT) {
        None => return true, // optional
        Some(v) => v,
    };
    let count = match get_int(jrtx, "count") {
        Some(v) => v as u16,
        None => return false,
    };
    let interval = match get_int(jrtx, "interval") {
        Some(v) => v as u16,
        None => return false,
    };
    node.net_transmit = Some(MeshConfigTransmit { count, interval });
    true
}

/// Parse the bindings array for a model.
fn parse_bindings(jarray: &Value) -> Option<Vec<u16>> {
    let arr = jarray.as_array()?;
    let mut bindings = Vec::with_capacity(arr.len());
    for entry in arr {
        let s = entry.as_str()?;
        let idx = u16::from_str_radix(s, 16).ok()?;
        if idx > MAX_KEY_INDEX {
            return None;
        }
        bindings.push(idx);
    }
    Some(bindings)
}

/// Parse a publication object from JSON.
fn parse_model_publication(jpub: &Value) -> Option<MeshConfigPub> {
    let addr_str = get_str(jpub, KEY_ADDRESS)?;
    let len = addr_str.len();

    let mut pub_cfg = MeshConfigPub {
        virt: false,
        addr: 0,
        idx: 0,
        ttl: 0,
        period: 0,
        retransmit_interval: 0,
        retransmit_count: 0,
        credential: false,
        virt_addr: [0u8; 16],
    };

    match len {
        4 => {
            pub_cfg.addr = u16::from_str_radix(addr_str, 16).ok()?;
        }
        32 => {
            if !util::str2hex(addr_str, &mut pub_cfg.virt_addr) {
                return None;
            }
            pub_cfg.virt = true;
        }
        _ => return None,
    }

    pub_cfg.idx = get_key_index(jpub, "index")?;
    pub_cfg.ttl = get_int(jpub, "ttl")? as u16;
    pub_cfg.period = get_int(jpub, "period")? as u32;
    pub_cfg.credential = get_int(jpub, "credentials")? != 0;

    let jrtx = jpub.get(KEY_RETRANSMIT)?;
    pub_cfg.retransmit_count = get_int(jrtx, "count")? as u16;
    pub_cfg.retransmit_interval = get_int(jrtx, "interval")? as u16;

    Some(pub_cfg)
}

/// Parse subscription addresses from JSON array.
fn parse_model_subscriptions(jsubs: &Value) -> Option<Vec<MeshConfigSub>> {
    let arr = jsubs.as_array()?;
    if arr.is_empty() {
        return Some(Vec::new());
    }
    let mut subs = Vec::with_capacity(arr.len());
    for entry in arr {
        let s = entry.as_str()?;
        let len = s.len();
        let mut sub = MeshConfigSub { virt: false, addr: 0, virt_addr: [0u8; 16] };
        match len {
            4 => {
                sub.addr = u16::from_str_radix(s, 16).ok()?;
            }
            32 => {
                if !util::str2hex(s, &mut sub.virt_addr) {
                    return None;
                }
                sub.virt = true;
            }
            _ => return None,
        }
        subs.push(sub);
    }
    Some(subs)
}

/// Parse models from a JSON array into an element.
fn parse_models(jmodels: &Value) -> Option<Vec<MeshConfigModel>> {
    let arr = jmodels.as_array()?;
    if arr.is_empty() {
        return Some(Vec::new());
    }
    let mut models = Vec::with_capacity(arr.len());
    for jmodel in arr {
        let id_str = get_str(jmodel, KEY_MODEL_ID)?;
        let len = id_str.len();
        let (id, vendor) = match len {
            4 => {
                let id = u32::from_str_radix(id_str, 16).ok()?;
                (id, false)
            }
            8 => {
                let id = u32::from_str_radix(id_str, 16).ok()?;
                (id, true)
            }
            _ => return None,
        };

        let bindings = if let Some(jbind) = jmodel.get(KEY_BIND) {
            if !jbind.is_array() {
                return None;
            }
            parse_bindings(jbind)?
        } else {
            Vec::new()
        };

        let pub_enabled = jmodel.get(KEY_PUB_ENABLED).and_then(|v| v.as_bool()).unwrap_or(true);

        let sub_enabled = jmodel.get(KEY_SUB_ENABLED).and_then(|v| v.as_bool()).unwrap_or(true);

        let pub_state = if let Some(jpub) = jmodel.get(KEY_PUBLISH) {
            Some(parse_model_publication(jpub)?)
        } else {
            None
        };

        let subs = if let Some(jsubs) = jmodel.get(KEY_SUBSCRIBE) {
            parse_model_subscriptions(jsubs)?
        } else {
            Vec::new()
        };

        models.push(MeshConfigModel {
            subs,
            pub_state,
            bindings,
            id,
            vendor,
            sub_enabled,
            pub_enabled,
        });
    }
    Some(models)
}

/// Parse elements from JSON array into a node.
fn parse_elements(jelems: &Value, node: &mut MeshConfigNode) -> bool {
    let arr = match jelems.as_array() {
        Some(a) => a,
        None => return false,
    };
    if arr.is_empty() {
        return true; // Allow empty nodes
    }

    let num_ele = arr.len();
    let mut elements = Vec::with_capacity(num_ele);

    for (i, jelement) in arr.iter().enumerate() {
        let index = match get_int(jelement, "elementIndex") {
            Some(v) if (v as usize) <= num_ele => v as u8,
            _ => return false,
        };

        let loc_str = match get_str(jelement, "location") {
            Some(s) => s,
            None => return false,
        };
        let location = match u16::from_str_radix(loc_str, 16) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let models = if let Some(jmodels) = jelement.get(KEY_MODELS) {
            if !jmodels.is_array() {
                return false;
            }
            match parse_models(jmodels) {
                Some(m) => m,
                None => return false,
            }
        } else {
            Vec::new()
        };

        let _ = i; // element index validation: index field should match position context
        elements.push(MeshConfigElement { models, location, index });
    }
    node.elements = elements;
    true
}

/// Read network keys from JSON (mandatory — at least one must exist).
fn read_net_keys(jobj: &Value, node: &mut MeshConfigNode) -> bool {
    let jarray = match jobj.get(KEY_NET_KEYS) {
        Some(v) if v.is_array() => v,
        _ => return false,
    };
    let arr = match jarray.as_array() {
        Some(a) if !a.is_empty() => a,
        _ => return false,
    };

    let mut netkeys = Vec::with_capacity(arr.len());
    for jtemp in arr {
        let idx = match get_key_index(jtemp, "index") {
            Some(v) => v,
            None => return false,
        };

        let key_str = match get_str(jtemp, "key") {
            Some(s) => s,
            None => return false,
        };
        let mut new_key = [0u8; 16];
        if !util::str2hex(key_str, &mut new_key) {
            return false;
        }

        let phase = jtemp
            .get(KEY_KEY_REFRESH)
            .and_then(|v| v.as_i64())
            .unwrap_or(KEY_REFRESH_PHASE_NONE as i64) as u8;

        if phase > KEY_REFRESH_PHASE_TWO {
            return false;
        }

        // Read old key if present. If oldKey exists but phase is NONE, that's invalid.
        let mut key = [0u8; 16];
        let key_source = if let Some(old_str) = get_str(jtemp, "oldKey") {
            if phase == KEY_REFRESH_PHASE_NONE {
                return false;
            }
            old_str
        } else {
            key_str
        };

        if !util::str2hex(key_source, &mut key) {
            return false;
        }

        netkeys.push(MeshConfigNetKey { idx, phase, key, new_key });
    }
    node.netkeys = netkeys;
    true
}

/// Read application keys from JSON (optional).
fn read_app_keys(jobj: &Value, node: &mut MeshConfigNode) -> bool {
    let jarray = match jobj.get(KEY_APP_KEYS) {
        None => return true, // optional
        Some(v) if v.is_array() => v,
        _ => return false,
    };
    let arr = match jarray.as_array() {
        Some(a) => a,
        None => return false,
    };
    if arr.is_empty() {
        return true;
    }

    let mut appkeys = Vec::with_capacity(arr.len());
    for jtemp in arr {
        let app_idx = match get_key_index(jtemp, "index") {
            Some(v) => v,
            None => return false,
        };
        let net_idx = match get_key_index(jtemp, KEY_BOUND_NET_KEY) {
            Some(v) => v,
            None => return false,
        };
        let key_str = match get_str(jtemp, "key") {
            Some(s) => s,
            None => return false,
        };
        let mut new_key = [0u8; 16];
        if !util::str2hex(key_str, &mut new_key) {
            return false;
        }

        // If oldKey is present, use it as current key; otherwise use key as both.
        let old_key_str = get_str(jtemp, "oldKey").unwrap_or(key_str);
        let mut key = [0u8; 16];
        if !util::str2hex(old_key_str, &mut key) {
            return false;
        }

        appkeys.push(MeshConfigAppKey { net_idx, app_idx, key, new_key });
    }
    node.appkeys = appkeys;
    true
}

/// Read composition pages from JSON (optional).
fn read_comp_pages(jobj: &Value, node: &mut MeshConfigNode) -> bool {
    let jarray = match jobj.get("pages") {
        None => return true, // optional
        Some(v) if v.is_array() => v,
        _ => return false,
    };
    let arr = match jarray.as_array() {
        Some(a) => a,
        None => return false,
    };

    let mut pages = Vec::with_capacity(arr.len());
    for entry in arr {
        let s = match entry.as_str() {
            Some(v) => v,
            None => continue,
        };
        let clen = s.len();
        // Minimum size check: page_num (2 chars) + MIN_COMP_SIZE * 2 data chars + 1 for odd
        if clen < (MIN_COMP_SIZE * 2) + 1 {
            continue;
        }

        let data_hex_len = clen - 2; // subtract 2 chars for page_num
        let data_len = data_hex_len / 2;

        let page_num = match u8::from_str_radix(&s[..2], 16) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let mut data = vec![0u8; data_len];
        if !util::str2hex(&s[2..2 + data_len * 2], &mut data) {
            return false;
        }

        pages.push(MeshConfigCompPage { page_num, data });
    }
    node.comp_pages = pages;
    true
}

/// Master node reader — orchestrates all parsing in the correct order.
fn read_node(jnode: &Value, node: &mut MeshConfigNode) -> bool {
    if !read_iv_index(jnode, node) {
        info!("Failed to read IV index");
        return false;
    }
    if !read_token(jnode, &mut node.token) {
        info!("Failed to read node token");
        return false;
    }
    if !read_device_key(jnode, &mut node.dev_key) {
        info!("Failed to read node device key");
        return false;
    }
    if !parse_composition(jnode, node) {
        info!("Failed to parse local node composition");
        return false;
    }
    parse_features(jnode, node);
    if !read_unicast_address(jnode, &mut node.unicast) {
        info!("Failed to parse unicast address");
        return false;
    }
    if !read_default_ttl(jnode, &mut node.ttl) {
        info!("Failed to parse default ttl");
        return false;
    }
    if !read_seq_number(jnode, &mut node.seq_number) {
        info!("Failed to parse sequence number");
        return false;
    }
    // Check for required "elements" property
    if jnode.get(KEY_ELEMENTS).is_none() {
        return false;
    }
    if !read_net_transmit(jnode, node) {
        info!("Failed to read node net transmit parameters");
        return false;
    }
    if !read_net_keys(jnode, node) {
        info!("Failed to read net keys");
        return false;
    }
    if !read_app_keys(jnode, node) {
        info!("Failed to read app keys");
        return false;
    }
    if !read_comp_pages(jnode, node) {
        info!("Failed to read Composition Pages");
        return false;
    }
    // Parse elements using the jvalue we already verified exists
    let jelems = &jnode[KEY_ELEMENTS];
    if !parse_elements(jelems, node) {
        info!("Failed to parse elements");
        return false;
    }
    true
}

// ============================================================================
// File I/O
// ============================================================================

/// Write JSON to a file, returning success.
fn save_config_to_file(jnode: &Value, fname: &Path) -> bool {
    let json_str = serde_json::to_string_pretty(jnode);
    match json_str {
        Ok(s) => match fs::write(fname, &s) {
            Ok(()) => true,
            Err(e) => {
                warn!("Incomplete write of mesh configuration: {}", e);
                false
            }
        },
        Err(e) => {
            error!("Failed to serialize JSON configuration: {}", e);
            false
        }
    }
}

/// Atomic save using tmp/bak/rename pattern.
/// This replicates the C `idle_save_config` exactly:
/// 1. Write to `.tmp`
/// 2. Remove existing `.bak`
/// 3. Rename current file to `.bak`
/// 4. Rename `.tmp` to current file
/// 5. Remove `.tmp` on failure
fn atomic_save_config(jnode: &Value, fname: &Path) -> bool {
    let fname_str = fname.to_string_lossy();
    let fname_tmp = PathBuf::from(format!("{}{}", fname_str, TMP_EXT));
    let fname_bak = PathBuf::from(format!("{}{}", fname_str, BAK_EXT));

    // Remove any stale tmp file
    let _ = fs::remove_file(&fname_tmp);

    // Write to tmp
    if !save_config_to_file(jnode, &fname_tmp) {
        let _ = fs::remove_file(&fname_tmp);
        return false;
    }

    // Remove old backup
    let _ = fs::remove_file(&fname_bak);

    // Rename current -> backup, tmp -> current
    let mut result = true;
    if fname.exists() && fs::rename(fname, &fname_bak).is_err() {
        result = false;
    }
    if result && fs::rename(&fname_tmp, fname).is_err() {
        result = false;
    }

    // Clean up tmp on failure
    let _ = fs::remove_file(&fname_tmp);

    result
}

// ============================================================================
// JSON Construction (for create/reset)
// ============================================================================

/// Build a model JSON object from a MeshConfigModel.
fn build_model_json(model: &MeshConfigModel) -> Value {
    let mut jmodel = json!({});
    if model.vendor {
        write_uint32_hex(&mut jmodel, KEY_MODEL_ID, model.id);
    } else {
        write_uint16_hex(&mut jmodel, KEY_MODEL_ID, model.id as u16);
    }

    if let Some(obj) = jmodel.as_object_mut() {
        obj.insert(KEY_SUB_ENABLED.to_string(), json!(model.sub_enabled));
        obj.insert(KEY_PUB_ENABLED.to_string(), json!(model.pub_enabled));
    }
    jmodel
}

/// Build the elements JSON array from a MeshConfigNode.
fn build_elements_json(node: &MeshConfigNode) -> Value {
    let mut jelems = Vec::new();
    for ele in &node.elements {
        let mut jelement = json!({});
        write_int_field(&mut jelement, "elementIndex", ele.index as i64);
        write_uint16_hex(&mut jelement, "location", ele.location);

        if !ele.models.is_empty() {
            let jmodels: Vec<Value> = ele.models.iter().map(build_model_json).collect();
            if let Some(obj) = jelement.as_object_mut() {
                obj.insert(KEY_MODELS.to_string(), Value::Array(jmodels));
            }
        }
        jelems.push(jelement);
    }
    Value::Array(jelems)
}

/// Create a full JSON configuration from a MeshConfigNode.
/// Returns the JSON value and creates the MeshConfigJson handle.
fn create_config(cfg_path: &str, uuid: &[u8; 16], node: &MeshConfigNode) -> Option<MeshConfigJson> {
    let mut jnode = json!({});
    let modes = &node.modes;

    // CID, PID, VID, crpl
    if !write_uint16_hex(&mut jnode, "cid", node.cid) {
        return None;
    }
    if !write_uint16_hex(&mut jnode, "pid", node.pid) {
        return None;
    }
    if !write_uint16_hex(&mut jnode, "vid", node.vid) {
        return None;
    }
    if !write_uint16_hex(&mut jnode, "crpl", node.crpl) {
        return None;
    }

    // Relay mode (nested object)
    {
        let mut jrelay = json!({});
        write_mode_field(&mut jrelay, "mode", modes.relay);
        write_int_field(&mut jrelay, "count", modes.relay_cnt as i64);
        write_int_field(&mut jrelay, "interval", modes.relay_interval as i64);
        if let Some(obj) = jnode.as_object_mut() {
            obj.insert("relay".to_string(), jrelay);
        }
    }

    // Feature modes
    write_mode_field(&mut jnode, "lowPower", modes.lpn);
    write_mode_field(&mut jnode, "friend", modes.friend);
    write_mode_field(&mut jnode, "proxy", modes.proxy);
    write_mode_field(&mut jnode, "beacon", modes.beacon);
    write_mode_field(&mut jnode, "mpb", modes.mpb);

    if modes.mpb != 0 {
        write_int_field(&mut jnode, "mpbPeriod", modes.mpb_period as i64);
    }

    // IV index
    write_int_field(&mut jnode, "IVindex", node.iv_index as i64);
    write_int_field(&mut jnode, "IVupdate", if node.iv_update { 1 } else { 0 });

    // Unicast address
    write_uint16_hex(&mut jnode, KEY_UNICAST_ADDRESS, node.unicast);

    // Device key
    add_key_value(&mut jnode, KEY_DEVICE_KEY, &node.dev_key);

    // Token
    add_u64_value(&mut jnode, "token", &node.token);

    // Sequence number
    write_int_field(&mut jnode, KEY_SEQUENCE_NUMBER, node.seq_number as i64);

    // Default TTL
    write_int_field(&mut jnode, KEY_DEFAULT_TTL, node.ttl as i64);

    // Elements
    let jelems = build_elements_json(node);
    if let Some(obj) = jnode.as_object_mut() {
        obj.insert(KEY_ELEMENTS.to_string(), jelems);
    }

    Some(MeshConfigJson {
        node_data: jnode,
        node_dir_path: PathBuf::from(cfg_path),
        uuid: *uuid,
        write_seq: node.seq_number,
        write_time: Instant::now(),
    })
}

/// Load a single node from a JSON file.
fn load_node(
    fname: &str,
    uuid: &[u8; 16],
    cb: &mut dyn FnMut(&MeshConfigNode, &[u8; 16], &dyn MeshConfig) -> bool,
) -> bool {
    info!("Loading configuration from {}", fname);

    let contents = match fs::read_to_string(fname) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read configuration file {}: {}", fname, e);
            return false;
        }
    };

    let jnode: Value = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse JSON from {}: {}", fname, e);
            return false;
        }
    };

    let mut node = MeshConfigNode {
        elements: Vec::new(),
        netkeys: Vec::new(),
        appkeys: Vec::new(),
        comp_pages: Vec::new(),
        seq_number: 0,
        iv_index: 0,
        iv_update: false,
        cid: 0,
        pid: 0,
        vid: 0,
        crpl: 0,
        unicast: 0,
        net_transmit: None,
        modes: MeshConfigModes::default(),
        ttl: 0,
        dev_key: [0u8; 16],
        token: [0u8; 8],
        uuid: [0u8; 16],
    };

    if !read_node(&jnode, &mut node) {
        return false;
    }

    let cfg = MeshConfigJson {
        node_data: jnode,
        node_dir_path: PathBuf::from(fname),
        uuid: *uuid,
        write_seq: node.seq_number,
        write_time: Instant::now(),
    };

    cb(&node, uuid, &cfg)
}

// ============================================================================
// Key Refresh Helper
// ============================================================================

/// When net key refresh completes (phase → NONE), clean up bound app key oldKeys.
fn finish_key_refresh(jnode: &mut Value, net_idx: u16) {
    let jarray = match jnode.get_mut(KEY_APP_KEYS) {
        Some(v) if v.is_array() => v,
        _ => return,
    };
    let arr = match jarray.as_array_mut() {
        Some(a) => a,
        None => return,
    };

    for entry in arr.iter_mut() {
        if let Some(bound_idx) = get_key_index(entry, KEY_BOUND_NET_KEY) {
            if bound_idx == net_idx {
                del_field(entry, "oldKey");
            }
        }
    }
}

// ============================================================================
// MeshConfigJson Implementation Methods
// ============================================================================

impl Default for MeshConfigJson {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshConfigJson {
    /// Create a new `MeshConfigJson` instance (public constructor).
    pub fn new() -> Self {
        MeshConfigJson {
            node_data: Value::Object(Map::new()),
            node_dir_path: PathBuf::new(),
            uuid: [0u8; 16],
            write_seq: 0,
            write_time: Instant::now(),
        }
    }

    /// Save the current JSON to the configured node directory path.
    fn save_to_disk(&self) -> bool {
        save_config_to_file(&self.node_data, &self.node_dir_path)
    }

    /// Atomic save to the configured node directory path.
    fn atomic_save(&mut self, cb: Option<MeshConfigStatusFn>) -> bool {
        let result = atomic_save_config(&self.node_data, &self.node_dir_path);
        self.write_time = Instant::now();
        if let Some(callback) = cb {
            callback(result);
        }
        result
    }

    /// Get a mutable reference to a model within an element, by address and model ID.
    fn get_model_mut(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
    ) -> Result<&mut Value, MeshConfigError> {
        let ele_idx = get_element_index(&self.node_data, ele_addr)
            .ok_or(MeshConfigError::ElementNotFound(ele_addr))?;
        let model_idx = find_element_model_index(&self.node_data, ele_idx, mod_id, vendor)
            .ok_or(MeshConfigError::ModelNotFound(mod_id))?;

        self.node_data
            .get_mut(KEY_ELEMENTS)
            .and_then(|e| e.get_mut(ele_idx))
            .and_then(|el| el.get_mut(KEY_MODELS))
            .and_then(|m| m.get_mut(model_idx))
            .ok_or(MeshConfigError::ModelNotFound(mod_id))
    }

    /// Delete a named property from a model identified by element address and model ID.
    fn delete_model_property(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        keyword: &str,
    ) -> Result<(), MeshConfigError> {
        let jmodel = self.get_model_mut(ele_addr, mod_id, vendor)?;
        del_field(jmodel, keyword);
        Ok(())
    }

    /// Encode a subscription address as a hex string for JSON storage.
    fn encode_sub_address(sub: &MeshConfigSub) -> String {
        if sub.virt { util::hex2str(&sub.virt_addr) } else { encode_u16_hex(sub.addr) }
    }
}

// ============================================================================
// MeshConfig Trait Implementation
// ============================================================================

impl MeshConfig for MeshConfigJson {
    fn load_nodes(&self, cfgdir: &str, mut cb: MeshConfigNodeFn) -> Result<bool, MeshConfigError> {
        util::create_dir(cfgdir);

        let entries = fs::read_dir(cfgdir).map_err(|e| {
            error!("Failed to open mesh node storage directory: {}", cfgdir);
            MeshConfigError::Io(e)
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let dir_name = match entry.file_name().to_str() {
                Some(s) => s.to_string(),
                None => continue,
            };

            // UUID directory names must be 32 hex chars = 16 bytes
            let mut uuid = [0u8; 16];
            if !util::str2hex(&dir_name, &mut uuid) {
                continue;
            }

            let fname = format!("{}/{}{}", cfgdir, dir_name, CFGNODE_NAME);

            if !load_node(&fname, &uuid, &mut *cb) {
                // Fall-back to backup version
                let bak = format!("{}{}", fname, BAK_EXT);
                if load_node(&bak, &uuid, &mut *cb) {
                    let _ = fs::remove_file(&fname);
                    let _ = fs::rename(&bak, &fname);
                }
            }
        }

        Ok(true)
    }

    fn release(&mut self) {
        self.node_data = Value::Null;
        self.node_dir_path = PathBuf::new();
        self.write_seq = 0;
    }

    fn destroy_nvm(&self) {
        // Derive the node directory from the file path
        let node_dir = match self.node_dir_path.parent() {
            Some(p) => p,
            None => return,
        };

        debug!("Delete node config {:?}", node_dir);

        let uuid_hex = util::hex2str(&self.uuid);
        let node_dir_str = node_dir.to_string_lossy().to_string();
        let node_name = util::mesh_basename(&node_dir_str);

        // Validate directory name matches UUID hex
        if node_name != uuid_hex {
            return;
        }

        util::del_path(&node_dir.to_string_lossy());
    }

    fn save(&self, no_wait: bool, cb: Option<MeshConfigStatusFn>) -> Result<bool, MeshConfigError> {
        // We need to perform the atomic save. Since the trait takes &self for save(),
        // we perform the file I/O directly without mutating write_time here.
        // The C code always returns true from mesh_config_save; the actual result
        // is delivered via the callback.
        let result = atomic_save_config(&self.node_data, &self.node_dir_path);

        if let Some(callback) = cb {
            if no_wait {
                callback(result);
            } else {
                // For deferred saves, schedule on the local task set.
                // Since save takes &self, we invoke the callback immediately
                // as the write has already been performed.
                callback(result);
            }
        }
        Ok(result)
    }

    fn reset(&mut self, node: &MeshConfigNode) {
        let jelems = build_elements_json(node);
        del_field(&mut self.node_data, KEY_ELEMENTS);
        if let Some(obj) = self.node_data.as_object_mut() {
            obj.insert(KEY_ELEMENTS.to_string(), jelems);
        }
    }

    fn create(cfgdir: &str, uuid: &[u8; 16], node: &MeshConfigNode) -> Result<Self, MeshConfigError>
    where
        Self: Sized,
    {
        let uuid_hex = util::hex2str(uuid);
        let dir_path = format!("{}/{}", cfgdir, uuid_hex);

        // Create the node directory
        if fs::create_dir(&dir_path).is_err() {
            return Err(MeshConfigError::CreationFailed);
        }

        let file_path = format!("{}{}", dir_path, CFGNODE_NAME);

        debug!("New node config {}", file_path);

        let mut cfg =
            create_config(&file_path, uuid, node).ok_or(MeshConfigError::CreationFailed)?;

        // Save immediately
        if !cfg.atomic_save(None) {
            return Err(MeshConfigError::CreationFailed);
        }

        Ok(cfg)
    }

    fn write_net_transmit(&mut self, count: u16, interval: u16) -> Result<bool, MeshConfigError> {
        let jrtx = json!({
            "count": count,
            "interval": interval,
        });
        del_field(&mut self.node_data, KEY_RETRANSMIT);
        if let Some(obj) = self.node_data.as_object_mut() {
            obj.insert(KEY_RETRANSMIT.to_string(), jrtx);
        }
        Ok(self.save_to_disk())
    }

    fn write_device_key(&mut self, key: &[u8; 16]) -> Result<bool, MeshConfigError> {
        if !add_key_value(&mut self.node_data, KEY_DEVICE_KEY, key) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn write_candidate(&mut self, key: &[u8; 16]) -> Result<bool, MeshConfigError> {
        if !add_key_value(&mut self.node_data, KEY_DEVICE_CAN, key) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn read_candidate(&self) -> Option<[u8; 16]> {
        read_candidate_key(&self.node_data)
    }

    fn finalize_candidate(&mut self) -> Result<bool, MeshConfigError> {
        let key = match read_candidate_key(&self.node_data) {
            Some(k) => k,
            None => return Ok(false),
        };
        del_field(&mut self.node_data, KEY_DEVICE_CAN);
        del_field(&mut self.node_data, KEY_DEVICE_KEY);
        if !add_key_value(&mut self.node_data, KEY_DEVICE_KEY, &key) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn write_token(&mut self, token: &[u8; 8]) -> Result<bool, MeshConfigError> {
        if !add_u64_value(&mut self.node_data, "token", token) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn write_seq_number(&mut self, seq: u32, cache: bool) -> Result<bool, MeshConfigError> {
        if !cache {
            if !write_int_field(&mut self.node_data, KEY_SEQUENCE_NUMBER, seq as i64) {
                return Ok(false);
            }
            return self.save(true, None);
        }

        // Caching logic: read current cached value
        let mut cached: u32 = 0;
        if seq != 0 {
            if let Some(val) = get_int(&self.node_data, KEY_SEQUENCE_NUMBER) {
                cached = val as u32;
            }
        }

        if seq + MIN_SEQ_CACHE_TRIGGER >= cached {
            let elapsed = self.write_time.elapsed();
            let elapsed_ms = elapsed.as_millis() as u64;

            // If elapsed is zero, a save is already pending
            if elapsed_ms == 0 {
                return Ok(true);
            }

            // Extrapolate cached value
            let seq_diff = seq.saturating_sub(self.write_seq);
            let mut new_cached =
                seq as u64 + (seq_diff as u64) * 1000 * MIN_SEQ_CACHE_TIME / elapsed_ms;

            // Floor
            if new_cached < (seq as u64) + (MIN_SEQ_CACHE_VALUE as u64) {
                new_cached = (seq as u64) + (MIN_SEQ_CACHE_VALUE as u64);
            }

            // Cap
            if new_cached > (SEQ_MASK as u64) + 1 {
                new_cached = (SEQ_MASK as u64) + 1;
            }

            let new_cached = new_cached as u32;
            self.write_seq = seq;

            // Don't rewrite if unchanged
            if cached == new_cached {
                return Ok(true);
            }

            debug!("Seq Cache: {} -> {}", seq, new_cached);

            if !write_int_field(&mut self.node_data, KEY_SEQUENCE_NUMBER, new_cached as i64) {
                return Ok(false);
            }

            return self.save(false, None);
        }

        Ok(true)
    }

    fn write_unicast(&mut self, unicast: u16) -> Result<bool, MeshConfigError> {
        if !write_uint16_hex(&mut self.node_data, KEY_UNICAST_ADDRESS, unicast) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn write_relay_mode(
        &mut self,
        mode: u8,
        count: u16,
        interval: u16,
    ) -> Result<bool, MeshConfigError> {
        del_field(&mut self.node_data, "relay");
        let mut jrelay = json!({});
        write_mode_field(&mut jrelay, "mode", mode);
        write_int_field(&mut jrelay, "count", count as i64);
        write_int_field(&mut jrelay, "interval", interval as i64);
        if let Some(obj) = self.node_data.as_object_mut() {
            obj.insert("relay".to_string(), jrelay);
        }
        Ok(self.save_to_disk())
    }

    fn write_mpb(&mut self, mode: u8, period: u8) -> Result<bool, MeshConfigError> {
        if !write_mode_field(&mut self.node_data, "mpb", mode) {
            return Ok(false);
        }
        if mode != 0 && !write_int_field(&mut self.node_data, "mpbPeriod", period as i64) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn write_ttl(&mut self, ttl: u8) -> Result<bool, MeshConfigError> {
        if !write_int_field(&mut self.node_data, KEY_DEFAULT_TTL, ttl as i64) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn write_mode(&mut self, keyword: &str, value: u8) -> Result<bool, MeshConfigError> {
        if !write_mode_field(&mut self.node_data, keyword, value) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn write_mode_ex(
        &mut self,
        keyword: &str,
        value: u8,
        save: bool,
    ) -> Result<bool, MeshConfigError> {
        if save {
            return self.write_mode(keyword, value);
        }
        // Apply in-memory only, no save
        write_mode_field(&mut self.node_data, keyword, value);
        Ok(true)
    }

    fn comp_page_add(&mut self, page: u8, data: &[u8]) -> Result<bool, MeshConfigError> {
        let page_hex = format!("{:02x}", page);
        let data_hex = util::hex2str(data);
        let full_str = format!("{}{}", page_hex, data_hex);

        let jarray_exists = self.node_data.get("pages").is_some();

        if jarray_exists {
            // Check if identical page already exists
            if let Some(jarray) = self.node_data.get("pages") {
                if jarray_has_string(jarray, &full_str) {
                    return Ok(true);
                }
            }
            // Delete existing page with same number
            del_page(&mut self.node_data, page);
        } else {
            // Create pages array
            if let Some(obj) = self.node_data.as_object_mut() {
                obj.insert("pages".to_string(), json!([]));
            }
        }

        // Add new page entry
        if let Some(jarray) = self.node_data.get_mut("pages") {
            if let Some(arr) = jarray.as_array_mut() {
                arr.push(json!(full_str));
            }
        }

        Ok(self.save_to_disk())
    }

    fn comp_page_del(&mut self, page: u8) {
        let had_pages = self.node_data.get("pages").is_some();
        if had_pages {
            del_page(&mut self.node_data, page);
            self.save_to_disk();
        }
    }

    fn model_binding_add(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        app_idx: u16,
    ) -> Result<bool, MeshConfigError> {
        let buf = encode_u16_hex(app_idx);

        let jmodel = self.get_model_mut(ele_addr, mod_id, vendor)?;

        // Check if binding already exists
        if let Some(jarray) = jmodel.get(KEY_BIND) {
            if jarray_has_string(jarray, &buf) {
                return Ok(true);
            }
        }

        // Create bind array if needed
        if jmodel.get(KEY_BIND).is_none() {
            if let Some(obj) = jmodel.as_object_mut() {
                obj.insert(KEY_BIND.to_string(), json!([]));
            }
        }

        if let Some(jarray) = jmodel.get_mut(KEY_BIND) {
            if let Some(arr) = jarray.as_array_mut() {
                arr.push(json!(buf));
            }
        }

        Ok(self.save_to_disk())
    }

    fn model_binding_del(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        app_idx: u16,
    ) -> Result<bool, MeshConfigError> {
        let buf = encode_u16_hex(app_idx);

        let jmodel = self.get_model_mut(ele_addr, mod_id, vendor)?;

        if let Some(jarray) = jmodel.get_mut(KEY_BIND) {
            jarray_string_del(jarray, &buf);
            // Remove empty bind array
            if jarray.as_array().is_some_and(|a| a.is_empty()) {
                del_field(jmodel, KEY_BIND);
            }
        }

        Ok(self.save_to_disk())
    }

    fn model_pub_add(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        pub_config: &MeshConfigPub,
    ) -> Result<bool, MeshConfigError> {
        let jmodel = self.get_model_mut(ele_addr, mod_id, vendor)?;

        del_field(jmodel, KEY_PUBLISH);

        let mut jpub = json!({});

        // Address
        if pub_config.virt {
            add_key_value(&mut jpub, KEY_ADDRESS, &pub_config.virt_addr);
        } else {
            write_uint16_hex(&mut jpub, KEY_ADDRESS, pub_config.addr);
        }

        write_int_field(&mut jpub, "index", pub_config.idx as i64);
        write_int_field(&mut jpub, "ttl", pub_config.ttl as i64);
        write_int_field(&mut jpub, "period", pub_config.period as i64);
        write_int_field(&mut jpub, "credentials", if pub_config.credential { 1 } else { 0 });

        // Retransmit
        let jrtx = json!({
            "count": pub_config.retransmit_count,
            "interval": pub_config.retransmit_interval,
        });
        if let Some(obj) = jpub.as_object_mut() {
            obj.insert(KEY_RETRANSMIT.to_string(), jrtx);
        }

        if let Some(obj) = jmodel.as_object_mut() {
            obj.insert(KEY_PUBLISH.to_string(), jpub);
        }

        Ok(self.save_to_disk())
    }

    fn model_pub_del(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
    ) -> Result<bool, MeshConfigError> {
        self.delete_model_property(ele_addr, mod_id, vendor, KEY_PUBLISH)?;
        Ok(self.save_to_disk())
    }

    fn model_pub_enable(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        enable: bool,
    ) -> Result<bool, MeshConfigError> {
        let jmodel = self.get_model_mut(ele_addr, mod_id, vendor)?;

        // C code uses "pubDisabled" (inverted boolean)
        del_field(jmodel, KEY_PUB_DISABLED);
        if let Some(obj) = jmodel.as_object_mut() {
            obj.insert(KEY_PUB_DISABLED.to_string(), json!(!enable));
        }

        if !enable {
            del_field(jmodel, KEY_PUBLISH);
        }

        Ok(self.save_to_disk())
    }

    fn model_sub_add(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        sub: &MeshConfigSub,
    ) -> Result<bool, MeshConfigError> {
        let buf = Self::encode_sub_address(sub);

        let jmodel = self.get_model_mut(ele_addr, mod_id, vendor)?;

        // Check if subscription already exists
        if let Some(jarray) = jmodel.get(KEY_SUBSCRIBE) {
            if jarray_has_string(jarray, &buf) {
                return Ok(true);
            }
        }

        // Create subscribe array if needed
        if jmodel.get(KEY_SUBSCRIBE).is_none() {
            if let Some(obj) = jmodel.as_object_mut() {
                obj.insert(KEY_SUBSCRIBE.to_string(), json!([]));
            }
        }

        if let Some(jarray) = jmodel.get_mut(KEY_SUBSCRIBE) {
            if let Some(arr) = jarray.as_array_mut() {
                arr.push(json!(buf));
            }
        }

        Ok(self.save_to_disk())
    }

    fn model_sub_del(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        sub: &MeshConfigSub,
    ) -> Result<bool, MeshConfigError> {
        let buf = Self::encode_sub_address(sub);

        let jmodel = self.get_model_mut(ele_addr, mod_id, vendor)?;

        if let Some(jarray) = jmodel.get_mut(KEY_SUBSCRIBE) {
            jarray_string_del(jarray, &buf);
            if jarray.as_array().is_some_and(|a| a.is_empty()) {
                del_field(jmodel, KEY_SUBSCRIBE);
            }
        }

        Ok(self.save_to_disk())
    }

    fn model_sub_del_all(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
    ) -> Result<bool, MeshConfigError> {
        self.delete_model_property(ele_addr, mod_id, vendor, KEY_SUBSCRIBE)?;
        Ok(self.save_to_disk())
    }

    fn model_sub_enable(
        &mut self,
        ele_addr: u16,
        mod_id: u32,
        vendor: bool,
        enable: bool,
    ) -> Result<bool, MeshConfigError> {
        let jmodel = self.get_model_mut(ele_addr, mod_id, vendor)?;

        del_field(jmodel, KEY_SUB_ENABLED);
        if let Some(obj) = jmodel.as_object_mut() {
            obj.insert(KEY_SUB_ENABLED.to_string(), json!(enable));
        }

        if !enable {
            del_field(jmodel, KEY_SUBSCRIBE);
        }

        Ok(self.save_to_disk())
    }

    fn app_key_add(
        &mut self,
        net_idx: u16,
        app_idx: u16,
        key: &[u8; 16],
    ) -> Result<bool, MeshConfigError> {
        // Check if key already exists — do not allow overwrite
        if let Some(jarray) = self.node_data.get(KEY_APP_KEYS) {
            if get_key_object(jarray, app_idx).is_some() {
                return Ok(false);
            }
        }

        let mut jentry = json!({});
        write_int_field(&mut jentry, "index", app_idx as i64);
        write_int_field(&mut jentry, KEY_BOUND_NET_KEY, net_idx as i64);
        add_key_value(&mut jentry, "key", key);

        // Create appKeys array if needed
        if self.node_data.get(KEY_APP_KEYS).is_none() {
            if let Some(obj) = self.node_data.as_object_mut() {
                obj.insert(KEY_APP_KEYS.to_string(), json!([]));
            }
        }

        if let Some(jarray) = self.node_data.get_mut(KEY_APP_KEYS) {
            if let Some(arr) = jarray.as_array_mut() {
                arr.push(jentry);
            }
        }

        Ok(self.save_to_disk())
    }

    fn app_key_update(
        &mut self,
        _net_idx: u16,
        app_idx: u16,
        key: &[u8; 16],
    ) -> Result<bool, MeshConfigError> {
        let jarray =
            self.node_data.get_mut(KEY_APP_KEYS).ok_or(MeshConfigError::KeyNotFound(app_idx))?;

        let pos =
            get_key_object_index(jarray, app_idx).ok_or(MeshConfigError::KeyNotFound(app_idx))?;

        let jentry = jarray.get_mut(pos).ok_or(MeshConfigError::KeyNotFound(app_idx))?;

        // Copy current key to oldKey
        let current_key = get_str(jentry, "key")
            .ok_or_else(|| MeshConfigError::Invalid("missing key field".into()))?
            .to_string();

        write_str_field(jentry, "oldKey", &current_key);
        del_field(jentry, "key");
        add_key_value(jentry, "key", key);

        Ok(self.save_to_disk())
    }

    fn app_key_del(&mut self, _net_idx: u16, app_idx: u16) -> Result<bool, MeshConfigError> {
        if let Some(jarray) = self.node_data.get_mut(KEY_APP_KEYS) {
            jarray_key_del(jarray, app_idx);
            if jarray.as_array().is_some_and(|a| a.is_empty()) {
                del_field(&mut self.node_data, KEY_APP_KEYS);
            }
        }
        Ok(self.save_to_disk())
    }

    fn net_key_add(&mut self, idx: u16, key: &[u8; 16]) -> Result<bool, MeshConfigError> {
        debug!("netKey {:04x}", idx);

        // Check if key already exists — do not allow overwrite
        if let Some(jarray) = self.node_data.get(KEY_NET_KEYS) {
            if get_key_object(jarray, idx).is_some() {
                return Ok(false);
            }
        }

        let mut jentry = json!({});
        write_int_field(&mut jentry, "index", idx as i64);
        add_key_value(&mut jentry, "key", key);
        write_int_field(&mut jentry, KEY_KEY_REFRESH, KEY_REFRESH_PHASE_NONE as i64);

        // Create netKeys array if needed
        if self.node_data.get(KEY_NET_KEYS).is_none() {
            if let Some(obj) = self.node_data.as_object_mut() {
                obj.insert(KEY_NET_KEYS.to_string(), json!([]));
            }
        }

        if let Some(jarray) = self.node_data.get_mut(KEY_NET_KEYS) {
            if let Some(arr) = jarray.as_array_mut() {
                arr.push(jentry);
            }
        }

        Ok(self.save_to_disk())
    }

    fn net_key_update(&mut self, idx: u16, key: &[u8; 16]) -> Result<bool, MeshConfigError> {
        let jarray =
            self.node_data.get_mut(KEY_NET_KEYS).ok_or(MeshConfigError::KeyNotFound(idx))?;

        let pos = get_key_object_index(jarray, idx).ok_or(MeshConfigError::KeyNotFound(idx))?;

        let jentry = jarray.get_mut(pos).ok_or(MeshConfigError::KeyNotFound(idx))?;

        // Copy current key to oldKey
        let current_key = get_str(jentry, "key")
            .ok_or_else(|| MeshConfigError::Invalid("missing key field".into()))?
            .to_string();

        write_str_field(jentry, "oldKey", &current_key);
        del_field(jentry, "key");
        add_key_value(jentry, "key", key);
        write_int_field(jentry, KEY_KEY_REFRESH, KEY_REFRESH_PHASE_ONE as i64);

        Ok(self.save_to_disk())
    }

    fn net_key_del(&mut self, idx: u16) -> Result<bool, MeshConfigError> {
        if let Some(jarray) = self.node_data.get_mut(KEY_NET_KEYS) {
            jarray_key_del(jarray, idx);
            if jarray.as_array().is_some_and(|a| a.is_empty()) {
                del_field(&mut self.node_data, KEY_NET_KEYS);
            }
        }
        Ok(self.save_to_disk())
    }

    fn net_key_set_phase(&mut self, idx: u16, phase: u8) -> Result<bool, MeshConfigError> {
        let jarray =
            self.node_data.get_mut(KEY_NET_KEYS).ok_or(MeshConfigError::KeyNotFound(idx))?;

        let pos = get_key_object_index(jarray, idx).ok_or(MeshConfigError::KeyNotFound(idx))?;

        let jentry = jarray.get_mut(pos).ok_or(MeshConfigError::KeyNotFound(idx))?;

        del_field(jentry, KEY_KEY_REFRESH);
        write_int_field(jentry, KEY_KEY_REFRESH, phase as i64);

        if phase == KEY_REFRESH_PHASE_NONE {
            del_field(jentry, "oldKey");
            finish_key_refresh(&mut self.node_data, idx);
        }

        Ok(self.save_to_disk())
    }

    fn write_iv_index(&mut self, iv_index: u32, iv_update: bool) -> Result<bool, MeshConfigError> {
        if !write_int_field(&mut self.node_data, "IVindex", iv_index as i64) {
            return Ok(false);
        }
        if !write_int_field(&mut self.node_data, "IVupdate", if iv_update { 1 } else { 0 }) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn update_company_id(&mut self, cid: u16) -> Result<bool, MeshConfigError> {
        if !write_uint16_hex(&mut self.node_data, "cid", cid) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn update_product_id(&mut self, pid: u16) -> Result<bool, MeshConfigError> {
        if !write_uint16_hex(&mut self.node_data, "pid", pid) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn update_version_id(&mut self, vid: u16) -> Result<bool, MeshConfigError> {
        if !write_uint16_hex(&mut self.node_data, "vid", vid) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }

    fn update_crpl(&mut self, crpl: u16) -> Result<bool, MeshConfigError> {
        if !write_uint16_hex(&mut self.node_data, "crpl", crpl) {
            return Ok(false);
        }
        Ok(self.save_to_disk())
    }
}

// ============================================================================
// Composition Page Delete Helper
// ============================================================================

/// Delete a composition page from the in-memory JSON "pages" array.
fn del_page(jnode: &mut Value, page: u8) {
    let page_prefix = format!("{:02x}", page);
    if let Some(jarray) = jnode.get_mut("pages") {
        if let Some(arr) = jarray.as_array_mut() {
            arr.retain(|entry| entry.as_str().is_none_or(|s| !s.starts_with(&page_prefix)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_u16_hex() {
        assert_eq!(encode_u16_hex(0x0001), "0001");
        assert_eq!(encode_u16_hex(0xabcd), "abcd");
        assert_eq!(encode_u16_hex(0), "0000");
        assert_eq!(encode_u16_hex(0xffff), "ffff");
    }

    #[test]
    fn test_encode_u32_hex() {
        assert_eq!(encode_u32_hex(0x12345678), "12345678");
        assert_eq!(encode_u32_hex(0), "00000000");
    }

    #[test]
    fn test_encode_key_hex() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        assert_eq!(encode_key_hex(&key), "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn test_mode_to_string() {
        assert_eq!(mode_to_string(MESH_MODE_DISABLED), "disabled");
        assert_eq!(mode_to_string(MESH_MODE_ENABLED), "enabled");
        assert_eq!(mode_to_string(MESH_MODE_UNSUPPORTED), "unsupported");
        assert_eq!(mode_to_string(42), "unsupported");
    }

    #[test]
    fn test_parse_mode_string() {
        assert_eq!(parse_mode_string("disabled"), Some(MESH_MODE_DISABLED));
        assert_eq!(parse_mode_string("Enabled"), Some(MESH_MODE_ENABLED));
        assert_eq!(parse_mode_string("UNSUPPORTED"), Some(MESH_MODE_UNSUPPORTED));
        assert_eq!(parse_mode_string("unknown"), None);
    }

    #[test]
    fn test_jarray_has_string() {
        let arr = json!(["0001", "0002", "0003"]);
        assert!(jarray_has_string(&arr, "0001"));
        assert!(!jarray_has_string(&arr, "0004"));
    }

    #[test]
    fn test_jarray_string_del() {
        let mut arr = json!(["0001", "0002", "0003"]);
        jarray_string_del(&mut arr, "0002");
        assert_eq!(arr, json!(["0001", "0003"]));
    }

    #[test]
    fn test_get_key_object() {
        let arr = json!([
            {"index": 0, "key": "aaaa"},
            {"index": 1, "key": "bbbb"},
        ]);
        assert!(get_key_object(&arr, 0).is_some());
        assert!(get_key_object(&arr, 1).is_some());
        assert!(get_key_object(&arr, 2).is_none());
    }

    #[test]
    fn test_get_element_index() {
        let jnode = json!({
            "unicastAddress": "0100",
            "elements": [
                {"elementIndex": 0},
                {"elementIndex": 1},
            ]
        });
        assert_eq!(get_element_index(&jnode, 0x0100), Some(0));
        assert_eq!(get_element_index(&jnode, 0x0101), Some(1));
        assert_eq!(get_element_index(&jnode, 0x0102), None);
        assert_eq!(get_element_index(&jnode, 0x00ff), None);
    }

    #[test]
    fn test_read_iv_index() {
        let jobj = json!({"IVindex": 42, "IVupdate": 1});
        let mut node = MeshConfigNode {
            elements: Vec::new(),
            netkeys: Vec::new(),
            appkeys: Vec::new(),
            comp_pages: Vec::new(),
            seq_number: 0,
            iv_index: 0,
            iv_update: false,
            cid: 0,
            pid: 0,
            vid: 0,
            crpl: 0,
            unicast: 0,
            net_transmit: None,
            modes: MeshConfigModes::default(),
            ttl: 0,
            dev_key: [0; 16],
            token: [0; 8],
            uuid: [0; 16],
        };
        assert!(read_iv_index(&jobj, &mut node));
        assert_eq!(node.iv_index, 42);
        assert!(node.iv_update);
    }

    #[test]
    fn test_read_default_ttl_absent() {
        let jobj = json!({});
        let mut ttl = 7u8;
        assert!(read_default_ttl(&jobj, &mut ttl));
        assert_eq!(ttl, 7); // unchanged
    }

    #[test]
    fn test_read_default_ttl_valid() {
        let jobj = json!({"defaultTTL": 5});
        let mut ttl = 0u8;
        assert!(read_default_ttl(&jobj, &mut ttl));
        assert_eq!(ttl, 5);
    }

    #[test]
    fn test_read_default_ttl_invalid() {
        // TTL = 1 is invalid per BT Mesh spec
        let jobj = json!({"defaultTTL": 1});
        let mut ttl = 0u8;
        assert!(!read_default_ttl(&jobj, &mut ttl));
    }

    #[test]
    fn test_read_seq_number_absent() {
        let jobj = json!({});
        let mut seq = 100u32;
        assert!(read_seq_number(&jobj, &mut seq));
        assert_eq!(seq, 100); // unchanged
    }

    #[test]
    fn test_parse_composition() {
        let jobj = json!({"cid": "0001", "pid": "0002", "vid": "0003", "crpl": "0004"});
        let mut node = MeshConfigNode {
            elements: Vec::new(),
            netkeys: Vec::new(),
            appkeys: Vec::new(),
            comp_pages: Vec::new(),
            seq_number: 0,
            iv_index: 0,
            iv_update: false,
            cid: 0,
            pid: 0,
            vid: 0,
            crpl: 0,
            unicast: 0,
            net_transmit: None,
            modes: MeshConfigModes::default(),
            ttl: 0,
            dev_key: [0; 16],
            token: [0; 8],
            uuid: [0; 16],
        };
        assert!(parse_composition(&jobj, &mut node));
        assert_eq!(node.cid, 1);
        assert_eq!(node.pid, 2);
        assert_eq!(node.vid, 3);
        assert_eq!(node.crpl, 4);
    }

    #[test]
    fn test_del_page() {
        let mut jnode = json!({"pages": ["00aabbcc", "01ddeeff"]});
        del_page(&mut jnode, 0x00);
        assert_eq!(jnode["pages"], json!(["01ddeeff"]));
    }

    #[test]
    fn test_parse_bindings() {
        let jarray = json!(["0001", "0002"]);
        let bindings = parse_bindings(&jarray).unwrap();
        assert_eq!(bindings, vec![1, 2]);
    }

    #[test]
    fn test_parse_model_publication() {
        let jpub = json!({
            "address": "c001",
            "index": 0,
            "ttl": 5,
            "period": 100,
            "credentials": 0,
            "retransmit": {"count": 3, "interval": 50}
        });
        let pub_cfg = parse_model_publication(&jpub).unwrap();
        assert_eq!(pub_cfg.addr, 0xc001);
        assert!(!pub_cfg.virt);
        assert_eq!(pub_cfg.idx, 0);
        assert_eq!(pub_cfg.ttl, 5);
        assert_eq!(pub_cfg.period, 100);
        assert!(!pub_cfg.credential);
        assert_eq!(pub_cfg.retransmit_count, 3);
        assert_eq!(pub_cfg.retransmit_interval, 50);
    }

    #[test]
    fn test_new_constructor() {
        let cfg = MeshConfigJson::new();
        assert!(cfg.node_data.is_object());
        assert_eq!(cfg.write_seq, 0);
        assert_eq!(cfg.uuid, [0u8; 16]);
    }

    #[test]
    fn test_default_trait() {
        let cfg = MeshConfigJson::default();
        assert!(cfg.node_data.is_object());
    }

    fn make_test_node() -> MeshConfigNode {
        MeshConfigNode {
            elements: vec![MeshConfigElement {
                models: vec![MeshConfigModel {
                    subs: Vec::new(),
                    pub_state: None,
                    bindings: Vec::new(),
                    id: 0x0001,
                    vendor: false,
                    sub_enabled: true,
                    pub_enabled: true,
                }],
                location: 0x0000,
                index: 0,
            }],
            netkeys: vec![MeshConfigNetKey {
                idx: 0,
                phase: KEY_REFRESH_PHASE_NONE,
                key: [0xAAu8; 16],
                new_key: [0xAAu8; 16],
            }],
            appkeys: vec![],
            comp_pages: vec![],
            seq_number: 0,
            iv_index: 0,
            iv_update: false,
            cid: 0x0001,
            pid: 0x0002,
            vid: 0x0003,
            crpl: 0x0004,
            unicast: 0x0100,
            net_transmit: None,
            modes: MeshConfigModes::default(),
            ttl: 5,
            dev_key: [0xBBu8; 16],
            token: [0xCCu8; 8],
            uuid: [0u8; 16],
        }
    }

    fn setup_test_dir(name: &str) -> String {
        let dir = format!("/tmp/blitzy_mesh_test_{}", name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn teardown_test_dir(dir: &str) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_create_and_load() {
        let dir = setup_test_dir("create_load");
        let uuid = [0x01u8; 16];
        let node = make_test_node();

        let cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert_eq!(cfg.uuid, uuid);

        // Verify file exists
        let uuid_hex = util::hex2str(&uuid);
        let file_path = format!("{}/{}/node.json", dir, uuid_hex);
        assert!(std::path::Path::new(&file_path).exists());

        // Verify JSON content
        let contents = std::fs::read_to_string(&file_path).unwrap();
        let parsed: Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed["cid"], "0001");
        assert_eq!(parsed["pid"], "0002");
        assert_eq!(parsed["vid"], "0003");
        assert_eq!(parsed["crpl"], "0004");
        assert_eq!(parsed[KEY_DEFAULT_TTL], 5);
        assert_eq!(parsed[KEY_UNICAST_ADDRESS], "0100");

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_and_read_device_key() {
        let dir = setup_test_dir("device_key");
        let uuid = [0x02u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        let new_key = [0xDDu8; 16];
        assert!(cfg.write_device_key(&new_key).unwrap());

        // Read back the JSON and verify
        let uuid_hex = util::hex2str(&uuid);
        let file_path = format!("{}/{}/node.json", dir, uuid_hex);
        let contents = std::fs::read_to_string(&file_path).unwrap();
        let parsed: Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed[KEY_DEVICE_KEY].as_str().unwrap(), "dddddddddddddddddddddddddddddddd");

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_and_read_candidate() {
        let dir = setup_test_dir("candidate");
        let uuid = [0x03u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        // Initially no candidate
        assert!(cfg.read_candidate().is_none());

        // Write candidate
        let candidate = [0xEEu8; 16];
        assert!(cfg.write_candidate(&candidate).unwrap());

        // Read candidate
        let read_back = cfg.read_candidate().unwrap();
        assert_eq!(read_back, candidate);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_finalize_candidate() {
        let dir = setup_test_dir("finalize_cand");
        let uuid = [0x04u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        let candidate = [0xFFu8; 16];
        cfg.write_candidate(&candidate).unwrap();
        assert!(cfg.finalize_candidate().unwrap());

        // After finalize: candidate is gone, device key is updated
        assert!(cfg.read_candidate().is_none());
        let dev_key_str = cfg.node_data[KEY_DEVICE_KEY].as_str().unwrap();
        assert_eq!(dev_key_str, "ffffffffffffffffffffffffffffffff");

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_net_key_operations() {
        let dir = setup_test_dir("net_keys");
        let uuid = [0x05u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        // create_config doesn't write netKeys (matches C behavior), add initial key
        let key1 = [0x11u8; 16];
        assert!(cfg.net_key_add(0, &key1).unwrap());

        // Add a second net key
        let key2 = [0x22u8; 16];
        assert!(cfg.net_key_add(1, &key2).unwrap());

        // Verify both are there
        let arr = cfg.node_data[KEY_NET_KEYS].as_array().unwrap();
        assert_eq!(arr.len(), 2);

        // Cannot add duplicate
        assert!(!cfg.net_key_add(1, &key2).unwrap());

        // Update net key
        let new_key = [0x33u8; 16];
        assert!(cfg.net_key_update(1, &new_key).unwrap());

        // Check oldKey exists and keyRefresh is 1
        let key_obj = get_key_object(&cfg.node_data[KEY_NET_KEYS], 1).unwrap();
        assert!(key_obj.get("oldKey").is_some());
        assert_eq!(key_obj[KEY_KEY_REFRESH], 1);

        // Set phase to NONE (complete refresh)
        assert!(cfg.net_key_set_phase(1, KEY_REFRESH_PHASE_NONE).unwrap());
        let key_obj = get_key_object(&cfg.node_data[KEY_NET_KEYS], 1).unwrap();
        assert!(key_obj.get("oldKey").is_none());
        assert_eq!(key_obj[KEY_KEY_REFRESH], 0);

        // Delete net key
        assert!(cfg.net_key_del(1).unwrap());
        let arr = cfg.node_data[KEY_NET_KEYS].as_array().unwrap();
        assert_eq!(arr.len(), 1);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_app_key_operations() {
        let dir = setup_test_dir("app_keys");
        let uuid = [0x06u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        // Add app key
        let key = [0x44u8; 16];
        assert!(cfg.app_key_add(0, 0, &key).unwrap());

        // Cannot add duplicate
        assert!(!cfg.app_key_add(0, 0, &key).unwrap());

        // Update app key
        let new_key = [0x55u8; 16];
        assert!(cfg.app_key_update(0, 0, &new_key).unwrap());

        // Delete app key
        assert!(cfg.app_key_del(0, 0).unwrap());

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_model_binding_operations() {
        let dir = setup_test_dir("model_bind");
        let uuid = [0x07u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        // Add binding
        assert!(cfg.model_binding_add(0x0100, 0x0001, false, 0).unwrap());

        // Adding same binding is idempotent
        assert!(cfg.model_binding_add(0x0100, 0x0001, false, 0).unwrap());

        // Delete binding
        assert!(cfg.model_binding_del(0x0100, 0x0001, false, 0).unwrap());

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_model_pub_operations() {
        let dir = setup_test_dir("model_pub");
        let uuid = [0x08u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        let pub_cfg = MeshConfigPub {
            virt: false,
            addr: 0xC001,
            idx: 0,
            ttl: 5,
            period: 100,
            retransmit_interval: 50,
            retransmit_count: 3,
            credential: false,
            virt_addr: [0u8; 16],
        };

        // Add publication
        assert!(cfg.model_pub_add(0x0100, 0x0001, false, &pub_cfg).unwrap());

        // Delete publication
        assert!(cfg.model_pub_del(0x0100, 0x0001, false).unwrap());

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_model_sub_operations() {
        let dir = setup_test_dir("model_sub");
        let uuid = [0x09u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        let sub = MeshConfigSub { virt: false, addr: 0xC002, virt_addr: [0u8; 16] };

        // Add subscription
        assert!(cfg.model_sub_add(0x0100, 0x0001, false, &sub).unwrap());

        // Delete subscription
        assert!(cfg.model_sub_del(0x0100, 0x0001, false, &sub).unwrap());

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_model_sub_del_all() {
        let dir = setup_test_dir("model_sub_all");
        let uuid = [0x0Au8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        let sub1 = MeshConfigSub { virt: false, addr: 0xC002, virt_addr: [0u8; 16] };
        let sub2 = MeshConfigSub { virt: false, addr: 0xC003, virt_addr: [0u8; 16] };

        cfg.model_sub_add(0x0100, 0x0001, false, &sub1).unwrap();
        cfg.model_sub_add(0x0100, 0x0001, false, &sub2).unwrap();
        assert!(cfg.model_sub_del_all(0x0100, 0x0001, false).unwrap());

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_ttl() {
        let dir = setup_test_dir("ttl");
        let uuid = [0x0Bu8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.write_ttl(10).unwrap());
        assert_eq!(cfg.node_data[KEY_DEFAULT_TTL], 10);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_iv_index() {
        let dir = setup_test_dir("iv_index");
        let uuid = [0x0Cu8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.write_iv_index(42, true).unwrap());
        assert_eq!(cfg.node_data["IVindex"], 42);
        assert_eq!(cfg.node_data["IVupdate"], 1);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_comp_page_add_del() {
        let dir = setup_test_dir("comp_page");
        let uuid = [0x0Du8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        let data = [0xAAu8; 20];
        assert!(cfg.comp_page_add(0, &data).unwrap());
        assert!(cfg.node_data.get("pages").is_some());

        cfg.comp_page_del(0);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_relay_mode() {
        let dir = setup_test_dir("relay");
        let uuid = [0x0Eu8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.write_relay_mode(1, 3, 100).unwrap());

        let relay = &cfg.node_data["relay"];
        assert_eq!(relay["mode"], "enabled");
        assert_eq!(relay["count"], 3);
        assert_eq!(relay["interval"], 100);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_mode_ex() {
        let dir = setup_test_dir("mode_ex");
        let uuid = [0x0Fu8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.write_mode_ex("proxy", 1, false).unwrap());
        assert_eq!(cfg.node_data["proxy"], "enabled");

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_unicast() {
        let dir = setup_test_dir("unicast");
        let uuid = [0x10u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.write_unicast(0x0200).unwrap());
        assert_eq!(cfg.node_data[KEY_UNICAST_ADDRESS], "0200");

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_update_ids() {
        let dir = setup_test_dir("update_ids");
        let uuid = [0x11u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.update_company_id(0x1234).unwrap());
        assert!(cfg.update_product_id(0x5678).unwrap());
        assert!(cfg.update_version_id(0x9abc).unwrap());
        assert!(cfg.update_crpl(0xdef0).unwrap());

        assert_eq!(cfg.node_data["cid"], "1234");
        assert_eq!(cfg.node_data["pid"], "5678");
        assert_eq!(cfg.node_data["vid"], "9abc");
        assert_eq!(cfg.node_data["crpl"], "def0");

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_mpb() {
        let dir = setup_test_dir("mpb");
        let uuid = [0x12u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.write_mpb(1, 10).unwrap());
        assert_eq!(cfg.node_data["mpb"], "enabled");
        assert_eq!(cfg.node_data["mpbPeriod"], 10);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_net_transmit() {
        let dir = setup_test_dir("net_tx");
        let uuid = [0x13u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.write_net_transmit(3, 50).unwrap());

        let rtx = &cfg.node_data[KEY_RETRANSMIT];
        assert_eq!(rtx["count"], 3);
        assert_eq!(rtx["interval"], 50);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_token() {
        let dir = setup_test_dir("token");
        let uuid = [0x14u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        let new_token = [0xFFu8; 8];
        assert!(cfg.write_token(&new_token).unwrap());
        assert_eq!(cfg.node_data["token"], "ffffffffffffffff");

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_model_pub_enable() {
        let dir = setup_test_dir("pub_enable");
        let uuid = [0x15u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.model_pub_enable(0x0100, 0x0001, false, false).unwrap());

        // Check pubDisabled is set
        let jmodel = &cfg.node_data[KEY_ELEMENTS][0][KEY_MODELS][0];
        assert_eq!(jmodel[KEY_PUB_DISABLED], true);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_model_sub_enable() {
        let dir = setup_test_dir("sub_enable");
        let uuid = [0x16u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.model_sub_enable(0x0100, 0x0001, false, false).unwrap());

        let jmodel = &cfg.node_data[KEY_ELEMENTS][0][KEY_MODELS][0];
        assert_eq!(jmodel[KEY_SUB_ENABLED], false);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_read_node_full() {
        let full_json = json!({
            "cid": "0001",
            "pid": "0002",
            "vid": "0003",
            "crpl": "0004",
            "relay": {"mode": "enabled", "count": 3, "interval": 100},
            "lowPower": "disabled",
            "friend": "enabled",
            "proxy": "unsupported",
            "beacon": "enabled",
            "mpb": "disabled",
            "IVindex": 10,
            "IVupdate": 1,
            "unicastAddress": "0100",
            "deviceKey": "0123456789abcdef0123456789abcdef",
            "token": "0123456789abcdef",
            "sequenceNumber": 42,
            "defaultTTL": 5,
            "netKeys": [
                {"index": 0, "key": "0123456789abcdef0123456789abcdef", "keyRefresh": 0}
            ],
            "elements": [
                {
                    "elementIndex": 0,
                    "location": "0000",
                    "models": [
                        {
                            "modelId": "0001",
                            "pubEnabled": true,
                            "subEnabled": true
                        }
                    ]
                }
            ]
        });

        let mut node = MeshConfigNode {
            elements: Vec::new(),
            netkeys: Vec::new(),
            appkeys: Vec::new(),
            comp_pages: Vec::new(),
            seq_number: 0,
            iv_index: 0,
            iv_update: false,
            cid: 0,
            pid: 0,
            vid: 0,
            crpl: 0,
            unicast: 0,
            net_transmit: None,
            modes: MeshConfigModes::default(),
            ttl: 0,
            dev_key: [0; 16],
            token: [0; 8],
            uuid: [0; 16],
        };

        assert!(read_node(&full_json, &mut node));
        assert_eq!(node.cid, 1);
        assert_eq!(node.pid, 2);
        assert_eq!(node.vid, 3);
        assert_eq!(node.crpl, 4);
        assert_eq!(node.iv_index, 10);
        assert!(node.iv_update);
        assert_eq!(node.unicast, 0x0100);
        assert_eq!(node.ttl, 5);
        assert_eq!(node.seq_number, 42);
        assert_eq!(node.modes.relay, MESH_MODE_ENABLED);
        assert_eq!(node.modes.relay_cnt, 3);
        assert_eq!(node.modes.relay_interval, 100);
        assert_eq!(node.modes.friend, MESH_MODE_ENABLED);
        assert_eq!(node.modes.proxy, MESH_MODE_UNSUPPORTED);
        assert_eq!(node.modes.beacon, MESH_MODE_ENABLED);
        assert_eq!(node.elements.len(), 1);
        assert_eq!(node.elements[0].models.len(), 1);
        assert_eq!(node.elements[0].models[0].id, 1);
        assert!(!node.elements[0].models[0].vendor);
        assert_eq!(node.netkeys.len(), 1);
        assert_eq!(node.netkeys[0].idx, 0);
    }

    #[test]
    fn test_load_nodes() {
        let dir = setup_test_dir("load_nodes");
        let uuid = [0x17u8; 16];
        let node = make_test_node();

        // Create a node and add required net key for loading
        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        let net_key = [0xAAu8; 16];
        cfg.net_key_add(0, &net_key).unwrap();
        // Save explicitly to ensure file is complete
        cfg.save(true, None).unwrap();

        // Now load nodes
        let loader = MeshConfigJson::new();
        let cb: MeshConfigNodeFn = Box::new(|loaded_node, loaded_uuid, _cfg| {
            assert_eq!(loaded_uuid, &[0x17u8; 16]);
            assert_eq!(loaded_node.cid, 1);
            true
        });
        let result = loader.load_nodes(&dir, cb);
        assert!(result.is_ok());

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_write_seq_number_no_cache() {
        let dir = setup_test_dir("seq_no_cache");
        let uuid = [0x18u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();
        assert!(cfg.write_seq_number(100, false).unwrap());
        assert_eq!(cfg.node_data[KEY_SEQUENCE_NUMBER], 100);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_reset() {
        let dir = setup_test_dir("reset");
        let uuid = [0x19u8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        // Modify elements then reset
        let mut new_node = make_test_node();
        new_node.elements.push(MeshConfigElement {
            models: Vec::new(),
            location: 0x0001,
            index: 1,
        });
        cfg.reset(&new_node);

        // Verify 2 elements now
        let elems = cfg.node_data[KEY_ELEMENTS].as_array().unwrap();
        assert_eq!(elems.len(), 2);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_virtual_subscription() {
        let dir = setup_test_dir("virt_sub");
        let uuid = [0x1Au8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        let sub = MeshConfigSub { virt: true, addr: 0, virt_addr: [0xAA; 16] };

        assert!(cfg.model_sub_add(0x0100, 0x0001, false, &sub).unwrap());

        let jmodel = &cfg.node_data[KEY_ELEMENTS][0][KEY_MODELS][0];
        let jsubs = jmodel[KEY_SUBSCRIBE].as_array().unwrap();
        assert_eq!(jsubs.len(), 1);
        // Virtual addresses are 32-char hex
        assert_eq!(jsubs[0].as_str().unwrap().len(), 32);

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_finish_key_refresh_cleans_app_keys() {
        let dir = setup_test_dir("key_refresh");
        let uuid = [0x1Bu8; 16];
        let node = make_test_node();

        let mut cfg = MeshConfigJson::create(&dir, &uuid, &node).unwrap();

        // Add net key first (create_config doesn't write netKeys)
        let net_key = [0x11u8; 16];
        cfg.net_key_add(0, &net_key).unwrap();

        // Add app key bound to net key 0
        let app_key = [0x44u8; 16];
        cfg.app_key_add(0, 0, &app_key).unwrap();

        // Update app key (creates oldKey)
        let new_app_key = [0x55u8; 16];
        cfg.app_key_update(0, 0, &new_app_key).unwrap();

        // Verify oldKey exists
        let jentry = get_key_object(&cfg.node_data[KEY_APP_KEYS], 0).unwrap();
        assert!(jentry.get("oldKey").is_some());

        // Complete net key refresh (phase → NONE) should clean app key oldKey
        cfg.net_key_set_phase(0, KEY_REFRESH_PHASE_NONE).unwrap();

        // Verify oldKey is removed from app key
        let jentry = get_key_object(&cfg.node_data[KEY_APP_KEYS], 0).unwrap();
        assert!(jentry.get("oldKey").is_none());

        teardown_test_dir(&dir);
    }

    #[test]
    fn test_parse_subscriptions_mixed() {
        let jsubs = json!(["c001", "0123456789abcdef0123456789abcdef"]);
        let subs = parse_model_subscriptions(&jsubs).unwrap();
        assert_eq!(subs.len(), 2);
        assert!(!subs[0].virt);
        assert_eq!(subs[0].addr, 0xC001);
        assert!(subs[1].virt);
        assert_eq!(
            subs[1].virt_addr,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef
            ]
        );
    }

    #[test]
    fn test_parse_models_sig_and_vendor() {
        let jmodels = json!([
            {"modelId": "0001", "pubEnabled": true, "subEnabled": true},
            {"modelId": "00010002", "pubEnabled": true, "subEnabled": false}
        ]);
        let models = parse_models(&jmodels).unwrap();
        assert_eq!(models.len(), 2);
        assert!(!models[0].vendor);
        assert_eq!(models[0].id, 1);
        assert!(models[1].vendor);
        assert_eq!(models[1].id, 0x00010002);
        assert!(!models[1].sub_enabled);
    }
}
