// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
// Copyright (C) 2017-2019 Intel Corporation. All rights reserved.
//
// Complete Rust rewrite of `mesh/cfgmod-server.c` (1136 lines) and
// `mesh/cfgmod.h` (89 lines) from BlueZ v5.86.
//
// Implements the Configuration Server model opcode dispatcher: key management
// (NetKey/AppKey add/update/delete/get/list), model bindings,
// publication/subscription, default TTL, relay/proxy/friend/beacon features,
// heartbeat pub/sub, network transmit, composition data, key refresh phase,
// node identity, and Node Reset.

//! Configuration Server Model for the Bluetooth Mesh daemon.
//!
//! This module defines every Configuration Model opcode constant and provides
//! the complete opcode dispatcher that handles all incoming Config messages.
//! Registration is performed via [`cfgmod_server_init`].

use std::sync::Arc;

use tracing::debug;

use crate::appkey::{appkey_key_add, appkey_key_delete, appkey_key_update, appkey_list};
use crate::config::MeshConfigPub;
use crate::mesh::{
    APP_IDX_DEV_LOCAL, APP_IDX_MASK, DEFAULT_TTL, KEY_REFRESH_TRANS_THREE, KEY_REFRESH_TRANS_TWO,
    MAX_MSG_LEN, MESH_MODE_ENABLED, MESH_STATUS_CANNOT_SET, MESH_STATUS_INVALID_ADDRESS,
    MESH_STATUS_INVALID_MODEL, MESH_STATUS_SUCCESS, NET_IDX_MAX, UNASSIGNED_ADDRESS, is_unassigned,
};
use crate::model::{
    MeshModelOps, MeshModelPub, SIG_VENDOR, is_vendor, mesh_model_binding_add,
    mesh_model_binding_del, mesh_model_get_bindings, mesh_model_opcode_get, mesh_model_opcode_set,
    mesh_model_pub_get, mesh_model_pub_set, mesh_model_register, mesh_model_send,
    mesh_model_sub_add, mesh_model_sub_del, mesh_model_sub_del_all, mesh_model_sub_get,
    mesh_model_sub_ovrt, mesh_model_virt_sub_add, mesh_model_virt_sub_del,
    mesh_model_virt_sub_ovrt, model_id, set_id, vendor_id,
};
use crate::net::{MeshNetHeartbeatPub, MeshNetHeartbeatSub};
use crate::node::{
    MeshNode, node_beacon_mode_get, node_beacon_mode_set, node_default_ttl_get,
    node_default_ttl_set, node_friend_mode_get, node_friend_mode_set, node_get_comp,
    node_proxy_mode_get, node_proxy_mode_set, node_relay_mode_get, node_relay_mode_set,
    node_relay_params_get, node_remove,
};

// =========================================================================
// Model IDs (from mesh/cfgmod.h lines 12-13)
// =========================================================================

/// Configuration Server model ID (SIG model 0x0000).
pub const CONFIG_SRV_MODEL: u32 = set_id(SIG_VENDOR, 0x0000);

/// Configuration Client model ID (SIG model 0x0001).
pub const CONFIG_CLI_MODEL: u32 = set_id(SIG_VENDOR, 0x0001);

// =========================================================================
// Configuration Opcodes (from mesh/cfgmod.h lines 16-86)
// =========================================================================

/// AppKey Add opcode.
pub const OP_APPKEY_ADD: u32 = 0x00;
/// AppKey Update opcode.
pub const OP_APPKEY_UPDATE: u32 = 0x01;
/// Device Composition Data Status opcode.
pub const OP_DEV_COMP_STATUS: u32 = 0x02;
/// Config Model Publication Set opcode.
pub const OP_CONFIG_MODEL_PUB_SET: u32 = 0x03;
/// Config Heartbeat Publication Status opcode.
pub const OP_CONFIG_HEARTBEAT_PUB_STATUS: u32 = 0x06;
/// AppKey Delete opcode.
pub const OP_APPKEY_DELETE: u32 = 0x8000;
/// AppKey Get opcode.
pub const OP_APPKEY_GET: u32 = 0x8001;
/// AppKey List opcode.
pub const OP_APPKEY_LIST: u32 = 0x8002;
/// AppKey Status opcode.
pub const OP_APPKEY_STATUS: u32 = 0x8003;
/// Device Composition Data Get opcode.
pub const OP_DEV_COMP_GET: u32 = 0x8008;
/// Config Beacon Get opcode.
pub const OP_CONFIG_BEACON_GET: u32 = 0x8009;
/// Config Beacon Set opcode.
pub const OP_CONFIG_BEACON_SET: u32 = 0x800A;
/// Config Beacon Status opcode.
pub const OP_CONFIG_BEACON_STATUS: u32 = 0x800B;
/// Config Default TTL Get opcode.
pub const OP_CONFIG_DEFAULT_TTL_GET: u32 = 0x800C;
/// Config Default TTL Set opcode.
pub const OP_CONFIG_DEFAULT_TTL_SET: u32 = 0x800D;
/// Config Default TTL Status opcode.
pub const OP_CONFIG_DEFAULT_TTL_STATUS: u32 = 0x800E;
/// Config Friend Get opcode.
pub const OP_CONFIG_FRIEND_GET: u32 = 0x800F;
/// Config Friend Set opcode.
pub const OP_CONFIG_FRIEND_SET: u32 = 0x8010;
/// Config Friend Status opcode.
pub const OP_CONFIG_FRIEND_STATUS: u32 = 0x8011;
/// Config Proxy Get opcode.
pub const OP_CONFIG_PROXY_GET: u32 = 0x8012;
/// Config Proxy Set opcode.
pub const OP_CONFIG_PROXY_SET: u32 = 0x8013;
/// Config Proxy Status opcode.
pub const OP_CONFIG_PROXY_STATUS: u32 = 0x8014;
/// Config Key Refresh Phase Get opcode.
pub const OP_CONFIG_KEY_REFRESH_PHASE_GET: u32 = 0x8015;
/// Config Key Refresh Phase Set opcode.
pub const OP_CONFIG_KEY_REFRESH_PHASE_SET: u32 = 0x8016;
/// Config Key Refresh Phase Status opcode.
pub const OP_CONFIG_KEY_REFRESH_PHASE_STATUS: u32 = 0x8017;
/// Config Model Publication Get opcode.
pub const OP_CONFIG_MODEL_PUB_GET: u32 = 0x8018;
/// Config Model Publication Status opcode.
pub const OP_CONFIG_MODEL_PUB_STATUS: u32 = 0x8019;
/// Config Model Publication Virtual Address Set opcode.
pub const OP_CONFIG_MODEL_PUB_VIRT_SET: u32 = 0x801A;
/// Config Model Subscription Add opcode.
pub const OP_CONFIG_MODEL_SUB_ADD: u32 = 0x801B;
/// Config Model Subscription Delete opcode.
pub const OP_CONFIG_MODEL_SUB_DELETE: u32 = 0x801C;
/// Config Model Subscription Delete All opcode.
pub const OP_CONFIG_MODEL_SUB_DELETE_ALL: u32 = 0x801D;
/// Config Model Subscription Overwrite opcode.
pub const OP_CONFIG_MODEL_SUB_OVERWRITE: u32 = 0x801E;
/// Config Model Subscription Status opcode.
pub const OP_CONFIG_MODEL_SUB_STATUS: u32 = 0x801F;
/// Config Model Subscription Virtual Address Add opcode.
pub const OP_CONFIG_MODEL_SUB_VIRT_ADD: u32 = 0x8020;
/// Config Model Subscription Virtual Address Delete opcode.
pub const OP_CONFIG_MODEL_SUB_VIRT_DELETE: u32 = 0x8021;
/// Config Model Subscription Virtual Address Overwrite opcode.
pub const OP_CONFIG_MODEL_SUB_VIRT_OVERWRITE: u32 = 0x8022;
/// Config Network Transmit Get opcode.
pub const OP_CONFIG_NETWORK_TRANSMIT_GET: u32 = 0x8023;
/// Config Network Transmit Set opcode.
pub const OP_CONFIG_NETWORK_TRANSMIT_SET: u32 = 0x8024;
/// Config Network Transmit Status opcode.
pub const OP_CONFIG_NETWORK_TRANSMIT_STATUS: u32 = 0x8025;
/// Config Relay Get opcode.
pub const OP_CONFIG_RELAY_GET: u32 = 0x8026;
/// Config Relay Set opcode.
pub const OP_CONFIG_RELAY_SET: u32 = 0x8027;
/// Config Relay Status opcode.
pub const OP_CONFIG_RELAY_STATUS: u32 = 0x8028;
/// Config Model Subscription Get (SIG model) opcode.
pub const OP_CONFIG_MODEL_SUB_GET: u32 = 0x8029;
/// Config Model Subscription List (SIG model) opcode.
pub const OP_CONFIG_MODEL_SUB_LIST: u32 = 0x802A;
/// Config Vendor Model Subscription Get opcode.
pub const OP_CONFIG_VEND_MODEL_SUB_GET: u32 = 0x802B;
/// Config Vendor Model Subscription List opcode.
pub const OP_CONFIG_VEND_MODEL_SUB_LIST: u32 = 0x802C;
/// Config Low Power Node PollTimeout Get opcode.
pub const OP_CONFIG_POLL_TIMEOUT_GET: u32 = 0x802D;
/// Config Low Power Node PollTimeout Status opcode.
pub const OP_CONFIG_POLL_TIMEOUT_STATUS: u32 = 0x802E;
/// Config Heartbeat Publication Get opcode.
pub const OP_CONFIG_HEARTBEAT_PUB_GET: u32 = 0x8038;
/// Config Heartbeat Publication Set opcode.
pub const OP_CONFIG_HEARTBEAT_PUB_SET: u32 = 0x8039;
/// Config Heartbeat Subscription Get opcode.
pub const OP_CONFIG_HEARTBEAT_SUB_GET: u32 = 0x803A;
/// Config Heartbeat Subscription Set opcode.
pub const OP_CONFIG_HEARTBEAT_SUB_SET: u32 = 0x803B;
/// Config Heartbeat Subscription Status opcode.
pub const OP_CONFIG_HEARTBEAT_SUB_STATUS: u32 = 0x803C;
/// Model App Bind opcode.
pub const OP_MODEL_APP_BIND: u32 = 0x803D;
/// Model App Status opcode.
pub const OP_MODEL_APP_STATUS: u32 = 0x803E;
/// Model App Unbind opcode.
pub const OP_MODEL_APP_UNBIND: u32 = 0x803F;
/// NetKey Add opcode.
pub const OP_NETKEY_ADD: u32 = 0x8040;
/// NetKey Delete opcode.
pub const OP_NETKEY_DELETE: u32 = 0x8041;
/// NetKey Get opcode.
pub const OP_NETKEY_GET: u32 = 0x8042;
/// NetKey List opcode.
pub const OP_NETKEY_LIST: u32 = 0x8043;
/// NetKey Status opcode.
pub const OP_NETKEY_STATUS: u32 = 0x8044;
/// NetKey Update opcode.
pub const OP_NETKEY_UPDATE: u32 = 0x8045;
/// Node Identity Get opcode.
pub const OP_NODE_IDENTITY_GET: u32 = 0x8046;
/// Node Identity Set opcode.
pub const OP_NODE_IDENTITY_SET: u32 = 0x8047;
/// Node Identity Status opcode.
pub const OP_NODE_IDENTITY_STATUS: u32 = 0x8048;
/// Node Reset opcode.
pub const OP_NODE_RESET: u32 = 0x8049;
/// Node Reset Status opcode.
pub const OP_NODE_RESET_STATUS: u32 = 0x804A;
/// Model App Get (SIG model) opcode.
pub const OP_MODEL_APP_GET: u32 = 0x804B;
/// Model App List (SIG model) opcode.
pub const OP_MODEL_APP_LIST: u32 = 0x804C;
/// Vendor Model App Get opcode.
pub const OP_VEND_MODEL_APP_GET: u32 = 0x804D;
/// Vendor Model App List opcode.
pub const OP_VEND_MODEL_APP_LIST: u32 = 0x804E;

// =========================================================================
// Internal Constants
// =========================================================================

/// Credential flag mask within AppKey index for publication (bit 12).
const CREDFLAG_MASK: u16 = 0x1000;

/// Supported composition data page numbers, checked in descending order.
static SUPPORTED_PAGES: &[u8] = &[128, 0];

// =========================================================================
// Helper Functions
// =========================================================================

/// Extract a model ID from a packet payload.
///
/// If `vendor` is true, reads a 4-byte vendor model ID (CID + PID);
/// otherwise reads a 2-byte SIG model ID.
/// Replaces C macro `CFG_GET_ID(vendor, pkt)`.
fn cfg_get_id(vendor: bool, pkt: &[u8]) -> u32 {
    if vendor {
        let cid = u16::from_le_bytes([pkt[0], pkt[1]]);
        let pid = u16::from_le_bytes([pkt[2], pkt[3]]);
        set_id(cid, pid)
    } else {
        set_id(SIG_VENDOR, u16::from_le_bytes([pkt[0], pkt[1]]))
    }
}

/// Convert a value to its logarithmic (base-2) representation for heartbeat.
///
/// Returns the smallest n such that 2^(n-1) >= val, or 0 if val is 0.
/// Replaces C `uint32_to_log()`.
fn uint32_to_log(val: u32) -> u8 {
    if val == 0 {
        return 0;
    }
    let mut power: u32 = 1;
    let mut log_val: u8 = 1;
    while power < val && log_val < 32 {
        power <<= 1;
        log_val += 1;
    }
    log_val
}

/// Convert a heartbeat log-period to actual seconds: 2^(n-1).
fn log_to_uint32(log_val: u8) -> u32 {
    if log_val == 0 {
        return 0;
    }
    if log_val > 17 {
        return 0xFFFF;
    }
    1u32 << (u32::from(log_val) - 1)
}

/// Build a `OP_CONFIG_MODEL_PUB_STATUS` response message.
///
/// Replaces C `set_pub_status()` (cfgmod-server.c lines 41-68).
fn set_pub_status(
    msg: &mut [u8],
    status: u8,
    ele_addr: u16,
    pub_addr: u16,
    mod_id: u32,
    pub_state: Option<&MeshModelPub>,
) -> usize {
    let mut n = mesh_model_opcode_set(OP_CONFIG_MODEL_PUB_STATUS, msg);

    msg[n] = status;
    n += 1;

    msg[n..n + 2].copy_from_slice(&ele_addr.to_le_bytes());
    n += 2;

    let (idx, ttl, period, rtx) = if let Some(pub_s) = pub_state {
        let mut idx_val = pub_s.idx & APP_IDX_MASK;
        if pub_s.credential != 0 {
            idx_val |= CREDFLAG_MASK;
        }
        let rtx_byte = (u8::try_from(pub_s.rtx.interval / 50).unwrap_or(0) << 3) | pub_s.rtx.cnt;
        (idx_val, pub_s.ttl, pub_s.period, rtx_byte)
    } else {
        (0u16, 0u8, 0u8, 0u8)
    };

    msg[n..n + 2].copy_from_slice(&pub_addr.to_le_bytes());
    n += 2;

    msg[n..n + 2].copy_from_slice(&idx.to_le_bytes());
    n += 2;

    msg[n] = ttl;
    n += 1;
    msg[n] = period;
    n += 1;
    msg[n] = rtx;
    n += 1;

    let vendor = is_vendor(mod_id);
    if vendor {
        let vid = vendor_id(mod_id);
        msg[n..n + 2].copy_from_slice(&vid.to_le_bytes());
        n += 2;
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    } else {
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    }

    n
}

// =========================================================================
// Sub-Handler Functions
// =========================================================================

/// Handle Config Model Publication Get.
///
/// Replaces C `config_pub_get()` (cfgmod-server.c lines 70-120).
fn config_pub_get(node: &MeshNode, pkt: &[u8], vendor: bool, msg: &mut [u8]) -> usize {
    let expected_len = if vendor { 6 } else { 4 };
    if pkt.len() < expected_len {
        return 0;
    }

    let ele_addr = u16::from_le_bytes([pkt[0], pkt[1]]);
    let mod_id = cfg_get_id(vendor, &pkt[2..]);

    let pub_opt = mesh_model_pub_get(node, ele_addr, mod_id);

    let (status, pub_addr) = match &pub_opt {
        Some(pub_s) => (MESH_STATUS_SUCCESS, pub_s.addr),
        None => (MESH_STATUS_INVALID_MODEL, 0u16),
    };

    set_pub_status(msg, status, ele_addr, pub_addr, mod_id, pub_opt.as_ref())
}

/// Handle Config Model Publication Set (regular and virtual).
///
/// Replaces C `config_pub_set()` (cfgmod-server.c lines 122-199).
fn config_pub_set(node: &MeshNode, pkt: &[u8], virt: bool, vendor: bool, msg: &mut [u8]) -> usize {
    // Calculate expected minimum length:
    // ele_addr(2) + addr_or_label(2 or 16) + idx(2) + ttl(1) + period(1) + rtx(1) + model(2|4)
    let addr_len: usize = if virt { 16 } else { 2 };
    let mod_len: usize = if vendor { 4 } else { 2 };
    let expected_len = 2 + addr_len + 2 + 1 + 1 + 1 + mod_len;
    if pkt.len() < expected_len {
        return 0;
    }

    let ele_addr = u16::from_le_bytes([pkt[0], pkt[1]]);
    let mut offset = 2;

    let mut label = [0u8; 16];
    let pub_addr: u16;
    if virt {
        label.copy_from_slice(&pkt[offset..offset + 16]);
        pub_addr = 0;
        offset += 16;
    } else {
        pub_addr = u16::from_le_bytes([pkt[offset], pkt[offset + 1]]);
        offset += 2;
    }

    let idx_raw = u16::from_le_bytes([pkt[offset], pkt[offset + 1]]);
    offset += 2;

    let ttl = pkt[offset];
    offset += 1;
    let period = pkt[offset];
    offset += 1;
    let rtx = pkt[offset];
    offset += 1;

    let mod_id = cfg_get_id(vendor, &pkt[offset..]);

    let app_idx = idx_raw & APP_IDX_MASK;
    let cred_flag = (idx_raw & CREDFLAG_MASK) != 0;

    let retransmit_cnt = u16::from(rtx & 0x07);
    let retransmit_interval = u16::from(rtx >> 3) * 50;

    let period_ms = pub_period_to_ms(period);

    let pub_cfg = MeshConfigPub {
        virt,
        addr: if virt { 0 } else { pub_addr },
        idx: app_idx,
        ttl: u16::from(ttl),
        period: period_ms,
        retransmit_interval,
        retransmit_count: retransmit_cnt,
        credential: cred_flag,
        virt_addr: label,
    };

    let status = mesh_model_pub_set(node, ele_addr, mod_id, &pub_cfg);

    // Read back to get the resolved address (especially for virtual)
    let pub_opt = mesh_model_pub_get(node, ele_addr, mod_id);
    let final_addr = match &pub_opt {
        Some(p) => p.addr,
        None => 0,
    };

    set_pub_status(msg, status, ele_addr, final_addr, mod_id, pub_opt.as_ref())
}

/// Convert a period byte to milliseconds.
///
/// The period byte encodes step resolution in bits 6-7 and number of steps
/// in bits 0-5.
fn pub_period_to_ms(period: u8) -> u32 {
    let steps = u32::from(period & 0x3F);
    let resolution = period >> 6;
    match resolution {
        0 => steps * 100,
        1 => steps * 1000,
        2 => steps * 10_000,
        3 => steps * 600_000,
        _ => 0,
    }
}

/// Build subscription sub-list response (SIG or vendor model).
///
/// Replaces C `cfg_sub_get_msg()` (cfgmod-server.c lines 201-237).
fn cfg_sub_get_msg(node: &MeshNode, pkt: &[u8], vendor: bool, msg: &mut [u8]) -> usize {
    let expected_len = if vendor { 6 } else { 4 };
    if pkt.len() < expected_len {
        return 0;
    }

    let ele_addr = u16::from_le_bytes([pkt[0], pkt[1]]);
    let mod_id = cfg_get_id(vendor, &pkt[2..]);

    let opcode = if vendor { OP_CONFIG_VEND_MODEL_SUB_LIST } else { OP_CONFIG_MODEL_SUB_LIST };

    let mut n = mesh_model_opcode_set(opcode, msg);

    let subs = mesh_model_sub_get(node, ele_addr, mod_id);
    let status = if subs.is_some() { MESH_STATUS_SUCCESS } else { MESH_STATUS_INVALID_MODEL };

    msg[n] = status;
    n += 1;

    msg[n..n + 2].copy_from_slice(&ele_addr.to_le_bytes());
    n += 2;

    if vendor {
        let vid = vendor_id(mod_id);
        msg[n..n + 2].copy_from_slice(&vid.to_le_bytes());
        n += 2;
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    } else {
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    }

    if let Some(sub_list) = subs {
        for sub_addr in &sub_list {
            if n + 2 > MAX_MSG_LEN as usize {
                break;
            }
            msg[n..n + 2].copy_from_slice(&sub_addr.to_le_bytes());
            n += 2;
        }
    }

    n
}

/// Build subscription add/delete/overwrite response message.
///
/// Replaces C `cfg_sub_add_msg()` (cfgmod-server.c lines 256-313).
fn cfg_sub_add_msg(node: &MeshNode, pkt: &[u8], opcode: u32, msg: &mut [u8]) -> usize {
    let vendor: bool;
    // ele_addr(2) + grp_addr(2) + sig_model(2) = 6
    // OR ele_addr(2) + grp_addr(2) + vendor_model(4) = 8
    if pkt.len() >= 8 {
        vendor = true;
    } else if pkt.len() >= 6 {
        vendor = false;
    } else {
        return 0;
    }

    let ele_addr = u16::from_le_bytes([pkt[0], pkt[1]]);
    let grp_addr = u16::from_le_bytes([pkt[2], pkt[3]]);
    let mod_id = cfg_get_id(vendor, &pkt[4..]);

    let status = match opcode {
        OP_CONFIG_MODEL_SUB_ADD => mesh_model_sub_add(node, ele_addr, mod_id, grp_addr),
        OP_CONFIG_MODEL_SUB_DELETE => mesh_model_sub_del(node, ele_addr, mod_id, grp_addr),
        OP_CONFIG_MODEL_SUB_OVERWRITE => mesh_model_sub_ovrt(node, ele_addr, mod_id, grp_addr),
        _ => return 0,
    };

    let mut n = mesh_model_opcode_set(OP_CONFIG_MODEL_SUB_STATUS, msg);
    msg[n] = status;
    n += 1;

    msg[n..n + 2].copy_from_slice(&ele_addr.to_le_bytes());
    n += 2;

    msg[n..n + 2].copy_from_slice(&grp_addr.to_le_bytes());
    n += 2;

    if vendor {
        let vid = vendor_id(mod_id);
        msg[n..n + 2].copy_from_slice(&vid.to_le_bytes());
        n += 2;
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    } else {
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    }

    n
}

/// Build virtual subscription add/delete/overwrite response message.
///
/// Replaces C `cfg_virt_sub_add_msg()` (cfgmod-server.c lines 315-370).
fn cfg_virt_sub_add_msg(node: &MeshNode, pkt: &[u8], opcode: u32, msg: &mut [u8]) -> usize {
    let vendor: bool;
    // ele_addr(2) + label(16) + sig_model(2) = 20
    // ele_addr(2) + label(16) + vendor_model(4) = 22
    if pkt.len() >= 22 {
        vendor = true;
    } else if pkt.len() >= 20 {
        vendor = false;
    } else {
        return 0;
    }

    let ele_addr = u16::from_le_bytes([pkt[0], pkt[1]]);
    let mut label = [0u8; 16];
    label.copy_from_slice(&pkt[2..18]);
    let mod_id = cfg_get_id(vendor, &pkt[18..]);

    let (status, grp_addr) = match opcode {
        OP_CONFIG_MODEL_SUB_VIRT_ADD => mesh_model_virt_sub_add(node, ele_addr, mod_id, &label),
        OP_CONFIG_MODEL_SUB_VIRT_DELETE => mesh_model_virt_sub_del(node, ele_addr, mod_id, &label),
        OP_CONFIG_MODEL_SUB_VIRT_OVERWRITE => {
            mesh_model_virt_sub_ovrt(node, ele_addr, mod_id, &label)
        }
        _ => return 0,
    };

    let mut n = mesh_model_opcode_set(OP_CONFIG_MODEL_SUB_STATUS, msg);
    msg[n] = status;
    n += 1;

    msg[n..n + 2].copy_from_slice(&ele_addr.to_le_bytes());
    n += 2;

    msg[n..n + 2].copy_from_slice(&grp_addr.to_le_bytes());
    n += 2;

    if vendor {
        let vid = vendor_id(mod_id);
        msg[n..n + 2].copy_from_slice(&vid.to_le_bytes());
        n += 2;
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    } else {
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    }

    n
}

/// Handle Config Model Subscription Delete All.
///
/// Replaces C `config_sub_del_all()` (cfgmod-server.c lines 372-407).
fn config_sub_del_all(node: &MeshNode, pkt: &[u8], msg: &mut [u8]) -> usize {
    let vendor: bool;
    // ele_addr(2) + sig_model(2) = 4  OR  ele_addr(2) + vendor_model(4) = 6
    if pkt.len() >= 6 {
        vendor = true;
    } else if pkt.len() >= 4 {
        vendor = false;
    } else {
        return 0;
    }

    let ele_addr = u16::from_le_bytes([pkt[0], pkt[1]]);
    let mod_id = cfg_get_id(vendor, &pkt[2..]);

    let status = mesh_model_sub_del_all(node, ele_addr, mod_id);

    let mut n = mesh_model_opcode_set(OP_CONFIG_MODEL_SUB_STATUS, msg);
    msg[n] = status;
    n += 1;

    msg[n..n + 2].copy_from_slice(&ele_addr.to_le_bytes());
    n += 2;

    msg[n..n + 2].copy_from_slice(&UNASSIGNED_ADDRESS.to_le_bytes());
    n += 2;

    if vendor {
        let vid = vendor_id(mod_id);
        msg[n..n + 2].copy_from_slice(&vid.to_le_bytes());
        n += 2;
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    } else {
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    }

    n
}

/// Build a Model App Bind/Unbind response.
///
/// Replaces C `model_app_bind()` (cfgmod-server.c lines 435-481).
fn model_app_bind_msg(node: &MeshNode, pkt: &[u8], unbind: bool, msg: &mut [u8]) -> usize {
    let vendor: bool;
    // ele_addr(2) + app_idx(2) + sig_model(2) = 6
    // OR ele_addr(2) + app_idx(2) + vendor_model(4) = 8
    if pkt.len() >= 8 {
        vendor = true;
    } else if pkt.len() >= 6 {
        vendor = false;
    } else {
        return 0;
    }

    let ele_addr = u16::from_le_bytes([pkt[0], pkt[1]]);
    let app_idx = u16::from_le_bytes([pkt[2], pkt[3]]);
    let mod_id = cfg_get_id(vendor, &pkt[4..]);

    let primary = node.get_primary();
    let ele_idx = if ele_addr >= primary {
        (ele_addr - primary) as u8
    } else {
        // Invalid element address
        let mut n = mesh_model_opcode_set(OP_MODEL_APP_STATUS, msg);
        msg[n] = MESH_STATUS_INVALID_ADDRESS;
        n += 1;
        msg[n..n + 2].copy_from_slice(&ele_addr.to_le_bytes());
        n += 2;
        msg[n..n + 2].copy_from_slice(&app_idx.to_le_bytes());
        n += 2;
        if vendor {
            let vid = vendor_id(mod_id);
            msg[n..n + 2].copy_from_slice(&vid.to_le_bytes());
            n += 2;
            let mid = model_id(mod_id);
            msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
            n += 2;
        } else {
            let mid = model_id(mod_id);
            msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
            n += 2;
        }
        return n;
    };

    let status = if unbind {
        mesh_model_binding_del(node, ele_idx, mod_id, app_idx)
    } else {
        mesh_model_binding_add(node, ele_idx, mod_id, app_idx)
    };

    let mut n = mesh_model_opcode_set(OP_MODEL_APP_STATUS, msg);
    msg[n] = status;
    n += 1;

    msg[n..n + 2].copy_from_slice(&ele_addr.to_le_bytes());
    n += 2;

    msg[n..n + 2].copy_from_slice(&app_idx.to_le_bytes());
    n += 2;

    if vendor {
        let vid = vendor_id(mod_id);
        msg[n..n + 2].copy_from_slice(&vid.to_le_bytes());
        n += 2;
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    } else {
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    }

    n
}

/// Build a Model App List response (SIG or vendor).
///
/// Replaces C `model_app_list()` (cfgmod-server.c lines 409-433).
fn model_app_list(node: &MeshNode, pkt: &[u8], vendor: bool, msg: &mut [u8]) -> usize {
    let expected_len = if vendor { 6 } else { 4 };
    if pkt.len() < expected_len {
        return 0;
    }

    let ele_addr = u16::from_le_bytes([pkt[0], pkt[1]]);
    let mod_id = cfg_get_id(vendor, &pkt[2..]);

    let opcode = if vendor { OP_VEND_MODEL_APP_LIST } else { OP_MODEL_APP_LIST };

    let mut n = mesh_model_opcode_set(opcode, msg);

    let primary = node.get_primary();
    let ele_idx = if ele_addr >= primary {
        (ele_addr - primary) as u8
    } else {
        msg[n] = MESH_STATUS_INVALID_ADDRESS;
        n += 1;
        msg[n..n + 2].copy_from_slice(&ele_addr.to_le_bytes());
        n += 2;
        if vendor {
            let vid = vendor_id(mod_id);
            msg[n..n + 2].copy_from_slice(&vid.to_le_bytes());
            n += 2;
            let mid = model_id(mod_id);
            msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
            n += 2;
        } else {
            let mid = model_id(mod_id);
            msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
            n += 2;
        }
        return n;
    };

    let bindings = mesh_model_get_bindings(node, ele_idx, mod_id);
    let status = if bindings.is_some() { MESH_STATUS_SUCCESS } else { MESH_STATUS_INVALID_MODEL };

    msg[n] = status;
    n += 1;

    msg[n..n + 2].copy_from_slice(&ele_addr.to_le_bytes());
    n += 2;

    if vendor {
        let vid = vendor_id(mod_id);
        msg[n..n + 2].copy_from_slice(&vid.to_le_bytes());
        n += 2;
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    } else {
        let mid = model_id(mod_id);
        msg[n..n + 2].copy_from_slice(&mid.to_le_bytes());
        n += 2;
    }

    if let Some(bind_list) = bindings {
        // Pack bindings as 12-bit index pairs (same format as appkey_list)
        let mut idx_pair: u32 = 0;
        let mut i: usize = 0;
        for &b in &bind_list {
            if (i & 1) == 0 {
                idx_pair = u32::from(b);
            } else {
                idx_pair = (idx_pair << 12) + u32::from(b);
                if n + 3 > MAX_MSG_LEN as usize {
                    break;
                }
                let le_bytes = idx_pair.to_le_bytes();
                msg[n] = le_bytes[0];
                msg[n + 1] = le_bytes[1];
                msg[n + 2] = le_bytes[2];
                n += 3;
            }
            i += 1;
        }
        // Odd trailing index
        if (i & 1) == 1 && n + 2 <= MAX_MSG_LEN as usize {
            let le = (idx_pair as u16).to_le_bytes();
            msg[n] = le[0];
            msg[n + 1] = le[1];
            n += 2;
        }
    }

    n
}

/// Build a Config Relay Status response.
///
/// Replaces C `cfg_relay_msg()` (cfgmod-server.c lines 483-509).
fn cfg_relay_msg(node: &MeshNode, msg: &mut [u8]) -> usize {
    let mut n = mesh_model_opcode_set(OP_CONFIG_RELAY_STATUS, msg);

    let mode = node_relay_mode_get(node);
    msg[n] = mode;
    n += 1;

    let (cnt, interval) = node_relay_params_get(node);

    // Encode: count in bits 0-2, interval steps in bits 3-7
    let interval_steps = if interval >= 10 { ((interval / 10) - 1).min(31) as u8 } else { 0u8 };
    msg[n] = ((interval_steps & 0x1F) << 3) | ((cnt as u8) & 0x07);
    n += 1;

    n
}

/// Build a Config Key Refresh Phase Status response.
///
/// Replaces C `cfg_key_refresh_phase()` (cfgmod-server.c lines 511-535).
fn cfg_key_refresh_phase(node: &MeshNode, net_idx: u16, msg: &mut [u8]) -> usize {
    let mut n = mesh_model_opcode_set(OP_CONFIG_KEY_REFRESH_PHASE_STATUS, msg);

    let net = node.net.lock().unwrap();
    let phase = net.key_refresh_phase_get(net_idx);
    drop(net);

    msg[n] = MESH_STATUS_SUCCESS;
    n += 1;
    msg[n..n + 2].copy_from_slice(&net_idx.to_le_bytes());
    n += 2;
    msg[n] = phase;
    n += 1;

    n
}

/// Build a Heartbeat Subscription Status response.
///
/// Replaces C `hb_subscription_status()` (cfgmod-server.c lines 537-575).
fn hb_subscription_status(node: &MeshNode, msg: &mut [u8]) -> usize {
    let mut n = mesh_model_opcode_set(OP_CONFIG_HEARTBEAT_SUB_STATUS, msg);

    let net = node.net.lock().unwrap();
    let sub = net.get_heartbeat_sub();
    drop(net);

    msg[n] = MESH_STATUS_SUCCESS;
    n += 1;

    msg[n..n + 2].copy_from_slice(&sub.src.to_le_bytes());
    n += 2;

    msg[n..n + 2].copy_from_slice(&sub.dst.to_le_bytes());
    n += 2;

    let period_log = if sub.enabled && sub.period > 0 { uint32_to_log(sub.period) } else { 0 };
    msg[n] = period_log;
    n += 1;

    let count_log = if sub.count > 0 { uint32_to_log(sub.count) } else { 0 };
    msg[n] = count_log;
    n += 1;

    msg[n] = sub.min_hops;
    n += 1;

    msg[n] = sub.max_hops;
    n += 1;

    n
}

/// Handle Heartbeat Subscription Get.
fn hb_subscription_get(node: &MeshNode, msg: &mut [u8]) -> usize {
    hb_subscription_status(node, msg)
}

/// Handle Heartbeat Subscription Set.
///
/// Replaces C `hb_subscription_set()` (cfgmod-server.c lines 581-634).
fn hb_subscription_set(node: &MeshNode, pkt: &[u8], msg: &mut [u8]) -> usize {
    if pkt.len() < 5 {
        return 0;
    }

    let src = u16::from_le_bytes([pkt[0], pkt[1]]);
    let dst = u16::from_le_bytes([pkt[2], pkt[3]]);
    let period_log = pkt[4];

    debug!("Heartbeat Sub Set: src={:#06x} dst={:#06x} period_log={}", src, dst, period_log);

    let sub = if period_log == 0 || is_unassigned(src) || is_unassigned(dst) {
        MeshNetHeartbeatSub {
            src: UNASSIGNED_ADDRESS,
            dst: UNASSIGNED_ADDRESS,
            period: 0,
            count: 0,
            features: 0,
            min_hops: 0,
            max_hops: 0,
            enabled: false,
        }
    } else {
        let period = log_to_uint32(period_log);
        MeshNetHeartbeatSub {
            src,
            dst,
            period,
            count: 0,
            features: 0,
            min_hops: 0x7F,
            max_hops: 0,
            enabled: true,
        }
    };

    {
        let mut net = node.net.lock().unwrap();
        net.set_heartbeat_sub(sub);
    }

    hb_subscription_status(node, msg)
}

/// Build a Heartbeat Publication Status response.
fn hb_publication_status(node: &MeshNode, msg: &mut [u8]) -> usize {
    let mut n = mesh_model_opcode_set(OP_CONFIG_HEARTBEAT_PUB_STATUS, msg);

    let net = node.net.lock().unwrap();
    let pub_state = net.get_heartbeat_pub();
    drop(net);

    msg[n] = MESH_STATUS_SUCCESS;
    n += 1;

    msg[n..n + 2].copy_from_slice(&pub_state.dst.to_le_bytes());
    n += 2;

    let count_log = uint32_to_log(u32::from(pub_state.count));
    msg[n] = count_log;
    n += 1;

    let period_log = uint32_to_log(u32::from(pub_state.period));
    msg[n] = period_log;
    n += 1;

    msg[n] = pub_state.ttl;
    n += 1;

    msg[n..n + 2].copy_from_slice(&pub_state.features.to_le_bytes());
    n += 2;

    msg[n..n + 2].copy_from_slice(&pub_state.net_idx.to_le_bytes());
    n += 2;

    n
}

/// Handle Heartbeat Publication Get.
fn hb_publication_get(node: &MeshNode, msg: &mut [u8]) -> usize {
    hb_publication_status(node, msg)
}

/// Handle Heartbeat Publication Set.
///
/// Replaces C `hb_publication_set()` (cfgmod-server.c lines 673-708).
fn hb_publication_set(node: &MeshNode, pkt: &[u8], msg: &mut [u8]) -> usize {
    if pkt.len() < 9 {
        return 0;
    }

    let dst = u16::from_le_bytes([pkt[0], pkt[1]]);
    let count_log = pkt[2];
    let period_log = pkt[3];
    let ttl = pkt[4];
    let features = u16::from_le_bytes([pkt[5], pkt[6]]);
    let net_idx = u16::from_le_bytes([pkt[7], pkt[8]]);

    debug!(
        "Heartbeat Pub Set: dst={:#06x} count_log={} period_log={} ttl={} features={:#06x} net_idx={:#06x}",
        dst, count_log, period_log, ttl, features, net_idx
    );

    let count = log_to_uint32(count_log) as u16;
    let period = log_to_uint32(period_log) as u16;

    let pub_state = MeshNetHeartbeatPub { dst, count, period, ttl, features, net_idx };

    {
        let mut net = node.net.lock().unwrap();
        net.set_heartbeat_pub(pub_state);
    }

    hb_publication_status(node, msg)
}

/// Handle NetKey Add/Update/Delete and build status.
///
/// Replaces C `cfg_netkey_msg()` (cfgmod-server.c lines 735-759).
fn cfg_netkey_msg(node: &MeshNode, pkt: &[u8], opcode: u32, msg: &mut [u8]) -> usize {
    let required = if opcode == OP_NETKEY_DELETE { 2 } else { 18 };
    if pkt.len() < required {
        return 0;
    }

    let net_idx = u16::from_le_bytes([pkt[0], pkt[1]]) & NET_IDX_MAX;

    let status = match opcode {
        OP_NETKEY_ADD => {
            let mut key = [0u8; 16];
            key.copy_from_slice(&pkt[2..18]);
            let mut net = node.net.lock().unwrap();
            net.add_key(net_idx, &key)
        }
        OP_NETKEY_UPDATE => {
            let mut key = [0u8; 16];
            key.copy_from_slice(&pkt[2..18]);
            let mut net = node.net.lock().unwrap();
            net.update_key(net_idx, &key)
        }
        OP_NETKEY_DELETE => {
            let mut net = node.net.lock().unwrap();
            net.del_key(net_idx)
        }
        _ => return 0,
    };

    let mut n = mesh_model_opcode_set(OP_NETKEY_STATUS, msg);
    msg[n] = status;
    n += 1;
    msg[n..n + 2].copy_from_slice(&net_idx.to_le_bytes());
    n += 2;

    n
}

/// Handle AppKey Add/Update/Delete and build status.
///
/// Replaces C `cfg_appkey_msg()` (cfgmod-server.c lines 710-733).
fn cfg_appkey_msg(node: &MeshNode, pkt: &[u8], opcode: u32, msg: &mut [u8]) -> usize {
    let required = if opcode == OP_APPKEY_DELETE { 3 } else { 19 };
    if pkt.len() < required {
        return 0;
    }

    // Packed key index: 3 bytes = net_idx(12 bits) + app_idx(12 bits)
    let b0 = u32::from(pkt[0]);
    let b1 = u32::from(pkt[1]);
    let b2 = u32::from(pkt[2]);

    let net_idx = ((b0 | ((b1 & 0x0F) << 8)) & 0x0FFF) as u16;
    let app_idx = (((b1 >> 4) | (b2 << 4)) & 0x0FFF) as u16;

    let status = {
        let mut net = node.net.lock().unwrap();
        match opcode {
            OP_APPKEY_ADD => {
                let mut key = [0u8; 16];
                key.copy_from_slice(&pkt[3..19]);
                appkey_key_add(&mut net, net_idx, app_idx, &key) as u8
            }
            OP_APPKEY_UPDATE => {
                let mut key = [0u8; 16];
                key.copy_from_slice(&pkt[3..19]);
                appkey_key_update(&mut net, net_idx, app_idx, &key) as u8
            }
            OP_APPKEY_DELETE => appkey_key_delete(&mut net, net_idx, app_idx) as u8,
            _ => return 0,
        }
    };

    let mut n = mesh_model_opcode_set(OP_APPKEY_STATUS, msg);
    msg[n] = status;
    n += 1;

    // Pack net_idx + app_idx back into 3 bytes
    let idx_packed = u32::from(net_idx) | (u32::from(app_idx) << 12);
    let le = idx_packed.to_le_bytes();
    msg[n] = le[0];
    msg[n + 1] = le[1];
    msg[n + 2] = le[2];
    n += 3;

    n
}

/// Handle Config AppKey Get (list app keys bound to a net key).
///
/// Replaces C `cfg_get_appkeys_msg()` (cfgmod-server.c lines 761-783).
fn cfg_get_appkeys_msg(node: &MeshNode, pkt: &[u8], msg: &mut [u8]) -> usize {
    if pkt.len() < 2 {
        return 0;
    }

    let net_idx = u16::from_le_bytes([pkt[0], pkt[1]]) & NET_IDX_MAX;

    let mut n = mesh_model_opcode_set(OP_APPKEY_LIST, msg);

    let net = node.net.lock().unwrap();
    let (status, packed_len) = appkey_list(&net, net_idx, &mut msg[n + 3..]);
    drop(net);

    msg[n] = status;
    n += 1;
    msg[n..n + 2].copy_from_slice(&net_idx.to_le_bytes());
    n += 2;
    n += packed_len as usize;

    n
}

/// Handle Config Low Power Node PollTimeout Get.
///
/// Replaces C `cfg_poll_timeout_msg()` (cfgmod-server.c lines 785-814).
fn cfg_poll_timeout_msg(node: &MeshNode, pkt: &[u8], msg: &mut [u8]) -> usize {
    if pkt.len() < 2 {
        return 0;
    }

    let lpn_addr = u16::from_le_bytes([pkt[0], pkt[1]]);

    // Look up the friend entry by LPN address to get poll timeout
    let poll_timeout: u32 = {
        let net = node.net.lock().unwrap();
        let friends = net.get_friends();
        friends.iter().find(|f| f.lp_addr == lpn_addr).map(|f| f.poll_timeout).unwrap_or(0)
    };

    let mut n = mesh_model_opcode_set(OP_CONFIG_POLL_TIMEOUT_STATUS, msg);

    msg[n..n + 2].copy_from_slice(&lpn_addr.to_le_bytes());
    n += 2;

    // Poll timeout encoded as 3 bytes LE (24-bit value)
    let pt_le = poll_timeout.to_le_bytes();
    msg[n] = pt_le[0];
    msg[n + 1] = pt_le[1];
    msg[n + 2] = pt_le[2];
    n += 3;

    n
}

/// Handle Config Network Transmit Get/Set and build status.
///
/// Replaces C `cfg_net_tx_msg()` (cfgmod-server.c lines 816-848).
fn cfg_net_tx_msg(node: &MeshNode, pkt: &[u8], is_set: bool, msg: &mut [u8]) -> usize {
    if is_set {
        if pkt.is_empty() {
            return 0;
        }
        let val = pkt[0];
        let count = val & 0x07;
        let interval = u16::from((val >> 3) & 0x1F) * 10 + 10;

        {
            let mut net = node.net.lock().unwrap();
            net.transmit_params_set(count, interval);
        }

        // Persist
        {
            let mut cfg = node.config.lock().unwrap();
            if let Some(ref mut config) = *cfg {
                let _ = config.write_net_transmit(u16::from(count), interval);
            }
        }
    }

    let (count, interval) = {
        let net = node.net.lock().unwrap();
        net.transmit_params_get()
    };

    let mut n = mesh_model_opcode_set(OP_CONFIG_NETWORK_TRANSMIT_STATUS, msg);

    let interval_steps = if interval >= 10 { ((interval / 10) - 1).min(31) as u8 } else { 0u8 };
    msg[n] = ((interval_steps & 0x1F) << 3) | (count & 0x07);
    n += 1;

    n
}

/// Handle Device Composition Data Get.
///
/// Replaces C `get_composition()` (cfgmod-server.c lines 850-877).
fn get_composition(node: &MeshNode, pkt: &[u8], msg: &mut [u8]) -> usize {
    if pkt.is_empty() {
        return 0;
    }

    let requested_page = pkt[0];

    // Find the highest supported page <= requested page
    let page = SUPPORTED_PAGES.iter().copied().find(|&p| p <= requested_page);

    let comp = page.and_then(|p| node_get_comp(node, p));

    let mut n = mesh_model_opcode_set(OP_DEV_COMP_STATUS, msg);

    match comp {
        Some(comp_page) => {
            msg[n] = comp_page.page_num;
            n += 1;
            let copy_len = comp_page.data.len().min(MAX_MSG_LEN as usize - n);
            msg[n..n + copy_len].copy_from_slice(&comp_page.data[..copy_len]);
            n += copy_len;
        }
        None => {
            msg[n] = requested_page;
            n += 1;
        }
    }

    n
}

/// Handle Node Reset and deferred removal.
///
/// Replaces C `node_reset()` (cfgmod-server.c lines 879-893).
fn handle_node_reset(node: &Arc<MeshNode>, src: u16, net_idx: u16, msg: &mut [u8]) -> usize {
    let n = mesh_model_opcode_set(OP_NODE_RESET_STATUS, msg);

    // Send the status reply first, THEN schedule deferred removal
    mesh_model_send(node, 0, src, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, false, &msg[..n]);

    // Schedule deferred node removal via tokio::spawn
    let node_clone = Arc::clone(node);
    tokio::spawn(async move {
        node_remove(&node_clone);
    });

    // Return 0 to suppress the normal send in the dispatcher
    0
}

// =========================================================================
// Main Configuration Server Packet Dispatcher
// =========================================================================

/// Configuration Server model message dispatcher.
///
/// Processes all incoming Configuration Server opcodes, dispatching to the
/// appropriate sub-handler. This is the direct Rust equivalent of
/// `cfg_srv_pkt()` in `mesh/cfgmod-server.c` (lines ~250-1118).
///
/// Returns `true` if the message was handled, `false` otherwise.
fn cfg_srv_pkt(
    node: &Arc<MeshNode>,
    src: u16,
    _dst: u16,
    app_idx: u16,
    net_idx: u16,
    data: &[u8],
) -> bool {
    // Configuration Server only accepts messages on the device key
    if app_idx != APP_IDX_DEV_LOCAL {
        return false;
    }

    let Some((opcode, consumed)) = mesh_model_opcode_get(data) else {
        return false;
    };

    if consumed > data.len() {
        return false;
    }

    let pkt = &data[consumed..];
    let mut msg = [0u8; MAX_MSG_LEN as usize];

    let n: usize = match opcode {
        // ---------------------------------------------------------------
        // Composition Data
        // ---------------------------------------------------------------
        OP_DEV_COMP_GET => get_composition(node, pkt, &mut msg),

        // ---------------------------------------------------------------
        // Default TTL
        // ---------------------------------------------------------------
        OP_CONFIG_DEFAULT_TTL_GET => {
            let ttl = node_default_ttl_get(node);
            let mut n = mesh_model_opcode_set(OP_CONFIG_DEFAULT_TTL_STATUS, &mut msg);
            msg[n] = ttl;
            n += 1;
            n
        }

        OP_CONFIG_DEFAULT_TTL_SET => {
            if pkt.is_empty() {
                return true;
            }
            let ttl = pkt[0];
            // TTL must be <= 0x7F and must not be 1
            if ttl > 0x7F || ttl == 1 {
                return true;
            }
            if !node_default_ttl_set(node, ttl) {
                return true;
            }

            // Persist TTL
            {
                let mut cfg = node.config.lock().unwrap();
                if let Some(ref mut config) = *cfg {
                    let _ = config.write_ttl(ttl);
                }
            }

            let mut n = mesh_model_opcode_set(OP_CONFIG_DEFAULT_TTL_STATUS, &mut msg);
            msg[n] = ttl;
            n += 1;
            n
        }

        // ---------------------------------------------------------------
        // Relay
        // ---------------------------------------------------------------
        OP_CONFIG_RELAY_GET => cfg_relay_msg(node, &mut msg),

        OP_CONFIG_RELAY_SET => {
            if pkt.len() < 2 {
                return true;
            }
            let mode_val = pkt[0];
            let cnt = u16::from(pkt[1] & 0x07);
            let interval = u16::from((pkt[1] >> 3) & 0x1F) * 10 + 10;
            let enabled = mode_val == MESH_MODE_ENABLED;

            node_relay_mode_set(node, enabled, cnt, interval);

            // Persist relay mode
            {
                let mut cfg = node.config.lock().unwrap();
                if let Some(ref mut config) = *cfg {
                    let _ = config.write_relay_mode(mode_val, cnt, interval);
                }
            }

            cfg_relay_msg(node, &mut msg)
        }

        // ---------------------------------------------------------------
        // Beacon
        // ---------------------------------------------------------------
        OP_CONFIG_BEACON_GET => {
            let mode = node_beacon_mode_get(node);
            let mut n = mesh_model_opcode_set(OP_CONFIG_BEACON_STATUS, &mut msg);
            msg[n] = mode;
            n += 1;
            n
        }

        OP_CONFIG_BEACON_SET => {
            if pkt.is_empty() {
                return true;
            }
            let mode_val = pkt[0];
            if mode_val > MESH_MODE_ENABLED {
                return true;
            }
            let enabled = mode_val == MESH_MODE_ENABLED;
            node_beacon_mode_set(node, enabled);

            // Persist beacon mode
            {
                let mut cfg = node.config.lock().unwrap();
                if let Some(ref mut config) = *cfg {
                    let _ = config.write_mode("beacon", mode_val);
                }
            }

            let mode = node_beacon_mode_get(node);
            let mut n = mesh_model_opcode_set(OP_CONFIG_BEACON_STATUS, &mut msg);
            msg[n] = mode;
            n += 1;
            n
        }

        // ---------------------------------------------------------------
        // Friend
        // ---------------------------------------------------------------
        OP_CONFIG_FRIEND_GET => {
            let mode = node_friend_mode_get(node);
            let mut n = mesh_model_opcode_set(OP_CONFIG_FRIEND_STATUS, &mut msg);
            msg[n] = mode;
            n += 1;
            n
        }

        OP_CONFIG_FRIEND_SET => {
            if pkt.is_empty() {
                return true;
            }
            let mode_val = pkt[0];
            if mode_val > MESH_MODE_ENABLED {
                return true;
            }
            let enabled = mode_val == MESH_MODE_ENABLED;
            node_friend_mode_set(node, enabled);

            // Persist friend mode
            {
                let mut cfg = node.config.lock().unwrap();
                if let Some(ref mut config) = *cfg {
                    let _ = config.write_mode("friend", mode_val);
                }
            }

            let mode = node_friend_mode_get(node);
            let mut n = mesh_model_opcode_set(OP_CONFIG_FRIEND_STATUS, &mut msg);
            msg[n] = mode;
            n += 1;
            n
        }

        // ---------------------------------------------------------------
        // Proxy
        // ---------------------------------------------------------------
        OP_CONFIG_PROXY_GET => {
            let mode = node_proxy_mode_get(node);
            let mut n = mesh_model_opcode_set(OP_CONFIG_PROXY_STATUS, &mut msg);
            msg[n] = mode;
            n += 1;
            n
        }

        OP_CONFIG_PROXY_SET => {
            if pkt.is_empty() {
                return true;
            }
            let mode_val = pkt[0];
            if mode_val > MESH_MODE_ENABLED {
                return true;
            }
            let enabled = mode_val == MESH_MODE_ENABLED;
            node_proxy_mode_set(node, enabled);

            // Persist proxy mode
            {
                let mut cfg = node.config.lock().unwrap();
                if let Some(ref mut config) = *cfg {
                    let _ = config.write_mode("proxy", mode_val);
                }
            }

            let mode = node_proxy_mode_get(node);
            let mut n = mesh_model_opcode_set(OP_CONFIG_PROXY_STATUS, &mut msg);
            msg[n] = mode;
            n += 1;
            n
        }

        // ---------------------------------------------------------------
        // Network Transmit
        // ---------------------------------------------------------------
        OP_CONFIG_NETWORK_TRANSMIT_GET => cfg_net_tx_msg(node, pkt, false, &mut msg),
        OP_CONFIG_NETWORK_TRANSMIT_SET => cfg_net_tx_msg(node, pkt, true, &mut msg),

        // ---------------------------------------------------------------
        // Key Refresh Phase
        // ---------------------------------------------------------------
        OP_CONFIG_KEY_REFRESH_PHASE_GET => {
            if pkt.len() < 2 {
                return true;
            }
            let kf_net_idx = u16::from_le_bytes([pkt[0], pkt[1]]) & NET_IDX_MAX;
            cfg_key_refresh_phase(node, kf_net_idx, &mut msg)
        }

        OP_CONFIG_KEY_REFRESH_PHASE_SET => {
            if pkt.len() < 3 {
                return true;
            }
            let kf_net_idx = u16::from_le_bytes([pkt[0], pkt[1]]) & NET_IDX_MAX;
            let transition = pkt[2];

            let mut net = node.net.lock().unwrap();

            // Enforce valid transitions as per Mesh spec:
            // Only KEY_REFRESH_TRANS_TWO (=2) and KEY_REFRESH_TRANS_THREE (=3) are valid
            let status =
                if transition == KEY_REFRESH_TRANS_TWO || transition == KEY_REFRESH_TRANS_THREE {
                    net.key_refresh_phase_set(kf_net_idx, transition)
                } else {
                    MESH_STATUS_CANNOT_SET
                };

            drop(net);

            let mut n = mesh_model_opcode_set(OP_CONFIG_KEY_REFRESH_PHASE_STATUS, &mut msg);
            msg[n] = status;
            n += 1;
            msg[n..n + 2].copy_from_slice(&kf_net_idx.to_le_bytes());
            n += 2;

            let current_phase = {
                let net = node.net.lock().unwrap();
                net.key_refresh_phase_get(kf_net_idx)
            };
            msg[n] = current_phase;
            n += 1;

            n
        }

        // ---------------------------------------------------------------
        // NetKey Management
        // ---------------------------------------------------------------
        OP_NETKEY_ADD | OP_NETKEY_UPDATE | OP_NETKEY_DELETE => {
            cfg_netkey_msg(node, pkt, opcode, &mut msg)
        }

        OP_NETKEY_GET => {
            let mut n = mesh_model_opcode_set(OP_NETKEY_LIST, &mut msg);

            let net = node.net.lock().unwrap();
            let key_list = net.key_list_get();
            drop(net);

            // Pack net key indices: 12-bit packing (same format as appkey_list)
            let mut idx_pair: u32 = 0;
            let mut i: usize = 0;
            for &net_key_idx in &key_list {
                if (i & 1) == 0 {
                    idx_pair = u32::from(net_key_idx);
                } else {
                    idx_pair = (idx_pair << 12) + u32::from(net_key_idx);
                    if n + 3 > MAX_MSG_LEN as usize {
                        break;
                    }
                    let le = idx_pair.to_le_bytes();
                    msg[n] = le[0];
                    msg[n + 1] = le[1];
                    msg[n + 2] = le[2];
                    n += 3;
                }
                i += 1;
            }
            // Handle odd trailing index
            if (i & 1) == 1 && n + 2 <= MAX_MSG_LEN as usize {
                let le = (idx_pair as u16).to_le_bytes();
                msg[n] = le[0];
                msg[n + 1] = le[1];
                n += 2;
            }

            n
        }

        // ---------------------------------------------------------------
        // AppKey Management
        // ---------------------------------------------------------------
        OP_APPKEY_ADD | OP_APPKEY_UPDATE | OP_APPKEY_DELETE => {
            cfg_appkey_msg(node, pkt, opcode, &mut msg)
        }

        OP_APPKEY_GET => cfg_get_appkeys_msg(node, pkt, &mut msg),

        // ---------------------------------------------------------------
        // Model Publication
        // ---------------------------------------------------------------
        OP_CONFIG_MODEL_PUB_GET => config_pub_get(node, pkt, false, &mut msg),

        OP_CONFIG_MODEL_PUB_SET => {
            // ele_addr(2) + pub_addr(2) + idx(2) + ttl(1) + period(1) + rtx(1) + model(2|4)
            let vendor = pkt.len() >= 13; // 2+2+2+1+1+1+4
            config_pub_set(node, pkt, false, vendor, &mut msg)
        }

        OP_CONFIG_MODEL_PUB_VIRT_SET => {
            // ele_addr(2) + label(16) + idx(2) + ttl(1) + period(1) + rtx(1) + model(2|4)
            let vendor = pkt.len() >= 27; // 2+16+2+1+1+1+4
            config_pub_set(node, pkt, true, vendor, &mut msg)
        }

        // ---------------------------------------------------------------
        // Model Subscription (group address)
        // ---------------------------------------------------------------
        OP_CONFIG_MODEL_SUB_ADD | OP_CONFIG_MODEL_SUB_DELETE | OP_CONFIG_MODEL_SUB_OVERWRITE => {
            cfg_sub_add_msg(node, pkt, opcode, &mut msg)
        }

        OP_CONFIG_MODEL_SUB_DELETE_ALL => config_sub_del_all(node, pkt, &mut msg),

        // ---------------------------------------------------------------
        // Model Subscription (virtual address)
        // ---------------------------------------------------------------
        OP_CONFIG_MODEL_SUB_VIRT_ADD
        | OP_CONFIG_MODEL_SUB_VIRT_DELETE
        | OP_CONFIG_MODEL_SUB_VIRT_OVERWRITE => cfg_virt_sub_add_msg(node, pkt, opcode, &mut msg),

        // ---------------------------------------------------------------
        // Model Subscription Get (list)
        // ---------------------------------------------------------------
        OP_CONFIG_MODEL_SUB_GET => cfg_sub_get_msg(node, pkt, false, &mut msg),
        OP_CONFIG_VEND_MODEL_SUB_GET => cfg_sub_get_msg(node, pkt, true, &mut msg),

        // ---------------------------------------------------------------
        // Model App Bind / Unbind
        // ---------------------------------------------------------------
        OP_MODEL_APP_BIND => model_app_bind_msg(node, pkt, false, &mut msg),
        OP_MODEL_APP_UNBIND => model_app_bind_msg(node, pkt, true, &mut msg),

        // ---------------------------------------------------------------
        // Model App List
        // ---------------------------------------------------------------
        OP_MODEL_APP_GET => model_app_list(node, pkt, false, &mut msg),
        OP_VEND_MODEL_APP_GET => model_app_list(node, pkt, true, &mut msg),

        // ---------------------------------------------------------------
        // Heartbeat Publication
        // ---------------------------------------------------------------
        OP_CONFIG_HEARTBEAT_PUB_GET => hb_publication_get(node, &mut msg),
        OP_CONFIG_HEARTBEAT_PUB_SET => hb_publication_set(node, pkt, &mut msg),

        // ---------------------------------------------------------------
        // Heartbeat Subscription
        // ---------------------------------------------------------------
        OP_CONFIG_HEARTBEAT_SUB_GET => hb_subscription_get(node, &mut msg),
        OP_CONFIG_HEARTBEAT_SUB_SET => hb_subscription_set(node, pkt, &mut msg),

        // ---------------------------------------------------------------
        // Friend Poll Timeout
        // ---------------------------------------------------------------
        OP_CONFIG_POLL_TIMEOUT_GET => cfg_poll_timeout_msg(node, pkt, &mut msg),

        // ---------------------------------------------------------------
        // Node Identity
        // ---------------------------------------------------------------
        OP_NODE_IDENTITY_GET => {
            if pkt.len() < 2 {
                return true;
            }
            let id_net_idx = u16::from_le_bytes([pkt[0], pkt[1]]) & NET_IDX_MAX;

            let net = node.net.lock().unwrap();
            let identity = net.get_identity_mode(id_net_idx);
            drop(net);

            let mut n = mesh_model_opcode_set(OP_NODE_IDENTITY_STATUS, &mut msg);
            msg[n] = MESH_STATUS_SUCCESS;
            n += 1;
            msg[n..n + 2].copy_from_slice(&id_net_idx.to_le_bytes());
            n += 2;
            msg[n] = identity;
            n += 1;
            n
        }

        OP_NODE_IDENTITY_SET => {
            if pkt.len() < 3 {
                return true;
            }
            let id_net_idx = u16::from_le_bytes([pkt[0], pkt[1]]) & NET_IDX_MAX;
            let _identity_val = pkt[2];

            // Node Identity set is acknowledged but typically a no-op for
            // the config server (the proxy feature manages identity advertising).
            let net = node.net.lock().unwrap();
            let identity = net.get_identity_mode(id_net_idx);
            drop(net);

            let mut n = mesh_model_opcode_set(OP_NODE_IDENTITY_STATUS, &mut msg);
            msg[n] = MESH_STATUS_SUCCESS;
            n += 1;
            msg[n..n + 2].copy_from_slice(&id_net_idx.to_le_bytes());
            n += 2;
            msg[n] = identity;
            n += 1;
            n
        }

        // ---------------------------------------------------------------
        // Node Reset
        // ---------------------------------------------------------------
        OP_NODE_RESET => {
            debug!("Node Reset from {:#06x}", src);
            return handle_node_reset(node, src, net_idx, &mut msg) == 0;
        }

        // Unknown opcode — not handled
        _ => {
            return false;
        }
    };

    // Send the response if we have a non-zero length
    if n > 0 {
        mesh_model_send(node, 0, src, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, false, &msg[..n]);
    }

    true
}

// =========================================================================
// Model Ops Implementation
// =========================================================================

/// Configuration Server model operations.
///
/// Holds an `Arc<MeshNode>` for dispatching incoming configuration messages.
struct ConfigServerOps {
    node: Arc<MeshNode>,
}

impl MeshModelOps for ConfigServerOps {
    fn unregister(&self) {
        // No cleanup needed for the Configuration Server model
    }

    fn recv(&self, src: u16, unicast: u16, app_idx: u16, net_idx: u16, data: &[u8]) -> bool {
        cfg_srv_pkt(&self.node, src, unicast, app_idx, net_idx, data)
    }

    fn bind(&self, _app_idx: u16, _action: u8) -> i32 {
        // Configuration Server does not support app key binding
        -1
    }

    fn publish(&self, _pub_state: &MeshModelPub) -> i32 {
        // Configuration Server does not support publication
        -1
    }

    fn subscribe(&self, _sub_addr: u16, _action: u8) -> i32 {
        // Configuration Server does not support subscription
        -1
    }
}

// =========================================================================
// Public Initialization
// =========================================================================

/// Initialize the Configuration Server model on the given node element.
///
/// Registers the Configuration Server model handler using the
/// `mesh_model_register()` API. This is the direct Rust equivalent of
/// `cfgmod_server_init()` in `mesh/cfgmod-server.c`.
pub fn cfgmod_server_init(node: &Arc<MeshNode>, ele_idx: u8) {
    debug!("Config Server Init ele_idx={:#04x}", ele_idx);

    let ops = ConfigServerOps { node: Arc::clone(node) };

    mesh_model_register(node, ele_idx, CONFIG_SRV_MODEL, Box::new(ops));
}

// =========================================================================
// Unit Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{is_vendor, model_id};

    #[test]
    fn test_model_ids() {
        assert_eq!(CONFIG_SRV_MODEL, set_id(SIG_VENDOR, 0x0000));
        assert_eq!(CONFIG_CLI_MODEL, set_id(SIG_VENDOR, 0x0001));
        assert!(!is_vendor(CONFIG_SRV_MODEL));
        assert!(!is_vendor(CONFIG_CLI_MODEL));
        assert_eq!(model_id(CONFIG_SRV_MODEL), 0x0000);
        assert_eq!(model_id(CONFIG_CLI_MODEL), 0x0001);
    }

    #[test]
    fn test_opcode_values() {
        assert_eq!(OP_APPKEY_ADD, 0x00);
        assert_eq!(OP_APPKEY_UPDATE, 0x01);
        assert_eq!(OP_DEV_COMP_STATUS, 0x02);
        assert_eq!(OP_CONFIG_MODEL_PUB_SET, 0x03);
        assert_eq!(OP_CONFIG_HEARTBEAT_PUB_STATUS, 0x06);
        assert_eq!(OP_APPKEY_DELETE, 0x8000);
        assert_eq!(OP_DEV_COMP_GET, 0x8008);
        assert_eq!(OP_CONFIG_BEACON_GET, 0x8009);
        assert_eq!(OP_CONFIG_BEACON_SET, 0x800A);
        assert_eq!(OP_CONFIG_BEACON_STATUS, 0x800B);
        assert_eq!(OP_CONFIG_DEFAULT_TTL_GET, 0x800C);
        assert_eq!(OP_NETKEY_ADD, 0x8040);
        assert_eq!(OP_NETKEY_DELETE, 0x8041);
        assert_eq!(OP_NODE_RESET, 0x8049);
        assert_eq!(OP_NODE_RESET_STATUS, 0x804A);
        assert_eq!(OP_VEND_MODEL_APP_LIST, 0x804E);
    }

    #[test]
    fn test_opcode_uniqueness() {
        let opcodes = [
            OP_APPKEY_ADD,
            OP_APPKEY_DELETE,
            OP_APPKEY_GET,
            OP_APPKEY_LIST,
            OP_APPKEY_STATUS,
            OP_APPKEY_UPDATE,
            OP_DEV_COMP_GET,
            OP_DEV_COMP_STATUS,
            OP_CONFIG_BEACON_GET,
            OP_CONFIG_BEACON_SET,
            OP_CONFIG_BEACON_STATUS,
            OP_CONFIG_DEFAULT_TTL_GET,
            OP_CONFIG_DEFAULT_TTL_SET,
            OP_CONFIG_DEFAULT_TTL_STATUS,
            OP_CONFIG_FRIEND_GET,
            OP_CONFIG_FRIEND_SET,
            OP_CONFIG_FRIEND_STATUS,
            OP_CONFIG_PROXY_GET,
            OP_CONFIG_PROXY_SET,
            OP_CONFIG_PROXY_STATUS,
            OP_CONFIG_KEY_REFRESH_PHASE_GET,
            OP_CONFIG_KEY_REFRESH_PHASE_SET,
            OP_CONFIG_KEY_REFRESH_PHASE_STATUS,
            OP_CONFIG_MODEL_PUB_GET,
            OP_CONFIG_MODEL_PUB_SET,
            OP_CONFIG_MODEL_PUB_STATUS,
            OP_CONFIG_MODEL_PUB_VIRT_SET,
            OP_CONFIG_MODEL_SUB_ADD,
            OP_CONFIG_MODEL_SUB_DELETE,
            OP_CONFIG_MODEL_SUB_DELETE_ALL,
            OP_CONFIG_MODEL_SUB_OVERWRITE,
            OP_CONFIG_MODEL_SUB_STATUS,
            OP_CONFIG_MODEL_SUB_VIRT_ADD,
            OP_CONFIG_MODEL_SUB_VIRT_DELETE,
            OP_CONFIG_MODEL_SUB_VIRT_OVERWRITE,
            OP_CONFIG_NETWORK_TRANSMIT_GET,
            OP_CONFIG_NETWORK_TRANSMIT_SET,
            OP_CONFIG_NETWORK_TRANSMIT_STATUS,
            OP_CONFIG_RELAY_GET,
            OP_CONFIG_RELAY_SET,
            OP_CONFIG_RELAY_STATUS,
            OP_CONFIG_MODEL_SUB_GET,
            OP_CONFIG_MODEL_SUB_LIST,
            OP_CONFIG_VEND_MODEL_SUB_GET,
            OP_CONFIG_VEND_MODEL_SUB_LIST,
            OP_CONFIG_POLL_TIMEOUT_GET,
            OP_CONFIG_POLL_TIMEOUT_STATUS,
            OP_CONFIG_HEARTBEAT_PUB_GET,
            OP_CONFIG_HEARTBEAT_PUB_SET,
            OP_CONFIG_HEARTBEAT_PUB_STATUS,
            OP_CONFIG_HEARTBEAT_SUB_GET,
            OP_CONFIG_HEARTBEAT_SUB_SET,
            OP_CONFIG_HEARTBEAT_SUB_STATUS,
            OP_MODEL_APP_BIND,
            OP_MODEL_APP_STATUS,
            OP_MODEL_APP_UNBIND,
            OP_NETKEY_ADD,
            OP_NETKEY_DELETE,
            OP_NETKEY_GET,
            OP_NETKEY_LIST,
            OP_NETKEY_STATUS,
            OP_NETKEY_UPDATE,
            OP_NODE_IDENTITY_GET,
            OP_NODE_IDENTITY_SET,
            OP_NODE_IDENTITY_STATUS,
            OP_NODE_RESET,
            OP_NODE_RESET_STATUS,
            OP_MODEL_APP_GET,
            OP_MODEL_APP_LIST,
            OP_VEND_MODEL_APP_GET,
            OP_VEND_MODEL_APP_LIST,
        ];
        let mut seen = std::collections::HashSet::new();
        for &op in &opcodes {
            assert!(seen.insert(op), "Duplicate opcode value: {:#06x}", op);
        }
        assert_eq!(seen.len(), 71);
    }

    #[test]
    fn test_uint32_to_log() {
        assert_eq!(uint32_to_log(0), 0);
        assert_eq!(uint32_to_log(1), 1);
        assert_eq!(uint32_to_log(2), 2);
        assert_eq!(uint32_to_log(3), 3);
        assert_eq!(uint32_to_log(4), 3);
        assert_eq!(uint32_to_log(255), 9);
        assert_eq!(uint32_to_log(256), 9);
        assert_eq!(uint32_to_log(65535), 17);
    }

    #[test]
    fn test_log_to_uint32() {
        assert_eq!(log_to_uint32(0), 0);
        assert_eq!(log_to_uint32(1), 1);
        assert_eq!(log_to_uint32(2), 2);
        assert_eq!(log_to_uint32(3), 4);
        assert_eq!(log_to_uint32(8), 128);
        assert_eq!(log_to_uint32(17), 65536);
        assert_eq!(log_to_uint32(18), 0xFFFF);
    }

    #[test]
    fn test_pub_period_to_ms() {
        // Resolution 0: 100ms steps
        assert_eq!(pub_period_to_ms(0x01), 100);
        assert_eq!(pub_period_to_ms(0x0A), 1000);
        // Resolution 1: 1s steps
        assert_eq!(pub_period_to_ms(0x41), 1000);
        assert_eq!(pub_period_to_ms(0x4A), 10000);
        // Resolution 2: 10s steps
        assert_eq!(pub_period_to_ms(0x81), 10000);
        // Resolution 3: 10min steps
        assert_eq!(pub_period_to_ms(0xC1), 600000);
        // 0 steps
        assert_eq!(pub_period_to_ms(0x00), 0);
    }

    #[test]
    fn test_cfg_get_id_sig() {
        // SIG model ID: 2 bytes LE => set_id(SIG_VENDOR, model)
        let pkt = [0x00, 0x10]; // model 0x1000
        let id = cfg_get_id(false, &pkt);
        assert_eq!(id, set_id(SIG_VENDOR, 0x1000));
    }

    #[test]
    fn test_cfg_get_id_vendor() {
        // Vendor model: CID(2 LE) + PID(2 LE)
        let pkt = [0x0A, 0x00, 0x01, 0x00]; // CID=0x000A, PID=0x0001
        let id = cfg_get_id(true, &pkt);
        assert_eq!(id, set_id(0x000A, 0x0001));
    }
}
