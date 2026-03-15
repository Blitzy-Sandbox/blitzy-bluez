// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2023 Intel Corporation. All rights reserved.
//
// Rust rewrite of mesh/prvbeac-server.c and mesh/prv-beacon.h.
// Implements the Bluetooth Mesh Private Beacon Server model — handles
// Private Beacon Get/Set, and returns NOT_SUPPORTED for GATT Proxy
// and Node Identity operations.

use std::sync::Arc;

use tracing::debug;

use crate::mesh::{APP_IDX_DEV_LOCAL, DEFAULT_TTL};
use crate::model::{
    MeshModelOps, MeshModelPub, SIG_VENDOR, mesh_model_opcode_get, mesh_model_opcode_set,
    mesh_model_register, mesh_model_send, set_id,
};
use crate::node::{
    MeshNode, node_mpb_mode_get, node_mpb_mode_set, node_mpb_period_get, node_mpb_period_set,
};

// =========================================================================
// Model IDs (from mesh/prv-beacon.h lines 22-23)
// =========================================================================

/// Private Beacon Server model ID (SIG model 0x0008).
pub const PRV_BEACON_SRV_MODEL: u32 = set_id(SIG_VENDOR, 0x0008);

/// Private Beacon Client model ID (SIG model 0x0009).
pub const PRV_BEACON_CLI_MODEL: u32 = set_id(SIG_VENDOR, 0x0009);

// =========================================================================
// Opcodes (from mesh/prv-beacon.h lines 26-34)
// =========================================================================

/// Private Beacon Get opcode.
pub const OP_PRIVATE_BEACON_GET: u32 = 0x8060;

/// Private Beacon Set opcode.
pub const OP_PRIVATE_BEACON_SET: u32 = 0x8061;

/// Private Beacon Status opcode.
pub const OP_PRIVATE_BEACON_STATUS: u32 = 0x8062;

/// Private GATT Proxy Get opcode.
pub const OP_PRIVATE_GATT_PROXY_GET: u32 = 0x8063;

/// Private GATT Proxy Set opcode.
pub const OP_PRIVATE_GATT_PROXY_SET: u32 = 0x8064;

/// Private GATT Proxy Status opcode.
pub const OP_PRIVATE_GATT_PROXY_STATUS: u32 = 0x8065;

/// Private Node Identity Get opcode.
pub const OP_PRIVATE_NODE_ID_GET: u32 = 0x8066;

/// Private Node Identity Set opcode.
pub const OP_PRIVATE_NODE_ID_SET: u32 = 0x8067;

/// Private Node Identity Status opcode.
pub const OP_PRIVATE_NODE_ID_STATUS: u32 = 0x8068;

// =========================================================================
// Internal Constants (from prvbeac-server.c line 36)
// =========================================================================

/// Status code indicating the feature is not supported.
const NOT_SUPPORTED: u8 = 0x02;

// =========================================================================
// Message Dispatcher (from prvbeac-server.c lines 38-111)
// =========================================================================

/// Handle incoming Private Beacon Server model messages.
///
/// Implements the complete message dispatch for the Private Beacon Server model,
/// matching the C `prvbec_srv_pkt()` function behavior exactly.
///
/// # Arguments
/// * `node` - The mesh node this model is registered on.
/// * `src` - Source address of the incoming message (sender).
/// * `_unicast` - Destination unicast address (our address — unused because the
///   element index is always the primary element for this model).
/// * `app_idx` - Application key index (must be `APP_IDX_DEV_LOCAL`).
/// * `net_idx` - Network key index.
/// * `data` - Raw message data including the opcode prefix.
fn prvbec_srv_pkt(
    node: &MeshNode,
    src: u16,
    _unicast: u16,
    app_idx: u16,
    net_idx: u16,
    data: &[u8],
) -> bool {
    // Only accept device-key-encrypted messages (C: line 49).
    if app_idx != APP_IDX_DEV_LOCAL {
        return false;
    }

    // Decode the opcode from the message data (C: lines 52-56).
    let (opcode, consumed) = match mesh_model_opcode_get(data) {
        Some(v) => v,
        None => return false,
    };

    let pkt = &data[consumed..];
    let size = pkt.len();

    debug!("PRV-BEAC-SRV-opcode 0x{:x} size {} idx {:03x}", opcode, size, net_idx);

    // Response buffer — maximum 5 bytes (2 opcode + 2 payload + 1 spare).
    let mut msg = [0u8; 5];
    let n: usize;

    match opcode {
        // ── Private Beacon Set (C: lines 67-78) ─────────────────
        // Validates and applies mode (and optionally period), then
        // falls through to the GET/status response path.
        OP_PRIVATE_BEACON_SET => {
            // Determine the period value: if only the mode byte is supplied
            // (size == 1), keep the existing period; if two bytes (size == 2),
            // use the second byte as the new period.
            let period = if size == 1 {
                node_mpb_period_get(node)
            } else if size == 2 {
                pkt[1]
            } else {
                // Invalid payload length — silently accept but do not respond.
                return true;
            };

            // Mode must be 0 (disabled) or 1 (enabled).
            if pkt[0] > 1 {
                return true;
            }

            // Apply the new period first so that node_mpb_mode_set picks it
            // up when propagating to the network layer.
            node_mpb_period_set(node, period);
            node_mpb_mode_set(node, pkt[0] != 0);

            // Build status response (C fall-through to OP_PRIVATE_BEACON_GET).
            n = build_beacon_status(&mut msg, node);
            debug!("Get/Set Private Beacon ({})", msg[n - 2]);
        }

        // ── Private Beacon Get (C: lines 82-89) ─────────────────
        OP_PRIVATE_BEACON_GET => {
            n = build_beacon_status(&mut msg, node);
            debug!("Get/Set Private Beacon ({})", msg[n - 2]);
        }

        // ── Private GATT Proxy Get/Set (C: lines 91-96) ─────────
        // Not supported — always respond with NOT_SUPPORTED status.
        OP_PRIVATE_GATT_PROXY_SET | OP_PRIVATE_GATT_PROXY_GET => {
            let opcode_len = mesh_model_opcode_set(OP_PRIVATE_GATT_PROXY_STATUS, &mut msg);
            msg[opcode_len] = NOT_SUPPORTED;
            n = opcode_len + 1;
        }

        // ── Private Node Identity Get/Set (C: lines 98-103) ─────
        // Not supported — always respond with NOT_SUPPORTED status.
        OP_PRIVATE_NODE_ID_SET | OP_PRIVATE_NODE_ID_GET => {
            let opcode_len = mesh_model_opcode_set(OP_PRIVATE_NODE_ID_STATUS, &mut msg);
            msg[opcode_len] = NOT_SUPPORTED;
            n = opcode_len + 1;
        }

        // Unknown opcode — not handled by this model (C: default case, line 64-65).
        _ => return false,
    }

    // Send the response if a payload was constructed (C: lines 106-108).
    if n > 0 {
        mesh_model_send(node, 0, src, APP_IDX_DEV_LOCAL, net_idx, DEFAULT_TTL, false, &msg[..n]);
    }

    true
}

/// Build a Private Beacon Status response message.
///
/// Writes the `OP_PRIVATE_BEACON_STATUS` opcode followed by the current mode
/// and period values into `msg`. Returns the total number of bytes written.
fn build_beacon_status(msg: &mut [u8; 5], node: &MeshNode) -> usize {
    let mut n = mesh_model_opcode_set(OP_PRIVATE_BEACON_STATUS, msg);
    msg[n] = node_mpb_mode_get(node);
    n += 1;
    msg[n] = node_mpb_period_get(node);
    n += 1;
    n
}

// =========================================================================
// Model Ops Implementation (from prvbeac-server.c lines 113-123)
// =========================================================================

/// Private Beacon Server model operations.
///
/// Implements `MeshModelOps` to dispatch incoming messages to `prvbec_srv_pkt()`.
/// Binding, subscription, and publication are not applicable and return -1.
struct PrvBeaconServerOps {
    node: Arc<MeshNode>,
}

impl MeshModelOps for PrvBeaconServerOps {
    fn unregister(&self) {
        // No-op — matches the empty C `prvbec_srv_unregister()` (line 113-115).
    }

    fn recv(&self, src: u16, unicast: u16, app_idx: u16, net_idx: u16, data: &[u8]) -> bool {
        prvbec_srv_pkt(&self.node, src, unicast, app_idx, net_idx, data)
    }

    fn bind(&self, _app_idx: u16, _action: u8) -> i32 {
        -1
    }

    fn publish(&self, _pub_state: &MeshModelPub) -> i32 {
        -1
    }

    fn subscribe(&self, _sub_addr: u16, _action: u8) -> i32 {
        -1
    }
}

// =========================================================================
// Initialization (from prvbeac-server.c lines 125-129)
// =========================================================================

/// Register the Private Beacon Server model on the specified element.
///
/// Mirrors C `prv_beacon_server_init()` — logs the element index and registers
/// the model operations table on the given element of the node.
pub fn prv_beacon_server_init(node: &Arc<MeshNode>, ele_idx: u8) {
    debug!("{:02x}", ele_idx);
    let ops = PrvBeaconServerOps { node: Arc::clone(node) };
    mesh_model_register(node, ele_idx, PRV_BEACON_SRV_MODEL, Box::new(ops));
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SIG_VENDOR, mesh_model_opcode_set, set_id};

    // ── Model ID constants ──────────────────────────────────────

    #[test]
    fn test_prv_beacon_srv_model_id() {
        assert_eq!(PRV_BEACON_SRV_MODEL, set_id(SIG_VENDOR, 0x0008));
        assert_eq!(PRV_BEACON_SRV_MODEL, 0xFFFF_0008);
    }

    #[test]
    fn test_prv_beacon_cli_model_id() {
        assert_eq!(PRV_BEACON_CLI_MODEL, set_id(SIG_VENDOR, 0x0009));
        assert_eq!(PRV_BEACON_CLI_MODEL, 0xFFFF_0009);
    }

    // ── Opcode values ───────────────────────────────────────────

    #[test]
    fn test_private_beacon_opcodes() {
        assert_eq!(OP_PRIVATE_BEACON_GET, 0x8060);
        assert_eq!(OP_PRIVATE_BEACON_SET, 0x8061);
        assert_eq!(OP_PRIVATE_BEACON_STATUS, 0x8062);
    }

    #[test]
    fn test_private_gatt_proxy_opcodes() {
        assert_eq!(OP_PRIVATE_GATT_PROXY_GET, 0x8063);
        assert_eq!(OP_PRIVATE_GATT_PROXY_SET, 0x8064);
        assert_eq!(OP_PRIVATE_GATT_PROXY_STATUS, 0x8065);
    }

    #[test]
    fn test_private_node_id_opcodes() {
        assert_eq!(OP_PRIVATE_NODE_ID_GET, 0x8066);
        assert_eq!(OP_PRIVATE_NODE_ID_SET, 0x8067);
        assert_eq!(OP_PRIVATE_NODE_ID_STATUS, 0x8068);
    }

    // ── Opcode encoding ─────────────────────────────────────────

    #[test]
    fn test_opcodes_encode_as_two_bytes() {
        let mut buf = [0u8; 5];

        // OP_PRIVATE_BEACON_STATUS = 0x8062 -> 0x80, 0x62
        let n = mesh_model_opcode_set(OP_PRIVATE_BEACON_STATUS, &mut buf);
        assert_eq!(n, 2);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x62);

        // OP_PRIVATE_GATT_PROXY_STATUS = 0x8065 -> 0x80, 0x65
        let n = mesh_model_opcode_set(OP_PRIVATE_GATT_PROXY_STATUS, &mut buf);
        assert_eq!(n, 2);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x65);

        // OP_PRIVATE_NODE_ID_STATUS = 0x8068 -> 0x80, 0x68
        let n = mesh_model_opcode_set(OP_PRIVATE_NODE_ID_STATUS, &mut buf);
        assert_eq!(n, 2);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x68);
    }

    // ── All 9 opcodes are distinct and consecutive ──────────────

    #[test]
    fn test_all_opcodes_distinct_and_consecutive() {
        let opcodes = [
            OP_PRIVATE_BEACON_GET,
            OP_PRIVATE_BEACON_SET,
            OP_PRIVATE_BEACON_STATUS,
            OP_PRIVATE_GATT_PROXY_GET,
            OP_PRIVATE_GATT_PROXY_SET,
            OP_PRIVATE_GATT_PROXY_STATUS,
            OP_PRIVATE_NODE_ID_GET,
            OP_PRIVATE_NODE_ID_SET,
            OP_PRIVATE_NODE_ID_STATUS,
        ];

        // All 9 opcodes should be unique.
        for i in 0..opcodes.len() {
            for j in (i + 1)..opcodes.len() {
                assert_ne!(opcodes[i], opcodes[j], "Opcodes at indices {} and {} collide", i, j);
            }
        }

        // All opcodes should be consecutive from 0x8060 to 0x8068.
        for (idx, &op) in opcodes.iter().enumerate() {
            assert_eq!(
                op,
                0x8060 + idx as u32,
                "Opcode at index {} should be 0x{:04x}",
                idx,
                0x8060 + idx as u32
            );
        }
    }

    // ── NOT_SUPPORTED constant ──────────────────────────────────

    #[test]
    fn test_not_supported_value() {
        assert_eq!(NOT_SUPPORTED, 0x02);
    }
}
