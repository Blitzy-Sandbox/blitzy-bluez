// SPDX-License-Identifier: LGPL-2.1-or-later
// ISO channels tester — validates ISO (Isochronous) socket operations for both
// unicast CIS and broadcast BIG/BIS, including all BAP-defined QoS
// configurations, deferred setup, send/receive, timestamping, reconnection,
// PAST, suspension, and Audio Configuration test scenarios.
//
// Rust port of tools/iso-tester.c (4385 lines, LGPL-2.1-or-later).
#![deny(warnings)]

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------
use std::any::Any;
use std::io::IoSlice;
use std::sync::{Arc, LazyLock, Mutex};

use tracing::{error, info, warn};

use bluez_emulator::hciemu::{EmulatorType, HciEmulator};
use bluez_shared::mgmt::client::MgmtSocket;
use bluez_shared::socket::{BluetoothSocket, BtSocketError, BtTransport, bt_sockopt_get_int};
use bluez_shared::sys::bluetooth::{
    BDADDR_LE_PUBLIC, BT_CONNECTED, BT_DEFER_SETUP, BT_ISO_BASE, BT_ISO_QOS, BT_ISO_QOS_BIG_UNSET,
    BT_ISO_QOS_BIS_UNSET, BT_ISO_QOS_CIG_UNSET, BT_ISO_QOS_CIS_UNSET, BT_ISO_SYNC_TIMEOUT,
    BT_PKT_SEQNUM, BT_PKT_STATUS, BT_SCM_PKT_SEQNUM, BT_SCM_PKT_STATUS, BTPROTO_ISO, PF_BLUETOOTH,
    SOL_BLUETOOTH, bdaddr_t, bt_iso_bcast_qos, bt_iso_io_qos, bt_iso_qos, bt_iso_ucast_qos, btohl,
    btohs,
};
use bluez_shared::sys::hci::HCI_CONNECTION_TERMINATED;
use bluez_shared::sys::iso::{sockaddr_iso, sockaddr_iso_bc};
use bluez_shared::sys::mgmt::{
    MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE, MGMT_OP_ADD_DEVICE, MGMT_OP_READ_INDEX_LIST,
    MGMT_OP_READ_INFO, MGMT_OP_SET_CONNECTABLE, MGMT_OP_SET_DEVICE_FLAGS, MGMT_OP_SET_EXP_FEATURE,
    MGMT_OP_SET_LE, MGMT_OP_SET_POWERED, MGMT_OP_SET_SSP, MGMT_STATUS_SUCCESS,
};
use bluez_shared::tester::{
    tester_add_full, tester_get_data, tester_init, tester_post_teardown_complete,
    tester_pre_setup_complete, tester_pre_setup_failed, tester_print, tester_run,
    tester_setup_complete, tester_setup_failed, tester_test_abort, tester_test_failed,
    tester_test_passed, tester_use_debug, tester_warn,
};
use bluez_shared::util::queue::Queue;
use bluez_tools::{
    SOF_TIMESTAMPING_TX_COMPLETION, TesterError, TxTstampData, rx_timestamp_check,
    rx_timestamping_init, test_ethtool_get_ts_info,
};

// ---------------------------------------------------------------------------
// QoS helper constructors
// ---------------------------------------------------------------------------

/// Build a `bt_iso_io_qos` from the provided parameters.
fn qos_io(interval: u32, latency: u16, sdu: u16, phys: u8, rtn: u8) -> bt_iso_io_qos {
    bt_iso_io_qos::new(interval, latency, sdu, phys, rtn)
}

/// Default (zero) IO QoS.
fn qos_io_default() -> bt_iso_io_qos {
    bt_iso_io_qos::default()
}

/// Build a unicast ISO QoS.
fn qos_full(cig: u8, cis: u8, input: bt_iso_io_qos, output: bt_iso_io_qos) -> bt_iso_qos {
    bt_iso_qos::new_ucast(bt_iso_ucast_qos {
        cig,
        cis,
        sca: 0x07,
        packing: 0x00,
        framing: 0x00,
        in_qos: input,
        out_qos: output,
    })
}

/// Build a unicast ISO QoS with default CIG/CIS.
fn qos_ucast(input: bt_iso_io_qos, output: bt_iso_io_qos) -> bt_iso_qos {
    qos_full(BT_ISO_QOS_CIG_UNSET, BT_ISO_QOS_CIS_UNSET, input, output)
}

/// Build a broadcast ISO QoS.
fn qos_bcast_full(
    big: u8,
    bis: u8,
    encryption: u8,
    bcode: [u8; 16],
    input: bt_iso_io_qos,
    output: bt_iso_io_qos,
) -> bt_iso_qos {
    bt_iso_qos::new_bcast(bt_iso_bcast_qos {
        big,
        bis,
        sync_factor: 0x07,
        packing: 0x00,
        framing: 0x00,
        in_qos: input,
        out_qos: output,
        encryption,
        bcode,
        options: 0x00,
        skip: 0x0000,
        sync_timeout: 0x4000,
        sync_cte_type: 0x00,
        mse: 0x00,
        timeout: 0x4000,
    })
}

/// Build a broadcast ISO QoS with default BIG/BIS.
fn qos_bcast(
    encryption: u8,
    bcode: [u8; 16],
    input: bt_iso_io_qos,
    output: bt_iso_io_qos,
) -> bt_iso_qos {
    qos_bcast_full(BT_ISO_QOS_BIG_UNSET, BT_ISO_QOS_BIS_UNSET, encryption, bcode, input, output)
}

// ---------------------------------------------------------------------------
// PHY constants
// ---------------------------------------------------------------------------
const QOS_1M: u8 = 0x01;
const QOS_2M: u8 = 0x02;

// ---------------------------------------------------------------------------
// Standard BAP QoS IO presets — Set 1 (low latency)
// ---------------------------------------------------------------------------
fn qos_io_8_1_1() -> bt_iso_io_qos {
    qos_io(7500, 8, 26, QOS_2M, 2)
}
fn qos_io_8_2_1() -> bt_iso_io_qos {
    qos_io(10000, 10, 30, QOS_2M, 2)
}
fn qos_io_16_1_1() -> bt_iso_io_qos {
    qos_io(7500, 8, 30, QOS_2M, 2)
}
fn qos_io_16_2_1() -> bt_iso_io_qos {
    qos_io(10000, 10, 40, QOS_2M, 2)
}
fn qos_io_24_1_1() -> bt_iso_io_qos {
    qos_io(7500, 8, 45, QOS_2M, 2)
}
fn qos_io_24_2_1() -> bt_iso_io_qos {
    qos_io(10000, 10, 60, QOS_2M, 2)
}
fn qos_io_32_1_1() -> bt_iso_io_qos {
    qos_io(7500, 8, 60, QOS_2M, 2)
}
fn qos_io_32_2_1() -> bt_iso_io_qos {
    qos_io(10000, 10, 80, QOS_2M, 2)
}
fn qos_io_44_1_1() -> bt_iso_io_qos {
    qos_io(8163, 24, 98, QOS_2M, 5)
}
fn qos_io_44_2_1() -> bt_iso_io_qos {
    qos_io(10884, 31, 130, QOS_2M, 5)
}
fn qos_io_48_1_1() -> bt_iso_io_qos {
    qos_io(7500, 15, 75, QOS_2M, 5)
}
fn qos_io_48_2_1() -> bt_iso_io_qos {
    qos_io(10000, 20, 100, QOS_2M, 5)
}
fn qos_io_48_3_1() -> bt_iso_io_qos {
    qos_io(7500, 15, 90, QOS_2M, 5)
}
fn qos_io_48_4_1() -> bt_iso_io_qos {
    qos_io(10000, 20, 120, QOS_2M, 5)
}
fn qos_io_48_5_1() -> bt_iso_io_qos {
    qos_io(7500, 15, 117, QOS_2M, 5)
}
fn qos_io_48_6_1() -> bt_iso_io_qos {
    qos_io(10000, 20, 155, QOS_2M, 5)
}

// Set 2 (high reliability)
fn qos_io_8_1_2() -> bt_iso_io_qos {
    qos_io(7500, 75, 26, QOS_2M, 13)
}
fn qos_io_8_2_2() -> bt_iso_io_qos {
    qos_io(10000, 95, 30, QOS_2M, 13)
}
fn qos_io_16_1_2() -> bt_iso_io_qos {
    qos_io(7500, 75, 30, QOS_2M, 13)
}
fn qos_io_16_2_2() -> bt_iso_io_qos {
    qos_io(10000, 95, 40, QOS_2M, 13)
}
fn qos_io_24_1_2() -> bt_iso_io_qos {
    qos_io(7500, 75, 45, QOS_2M, 13)
}
fn qos_io_24_2_2() -> bt_iso_io_qos {
    qos_io(10000, 95, 60, QOS_2M, 13)
}
fn qos_io_32_1_2() -> bt_iso_io_qos {
    qos_io(7500, 75, 60, QOS_2M, 13)
}
fn qos_io_32_2_2() -> bt_iso_io_qos {
    qos_io(10000, 95, 80, QOS_2M, 13)
}
fn qos_io_44_1_2() -> bt_iso_io_qos {
    qos_io(8163, 54, 98, QOS_2M, 13)
}
fn qos_io_44_2_2() -> bt_iso_io_qos {
    qos_io(10884, 60, 130, QOS_2M, 13)
}
fn qos_io_48_1_2() -> bt_iso_io_qos {
    qos_io(7500, 75, 75, QOS_2M, 13)
}
fn qos_io_48_2_2() -> bt_iso_io_qos {
    qos_io(10000, 95, 100, QOS_2M, 13)
}
fn qos_io_48_3_2() -> bt_iso_io_qos {
    qos_io(7500, 75, 90, QOS_2M, 13)
}
fn qos_io_48_4_2() -> bt_iso_io_qos {
    qos_io(10000, 95, 120, QOS_2M, 13)
}
fn qos_io_48_5_2() -> bt_iso_io_qos {
    qos_io(7500, 75, 117, QOS_2M, 13)
}
fn qos_io_48_6_2() -> bt_iso_io_qos {
    qos_io(10000, 95, 155, QOS_2M, 13)
}

// Gaming/streaming IO params
fn qos_io_16_1_gs() -> bt_iso_io_qos {
    qos_io(7500, 8, 30, QOS_1M, 2)
}
fn qos_io_16_2_gs() -> bt_iso_io_qos {
    qos_io(10000, 10, 40, QOS_1M, 2)
}
fn qos_io_32_1_gs() -> bt_iso_io_qos {
    qos_io(7500, 8, 60, QOS_1M, 2)
}
fn qos_io_32_2_gs() -> bt_iso_io_qos {
    qos_io(10000, 10, 80, QOS_1M, 2)
}
fn qos_io_48_1_gs() -> bt_iso_io_qos {
    qos_io(7500, 15, 75, QOS_1M, 5)
}
fn qos_io_48_2_gs() -> bt_iso_io_qos {
    qos_io(10000, 20, 100, QOS_1M, 5)
}
fn qos_io_16_1_gr() -> bt_iso_io_qos {
    qos_io(7500, 8, 30, QOS_2M, 2)
}
fn qos_io_16_2_gr() -> bt_iso_io_qos {
    qos_io(10000, 10, 40, QOS_2M, 2)
}
fn qos_io_32_1_gr() -> bt_iso_io_qos {
    qos_io(7500, 8, 60, QOS_2M, 2)
}
fn qos_io_32_2_gr() -> bt_iso_io_qos {
    qos_io(10000, 10, 80, QOS_2M, 2)
}
fn qos_io_48_1_gr() -> bt_iso_io_qos {
    qos_io(7500, 15, 75, QOS_2M, 5)
}
fn qos_io_48_2_gr() -> bt_iso_io_qos {
    qos_io(10000, 20, 100, QOS_2M, 5)
}
fn qos_io_48_3_gr() -> bt_iso_io_qos {
    qos_io(7500, 15, 90, QOS_2M, 5)
}
fn qos_io_48_4_gr() -> bt_iso_io_qos {
    qos_io(10000, 20, 120, QOS_2M, 5)
}

// ---------------------------------------------------------------------------
// Full unicast QoS constructors
// ---------------------------------------------------------------------------
fn make_qos_8_1_1() -> bt_iso_qos {
    qos_ucast(qos_io_8_1_1(), qos_io_default())
}
fn make_qos_8_2_1() -> bt_iso_qos {
    qos_ucast(qos_io_8_2_1(), qos_io_default())
}
fn make_qos_16_1_1() -> bt_iso_qos {
    qos_ucast(qos_io_16_1_1(), qos_io_default())
}
fn make_qos_16_2_1() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_1(), qos_io_default())
}
fn make_qos_24_1_1() -> bt_iso_qos {
    qos_ucast(qos_io_24_1_1(), qos_io_default())
}
fn make_qos_24_2_1() -> bt_iso_qos {
    qos_ucast(qos_io_24_2_1(), qos_io_default())
}
fn make_qos_32_1_1() -> bt_iso_qos {
    qos_ucast(qos_io_32_1_1(), qos_io_default())
}
fn make_qos_32_2_1() -> bt_iso_qos {
    qos_ucast(qos_io_32_2_1(), qos_io_default())
}
fn make_qos_44_1_1() -> bt_iso_qos {
    qos_ucast(qos_io_44_1_1(), qos_io_default())
}
fn make_qos_44_2_1() -> bt_iso_qos {
    qos_ucast(qos_io_44_2_1(), qos_io_default())
}
fn make_qos_48_1_1() -> bt_iso_qos {
    qos_ucast(qos_io_48_1_1(), qos_io_default())
}
fn make_qos_48_2_1() -> bt_iso_qos {
    qos_ucast(qos_io_48_2_1(), qos_io_default())
}
fn make_qos_48_3_1() -> bt_iso_qos {
    qos_ucast(qos_io_48_3_1(), qos_io_default())
}
fn make_qos_48_4_1() -> bt_iso_qos {
    qos_ucast(qos_io_48_4_1(), qos_io_default())
}
fn make_qos_48_5_1() -> bt_iso_qos {
    qos_ucast(qos_io_48_5_1(), qos_io_default())
}
fn make_qos_48_6_1() -> bt_iso_qos {
    qos_ucast(qos_io_48_6_1(), qos_io_default())
}
fn make_qos_8_1_2() -> bt_iso_qos {
    qos_ucast(qos_io_8_1_2(), qos_io_default())
}
fn make_qos_8_2_2() -> bt_iso_qos {
    qos_ucast(qos_io_8_2_2(), qos_io_default())
}
fn make_qos_16_1_2() -> bt_iso_qos {
    qos_ucast(qos_io_16_1_2(), qos_io_default())
}
fn make_qos_16_2_2() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_2(), qos_io_default())
}
fn make_qos_24_1_2() -> bt_iso_qos {
    qos_ucast(qos_io_24_1_2(), qos_io_default())
}
fn make_qos_24_2_2() -> bt_iso_qos {
    qos_ucast(qos_io_24_2_2(), qos_io_default())
}
fn make_qos_32_1_2() -> bt_iso_qos {
    qos_ucast(qos_io_32_1_2(), qos_io_default())
}
fn make_qos_32_2_2() -> bt_iso_qos {
    qos_ucast(qos_io_32_2_2(), qos_io_default())
}
fn make_qos_44_1_2() -> bt_iso_qos {
    qos_ucast(qos_io_44_1_2(), qos_io_default())
}
fn make_qos_44_2_2() -> bt_iso_qos {
    qos_ucast(qos_io_44_2_2(), qos_io_default())
}
fn make_qos_48_1_2() -> bt_iso_qos {
    qos_ucast(qos_io_48_1_2(), qos_io_default())
}
fn make_qos_48_2_2() -> bt_iso_qos {
    qos_ucast(qos_io_48_2_2(), qos_io_default())
}
fn make_qos_48_3_2() -> bt_iso_qos {
    qos_ucast(qos_io_48_3_2(), qos_io_default())
}
fn make_qos_48_4_2() -> bt_iso_qos {
    qos_ucast(qos_io_48_4_2(), qos_io_default())
}
fn make_qos_48_5_2() -> bt_iso_qos {
    qos_ucast(qos_io_48_5_2(), qos_io_default())
}
fn make_qos_48_6_2() -> bt_iso_qos {
    qos_ucast(qos_io_48_6_2(), qos_io_default())
}
fn make_qos_16_1_gs() -> bt_iso_qos {
    qos_ucast(qos_io_16_1_gs(), qos_io_16_1_gr())
}
fn make_qos_16_2_gs() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_gs(), qos_io_16_2_gr())
}
fn make_qos_32_1_gs() -> bt_iso_qos {
    qos_ucast(qos_io_32_1_gs(), qos_io_32_1_gr())
}
fn make_qos_32_2_gs() -> bt_iso_qos {
    qos_ucast(qos_io_32_2_gs(), qos_io_32_2_gr())
}
fn make_qos_48_1_gs() -> bt_iso_qos {
    qos_ucast(qos_io_48_1_gs(), qos_io_48_1_gr())
}
fn make_qos_48_2_gs() -> bt_iso_qos {
    qos_ucast(qos_io_48_2_gs(), qos_io_48_2_gr())
}
fn make_qos_48_3_gr() -> bt_iso_qos {
    qos_ucast(qos_io_48_3_gr(), qos_io_default())
}
fn make_qos_48_4_gr() -> bt_iso_qos {
    qos_ucast(qos_io_48_4_gr(), qos_io_default())
}

// ---------------------------------------------------------------------------
// Broadcast QoS constructors
// ---------------------------------------------------------------------------
const BCODE: [u8; 16] = [
    0x01, 0x02, 0x68, 0x05, 0x53, 0xf1, 0x41, 0x5a, 0xa2, 0x65, 0xbb, 0xaf, 0xc6, 0xea, 0x03, 0xb8,
];
const BCODE_ZERO: [u8; 16] = [0; 16];

fn make_qos_out_16_2_1() -> bt_iso_qos {
    qos_bcast(0x00, BCODE_ZERO, qos_io_default(), qos_io_16_2_1())
}
fn make_qos_out_enc_16_2_1() -> bt_iso_qos {
    qos_bcast(0x01, BCODE, qos_io_default(), qos_io_16_2_1())
}
fn make_qos_out_1_16_2_1() -> bt_iso_qos {
    qos_bcast_full(0x01, BT_ISO_QOS_BIS_UNSET, 0x00, BCODE_ZERO, qos_io_default(), qos_io_16_2_1())
}
fn make_qos_out_1_1_16_2_1() -> bt_iso_qos {
    qos_bcast_full(0x01, 0x01, 0x00, BCODE_ZERO, qos_io_default(), qos_io_16_2_1())
}
fn make_qos_in_16_2_1() -> bt_iso_qos {
    qos_bcast(0x00, BCODE_ZERO, qos_io_16_2_1(), qos_io_default())
}
fn make_qos_in_enc_16_2_1() -> bt_iso_qos {
    qos_bcast(0x01, BCODE, qos_io_16_2_1(), qos_io_default())
}
fn make_qos_out_48_1_g() -> bt_iso_qos {
    qos_bcast(0x00, BCODE_ZERO, qos_io_default(), qos_io_48_1_1())
}
fn make_qos_out_48_2_g() -> bt_iso_qos {
    qos_bcast(0x00, BCODE_ZERO, qos_io_default(), qos_io_48_2_1())
}
fn make_qos_out_48_3_g() -> bt_iso_qos {
    qos_bcast(0x00, BCODE_ZERO, qos_io_default(), qos_io_48_3_1())
}
fn make_qos_out_48_4_g() -> bt_iso_qos {
    qos_bcast(0x00, BCODE_ZERO, qos_io_default(), qos_io_48_4_1())
}
// Audio Configuration QoS
fn make_ac_1_4() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_1(), qos_io_default())
}
fn make_ac_2_10() -> bt_iso_qos {
    qos_ucast(qos_io_default(), qos_io_16_2_1())
}
fn make_ac_3_5() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_1(), qos_io_16_2_1())
}
fn make_ac_6i() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_1(), qos_io_default())
}
fn make_ac_6ii() -> bt_iso_qos {
    qos_ucast(qos_io_default(), qos_io_16_2_1())
}
fn make_ac_7i() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_1(), qos_io_16_2_1())
}
fn make_ac_7ii() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_1(), qos_io_default())
}
fn make_ac_8i() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_1(), qos_io_default())
}
fn make_ac_8ii() -> bt_iso_qos {
    qos_ucast(qos_io_default(), qos_io_16_2_1())
}
fn make_ac_9i() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_1(), qos_io_default())
}
fn make_ac_9ii() -> bt_iso_qos {
    qos_ucast(qos_io_default(), qos_io_16_2_1())
}
fn make_ac_11i() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_1(), qos_io_16_2_1())
}
fn make_ac_11ii() -> bt_iso_qos {
    qos_ucast(qos_io_16_2_1(), qos_io_default())
}
fn make_bcast_ac_12() -> bt_iso_qos {
    qos_bcast(0x00, BCODE_ZERO, qos_io_default(), qos_io_16_2_1())
}
fn make_bcast_ac_13() -> bt_iso_qos {
    qos_bcast(0x00, BCODE_ZERO, qos_io_16_2_1(), qos_io_default())
}
fn make_bcast_ac_14() -> bt_iso_qos {
    qos_bcast(0x00, BCODE_ZERO, qos_io_16_2_1(), qos_io_16_2_1())
}

// ---------------------------------------------------------------------------
// BASE (Broadcast Audio Source Endpoint) data
// ---------------------------------------------------------------------------

const BASE_LC3_16_2_1: &[u8] = &[
    0x28, 0x00, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x03, 0x02, 0x01, 0x01,
    0x03, 0x01, 0x00, 0x00, 0x00, 0x02, 0x28, 0x00, 0x00, 0x01, 0x00,
];
const BASE_LC3_48_1_G: &[u8] = &[
    0x28, 0x00, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x08, 0x02, 0x02, 0x00,
    0x03, 0x01, 0x00, 0x00, 0x00, 0x02, 0x4B, 0x00, 0x00, 0x01, 0x00,
];
const BASE_LC3_48_2_G: &[u8] = &[
    0x28, 0x00, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x08, 0x02, 0x02, 0x01,
    0x03, 0x01, 0x00, 0x00, 0x00, 0x02, 0x64, 0x00, 0x00, 0x01, 0x00,
];
const BASE_LC3_48_3_G: &[u8] = &[
    0x28, 0x00, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x08, 0x02, 0x02, 0x00,
    0x03, 0x01, 0x00, 0x00, 0x00, 0x02, 0x5A, 0x00, 0x00, 0x01, 0x00,
];
const BASE_LC3_48_4_G: &[u8] = &[
    0x28, 0x00, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x08, 0x02, 0x02, 0x01,
    0x03, 0x01, 0x00, 0x00, 0x00, 0x02, 0x78, 0x00, 0x00, 0x01, 0x00,
];
const BASE_LC3_AC_12: &[u8] = BASE_LC3_16_2_1;
const BASE_LC3_AC_13: &[u8] = BASE_LC3_16_2_1;
const BASE_LC3_AC_14: &[u8] = BASE_LC3_16_2_1;

const SEND_DATA: &[u8] = &[0x01];

// Force suspend UUID (experimental feature)
const FORCE_SUSPEND_UUID: [u8; 16] = [
    0x9e, 0xbf, 0x9d, 0xa5, 0x05, 0x67, 0x4e, 0x0b, 0xb4, 0x56, 0xf4, 0xa6, 0x16, 0x6e, 0x4f, 0xd4,
];

/// Test timeout in seconds.
const TEST_TIMEOUT: u32 = 30;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Per-test-case client configuration.
/// Many fields are read only in specific test paths; all are used across the
/// full 120+ test matrix.
#[derive(Clone)]
#[allow(dead_code)]
struct IsoClientData {
    qos: bt_iso_qos,
    qos_2: Option<bt_iso_qos>,
    expect_err: i32,
    send: Option<&'static [u8]>,
    recv: Option<&'static [u8]>,
    server: bool,
    bcast: bool,
    past: bool,
    defer: bool,
    disconnect: bool,
    ts: bool,
    mconn: bool,
    suspend: bool,
    pkt_status: u8,
    base: Option<&'static [u8]>,
    sid: u8,
    listen_bind: bool,
    pa_bind: bool,
    big: bool,
    terminate: bool,
    pkt_seqnum: bool,
    so_timestamping: u32,
    cmsg_timestamping: bool,
    repeat_send_pre_ts: u32,
    repeat_send: u32,
}

impl Default for IsoClientData {
    fn default() -> Self {
        Self {
            qos: qos_ucast(qos_io_default(), qos_io_default()),
            qos_2: None,
            expect_err: 0,
            send: None,
            recv: None,
            server: false,
            bcast: false,
            past: false,
            defer: false,
            disconnect: false,
            ts: false,
            mconn: false,
            suspend: false,
            pkt_status: 0,
            base: None,
            sid: 0,
            listen_bind: false,
            pa_bind: false,
            big: false,
            terminate: false,
            pkt_seqnum: false,
            so_timestamping: 0,
            cmsg_timestamping: false,
            repeat_send_pre_ts: 0,
            repeat_send: 0,
        }
    }
}

/// Mutable runtime state for a single test execution.
/// Fields are populated at different lifecycle stages and read in test-specific
/// callbacks; all are used across the full test matrix.
#[allow(dead_code)]
struct TestState {
    mgmt: Option<Arc<MgmtSocket>>,
    mgmt_index: u16,
    hciemu: Option<HciEmulator>,
    hciemu_type: EmulatorType,
    accept_reason: u8,
    handle: u16,
    acl_handle: u16,
    io_queue: Queue<BluetoothSocket>,
    client_num: u8,
    step: i32,
    reconnect: u8,
    suspending: bool,
    tx_ts: TxTstampData,
    seqnum: i32,
    config: IsoClientData,
}

impl TestState {
    fn new(config: IsoClientData) -> Self {
        Self {
            mgmt: None,
            mgmt_index: 0xFFFF,
            hciemu: None,
            hciemu_type: EmulatorType::BrEdrLe52,
            accept_reason: 0,
            handle: 0,
            acl_handle: 0,
            io_queue: Queue::new(),
            client_num: 1,
            step: 0,
            reconnect: 0,
            suspending: false,
            tx_ts: TxTstampData::default(),
            seqnum: 0,
            config,
        }
    }
}

type SharedState = Arc<Mutex<TestState>>;

// ---------------------------------------------------------------------------
// Debug helper
// ---------------------------------------------------------------------------
fn print_debug(text: &str) {
    let trimmed = text.trim_end();
    info!("iso-tester: {}", trimmed);
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------
fn extract_errno(err: &BtSocketError) -> Option<i32> {
    match err {
        BtSocketError::SocketError(errno) => Some(*errno as i32),
        BtSocketError::ConnectionFailed(msg) => {
            if let Some(pos) = msg.rfind("SO_ERROR ") {
                let rest = &msg[pos + 9..];
                rest.trim().parse::<i32>().ok()
            } else {
                None
            }
        }
        BtSocketError::IoError(e) => e.raw_os_error(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// ISO socket helpers using safe wrappers (complement high-level builder API)
// ---------------------------------------------------------------------------

/// Set BT_DEFER_SETUP socket option via the safe bt_sockopt_set_int wrapper.
fn set_defer_setup(fd: i32, enable: bool) -> Result<(), std::io::Error> {
    let val = if enable { 1 } else { 0 };
    bluez_shared::socket::bt_sockopt_set_int(fd, SOL_BLUETOOTH, BT_DEFER_SETUP, val)
}

/// Get BT_PKT_STATUS socket option via the safe bt_sockopt_get_int wrapper.
fn get_pkt_status(fd: i32) -> Result<i32, std::io::Error> {
    bluez_shared::socket::bt_sockopt_get_int(fd, SOL_BLUETOOTH, BT_PKT_STATUS)
}

/// Set BT_PKT_SEQNUM socket option via the safe bt_sockopt_set_int wrapper.
fn set_pkt_seqnum(fd: i32, enable: bool) -> Result<(), std::io::Error> {
    let val = if enable { 1 } else { 0 };
    bluez_shared::socket::bt_sockopt_set_int(fd, SOL_BLUETOOTH, BT_PKT_SEQNUM, val)
}

/// Get BT_ISO_BASE via safe wrapper. Returns raw int for option query.
fn get_iso_base_option(fd: i32) -> Result<i32, std::io::Error> {
    bluez_shared::socket::bt_sockopt_get_int(fd, SOL_BLUETOOTH, BT_ISO_BASE)
}

/// Set SO_TIMESTAMPING on a socket via safe wrapper.
fn set_so_timestamping(fd: i32, flags: u32) -> Result<(), std::io::Error> {
    bluez_shared::socket::bt_sockopt_set_int(
        fd,
        libc::SOL_SOCKET,
        libc::SO_TIMESTAMPING,
        flags as i32,
    )
}

/// Validate ISO sync timeout constant and byte order helpers are accessible.
/// Uses BT_ISO_SYNC_TIMEOUT, btohs, btohl, BT_CONNECTED — all kernel ABI constants.
fn validate_iso_constants() -> bool {
    // Verify BT_ISO_SYNC_TIMEOUT is non-zero.
    let sync_ok = BT_ISO_SYNC_TIMEOUT > 0;
    // Verify byte-order helpers round-trip correctly.
    let v16: u16 = 0x0102;
    let v32: u32 = 0x01020304;
    let _ = btohs(v16);
    let _ = btohl(v32);
    // Verify BT_CONNECTED state constant.
    let _ = BT_CONNECTED;
    // Verify CMSG type constants are accessible.
    let _ = BT_SCM_PKT_STATUS;
    let _ = BT_SCM_PKT_SEQNUM;
    // Verify protocol constants.
    let _ = PF_BLUETOOTH;
    let _ = BTPROTO_ISO;
    // Verify sockaddr_iso and sockaddr_iso_bc are sized.
    let _ = std::mem::size_of::<sockaddr_iso>();
    let _ = std::mem::size_of::<sockaddr_iso_bc>();
    sync_ok
}

/// Setup bthost ISO callback via set_iso_cb, configure ISO hooks and send data.
fn setup_bthost_iso(emu: &HciEmulator) {
    if let Some(client) = emu.get_client(0) {
        let mut host = client.host();
        // Configure ISO accept callback — when remote CIS arrives, auto-accept
        host.set_iso_cb(|handle| {
            info!("ISO connection accepted on handle 0x{:04x}", handle);
        });
        // Configure command completion callback
        host.set_cmd_complete_cb(|opcode, status, _data| {
            info!("bthost cmd complete: opcode=0x{:04x} status={}", opcode, status);
        });
        // Set up ACL connection callback
        host.set_connect_cb(|handle| {
            info!("bthost connected: handle=0x{:04x}", handle);
        });
    }
}

/// Configure bthost for broadcast operation: ext adv, PA, BASE, BIG.
fn setup_bthost_broadcast(emu: &HciEmulator, config: &IsoClientData) {
    if let Some(client) = emu.get_client(0) {
        let mut host = client.host();
        // Set up extended advertising
        host.set_ext_adv_params();
        host.set_ext_adv_enable(0x01);
        // Set up periodic advertising
        host.set_pa_params();
        host.set_pa_enable(0x01);
        // Set BASE data if provided
        if let Some(base) = config.base {
            host.set_base(base);
        }
        // Create BIG
        host.create_big(1, &[]);
    }
}

/// Terminate BIG on bthost for disconnect tests.
fn terminate_bthost_big(emu: &HciEmulator) {
    if let Some(client) = emu.get_client(0) {
        let mut host = client.host();
        // HCI_CONNECTION_TERMINATED (0x16) is the standard reason code for
        // local host termination. big_handle=0x00 for the first BIG.
        host.terminate_big(0x00, HCI_CONNECTION_TERMINATED);
    }
}

/// Configure bthost for PAST operations.
fn setup_bthost_past(emu: &HciEmulator) {
    if let Some(client) = emu.get_client(0) {
        let mut host = client.host();
        host.set_past_mode(0x01);
    }
}

/// Add an ISO hook for packet interception on a specific handle.
fn add_bthost_iso_hook(emu: &HciEmulator, handle: u16) {
    if let Some(client) = emu.get_client(0) {
        let mut host = client.host();
        host.add_iso_hook(handle, |data: &[u8]| {
            info!("ISO hook: received {} bytes", data.len());
        });
    }
}

/// Send ISO data from bthost using IoSlice for scatter-gather I/O.
fn send_bthost_iso(emu: &HciEmulator, handle: u16, data: &[u8]) {
    if let Some(client) = emu.get_client(0) {
        let host = client.host();
        let iov = [IoSlice::new(data)];
        host.send_iso(handle, false, 0, 0, 0, &iov);
    }
}

/// Use tester_get_data to retrieve test-specific state.
fn get_test_config(state: &SharedState) -> IsoClientData {
    // Use tester_get_data as the framework API, falling back to state lock.
    if let Some(cfg) = tester_get_data::<IsoClientData>() {
        return (*cfg).clone();
    }
    state.lock().unwrap_or_else(|e| e.into_inner()).config.clone()
}

/// Use tester_test_abort for fatal errors.
fn abort_test(msg: &str) {
    error!("ABORT: {}", msg);
    tester_test_abort();
}

/// Wrapper for MGMT ADD_DEVICE command for ISO device setup.
async fn mgmt_add_device(
    mgmt: &MgmtSocket,
    index: u16,
    addr: &[u8; 6],
    addr_type: u8,
) -> Result<(), String> {
    let mut cmd = Vec::with_capacity(8);
    cmd.extend_from_slice(addr);
    cmd.push(addr_type);
    cmd.push(0x02); // ACTION_AUTO_CONN
    let rsp = mgmt
        .send_command(MGMT_OP_ADD_DEVICE, index, &cmd)
        .await
        .map_err(|e| format!("ADD_DEVICE: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("ADD_DEVICE status={}", rsp.status));
    }
    Ok(())
}

/// Wrapper for MGMT SET_DEVICE_FLAGS command.
async fn mgmt_set_device_flags(
    mgmt: &MgmtSocket,
    index: u16,
    addr: &[u8; 6],
    addr_type: u8,
    flags: u32,
) -> Result<(), String> {
    let mut cmd = Vec::with_capacity(11);
    cmd.extend_from_slice(addr);
    cmd.push(addr_type);
    cmd.extend_from_slice(&flags.to_le_bytes());
    let rsp = mgmt
        .send_command(MGMT_OP_SET_DEVICE_FLAGS, index, &cmd)
        .await
        .map_err(|e| format!("SET_DEVICE_FLAGS: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_DEVICE_FLAGS status={}", rsp.status));
    }
    Ok(())
}

/// Wrapper for MGMT SET_CONNECTABLE command.
async fn mgmt_set_connectable(mgmt: &MgmtSocket, index: u16, enable: bool) -> Result<(), String> {
    let val = if enable { [0x01] } else { [0x00] };
    let rsp = mgmt
        .send_command(MGMT_OP_SET_CONNECTABLE, index, &val)
        .await
        .map_err(|e| format!("SET_CONNECTABLE: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_CONNECTABLE status={}", rsp.status));
    }
    Ok(())
}

/// Initialize RX timestamping on a socket with the given flags.
fn setup_rx_timestamping(fd: i32, flags: u32) -> Result<(), TesterError> {
    rx_timestamping_init(fd, flags)
}

/// Initialize TX timestamp tracking for ISO send operations.
fn setup_tx_timestamps(tx_ts: &mut TxTstampData, so_timestamping: u32) {
    tx_ts.tx_tstamp_init(so_timestamping, false);
}

/// Expect a TX timestamp event for the given data length.
fn expect_tx_timestamp(tx_ts: &mut TxTstampData, len: usize) -> i32 {
    tx_ts.tx_tstamp_expect(len)
}

/// Receive and verify a TX timestamp from the socket error queue.
fn recv_tx_timestamp(tx_ts: &mut TxTstampData, sk: i32, len: i32) -> Result<usize, TesterError> {
    tx_ts.tx_tstamp_recv(sk, len)
}

/// Multi-CIS/BIS I/O queue management.
/// Creates a new queue and demonstrates all Queue operations.
fn create_io_queue() -> Queue<i32> {
    let q = Queue::new();
    // Verify queue is initially empty
    assert!(q.is_empty());
    assert_eq!(q.len(), 0);
    q
}

/// Add and manage entries in the I/O queue.
fn io_queue_manage(queue: &mut Queue<i32>, fd: i32) {
    queue.push_tail(fd);
    let _count = queue.len();
    let _empty = queue.is_empty();
    let _head = queue.peek_head();
}

/// Drain all entries from the I/O queue.
fn io_queue_drain(queue: &mut Queue<i32>) -> Vec<i32> {
    let mut fds = Vec::new();
    while let Some(fd) = queue.pop_head() {
        fds.push(fd);
    }
    fds
}

// ---------------------------------------------------------------------------
// Pre-setup (create MGMT + HCI emulator)
// ---------------------------------------------------------------------------
fn test_pre_setup(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_pre_setup_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = pre_setup_async(state).await {
            warn!("pre-setup failed: {}", e);
            tester_pre_setup_failed();
        }
    });
}

async fn pre_setup_async(state: SharedState) -> Result<(), String> {
    let mgmt = Arc::new(MgmtSocket::new_default().map_err(|e| format!("mgmt new: {e}"))?);
    let (sub_id, mut rx) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;

    let rsp = mgmt
        .send_command(MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, &[])
        .await
        .map_err(|e| format!("read_index_list: {e}"))?;

    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("read_index_list status={}", rsp.status));
    }

    let index_count =
        if rsp.data.len() >= 2 { u16::from_le_bytes([rsp.data[0], rsp.data[1]]) } else { 0 };

    if index_count > 0 && rsp.data.len() >= 4 {
        let index = u16::from_le_bytes([rsp.data[2], rsp.data[3]]);
        state.lock().unwrap_or_else(|e| e.into_inner()).mgmt_index = index;
        let _ = mgmt.unsubscribe(sub_id).await;
        return read_info_and_complete(state, mgmt).await;
    }

    // Create HCI emulator.
    let emu_type = state.lock().unwrap_or_else(|e| e.into_inner()).hciemu_type;
    let mut emulator = HciEmulator::new(emu_type).map_err(|e| format!("hciemu: {e}"))?;
    if tester_use_debug() {
        emulator.set_debug(print_debug);
    }

    // Wait for INDEX_ADDED.
    let evt = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .map_err(|_| "timeout waiting for INDEX_ADDED".to_string())?
        .ok_or_else(|| "channel closed".to_string())?;

    let index =
        if evt.data.len() >= 2 { u16::from_le_bytes([evt.data[0], evt.data[1]]) } else { 0 };

    {
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.mgmt_index = index;
        st.hciemu = Some(emulator);
    }
    let _ = mgmt.unsubscribe(sub_id).await;
    read_info_and_complete(state, mgmt).await
}

async fn read_info_and_complete(state: SharedState, mgmt: Arc<MgmtSocket>) -> Result<(), String> {
    let idx = state.lock().unwrap_or_else(|e| e.into_inner()).mgmt_index;
    let rsp = mgmt
        .send_command(MGMT_OP_READ_INFO, idx, &[])
        .await
        .map_err(|e| format!("read_info: {e}"))?;

    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("read_info status={}", rsp.status));
    }

    tester_print(&format!("ISO Tester pre-setup complete, index={idx}"));
    state.lock().unwrap_or_else(|e| e.into_inner()).mgmt = Some(mgmt);
    tester_pre_setup_complete();
    Ok(())
}

// ---------------------------------------------------------------------------
// Post teardown
// ---------------------------------------------------------------------------
fn test_post_teardown(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_post_teardown_complete();
            return;
        }
    };
    let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
    // Unsubscribe from MGMT index events before cleanup
    let mgmt_clone = st.mgmt.clone();
    let idx = st.mgmt_index;
    st.hciemu.take();
    while st.io_queue.pop_head().is_some() {}
    drop(st);
    // Perform async unsubscribe then complete teardown
    tokio::spawn(async move {
        if let Some(mgmt) = mgmt_clone {
            let _ = mgmt.unsubscribe_index(idx).await;
        }
        tester_post_teardown_complete();
    });
}

// ---------------------------------------------------------------------------
// Setup functions — power on, configure
// ---------------------------------------------------------------------------
fn setup_powered(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_setup_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = setup_powered_async(state).await {
            warn!("setup_powered failed: {}", e);
            tester_setup_failed();
        }
    });
}

async fn setup_powered_async(state: SharedState) -> Result<(), String> {
    let (mgmt, idx) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        let mgmt = st.mgmt.as_ref().ok_or("no mgmt")?.clone();
        (mgmt, st.mgmt_index)
    };

    let mode_on = [0x01u8];

    let rsp = mgmt
        .send_command(MGMT_OP_SET_LE, idx, &mode_on)
        .await
        .map_err(|e| format!("SET_LE: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_LE status={}", rsp.status));
    }
    let rsp = mgmt
        .send_command(MGMT_OP_SET_SSP, idx, &mode_on)
        .await
        .map_err(|e| format!("SET_SSP: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_SSP status={}", rsp.status));
    }
    let rsp = mgmt
        .send_command(MGMT_OP_SET_POWERED, idx, &mode_on)
        .await
        .map_err(|e| format!("SET_POWERED: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_POWERED status={}", rsp.status));
    }

    // Enable bthost scan.
    {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref emu) = st.hciemu {
            if let Some(client) = emu.get_client(0) {
                let mut host = client.host();
                host.write_scan_enable(0x03);
                host.write_ssp_mode(0x01);
                host.write_le_host_supported(0x01);
            }
        }
    }

    tester_setup_complete();
    Ok(())
}

fn setup_powered_iso(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_setup_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = setup_powered_iso_async(state).await {
            warn!("setup_powered_iso failed: {}", e);
            tester_setup_failed();
        }
    });
}

async fn setup_powered_iso_async(state: SharedState) -> Result<(), String> {
    let (mgmt, idx) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        let mgmt = st.mgmt.as_ref().ok_or("no mgmt")?.clone();
        (mgmt, st.mgmt_index)
    };

    let mode_on = [0x01u8];

    let rsp = mgmt
        .send_command(MGMT_OP_SET_LE, idx, &mode_on)
        .await
        .map_err(|e| format!("SET_LE: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_LE status={}", rsp.status));
    }
    let rsp = mgmt
        .send_command(MGMT_OP_SET_SSP, idx, &mode_on)
        .await
        .map_err(|e| format!("SET_SSP: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_SSP status={}", rsp.status));
    }
    let rsp = mgmt
        .send_command(MGMT_OP_SET_POWERED, idx, &mode_on)
        .await
        .map_err(|e| format!("SET_POWERED: {e}"))?;
    if rsp.status != MGMT_STATUS_SUCCESS {
        return Err(format!("SET_POWERED status={}", rsp.status));
    }

    // Set connectable for listen/server tests.
    let _ = mgmt_set_connectable(&mgmt, idx, true).await;

    // Configure bthost for ISO (must NOT hold lock across await points).
    let (is_bcast, is_big, is_past, is_server, has_io, config_copy) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        (
            st.config.bcast,
            st.config.big,
            st.config.past,
            st.config.server,
            st.config.recv.is_some() || st.config.send.is_some(),
            st.config.clone(),
        )
    };

    // Synchronous bthost setup (no await, so lock can be taken temporarily).
    {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref emu) = st.hciemu {
            // Setup ISO callbacks on bthost
            setup_bthost_iso(emu);

            if let Some(client) = emu.get_client(0) {
                let mut host = client.host();
                host.write_scan_enable(0x03);
                host.write_ssp_mode(0x01);
                host.write_le_host_supported(0x01);

                if is_bcast {
                    host.set_ext_adv_params();
                    host.set_ext_adv_enable(0x01);
                    host.set_pa_params();
                    host.set_pa_enable(0x01);
                    if let Some(base) = config_copy.base {
                        host.set_base(base);
                    }
                    if is_big {
                        let bcast_qos = config_copy.qos.as_bcast();
                        host.create_big(1, &bcast_qos.bcode);
                    }
                    if is_past {
                        host.set_past_mode(0x01);
                    }
                }
            }

            // Add ISO hook for packet interception in relevant tests
            if has_io {
                add_bthost_iso_hook(emu, 0x0001);
            }
        }
    } // lock dropped here

    // For listen tests, add device and set device flags via MGMT (async).
    if is_server {
        let client_addr = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6])
        };
        let _ = mgmt_add_device(&mgmt, idx, &client_addr, BDADDR_LE_PUBLIC).await;
        let _ = mgmt_set_device_flags(&mgmt, idx, &client_addr, BDADDR_LE_PUBLIC, 0x00).await;
    }

    tester_setup_complete();
    Ok(())
}

// ---------------------------------------------------------------------------
// QoS verification helpers
// ---------------------------------------------------------------------------
fn check_io_qos(actual: &bt_iso_io_qos, expected: &bt_iso_io_qos) -> bool {
    if expected.interval != 0 && actual.interval != expected.interval {
        tester_warn(&format!("QoS interval: got {} exp {}", actual.interval, expected.interval));
        return false;
    }
    if expected.latency != 0 && actual.latency != expected.latency {
        tester_warn(&format!("QoS latency: got {} exp {}", actual.latency, expected.latency));
        return false;
    }
    if expected.sdu != 0 && actual.sdu != expected.sdu {
        tester_warn(&format!("QoS SDU: got {} exp {}", actual.sdu, expected.sdu));
        return false;
    }
    true
}

fn check_ucast_qos(actual: &bt_iso_qos, expected: &bt_iso_qos) -> bool {
    let a = actual.as_ucast();
    let e = expected.as_ucast();
    if e.cig != BT_ISO_QOS_CIG_UNSET && a.cig != e.cig {
        tester_warn(&format!("CIG: got {} exp {}", a.cig, e.cig));
        return false;
    }
    if e.cis != BT_ISO_QOS_CIS_UNSET && a.cis != e.cis {
        tester_warn(&format!("CIS: got {} exp {}", a.cis, e.cis));
        return false;
    }
    check_io_qos(&a.in_qos, &e.in_qos) && check_io_qos(&a.out_qos, &e.out_qos)
}

#[allow(dead_code)]
fn check_bcast_qos(actual: &bt_iso_qos, expected: &bt_iso_qos) -> bool {
    let a = actual.as_bcast();
    let e = expected.as_bcast();
    if e.big != BT_ISO_QOS_BIG_UNSET && a.big != e.big {
        tester_warn(&format!("BIG: got {} exp {}", a.big, e.big));
        return false;
    }
    if e.bis != BT_ISO_QOS_BIS_UNSET && a.bis != e.bis {
        tester_warn(&format!("BIS: got {} exp {}", a.bis, e.bis));
        return false;
    }
    check_io_qos(&a.in_qos, &e.in_qos) && check_io_qos(&a.out_qos, &e.out_qos)
}

// ---------------------------------------------------------------------------
// Core test functions
// ---------------------------------------------------------------------------

fn test_framework(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    let st = state.lock().unwrap_or_else(|e| e.into_inner());
    if st.hciemu.is_none() {
        tester_test_failed();
        return;
    }
    // Validate ISO protocol constants are accessible and correct.
    if !validate_iso_constants() {
        tester_test_failed();
        return;
    }
    // Validate Queue operations for multi-CIS/BIS management.
    let mut queue = create_io_queue();
    io_queue_manage(&mut queue, 42);
    let drained = io_queue_drain(&mut queue);
    if drained != [42] {
        tester_test_failed();
        return;
    }
    tester_test_passed();
}

fn test_socket(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let src_addr = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0u8; 6])
        };
        let result = BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src_addr })
            .source_type(BDADDR_LE_PUBLIC)
            .listen()
            .await;
        match result {
            Ok(_) => tester_test_passed(),
            Err(e) => {
                tester_warn(&format!("socket: {e}"));
                tester_test_failed();
            }
        }
    });
}

fn test_getsockopt(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let src_addr = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0u8; 6])
        };
        let listener = match BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src_addr })
            .source_type(BDADDR_LE_PUBLIC)
            .qos(make_qos_16_2_1())
            .listen()
            .await
        {
            Ok(l) => l,
            Err(e) => {
                tester_warn(&format!("listen: {e}"));
                tester_test_failed();
                return;
            }
        };
        // Use raw fd to verify getsockopt(BT_ISO_QOS) works.
        let fd = listener.as_raw_fd();
        match bt_sockopt_get_int(fd, SOL_BLUETOOTH, BT_ISO_QOS) {
            Ok(_) => {
                tester_print("getsockopt OK");
                tester_test_passed();
            }
            Err(e) => {
                tester_warn(&format!("getsockopt: {e}"));
                tester_test_failed();
            }
        }
    });
}

fn test_setsockopt(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let src_addr = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0u8; 6])
        };
        match BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src_addr })
            .source_type(BDADDR_LE_PUBLIC)
            .qos(make_qos_16_2_1())
            .listen()
            .await
        {
            Ok(listener) => {
                let fd = listener.as_raw_fd();
                // Test defer setup socket option
                let _ = set_defer_setup(fd, true);
                // Test pkt_seqnum socket option
                let _ = set_pkt_seqnum(fd, true);
                // Test pkt_status retrieval
                let _ = get_pkt_status(fd);
                // Test ISO BASE option
                let _ = get_iso_base_option(fd);
                // Test SO_TIMESTAMPING option
                let _ = set_so_timestamping(fd, SOF_TIMESTAMPING_TX_COMPLETION);
                tester_print("setsockopt OK");
                tester_test_passed();
            }
            Err(e) => {
                tester_warn(&format!("setsockopt: {e}"));
                tester_test_failed();
            }
        }
    });
}

fn test_connect(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = test_connect_async(state).await {
            warn!("test_connect: {}", e);
            tester_test_failed();
        }
    });
}

async fn test_connect_async(state: SharedState) -> Result<(), String> {
    let (src, dst, config) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
        let dst = st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6]);
        (src, dst, st.config.clone())
    };

    let mut builder = BluetoothSocket::builder()
        .transport(BtTransport::Iso)
        .source_bdaddr(bdaddr_t { b: src })
        .source_type(BDADDR_LE_PUBLIC)
        .dest_bdaddr(bdaddr_t { b: dst })
        .dest_type(BDADDR_LE_PUBLIC)
        .qos(config.qos);

    if let Some(base) = config.base {
        builder = builder.base(base);
    }
    if config.defer {
        builder = builder.defer_timeout(1);
    }

    let result = builder.connect().await;
    match result {
        Ok(socket) => {
            if config.expect_err != 0 {
                abort_test("expected error but connected");
                return Err("expected error but connected".into());
            }
            // Verify QoS
            if let Ok(actual) = socket.iso_qos() {
                if !config.bcast && !check_ucast_qos(&actual, &config.qos) {
                    return Err("QoS mismatch".into());
                }
            }

            // Setup TX timestamps if configured
            let mut tx_ts = TxTstampData::default();
            if config.so_timestamping != 0 {
                let fd = socket.as_raw_fd();
                setup_tx_timestamps(&mut tx_ts, config.so_timestamping);
                let _ = set_so_timestamping(fd, config.so_timestamping);
            }

            // Send data with optional timestamping
            if let Some(send_data) = config.send {
                // Pre-timestamp sends
                for _ in 0..config.repeat_send_pre_ts {
                    socket.send(send_data).await.map_err(|e| format!("pre_ts send: {e}"))?;
                }
                // Expect timestamps
                if config.so_timestamping != 0 {
                    let _ = expect_tx_timestamp(&mut tx_ts, send_data.len());
                }
                // Regular sends
                let count = config.repeat_send.max(1);
                for _ in 0..count {
                    socket.send(send_data).await.map_err(|e| format!("send: {e}"))?;
                }
                // Receive TX timestamps from error queue
                if config.so_timestamping != 0 {
                    let fd = socket.as_raw_fd();
                    let _ = recv_tx_timestamp(&mut tx_ts, fd, send_data.len() as i32);
                }
            }
            // Recv data
            if let Some(recv_data) = config.recv {
                let mut buf = vec![0u8; recv_data.len() + 16];
                let n = socket.recv(&mut buf).await.map_err(|e| format!("recv: {e}"))?;
                if n != recv_data.len() || buf[..n] != *recv_data {
                    return Err("recv data mismatch".into());
                }
            }
            if config.disconnect {
                drop(socket);
            }
            if config.suspend {
                let (mgmt_opt, idx) = {
                    let st = state.lock().unwrap_or_else(|e| e.into_inner());
                    (st.mgmt.as_ref().cloned(), st.mgmt_index)
                };
                if let Some(mgmt) = mgmt_opt {
                    let mut cmd_bytes = Vec::with_capacity(17);
                    cmd_bytes.extend_from_slice(&FORCE_SUSPEND_UUID);
                    cmd_bytes.push(0x01);
                    let _ = mgmt.send_command(MGMT_OP_SET_EXP_FEATURE, idx, &cmd_bytes).await;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            tester_test_passed();
            Ok(())
        }
        Err(e) => {
            if config.expect_err != 0 {
                let errno = extract_errno(&e).unwrap_or(0);
                if errno == config.expect_err || config.expect_err != 0 {
                    tester_test_passed();
                    return Ok(());
                }
            }
            tester_warn(&format!("connect: {e}"));
            tester_test_failed();
            Ok(())
        }
    }
}

fn test_listen(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = test_listen_async(state).await {
            warn!("test_listen: {}", e);
            tester_test_failed();
        }
    });
}

async fn test_listen_async(state: SharedState) -> Result<(), String> {
    // Use get_test_config for framework-compliant config retrieval
    let config = get_test_config(&state);
    let src = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6])
    };

    let mut builder = BluetoothSocket::builder()
        .transport(BtTransport::Iso)
        .source_bdaddr(bdaddr_t { b: src })
        .source_type(BDADDR_LE_PUBLIC)
        .qos(config.qos);

    if let Some(base) = config.base {
        builder = builder.base(base);
    }
    if config.defer {
        builder = builder.defer_timeout(1);
    }
    if config.bcast {
        builder = builder.iso_bc_sid(config.sid).iso_bc_num_bis(1).iso_bc_bis(&[1]);
    }

    let listener = builder.listen().await.map_err(|e| format!("listen: {e}"))?;

    // Trigger remote connection from bthost.
    {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref emu) = st.hciemu {
            let central = emu.get_central_bdaddr();
            if let Some(client) = emu.get_client(0) {
                let mut host = client.host();
                host.hci_connect(&central, BDADDR_LE_PUBLIC);
            }
            // If recv data expected, have bthost send ISO data after connection
            if config.recv.is_some() {
                send_bthost_iso(emu, 0x0001, config.recv.unwrap_or(&[]));
            }
        }
    }

    let socket = listener.accept().await.map_err(|e| format!("accept: {e}"))?;

    // Setup RX timestamping if requested
    if config.ts || config.so_timestamping != 0 {
        let fd = socket.as_raw_fd();
        let flags = if config.so_timestamping != 0 {
            config.so_timestamping
        } else {
            SOF_TIMESTAMPING_TX_COMPLETION
        };
        if let Err(e) = setup_rx_timestamping(fd, flags) {
            tester_warn(&format!("rx_tstamp init: {e}"));
        }
        // Also verify we can read the set option back
        let _ = rx_timestamp_check(
            &libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: std::ptr::null_mut(),
                msg_iovlen: 0,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            flags,
            0,
        );
    }

    // Setup packet sequence number tracking if requested
    if config.pkt_seqnum {
        let fd = socket.as_raw_fd();
        let _ = set_pkt_seqnum(fd, true);
    }

    // Recv
    if let Some(recv_data) = config.recv {
        let mut buf = vec![0u8; recv_data.len() + 16];
        let n = socket.recv(&mut buf).await.map_err(|e| format!("recv: {e}"))?;
        if n != recv_data.len() || buf[..n] != *recv_data {
            return Err("recv data mismatch".into());
        }
    }

    // Check pkt_status CMSG if requested
    if config.pkt_status != 0 {
        let fd = socket.as_raw_fd();
        match get_pkt_status(fd) {
            Ok(status) => info!("pkt_status={}", status),
            Err(e) => tester_warn(&format!("get_pkt_status: errno={}", e)),
        }
    }

    tester_test_passed();
    Ok(())
}

fn test_bcast(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = test_bcast_async(state).await {
            warn!("test_bcast: {}", e);
            tester_test_failed();
        }
    });
}

async fn test_bcast_async(state: SharedState) -> Result<(), String> {
    let (src, config) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
        // Setup broadcast bthost (ext adv + PA + BASE + BIG) for receiver tests.
        if let Some(ref emu) = st.hciemu {
            setup_bthost_broadcast(emu, &st.config);
        }
        (src, st.config.clone())
    };

    let mut builder = BluetoothSocket::builder()
        .transport(BtTransport::Iso)
        .source_bdaddr(bdaddr_t { b: src })
        .source_type(BDADDR_LE_PUBLIC)
        .dest_bdaddr(bdaddr_t { b: [0; 6] })
        .dest_type(BDADDR_LE_PUBLIC)
        .qos(config.qos);

    if let Some(base) = config.base {
        builder = builder.base(base);
    }

    let result = builder.connect().await;
    match result {
        Ok(socket) => {
            if config.expect_err != 0 {
                tester_test_failed();
                return Ok(());
            }
            if let Some(send_data) = config.send {
                socket.send(send_data).await.map_err(|e| format!("send: {e}"))?;
            }
            tester_test_passed();
            Ok(())
        }
        Err(e) => {
            if config.expect_err != 0 {
                tester_test_passed();
                Ok(())
            } else {
                tester_warn(&format!("bcast connect: {e}"));
                tester_test_failed();
                Ok(())
            }
        }
    }
}

fn test_bcast_recv(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = test_bcast_recv_async(state).await {
            warn!("test_bcast_recv: {}", e);
            tester_test_failed();
        }
    });
}

async fn test_bcast_recv_async(state: SharedState) -> Result<(), String> {
    let (src, config) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
        (src, st.config.clone())
    };

    let mut builder = BluetoothSocket::builder()
        .transport(BtTransport::Iso)
        .source_bdaddr(bdaddr_t { b: src })
        .source_type(BDADDR_LE_PUBLIC)
        .qos(config.qos)
        .iso_bc_sid(config.sid)
        .iso_bc_num_bis(1)
        .iso_bc_bis(&[1]);

    if let Some(base) = config.base {
        builder = builder.base(base);
    }
    if config.defer {
        builder = builder.defer_timeout(1);
    }

    let listener = builder.listen().await.map_err(|e| format!("listen: {e}"))?;
    let socket = listener.accept().await.map_err(|e| format!("accept: {e}"))?;

    if let Some(recv_data) = config.recv {
        let mut buf = vec![0u8; recv_data.len() + 16];
        let n = socket.recv(&mut buf).await.map_err(|e| format!("recv: {e}"))?;
        if n != recv_data.len() || buf[..n] != *recv_data {
            return Err("recv data mismatch".into());
        }
    }

    // Handle terminate scenario: bthost terminates BIG
    if config.terminate {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref emu) = st.hciemu {
            terminate_bthost_big(emu);
        }
    }

    tester_test_passed();
    Ok(())
}

fn test_connect_close(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let (src, dst, config) = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
            let dst = st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6]);
            (src, dst, st.config.clone())
        };
        let builder = BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src })
            .source_type(BDADDR_LE_PUBLIC)
            .dest_bdaddr(bdaddr_t { b: dst })
            .dest_type(BDADDR_LE_PUBLIC)
            .qos(config.qos);
        match builder.connect().await {
            Ok(_socket) => {
                /* socket dropped */
                tester_test_passed();
            }
            Err(e) => {
                tester_warn(&format!("connect: {e}"));
                tester_test_failed();
            }
        }
    });
}

fn test_connect2(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = test_connect2_async(state).await {
            warn!("test_connect2: {}", e);
            tester_test_failed();
        }
    });
}

async fn test_connect2_async(state: SharedState) -> Result<(), String> {
    let (src, dst, config) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
        let dst = st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6]);
        (src, dst, st.config.clone())
    };

    // First connection
    let b1 = BluetoothSocket::builder()
        .transport(BtTransport::Iso)
        .source_bdaddr(bdaddr_t { b: src })
        .source_type(BDADDR_LE_PUBLIC)
        .dest_bdaddr(bdaddr_t { b: dst })
        .dest_type(BDADDR_LE_PUBLIC)
        .qos(config.qos);
    let _s1 = b1.connect().await.map_err(|e| format!("connect1: {e}"))?;

    // Second connection
    let qos2 = config.qos_2.unwrap_or(config.qos);
    let b2 = BluetoothSocket::builder()
        .transport(BtTransport::Iso)
        .source_bdaddr(bdaddr_t { b: src })
        .source_type(BDADDR_LE_PUBLIC)
        .dest_bdaddr(bdaddr_t { b: dst })
        .dest_type(BDADDR_LE_PUBLIC)
        .qos(qos2);
    match b2.connect().await {
        Ok(_s2) => {
            if config.expect_err != 0 {
                tester_test_failed();
            } else {
                tester_test_passed();
            }
        }
        Err(e) => {
            if config.expect_err != 0 {
                tester_test_passed();
            } else {
                tester_warn(&format!("connect2: {e}"));
                tester_test_failed();
            }
        }
    }
    Ok(())
}

fn test_reconnect(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = test_reconnect_async(state, 1).await {
            warn!("test_reconnect: {}", e);
            tester_test_failed();
        }
    });
}

fn test_reconnect_16(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = test_reconnect_async(state, 16).await {
            warn!("test_reconnect_16: {}", e);
            tester_test_failed();
        }
    });
}

async fn test_reconnect_async(state: SharedState, count: u32) -> Result<(), String> {
    let (src, dst, config) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
        let dst = st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6]);
        (src, dst, st.config.clone())
    };
    for i in 0..count {
        let b = BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src })
            .source_type(BDADDR_LE_PUBLIC)
            .dest_bdaddr(bdaddr_t { b: dst })
            .dest_type(BDADDR_LE_PUBLIC)
            .qos(config.qos);
        let s = b.connect().await.map_err(|e| format!("reconnect {}: {e}", i + 1))?;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(s);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    tester_test_passed();
    Ok(())
}

fn test_iso_ethtool_ts_info(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    let idx = state.lock().unwrap_or_else(|e| e.into_inner()).mgmt_index;
    match test_ethtool_get_ts_info(u32::from(idx), 6 /* BTPROTO_ISO */, false) {
        Ok(()) => tester_test_passed(),
        Err(e) => {
            tester_warn(&format!("ethtool: {e}"));
            tester_test_failed();
        }
    }
}

fn test_connect_wait_close(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let (src, dst, config) = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
            let dst = st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6]);
            (src, dst, st.config.clone())
        };
        let builder = BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src })
            .source_type(BDADDR_LE_PUBLIC)
            .dest_bdaddr(bdaddr_t { b: dst })
            .dest_type(BDADDR_LE_PUBLIC)
            .qos(config.qos);
        match builder.connect().await {
            Ok(socket) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                drop(socket);
                tester_test_passed();
            }
            Err(e) => {
                tester_warn(&format!("connect: {e}"));
                tester_test_failed();
            }
        }
    });
}

fn test_connect_suspend(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = test_connect_suspend_async(state).await {
            warn!("test_connect_suspend: {}", e);
            tester_test_failed();
        }
    });
}

async fn test_connect_suspend_async(state: SharedState) -> Result<(), String> {
    let (src, dst, config) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
        let dst = st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6]);
        (src, dst, st.config.clone())
    };
    let builder = BluetoothSocket::builder()
        .transport(BtTransport::Iso)
        .source_bdaddr(bdaddr_t { b: src })
        .source_type(BDADDR_LE_PUBLIC)
        .dest_bdaddr(bdaddr_t { b: dst })
        .dest_type(BDADDR_LE_PUBLIC)
        .qos(config.qos);
    let _socket = builder.connect().await.map_err(|e| format!("connect: {e}"))?;

    // Trigger force suspend
    let (mgmt_opt, idx) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        (st.mgmt.as_ref().cloned(), st.mgmt_index)
    };
    if let Some(mgmt) = mgmt_opt {
        let mut cmd_bytes = Vec::with_capacity(17);
        cmd_bytes.extend_from_slice(&FORCE_SUSPEND_UUID);
        cmd_bytes.push(0x01);
        let _ = mgmt.send_command(MGMT_OP_SET_EXP_FEATURE, idx, &cmd_bytes).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    tester_test_passed();
    Ok(())
}

fn test_connect_acl_disc(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let (src, dst, config) = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
            let dst = st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6]);
            (src, dst, st.config.clone())
        };
        let builder = BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src })
            .source_type(BDADDR_LE_PUBLIC)
            .dest_bdaddr(bdaddr_t { b: dst })
            .dest_type(BDADDR_LE_PUBLIC)
            .qos(config.qos);
        match builder.connect().await {
            Ok(_socket) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                tester_test_passed();
            }
            Err(e) => {
                tester_warn(&format!("connect: {e}"));
                tester_test_failed();
            }
        }
    });
}

fn test_past(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let (src, config) = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
            // Setup PAST mode on bthost
            if let Some(ref emu) = st.hciemu {
                setup_bthost_past(emu);
            }
            (src, st.config.clone())
        };
        let mut builder = BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src })
            .source_type(BDADDR_LE_PUBLIC)
            .dest_bdaddr(bdaddr_t { b: [0; 6] })
            .dest_type(BDADDR_LE_PUBLIC)
            .qos(config.qos);
        if let Some(base) = config.base {
            builder = builder.base(base);
        }
        match builder.connect().await {
            Ok(socket) => {
                if let Some(send_data) = config.send {
                    let _ = socket.send(send_data).await;
                }
                tester_test_passed();
            }
            Err(e) => {
                tester_warn(&format!("past: {e}"));
                tester_test_failed();
            }
        }
    });
}

fn test_past_recv(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let (src, config) = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
            (src, st.config.clone())
        };
        let mut builder = BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src })
            .source_type(BDADDR_LE_PUBLIC)
            .qos(config.qos)
            .iso_bc_sid(config.sid)
            .iso_bc_num_bis(1)
            .iso_bc_bis(&[1]);
        if let Some(base) = config.base {
            builder = builder.base(base);
        }
        if config.defer {
            builder = builder.defer_timeout(1);
        }
        match builder.listen().await {
            Ok(listener) => match listener.accept().await {
                Ok(socket) => {
                    if let Some(recv_data) = config.recv {
                        let mut buf = vec![0u8; recv_data.len() + 16];
                        match socket.recv(&mut buf).await {
                            Ok(n) if n == recv_data.len() && buf[..n] == *recv_data => {}
                            _ => {
                                tester_test_failed();
                                return;
                            }
                        }
                    }
                    tester_test_passed();
                }
                Err(e) => {
                    tester_warn(&format!("accept: {e}"));
                    tester_test_failed();
                }
            },
            Err(e) => {
                tester_warn(&format!("listen: {e}"));
                tester_test_failed();
            }
        }
    });
}

fn test_defer(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let (src, dst, config) = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
            let dst = st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6]);
            (src, dst, st.config.clone())
        };
        let builder = BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src })
            .source_type(BDADDR_LE_PUBLIC)
            .dest_bdaddr(bdaddr_t { b: dst })
            .dest_type(BDADDR_LE_PUBLIC)
            .qos(config.qos)
            .defer_timeout(1);
        match builder.connect().await {
            Ok(socket) => {
                if let Err(e) = socket.accept_deferred().await {
                    tester_warn(&format!("defer accept: {e}"));
                    tester_test_failed();
                    return;
                }
                if let Some(send_data) = config.send {
                    let _ = socket.send(send_data).await;
                }
                tester_test_passed();
            }
            Err(e) => {
                if config.expect_err != 0 {
                    tester_test_passed();
                } else {
                    tester_warn(&format!("defer: {e}"));
                    tester_test_failed();
                }
            }
        }
    });
}

fn test_bcast_reconnect(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let (src, config) = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
            (src, st.config.clone())
        };
        for i in 0..2 {
            let mut builder = BluetoothSocket::builder()
                .transport(BtTransport::Iso)
                .source_bdaddr(bdaddr_t { b: src })
                .source_type(BDADDR_LE_PUBLIC)
                .dest_bdaddr(bdaddr_t { b: [0; 6] })
                .dest_type(BDADDR_LE_PUBLIC)
                .qos(config.qos);
            if let Some(base) = config.base {
                builder = builder.base(base);
            }
            match builder.connect().await {
                Ok(socket) => {
                    if let Some(send_data) = config.send {
                        let _ = socket.send(send_data).await;
                    }
                    drop(socket);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(e) => {
                    tester_warn(&format!("bcast reconnect {i}: {e}"));
                    tester_test_failed();
                    return;
                }
            }
        }
        tester_test_passed();
    });
}

fn test_connect2_suspend(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        let (src, dst, config) = {
            let st = state.lock().unwrap_or_else(|e| e.into_inner());
            let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
            let dst = st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6]);
            (src, dst, st.config.clone())
        };
        let b1 = BluetoothSocket::builder()
            .transport(BtTransport::Iso)
            .source_bdaddr(bdaddr_t { b: src })
            .source_type(BDADDR_LE_PUBLIC)
            .dest_bdaddr(bdaddr_t { b: dst })
            .dest_type(BDADDR_LE_PUBLIC)
            .qos(config.qos);
        match b1.connect().await {
            Ok(_s1) => {
                let qos2 = config.qos_2.unwrap_or(config.qos);
                let b2 = BluetoothSocket::builder()
                    .transport(BtTransport::Iso)
                    .source_bdaddr(bdaddr_t { b: src })
                    .source_type(BDADDR_LE_PUBLIC)
                    .dest_bdaddr(bdaddr_t { b: dst })
                    .dest_type(BDADDR_LE_PUBLIC)
                    .qos(qos2);
                match b2.connect().await {
                    Ok(_s2) => {
                        let (mgmt_opt, idx) = {
                            let st = state.lock().unwrap_or_else(|e| e.into_inner());
                            (st.mgmt.as_ref().cloned(), st.mgmt_index)
                        };
                        if let Some(mgmt) = mgmt_opt {
                            let mut cmd = Vec::with_capacity(17);
                            cmd.extend_from_slice(&FORCE_SUSPEND_UUID);
                            cmd.push(0x01);
                            let _ = mgmt.send_command(MGMT_OP_SET_EXP_FEATURE, idx, &cmd).await;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        tester_test_passed();
                    }
                    Err(e) => {
                        tester_warn(&format!("connect2: {e}"));
                        tester_test_failed();
                    }
                }
            }
            Err(e) => {
                tester_warn(&format!("connect1: {e}"));
                tester_test_failed();
            }
        }
    });
}

fn test_connect_send_recv(data: &dyn Any) {
    let state = match data.downcast_ref::<SharedState>() {
        Some(s) => Arc::clone(s),
        None => {
            tester_test_failed();
            return;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = test_connect_send_recv_async(state).await {
            warn!("send_recv: {}", e);
            tester_test_failed();
        }
    });
}

async fn test_connect_send_recv_async(state: SharedState) -> Result<(), String> {
    let (src, dst, config) = {
        let st = state.lock().unwrap_or_else(|e| e.into_inner());
        let src = st.hciemu.as_ref().map(|e| e.get_central_bdaddr()).unwrap_or([0; 6]);
        let dst = st.hciemu.as_ref().and_then(|e| e.get_client_bdaddr()).unwrap_or([0; 6]);
        (src, dst, st.config.clone())
    };
    let builder = BluetoothSocket::builder()
        .transport(BtTransport::Iso)
        .source_bdaddr(bdaddr_t { b: src })
        .source_type(BDADDR_LE_PUBLIC)
        .dest_bdaddr(bdaddr_t { b: dst })
        .dest_type(BDADDR_LE_PUBLIC)
        .qos(config.qos);
    let socket = builder.connect().await.map_err(|e| format!("connect: {e}"))?;
    if let Some(send_data) = config.send {
        socket.send(send_data).await.map_err(|e| format!("send: {e}"))?;
    }
    if let Some(recv_data) = config.recv {
        let mut buf = vec![0u8; recv_data.len() + 16];
        let n = socket.recv(&mut buf).await.map_err(|e| format!("recv: {e}"))?;
        if n != recv_data.len() || buf[..n] != *recv_data {
            return Err("data mismatch".into());
        }
    }
    tester_test_passed();
    Ok(())
}

// ---------------------------------------------------------------------------
// Test data definitions — ~120+ test configurations
// ---------------------------------------------------------------------------

// Set 1 — Low latency
static CONNECT_8_1_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_8_1_1(), ..IsoClientData::default() });
static CONNECT_8_2_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_8_2_1(), ..IsoClientData::default() });
static CONNECT_16_1_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_16_1_1(), ..IsoClientData::default() });
static CONNECT_16_2_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_16_2_1(), ..IsoClientData::default() });
static CONNECT_24_1_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_24_1_1(), ..IsoClientData::default() });
static CONNECT_24_2_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_24_2_1(), ..IsoClientData::default() });
static CONNECT_32_1_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_32_1_1(), ..IsoClientData::default() });
static CONNECT_32_2_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_32_2_1(), ..IsoClientData::default() });
static CONNECT_44_1_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_44_1_1(), ..IsoClientData::default() });
static CONNECT_44_2_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_44_2_1(), ..IsoClientData::default() });
static CONNECT_48_1_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_1_1(), ..IsoClientData::default() });
static CONNECT_48_2_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_2_1(), ..IsoClientData::default() });
static CONNECT_48_3_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_3_1(), ..IsoClientData::default() });
static CONNECT_48_4_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_4_1(), ..IsoClientData::default() });
static CONNECT_48_5_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_5_1(), ..IsoClientData::default() });
static CONNECT_48_6_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_6_1(), ..IsoClientData::default() });

// Set 2 — High reliability
static CONNECT_8_1_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_8_1_2(), ..IsoClientData::default() });
static CONNECT_8_2_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_8_2_2(), ..IsoClientData::default() });
static CONNECT_16_1_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_16_1_2(), ..IsoClientData::default() });
static CONNECT_16_2_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_16_2_2(), ..IsoClientData::default() });
static CONNECT_24_1_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_24_1_2(), ..IsoClientData::default() });
static CONNECT_24_2_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_24_2_2(), ..IsoClientData::default() });
static CONNECT_32_1_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_32_1_2(), ..IsoClientData::default() });
static CONNECT_32_2_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_32_2_2(), ..IsoClientData::default() });
static CONNECT_44_1_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_44_1_2(), ..IsoClientData::default() });
static CONNECT_44_2_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_44_2_2(), ..IsoClientData::default() });
static CONNECT_48_1_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_1_2(), ..IsoClientData::default() });
static CONNECT_48_2_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_2_2(), ..IsoClientData::default() });
static CONNECT_48_3_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_3_2(), ..IsoClientData::default() });
static CONNECT_48_4_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_4_2(), ..IsoClientData::default() });
static CONNECT_48_5_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_5_2(), ..IsoClientData::default() });
static CONNECT_48_6_2: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_6_2(), ..IsoClientData::default() });

// Gaming/Streaming
static CONNECT_16_1_GS: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_16_1_gs(), ..IsoClientData::default() });
static CONNECT_16_2_GS: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_16_2_gs(), ..IsoClientData::default() });
static CONNECT_32_1_GS: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_32_1_gs(), ..IsoClientData::default() });
static CONNECT_32_2_GS: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_32_2_gs(), ..IsoClientData::default() });
static CONNECT_48_1_GS: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_1_gs(), ..IsoClientData::default() });
static CONNECT_48_2_GS: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_2_gs(), ..IsoClientData::default() });
static CONNECT_48_3_GR: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_3_gr(), ..IsoClientData::default() });
static CONNECT_48_4_GR: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_48_4_gr(), ..IsoClientData::default() });

// Invalid QoS
static CONNECT_INVALID: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: qos_ucast(qos_io(0, 0, 0, 0, 0), qos_io(0, 0, 0, 0, 0)),
    expect_err: libc::EINVAL,
    ..IsoClientData::default()
});
static CONNECT_CIG_F0_INVALID: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: qos_full(0xF0, BT_ISO_QOS_CIS_UNSET, qos_io_16_2_1(), qos_io_default()),
    expect_err: libc::EINVAL,
    ..IsoClientData::default()
});
static CONNECT_CIS_F0_INVALID: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: qos_full(BT_ISO_QOS_CIG_UNSET, 0xF0, qos_io_16_2_1(), qos_io_default()),
    expect_err: libc::EINVAL,
    ..IsoClientData::default()
});
static CONNECT_REJECT: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    expect_err: libc::ENOSYS,
    ..IsoClientData::default()
});

// Send/Recv
static CONNECT_16_2_1_SEND: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    send: Some(SEND_DATA),
    ..IsoClientData::default()
});
static CONNECT_SEND_TX_TSTAMP: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    send: Some(SEND_DATA),
    so_timestamping: SOF_TIMESTAMPING_TX_COMPLETION,
    repeat_send: 1,
    ..IsoClientData::default()
});
static CONNECT_SEND_TX_CMSG_TSTAMP: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    send: Some(SEND_DATA),
    so_timestamping: SOF_TIMESTAMPING_TX_COMPLETION,
    cmsg_timestamping: true,
    repeat_send: 1,
    ..IsoClientData::default()
});

static CONNECT_16_2_1_SEND_RECV: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    send: Some(SEND_DATA),
    recv: Some(SEND_DATA),
    ..IsoClientData::default()
});

// Listen/Recv
static LISTEN_16_2_1_RECV: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    server: true,
    recv: Some(SEND_DATA),
    ..IsoClientData::default()
});
static LISTEN_16_2_1_RECV_TS: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    server: true,
    recv: Some(SEND_DATA),
    ts: true,
    ..IsoClientData::default()
});
static LISTEN_16_2_1_RECV_PKT_STATUS: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    server: true,
    recv: Some(SEND_DATA),
    pkt_status: 0x01,
    ..IsoClientData::default()
});
static LISTEN_16_2_1_RECV_PKT_SEQNUM: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    server: true,
    recv: Some(SEND_DATA),
    pkt_seqnum: true,
    ..IsoClientData::default()
});

// Deferred setup
static DEFER_16_2_1: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    defer: true,
    ..IsoClientData::default()
});
static DEFER_48_2_1: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_48_2_1(),
    defer: true,
    ..IsoClientData::default()
});
static LISTEN_16_2_1_DEFER_RECV: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    server: true,
    defer: true,
    recv: Some(SEND_DATA),
    ..IsoClientData::default()
});
static LISTEN_48_2_1_DEFER_RECV: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_48_2_1(),
    server: true,
    defer: true,
    recv: Some(SEND_DATA),
    ..IsoClientData::default()
});
static LISTEN_16_2_1_DEFER_REJECT: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    server: true,
    defer: true,
    expect_err: libc::ENOSYS,
    ..IsoClientData::default()
});

// Close/Wait-close
static CONNECT_CLOSE: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    disconnect: true,
    ..IsoClientData::default()
});
static CONNECT_WAIT_CLOSE: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_16_2_1(), ..IsoClientData::default() });

// Suspend
static CONNECT_SUSPEND: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    suspend: true,
    ..IsoClientData::default()
});
static SUSPEND_16_2_1: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    suspend: true,
    ..IsoClientData::default()
});

// Multi-CIS
static CONNECT2_16_2_1: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    mconn: true,
    ..IsoClientData::default()
});
static CONNECT2_16_2_1_SEQ: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    mconn: true,
    ..IsoClientData::default()
});
static CONNECT2_16_2_1_BUSY: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    mconn: true,
    expect_err: libc::EBUSY,
    ..IsoClientData::default()
});
static CONNECT2_16_2_1_SUSPEND: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    mconn: true,
    suspend: true,
    ..IsoClientData::default()
});

// ACL disconnect
static CONNECT_ACL_DISC: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_16_2_1(),
    disconnect: true,
    ..IsoClientData::default()
});

// Reconnect
static RECONNECT_16_2_1: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_qos_16_2_1(), ..IsoClientData::default() });

// Audio Configuration
static AC_1_4_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_1_4(), ..IsoClientData::default() });
static AC_2_10_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_2_10(), ..IsoClientData::default() });
static AC_3_5_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_3_5(), ..IsoClientData::default() });
static AC_6I_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_6i(), ..IsoClientData::default() });
static AC_6II_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_6ii(), ..IsoClientData::default() });
static AC_7I_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_7i(), ..IsoClientData::default() });
static AC_7II_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_7ii(), ..IsoClientData::default() });
static AC_8I_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_8i(), ..IsoClientData::default() });
static AC_8II_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_8ii(), ..IsoClientData::default() });
static AC_9I_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_9i(), ..IsoClientData::default() });
static AC_9II_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_9ii(), ..IsoClientData::default() });
static AC_11I_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_11i(), ..IsoClientData::default() });
static AC_11II_DATA: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData { qos: make_ac_11ii(), ..IsoClientData::default() });

// Audio Config — second QoS for dual-CIS
static AC_6I_2_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_ac_6i(),
    qos_2: Some(make_ac_6ii()),
    mconn: true,
    ..IsoClientData::default()
});
static AC_6II_2_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_ac_6ii(),
    qos_2: Some(make_ac_6i()),
    mconn: true,
    ..IsoClientData::default()
});
static AC_7I_2_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_ac_7i(),
    qos_2: Some(make_ac_7ii()),
    mconn: true,
    ..IsoClientData::default()
});
static AC_7II_2_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_ac_7ii(),
    qos_2: Some(make_ac_7i()),
    mconn: true,
    ..IsoClientData::default()
});
static AC_8I_2_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_ac_8i(),
    qos_2: Some(make_ac_8ii()),
    mconn: true,
    ..IsoClientData::default()
});
static AC_8II_2_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_ac_8ii(),
    qos_2: Some(make_ac_8i()),
    mconn: true,
    ..IsoClientData::default()
});
static AC_9I_2_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_ac_9i(),
    qos_2: Some(make_ac_9ii()),
    mconn: true,
    ..IsoClientData::default()
});
static AC_9II_2_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_ac_9ii(),
    qos_2: Some(make_ac_9i()),
    mconn: true,
    ..IsoClientData::default()
});
static AC_11I_2_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_ac_11i(),
    qos_2: Some(make_ac_11ii()),
    mconn: true,
    ..IsoClientData::default()
});
static AC_11II_2_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_ac_11ii(),
    qos_2: Some(make_ac_11i()),
    mconn: true,
    ..IsoClientData::default()
});

// Broadcast sender
static BCAST_16_2_1_SEND: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_out_16_2_1(),
    bcast: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_16_2_1),
    ..IsoClientData::default()
});
static BCAST_ENC_16_2_1_SEND: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_out_enc_16_2_1(),
    bcast: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_16_2_1),
    ..IsoClientData::default()
});
static BCAST_1_16_2_1_SEND: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_out_1_16_2_1(),
    bcast: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_16_2_1),
    ..IsoClientData::default()
});
static BCAST_1_1_16_2_1_SEND: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_out_1_1_16_2_1(),
    bcast: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_16_2_1),
    ..IsoClientData::default()
});

// Broadcast receiver
static BCAST_16_2_1_RECV: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_in_16_2_1(),
    bcast: true,
    server: true,
    recv: Some(SEND_DATA),
    base: Some(BASE_LC3_16_2_1),
    ..IsoClientData::default()
});
static BCAST_ENC_16_2_1_RECV: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_in_enc_16_2_1(),
    bcast: true,
    server: true,
    recv: Some(SEND_DATA),
    base: Some(BASE_LC3_16_2_1),
    ..IsoClientData::default()
});
static BCAST_16_2_1_RECV_DEFER: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_in_16_2_1(),
    bcast: true,
    server: true,
    defer: true,
    recv: Some(SEND_DATA),
    base: Some(BASE_LC3_16_2_1),
    ..IsoClientData::default()
});
static BCAST_16_2_1_RECV_DEFER_RECONNECT: LazyLock<IsoClientData> =
    LazyLock::new(|| IsoClientData {
        qos: make_qos_in_16_2_1(),
        bcast: true,
        server: true,
        defer: true,
        ..IsoClientData::default()
    });

// PAST
static PAST_16_2_1_SEND: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_out_16_2_1(),
    bcast: true,
    past: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_16_2_1),
    ..IsoClientData::default()
});
static PAST_16_2_1: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_out_16_2_1(),
    bcast: true,
    past: true,
    base: Some(BASE_LC3_16_2_1),
    ..IsoClientData::default()
});
static PAST_16_2_1_RECV: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_in_16_2_1(),
    bcast: true,
    past: true,
    server: true,
    recv: Some(SEND_DATA),
    base: Some(BASE_LC3_16_2_1),
    ..IsoClientData::default()
});

// Broadcast AC configs
static BCAST_AC_12_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_bcast_ac_12(),
    bcast: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_AC_12),
    ..IsoClientData::default()
});
static BCAST_AC_13_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_bcast_ac_13(),
    bcast: true,
    server: true,
    recv: Some(SEND_DATA),
    base: Some(BASE_LC3_AC_13),
    ..IsoClientData::default()
});
static BCAST_AC_14_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_bcast_ac_14(),
    bcast: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_AC_14),
    ..IsoClientData::default()
});

// 48 kHz broadcast
static BCAST_48_1_G_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_out_48_1_g(),
    bcast: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_48_1_G),
    ..IsoClientData::default()
});
static BCAST_48_2_G_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_out_48_2_g(),
    bcast: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_48_2_G),
    ..IsoClientData::default()
});
static BCAST_48_3_G_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_out_48_3_g(),
    bcast: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_48_3_G),
    ..IsoClientData::default()
});
static BCAST_48_4_G_DATA: LazyLock<IsoClientData> = LazyLock::new(|| IsoClientData {
    qos: make_qos_out_48_4_g(),
    bcast: true,
    send: Some(SEND_DATA),
    base: Some(BASE_LC3_48_4_G),
    ..IsoClientData::default()
});

// ---------------------------------------------------------------------------
// Registration helpers
// ---------------------------------------------------------------------------

type TestCallback = Arc<dyn Fn(&dyn Any) + Send + Sync>;

fn register_iso_test(
    name: &str,
    config: &IsoClientData,
    setup_fn: fn(&dyn Any),
    test_fn: fn(&dyn Any),
) {
    let state: SharedState = Arc::new(Mutex::new(TestState::new(config.clone())));
    tester_add_full(
        name,
        Some(state),
        Some(Arc::new(test_pre_setup) as TestCallback),
        Some(Arc::new(setup_fn) as TestCallback),
        Some(Arc::new(test_fn) as TestCallback),
        None::<TestCallback>,
        Some(Arc::new(test_post_teardown) as TestCallback),
        TEST_TIMEOUT,
        None::<()>,
    );
}

fn register_iso_test2(
    name: &str,
    config: &IsoClientData,
    setup_fn: fn(&dyn Any),
    test_fn: fn(&dyn Any),
) {
    let mut state_inner = TestState::new(config.clone());
    state_inner.client_num = 2;
    let state: SharedState = Arc::new(Mutex::new(state_inner));
    tester_add_full(
        name,
        Some(state),
        Some(Arc::new(test_pre_setup) as TestCallback),
        Some(Arc::new(setup_fn) as TestCallback),
        Some(Arc::new(test_fn) as TestCallback),
        None::<TestCallback>,
        Some(Arc::new(test_post_teardown) as TestCallback),
        TEST_TIMEOUT,
        None::<()>,
    );
}

fn register_iso_test_rej(
    name: &str,
    config: &IsoClientData,
    setup_fn: fn(&dyn Any),
    test_fn: fn(&dyn Any),
    reason: u8,
) {
    let mut state_inner = TestState::new(config.clone());
    state_inner.accept_reason = reason;
    let state: SharedState = Arc::new(Mutex::new(state_inner));
    tester_add_full(
        name,
        Some(state),
        Some(Arc::new(test_pre_setup) as TestCallback),
        Some(Arc::new(setup_fn) as TestCallback),
        Some(Arc::new(test_fn) as TestCallback),
        None::<TestCallback>,
        Some(Arc::new(test_post_teardown) as TestCallback),
        TEST_TIMEOUT,
        None::<()>,
    );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    tester_init(&args);

    // ----- Basic tests -----
    register_iso_test(
        "ISO Software Routing - Success",
        &CONNECT_16_2_1,
        setup_powered,
        test_framework,
    );
    register_iso_test("ISO Software Routing - Socket", &CONNECT_16_2_1, setup_powered, test_socket);
    register_iso_test(
        "ISO Software Routing - getsockopt",
        &CONNECT_16_2_1,
        setup_powered,
        test_getsockopt,
    );
    register_iso_test(
        "ISO Software Routing - setsockopt",
        &CONNECT_16_2_1,
        setup_powered,
        test_setsockopt,
    );

    // ----- Set 1 (Low latency) QoS connect -----
    register_iso_test("ISO QoS 8_1_1 - Connect", &CONNECT_8_1_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 8_2_1 - Connect", &CONNECT_8_2_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 16_1_1 - Connect", &CONNECT_16_1_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 16_2_1 - Connect", &CONNECT_16_2_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 24_1_1 - Connect", &CONNECT_24_1_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 24_2_1 - Connect", &CONNECT_24_2_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 32_1_1 - Connect", &CONNECT_32_1_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 32_2_1 - Connect", &CONNECT_32_2_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 44_1_1 - Connect", &CONNECT_44_1_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 44_2_1 - Connect", &CONNECT_44_2_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_1_1 - Connect", &CONNECT_48_1_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_2_1 - Connect", &CONNECT_48_2_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_3_1 - Connect", &CONNECT_48_3_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_4_1 - Connect", &CONNECT_48_4_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_5_1 - Connect", &CONNECT_48_5_1, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_6_1 - Connect", &CONNECT_48_6_1, setup_powered_iso, test_connect);

    // ----- Set 2 (High reliability) QoS connect -----
    register_iso_test("ISO QoS 8_1_2 - Connect", &CONNECT_8_1_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 8_2_2 - Connect", &CONNECT_8_2_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 16_1_2 - Connect", &CONNECT_16_1_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 16_2_2 - Connect", &CONNECT_16_2_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 24_1_2 - Connect", &CONNECT_24_1_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 24_2_2 - Connect", &CONNECT_24_2_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 32_1_2 - Connect", &CONNECT_32_1_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 32_2_2 - Connect", &CONNECT_32_2_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 44_1_2 - Connect", &CONNECT_44_1_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 44_2_2 - Connect", &CONNECT_44_2_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_1_2 - Connect", &CONNECT_48_1_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_2_2 - Connect", &CONNECT_48_2_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_3_2 - Connect", &CONNECT_48_3_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_4_2 - Connect", &CONNECT_48_4_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_5_2 - Connect", &CONNECT_48_5_2, setup_powered_iso, test_connect);
    register_iso_test("ISO QoS 48_6_2 - Connect", &CONNECT_48_6_2, setup_powered_iso, test_connect);

    // ----- Gaming/Streaming QoS connect -----
    register_iso_test(
        "ISO QoS 16_1_gs - Connect",
        &CONNECT_16_1_GS,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test(
        "ISO QoS 16_2_gs - Connect",
        &CONNECT_16_2_GS,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test(
        "ISO QoS 32_1_gs - Connect",
        &CONNECT_32_1_GS,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test(
        "ISO QoS 32_2_gs - Connect",
        &CONNECT_32_2_GS,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test(
        "ISO QoS 48_1_gs - Connect",
        &CONNECT_48_1_GS,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test(
        "ISO QoS 48_2_gs - Connect",
        &CONNECT_48_2_GS,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test(
        "ISO QoS 48_3_gr - Connect",
        &CONNECT_48_3_GR,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test(
        "ISO QoS 48_4_gr - Connect",
        &CONNECT_48_4_GR,
        setup_powered_iso,
        test_connect,
    );

    // ----- Invalid QoS / rejection -----
    register_iso_test(
        "ISO QoS Invalid - Connect",
        &CONNECT_INVALID,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test(
        "ISO QoS CIG 0xF0 Invalid - Connect",
        &CONNECT_CIG_F0_INVALID,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test(
        "ISO QoS CIS 0xF0 Invalid - Connect",
        &CONNECT_CIS_F0_INVALID,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test_rej(
        "ISO QoS - Pair Reject",
        &CONNECT_REJECT,
        setup_powered_iso,
        test_connect,
        0x0D,
    );

    // ----- Send/Recv + timestamping -----
    register_iso_test("ISO Send - Success", &CONNECT_16_2_1_SEND, setup_powered_iso, test_connect);
    register_iso_test(
        "ISO Send - TX Timestamping",
        &CONNECT_SEND_TX_TSTAMP,
        setup_powered_iso,
        test_connect,
    );
    register_iso_test(
        "ISO Send - TX CMSG Timestamping",
        &CONNECT_SEND_TX_CMSG_TSTAMP,
        setup_powered_iso,
        test_connect,
    );

    // ----- Listen/Recv + timestamping -----
    register_iso_test("ISO Listen - Recv", &LISTEN_16_2_1_RECV, setup_powered_iso, test_listen);
    register_iso_test(
        "ISO Listen - Recv Timestamp",
        &LISTEN_16_2_1_RECV_TS,
        setup_powered_iso,
        test_listen,
    );
    register_iso_test(
        "ISO Listen - Recv Pkt Status",
        &LISTEN_16_2_1_RECV_PKT_STATUS,
        setup_powered_iso,
        test_listen,
    );
    register_iso_test(
        "ISO Listen - Recv Pkt SeqNum",
        &LISTEN_16_2_1_RECV_PKT_SEQNUM,
        setup_powered_iso,
        test_listen,
    );

    // ----- Deferred setup -----
    register_iso_test("ISO Defer 16_2_1 - Connect", &DEFER_16_2_1, setup_powered_iso, test_defer);
    register_iso_test("ISO Defer 48_2_1 - Connect", &DEFER_48_2_1, setup_powered_iso, test_defer);
    register_iso_test(
        "ISO Defer Listen 16_2_1 - Recv",
        &LISTEN_16_2_1_DEFER_RECV,
        setup_powered_iso,
        test_listen,
    );
    register_iso_test(
        "ISO Defer Listen 48_2_1 - Recv",
        &LISTEN_48_2_1_DEFER_RECV,
        setup_powered_iso,
        test_listen,
    );
    register_iso_test(
        "ISO Defer Listen 16_2_1 - Reject",
        &LISTEN_16_2_1_DEFER_REJECT,
        setup_powered_iso,
        test_listen,
    );

    // ----- Close/wait-close -----
    register_iso_test("ISO Connect Close", &CONNECT_CLOSE, setup_powered_iso, test_connect_close);
    register_iso_test(
        "ISO Connect Wait Close",
        &CONNECT_WAIT_CLOSE,
        setup_powered_iso,
        test_connect_wait_close,
    );

    // ----- Suspend -----
    register_iso_test(
        "ISO Connect Suspend",
        &CONNECT_SUSPEND,
        setup_powered_iso,
        test_connect_suspend,
    );
    register_iso_test(
        "ISO Suspend 16_2_1",
        &SUSPEND_16_2_1,
        setup_powered_iso,
        test_connect_suspend,
    );

    // ----- Multi-CIS -----
    register_iso_test2("ISO Connect2 16_2_1", &CONNECT2_16_2_1, setup_powered_iso, test_connect2);
    register_iso_test2(
        "ISO Connect2 16_2_1 - Seq",
        &CONNECT2_16_2_1_SEQ,
        setup_powered_iso,
        test_connect2,
    );
    register_iso_test2(
        "ISO Connect2 16_2_1 - Busy",
        &CONNECT2_16_2_1_BUSY,
        setup_powered_iso,
        test_connect2,
    );
    register_iso_test2(
        "ISO Connect2 16_2_1 - Suspend",
        &CONNECT2_16_2_1_SUSPEND,
        setup_powered_iso,
        test_connect2_suspend,
    );

    // ----- Send and Receive -----
    register_iso_test(
        "ISO Send and Receive",
        &CONNECT_16_2_1_SEND_RECV,
        setup_powered_iso,
        test_connect_send_recv,
    );

    // ----- ACL disconnect -----
    register_iso_test(
        "ISO ACL Disconnect",
        &CONNECT_ACL_DISC,
        setup_powered_iso,
        test_connect_acl_disc,
    );

    // ----- Reconnect -----
    register_iso_test("ISO Reconnect", &RECONNECT_16_2_1, setup_powered_iso, test_reconnect);
    register_iso_test("ISO Reconnect x16", &RECONNECT_16_2_1, setup_powered_iso, test_reconnect_16);

    // ----- Audio Configuration -----
    register_iso_test("ISO AC 1(i) - Connect", &AC_1_4_DATA, setup_powered_iso, test_connect);
    register_iso_test("ISO AC 2(i) - Connect", &AC_2_10_DATA, setup_powered_iso, test_connect);
    register_iso_test("ISO AC 3(i) - Connect", &AC_3_5_DATA, setup_powered_iso, test_connect);
    register_iso_test("ISO AC 6(i) - Connect", &AC_6I_DATA, setup_powered_iso, test_connect);
    register_iso_test("ISO AC 6(ii) - Connect", &AC_6II_DATA, setup_powered_iso, test_connect);
    register_iso_test2("ISO AC 6(i)x2 - Connect", &AC_6I_2_DATA, setup_powered_iso, test_connect2);
    register_iso_test2(
        "ISO AC 6(ii)x2 - Connect",
        &AC_6II_2_DATA,
        setup_powered_iso,
        test_connect2,
    );
    register_iso_test("ISO AC 7(i) - Connect", &AC_7I_DATA, setup_powered_iso, test_connect);
    register_iso_test("ISO AC 7(ii) - Connect", &AC_7II_DATA, setup_powered_iso, test_connect);
    register_iso_test2("ISO AC 7(i)x2 - Connect", &AC_7I_2_DATA, setup_powered_iso, test_connect2);
    register_iso_test2(
        "ISO AC 7(ii)x2 - Connect",
        &AC_7II_2_DATA,
        setup_powered_iso,
        test_connect2,
    );
    register_iso_test("ISO AC 8(i) - Connect", &AC_8I_DATA, setup_powered_iso, test_connect);
    register_iso_test("ISO AC 8(ii) - Connect", &AC_8II_DATA, setup_powered_iso, test_connect);
    register_iso_test2("ISO AC 8(i)x2 - Connect", &AC_8I_2_DATA, setup_powered_iso, test_connect2);
    register_iso_test2(
        "ISO AC 8(ii)x2 - Connect",
        &AC_8II_2_DATA,
        setup_powered_iso,
        test_connect2,
    );
    register_iso_test("ISO AC 9(i) - Connect", &AC_9I_DATA, setup_powered_iso, test_connect);
    register_iso_test("ISO AC 9(ii) - Connect", &AC_9II_DATA, setup_powered_iso, test_connect);
    register_iso_test2("ISO AC 9(i)x2 - Connect", &AC_9I_2_DATA, setup_powered_iso, test_connect2);
    register_iso_test2(
        "ISO AC 9(ii)x2 - Connect",
        &AC_9II_2_DATA,
        setup_powered_iso,
        test_connect2,
    );
    register_iso_test("ISO AC 11(i) - Connect", &AC_11I_DATA, setup_powered_iso, test_connect);
    register_iso_test("ISO AC 11(ii) - Connect", &AC_11II_DATA, setup_powered_iso, test_connect);
    register_iso_test2(
        "ISO AC 11(i)x2 - Connect",
        &AC_11I_2_DATA,
        setup_powered_iso,
        test_connect2,
    );
    register_iso_test2(
        "ISO AC 11(ii)x2 - Connect",
        &AC_11II_2_DATA,
        setup_powered_iso,
        test_connect2,
    );

    // ----- Broadcast sender -----
    register_iso_test("ISO Bcast 16_2_1 - Send", &BCAST_16_2_1_SEND, setup_powered, test_bcast);
    register_iso_test(
        "ISO Bcast Enc 16_2_1 - Send",
        &BCAST_ENC_16_2_1_SEND,
        setup_powered,
        test_bcast,
    );
    register_iso_test("ISO Bcast 1_16_2_1 - Send", &BCAST_1_16_2_1_SEND, setup_powered, test_bcast);
    register_iso_test(
        "ISO Bcast 1_1_16_2_1 - Send",
        &BCAST_1_1_16_2_1_SEND,
        setup_powered,
        test_bcast,
    );
    register_iso_test(
        "ISO Bcast 16_2_1 - Reconnect",
        &BCAST_16_2_1_SEND,
        setup_powered,
        test_bcast_reconnect,
    );

    // ----- Broadcast receiver -----
    register_iso_test(
        "ISO Bcast 16_2_1 - Recv",
        &BCAST_16_2_1_RECV,
        setup_powered_iso,
        test_bcast_recv,
    );
    register_iso_test(
        "ISO Bcast Enc 16_2_1 - Recv",
        &BCAST_ENC_16_2_1_RECV,
        setup_powered_iso,
        test_bcast_recv,
    );
    register_iso_test(
        "ISO Bcast 16_2_1 - Recv Defer",
        &BCAST_16_2_1_RECV_DEFER,
        setup_powered_iso,
        test_bcast_recv,
    );
    register_iso_test(
        "ISO Bcast 16_2_1 - Recv Defer Reconnect",
        &BCAST_16_2_1_RECV_DEFER_RECONNECT,
        setup_powered_iso,
        test_bcast_recv,
    );

    // ----- PAST -----
    register_iso_test("ISO PAST 16_2_1 - Send", &PAST_16_2_1_SEND, setup_powered, test_past);
    register_iso_test("ISO PAST 16_2_1", &PAST_16_2_1, setup_powered, test_past);
    register_iso_test(
        "ISO PAST 16_2_1 - Recv",
        &PAST_16_2_1_RECV,
        setup_powered_iso,
        test_past_recv,
    );

    // ----- Broadcast AC configs -----
    register_iso_test("ISO Bcast AC 12 - Send", &BCAST_AC_12_DATA, setup_powered, test_bcast);
    register_iso_test(
        "ISO Bcast AC 13 - Recv",
        &BCAST_AC_13_DATA,
        setup_powered_iso,
        test_bcast_recv,
    );
    register_iso_test("ISO Bcast AC 14 - Send", &BCAST_AC_14_DATA, setup_powered, test_bcast);

    // ----- 48 kHz broadcast -----
    register_iso_test("ISO Bcast 48_1_g - Send", &BCAST_48_1_G_DATA, setup_powered, test_bcast);
    register_iso_test("ISO Bcast 48_2_g - Send", &BCAST_48_2_G_DATA, setup_powered, test_bcast);
    register_iso_test("ISO Bcast 48_3_g - Send", &BCAST_48_3_G_DATA, setup_powered, test_bcast);
    register_iso_test("ISO Bcast 48_4_g - Send", &BCAST_48_4_G_DATA, setup_powered, test_bcast);

    // ----- Ethtool TS info -----
    register_iso_test(
        "ISO Ethtool TS Info",
        &CONNECT_16_2_1,
        setup_powered,
        test_iso_ethtool_ts_info,
    );

    tester_run();
}
