// SPDX-License-Identifier: LGPL-2.1-or-later
//
//  BlueZ - Bluetooth protocol stack for Linux
//
//  Copyright (C) 2021  Intel Corporation. All rights reserved.
//
// Mesh Configuration Model D-Bus tester.
//
// Rewritten from tools/mesh-cfgtest.c to idiomatic Rust using tokio + zbus.
// This tester validates the Bluetooth Mesh D-Bus interface (org.bluez.mesh)
// by provisioning a mesh node, performing configuration model operations
// (AppKey Add, TTL Set, Get Composition Data, Bind, etc.), and verifying
// D-Bus message sequences.

#![deny(warnings)]

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use bluez_shared::util::{get_be64, getrandom};
use tokio::process::{Child, Command};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};
use tracing::{debug, error, info, warn};
use zbus::Connection;
use zbus::connection::Builder;
use zbus::proxy::Proxy;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during mesh configuration testing.
#[derive(Debug, thiserror::Error)]
enum MeshTestError {
    #[error("D-Bus error: {0}")]
    DBus(#[from] zbus::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Test failed: {0}")]
    TestFailed(String),

    #[error("Setup error: {0}")]
    Setup(String),

    #[error("zbus::fdo error: {0}")]
    Fdo(#[from] zbus::fdo::Error),
}

// ---------------------------------------------------------------------------
// Constants (from mesh-cfgtest.c:38-49, mesh-defs.h, mesh.h)
// ---------------------------------------------------------------------------

const MAX_CRPL_SIZE: u16 = 0x7fff;
const CFG_SRV_MODEL: u16 = 0x0000;
const CFG_CLI_MODEL: u16 = 0x0001;
const RMT_PROV_SRV_MODEL: u16 = 0x0004;
const RMT_PROV_CLI_MODEL: u16 = 0x0005;
const PVT_BEACON_SRV_MODEL: u16 = 0x0008;
const DEFAULT_IV_INDEX: u32 = 0x0000;
const PRIMARY_ELE_IDX: u8 = 0x00;

const BLUEZ_MESH_NAME: &str = "org.bluez.mesh";
const MESH_NETWORK_INTERFACE: &str = "org.bluez.mesh.Network1";
const MESH_NODE_INTERFACE: &str = "org.bluez.mesh.Node1";
const MESH_MANAGEMENT_INTERFACE: &str = "org.bluez.mesh.Management1";

/// Object path constants for the mesh configuration test applications.
const CLI_APP_PATH: &str = "/mesh/cfgtest/client";
const CLI_ELE_PATH_00: &str = "/mesh/cfgtest/client/ele0";
const SRV_APP_PATH: &str = "/mesh/cfgtest/server";
const SRV_ELE_PATH_00: &str = "/mesh/cfgtest/server/ele0";
const SRV_ELE_PATH_01: &str = "/mesh/cfgtest/server/ele1";

/// Import data constants.
const IMPORT_NETKEY_IDX: u16 = 0x001;
const IMPORT_NODE_UNICAST: u16 = 0xbcd;

/// Check if a model ID is a Config Model (has pub/sub disabled).
fn is_config_model(x: u16) -> bool {
    x == CFG_SRV_MODEL || x == CFG_CLI_MODEL || x == RMT_PROV_SRV_MODEL || x == RMT_PROV_CLI_MODEL
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Element descriptor for a mesh application.
#[derive(Clone, Debug)]
struct MeshCfgEl {
    path: &'static str,
    index: u8,
    location: u16,
    mods: [u16; 4],
    vmods: [u32; 2],
}

/// Application descriptor for mesh D-Bus registration.
#[derive(Clone, Debug)]
struct MeshCfgApp {
    path: &'static str,
    num_ele: u8,
    ele: Vec<MeshCfgEl>,
    cid: u16,
    pid: u16,
    vid: u16,
    crpl: u16,
    uuid: [u8; 16],
}

/// Node state associated with a mesh application.
#[derive(Clone, Debug)]
struct MeshCfgNode {
    path: String,
    token: u64,
}

/// A message payload with its length (mirrors C msg_data).
#[derive(Clone, Debug)]
struct MsgData {
    len: u16,
    data: Vec<u8>,
}

/// Expected response descriptor — associates a test ID with response data.
#[derive(Clone, Debug)]
struct ExpRsp {
    test_id: u8,
    rsp: MsgData,
}

/// Key data for AddNetKey/AddAppKey operations.
#[derive(Clone, Debug)]
struct KeyData {
    idx: u16,
    update: bool,
}

/// Complete test descriptor for a single test case.
#[derive(Clone, Debug)]
struct TestCase {
    name: &'static str,
    req: TestReqData,
    expected: Option<ExpRsp>,
    /// If true, this test has a setup phase (create_appkey).
    has_setup: bool,
}

/// Describes what to send for a test — either a raw message or a key operation.
#[derive(Clone, Debug)]
enum TestReqData {
    CfgMsg(MsgData),
    KeyOp(KeyData),
}

// ---------------------------------------------------------------------------
// Static application data (mesh-cfgtest.c:143-188)
// ---------------------------------------------------------------------------

fn make_client_app() -> MeshCfgApp {
    MeshCfgApp {
        path: CLI_APP_PATH,
        cid: 0x05f1,
        pid: 0x0002,
        vid: 0x0001,
        crpl: MAX_CRPL_SIZE,
        num_ele: 1,
        ele: vec![MeshCfgEl {
            path: CLI_ELE_PATH_00,
            index: PRIMARY_ELE_IDX,
            location: 0x0001,
            mods: [CFG_SRV_MODEL, CFG_CLI_MODEL, RMT_PROV_SRV_MODEL, PVT_BEACON_SRV_MODEL],
            vmods: [0xffffffff, 0xffffffff],
        }],
        uuid: [0u8; 16],
    }
}

fn make_server_app() -> MeshCfgApp {
    MeshCfgApp {
        path: SRV_APP_PATH,
        cid: 0x05f1,
        pid: 0x0002,
        vid: 0x0001,
        crpl: MAX_CRPL_SIZE,
        num_ele: 2,
        ele: vec![
            MeshCfgEl {
                path: SRV_ELE_PATH_00,
                index: PRIMARY_ELE_IDX,
                location: 0x0001,
                mods: [CFG_SRV_MODEL, RMT_PROV_SRV_MODEL, PVT_BEACON_SRV_MODEL, 0xffff],
                vmods: [0xffffffff, 0xffffffff],
            },
            MeshCfgEl {
                path: SRV_ELE_PATH_01,
                index: PRIMARY_ELE_IDX + 1,
                location: 0x0002,
                mods: [0x1000, 0xffff, 0xffff, 0xffff],
                vmods: [0x005f_0001, 0xffffffff],
            },
        ],
        uuid: [0u8; 16],
    }
}

// ---------------------------------------------------------------------------
// Test data definitions (mesh-cfgtest.c:225-366)
// ---------------------------------------------------------------------------

/// Init add netkey response: opcode 0x8044, status 0x00, index 0x0100.
fn init_add_netkey_rsp() -> MsgData {
    MsgData { len: 5, data: vec![0x80, 0x44, 0x00, 0x01, 0x00] }
}

/// Init add appkey response: opcode 0x8003, status 0x00, index 0x011000.
fn init_add_appkey_rsp() -> MsgData {
    MsgData { len: 6, data: vec![0x80, 0x03, 0x00, 0x01, 0x10, 0x00] }
}

/// Build the five test cases matching the C source main() registration.
fn build_test_cases() -> Vec<TestCase> {
    vec![
        // Test 1: Config AppKey Add: Success
        TestCase {
            name: "Config AppKey Add: Success",
            req: TestReqData::KeyOp(KeyData { idx: 0x002, update: false }),
            expected: Some(ExpRsp {
                test_id: 1,
                rsp: MsgData { len: 6, data: vec![0x80, 0x03, 0x00, 0x01, 0x20, 0x00] },
            }),
            has_setup: true,
        },
        // Test 2: Config Default TTL Set: Success
        TestCase {
            name: "Config Default TTL Set: Success",
            req: TestReqData::CfgMsg(MsgData { len: 3, data: vec![0x80, 0x0D, 0x07] }),
            expected: Some(ExpRsp {
                test_id: 2,
                rsp: MsgData { len: 3, data: vec![0x80, 0x0E, 0x07] },
            }),
            has_setup: false,
        },
        // Test 3: Config Get Device Composition: Success
        TestCase {
            name: "Config Get Device Composition: Success",
            req: TestReqData::CfgMsg(MsgData { len: 3, data: vec![0x80, 0x08, 0x00] }),
            expected: Some(ExpRsp {
                test_id: 5,
                rsp: MsgData {
                    len: 32,
                    data: vec![
                        0x02, 0x00, 0xf1, 0x05, 0x02, 0x00, 0x01, 0x00, 0xff, 0x7f, 0x05, 0x00,
                        0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x02, 0x00,
                        0x01, 0x01, 0x00, 0x10, 0xf1, 0x05, 0x01, 0x00,
                    ],
                },
            }),
            has_setup: false,
        },
        // Test 4: Config Bind: Success
        TestCase {
            name: "Config Bind: Success",
            req: TestReqData::CfgMsg(MsgData {
                len: 8,
                data: vec![0x80, 0x3D, 0xCE, 0x0B, 0x01, 0x00, 0x00, 0x10],
            }),
            expected: Some(ExpRsp {
                test_id: 3,
                rsp: MsgData {
                    len: 9,
                    data: vec![0x80, 0x3E, 0x00, 0xCE, 0x0B, 0x01, 0x00, 0x00, 0x10],
                },
            }),
            has_setup: false,
        },
        // Test 5: Config Bind: Error Invalid Model
        TestCase {
            name: "Config Bind: Error Invalid Model",
            req: TestReqData::CfgMsg(MsgData {
                len: 8,
                data: vec![0x80, 0x3D, 0xCE, 0x0B, 0x01, 0x00, 0x00, 0x11],
            }),
            expected: Some(ExpRsp {
                test_id: 4,
                rsp: MsgData {
                    len: 9,
                    data: vec![0x80, 0x3E, 0x02, 0xCE, 0x0B, 0x01, 0x00, 0x00, 0x11],
                },
            }),
            has_setup: false,
        },
    ]
}

// ---------------------------------------------------------------------------
// Shared test state (replaces C global variables)
// ---------------------------------------------------------------------------

/// Central mutable state shared between D-Bus handlers and test orchestration.
#[derive(Debug)]
struct TestState {
    /// Client mesh node state (path + token) after CreateNetwork + JoinComplete.
    client_node: Option<MeshCfgNode>,
    /// Server mesh node state after Import + JoinComplete.
    server_node: Option<MeshCfgNode>,
    /// Import device key (randomised at import time).
    import_devkey: [u8; 16],
    /// Import network key (randomised at import time).
    import_netkey: [u8; 16],
    /// Current IV index.
    iv_index: u32,
    /// Whether the startup chain is complete.
    init_done: bool,
    /// Whether the startup chain has failed.
    init_failed: bool,
    /// Holds the current expected response for the running test.
    current_expected: Option<ExpRsp>,
    /// Result of the last DevKeyMessageReceived evaluation.
    last_test_result: Option<bool>,
}

impl TestState {
    fn new() -> Self {
        Self {
            client_node: None,
            server_node: None,
            import_devkey: [0u8; 16],
            import_netkey: [0u8; 16],
            iv_index: DEFAULT_IV_INDEX,
            init_done: false,
            init_failed: false,
            current_expected: None,
            last_test_result: None,
        }
    }
}

type SharedState = Arc<Mutex<TestState>>;

// ---------------------------------------------------------------------------
// D-Bus interface: org.bluez.mesh.Application1
// ---------------------------------------------------------------------------

/// Implements the mesh Application1 interface on a per-app object path.
/// The mesh daemon calls JoinComplete when network creation or import succeeds.
struct MeshApplicationIface {
    app_path: &'static str,
    cid: u16,
    pid: u16,
    vid: u16,
    crpl: u16,
    state: SharedState,
    /// true for client_app, false for server_app
    is_client: bool,
}

#[zbus::interface(name = "org.bluez.mesh.Application1")]
impl MeshApplicationIface {
    /// Called by the mesh daemon when join/create/import is complete.
    async fn join_complete(&self, token: u64) -> zbus::fdo::Result<()> {
        let mut st = self.state.lock().await;
        let be_token = get_be64(&token.to_ne_bytes());
        info!("JoinComplete on {}: token=0x{:016x}", self.app_path, be_token);
        let node = MeshCfgNode { path: String::new(), token: be_token };
        if self.is_client {
            st.client_node = Some(node);
        } else {
            st.server_node = Some(node);
        }
        Ok(())
    }

    /// CompanyID property.
    #[zbus(property, name = "CompanyID")]
    async fn company_id(&self) -> u16 {
        self.cid
    }

    /// VersionID property.
    #[zbus(property, name = "VersionID")]
    async fn version_id(&self) -> u16 {
        self.vid
    }

    /// ProductID property.
    #[zbus(property, name = "ProductID")]
    async fn product_id(&self) -> u16 {
        self.pid
    }

    /// CRPL property.
    #[zbus(property, name = "CRPL")]
    async fn crpl(&self) -> u16 {
        self.crpl
    }
}

// ---------------------------------------------------------------------------
// D-Bus interface: org.bluez.mesh.Element1
// ---------------------------------------------------------------------------

/// Implements the mesh Element1 interface on a per-element object path.
/// The mesh daemon calls DevKeyMessageReceived when a config message arrives.
struct MeshElementIface {
    index: u8,
    location: u16,
    mods: Vec<u16>,
    vmods: Vec<u32>,
    state: SharedState,
}

#[zbus::interface(name = "org.bluez.mesh.Element1")]
impl MeshElementIface {
    /// DevKeyMessageReceived — called by the mesh daemon with received
    /// config model messages.
    async fn dev_key_message_received(
        &self,
        source: u16,
        remote: bool,
        net_index: u16,
        data: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        let n = data.len();
        let hex: String = data.iter().map(|b| format!("{b:02x} ")).collect();
        info!("Received dev key message (len {}): {}", n, hex.trim_end());
        debug!("source=0x{source:04x} remote={remote} net_index=0x{net_index:04x}");

        let mut st = self.state.lock().await;

        // Check if this matches an init response (startup chain stage)
        let init_netkey_rsp = init_add_netkey_rsp();
        let init_appkey_rsp = init_add_appkey_rsp();

        if !st.init_done {
            // PRE_SETUP stage: match against init responses
            if n == init_netkey_rsp.len as usize && data[..n] == init_netkey_rsp.data[..n] {
                info!("Init: matched add_netkey_rsp");
                // Signal that this init step is done — the orchestrator
                // polls last_test_result
                st.last_test_result = Some(true);
            } else if n == init_appkey_rsp.len as usize && data[..n] == init_appkey_rsp.data[..n] {
                info!("Init: matched add_appkey_rsp");
                st.last_test_result = Some(true);
            } else {
                warn!("Init: unexpected message, failing pre-setup");
                st.init_failed = true;
                st.last_test_result = Some(false);
            }
            return Ok(());
        }

        // TEST stage: check against current expected response
        if let Some(ref exp) = st.current_expected {
            let rsp = &exp.rsp;
            let res = if exp.test_id == 5 {
                // Special: check device composition with flexible model ordering
                check_device_composition(rsp, n as u32, &data)
            } else {
                n == rsp.len as usize && data[..n] == rsp.data[..n]
            };
            st.last_test_result = Some(res);
        } else {
            st.last_test_result = Some(false);
        }

        Ok(())
    }

    /// Index property.
    #[zbus(property, name = "Index")]
    async fn index(&self) -> u8 {
        self.index
    }

    /// Location property.
    #[zbus(property, name = "Location")]
    async fn location(&self) -> u16 {
        self.location
    }

    /// Models property: array of (model_id, dict{str, variant}).
    #[zbus(property, name = "Models")]
    async fn models(&self) -> Vec<(u16, HashMap<String, OwnedValue>)> {
        let mut result = Vec::new();
        for &mod_id in &self.mods {
            if mod_id == 0xffff {
                continue;
            }
            let is_cfg = is_config_model(mod_id);
            let mut props: HashMap<String, OwnedValue> = HashMap::new();
            props.insert("Subscribe".to_string(), Value::from(!is_cfg).try_into().unwrap());
            props.insert("Publish".to_string(), Value::from(!is_cfg).try_into().unwrap());
            result.push((mod_id, props));
        }
        result
    }

    /// VendorModels property: array of (vendor_id, model_id, dict{str, variant}).
    #[zbus(property, name = "VendorModels")]
    async fn vendor_models(&self) -> Vec<(u16, u16, HashMap<String, OwnedValue>)> {
        let mut result = Vec::new();
        for &vmod in &self.vmods {
            if vmod == 0xffffffff {
                continue;
            }
            let vid = (vmod >> 16) as u16;
            let mid = (vmod & 0xffff) as u16;
            let mut props: HashMap<String, OwnedValue> = HashMap::new();
            props.insert("Subscribe".to_string(), Value::from(true).try_into().unwrap());
            props.insert("Publish".to_string(), Value::from(true).try_into().unwrap());
            result.push((vid, mid, props));
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Composition data verification (mesh-cfgtest.c:1012-1089)
// ---------------------------------------------------------------------------

/// Search `buf` for `mod_id` of size `sz` bytes. Returns true if found exactly
/// once (disallows duplicates), false otherwise.
fn find_model(buf: &[u8], len: usize, mod_id: &[u8], sz: usize) -> bool {
    let mut found = false;
    let mut offset = 0;
    while offset + sz <= len {
        if buf[offset..offset + sz] == mod_id[..sz] {
            if found {
                return false; // duplicate
            }
            found = true;
        }
        offset += sz;
    }
    found
}

/// Check if received composition data matches the expected response.
/// Allows different ordering of model IDs within each element.
fn check_device_composition(rsp: &MsgData, n: u32, data: &[u8]) -> bool {
    let len = rsp.len as usize;
    let n = n as usize;

    if n != len {
        return false;
    }

    // Exact match is the simple case
    if data[..n] == rsp.data[..n] {
        return true;
    }

    // Allow for different ordering of model IDs.
    // First 12 bytes are fixed-length header data.
    if data[..12] != rsp.data[..12] {
        return false;
    }

    let mut cnt: usize = 12;
    let mut dpos: usize = 12;

    while cnt < len {
        if (len - cnt) < 4 {
            return false;
        }

        // Check element header bytes
        if data[dpos..dpos + 4] != rsp.data[cnt..cnt + 4] {
            return false;
        }

        let s = data[dpos + 2] as usize;
        let v = data[dpos + 3] as usize;

        if cnt + 4 + s * 2 + v * 4 > len {
            return false;
        }

        dpos += 4;
        cnt += 4;

        // Check SIG models (2 bytes each) — order-independent
        for _ in 0..s {
            if !find_model(&rsp.data[cnt..], s * 2, &data[dpos..], 2) {
                return false;
            }
            dpos += 2;
        }
        cnt += s * 2;

        // Check vendor models (4 bytes each) — order-independent
        for _ in 0..v {
            if !find_model(&rsp.data[cnt..], v * 4, &data[dpos..], 4) {
                return false;
            }
            dpos += 4;
        }
        cnt += v * 4;
    }

    true
}

// ---------------------------------------------------------------------------
// D-Bus application registration
// ---------------------------------------------------------------------------

/// Register the Application1 and Element1 interfaces on the D-Bus connection
/// for a given mesh application.
async fn register_app(
    conn: &Connection,
    app: &MeshCfgApp,
    state: &SharedState,
    is_client: bool,
) -> Result<(), MeshTestError> {
    let app_iface = MeshApplicationIface {
        app_path: app.path,
        cid: app.cid,
        pid: app.pid,
        vid: app.vid,
        crpl: app.crpl,
        state: Arc::clone(state),
        is_client,
    };
    conn.object_server().at(app.path, app_iface).await.map_err(MeshTestError::DBus)?;

    for (i, ele) in app.ele.iter().enumerate() {
        if i >= app.num_ele as usize {
            break;
        }
        let ele_iface = MeshElementIface {
            index: ele.index,
            location: ele.location,
            mods: ele.mods.to_vec(),
            vmods: ele.vmods.to_vec(),
            state: Arc::clone(state),
        };
        conn.object_server().at(ele.path, ele_iface).await.map_err(MeshTestError::DBus)?;
    }

    info!("Registered app at {}", app.path);
    Ok(())
}

// ---------------------------------------------------------------------------
// D-Bus proxy helper
// ---------------------------------------------------------------------------

/// Create a zbus proxy for a given destination, path, and interface.
async fn make_proxy<'a>(
    conn: &'a Connection,
    dest: &str,
    path: &str,
    iface: &str,
) -> Result<Proxy<'a>, MeshTestError> {
    let proxy = zbus::proxy::Builder::new(conn)
        .destination(dest.to_string())
        .map_err(MeshTestError::DBus)?
        .path(path.to_string())
        .map_err(MeshTestError::DBus)?
        .interface(iface.to_string())
        .map_err(MeshTestError::DBus)?
        .build()
        .await
        .map_err(MeshTestError::DBus)?;
    Ok(proxy)
}

// ---------------------------------------------------------------------------
// Poll helper — wait for last_test_result to become Some
// ---------------------------------------------------------------------------

/// Poll the shared state for a test result, with a timeout.
async fn wait_for_result(state: &SharedState, timeout_secs: u64) -> Result<bool, MeshTestError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        {
            let mut st = state.lock().await;
            if let Some(res) = st.last_test_result.take() {
                return Ok(res);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(MeshTestError::TestFailed(
                "Timed out waiting for D-Bus response".to_string(),
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------
// Startup chain operations
// ---------------------------------------------------------------------------

/// Step 1: CreateNetwork — creates a mesh network for the client app.
async fn create_network(
    conn: &Connection,
    client_app: &mut MeshCfgApp,
    state: &SharedState,
) -> Result<(), MeshTestError> {
    getrandom(&mut client_app.uuid).map_err(|e| MeshTestError::Setup(format!("getrandom: {e}")))?;

    let net_proxy =
        make_proxy(conn, BLUEZ_MESH_NAME, "/org/bluez/mesh", MESH_NETWORK_INTERFACE).await?;

    info!("Calling CreateNetwork for {}", client_app.path);
    let path_val = ObjectPath::try_from(client_app.path)
        .map_err(|e| MeshTestError::Setup(format!("invalid path: {e}")))?;
    let uuid_vec: Vec<u8> = client_app.uuid.to_vec();

    net_proxy.call_method("CreateNetwork", &(path_val, uuid_vec)).await.map_err(|e| {
        error!("CreateNetwork failed: {e}");
        MeshTestError::DBus(e)
    })?;

    // Wait for JoinComplete callback to fire
    sleep(Duration::from_millis(500)).await;
    {
        let st = state.lock().await;
        if st.client_node.is_none() {
            return Err(MeshTestError::Setup(
                "CreateNetwork: JoinComplete not received".to_string(),
            ));
        }
    }
    info!("CreateNetwork completed successfully");
    Ok(())
}

/// Step 2: Import — imports the server node into the mesh network.
async fn import_node(
    conn: &Connection,
    server_app: &mut MeshCfgApp,
    state: &SharedState,
) -> Result<(), MeshTestError> {
    getrandom(&mut server_app.uuid)
        .map_err(|e| MeshTestError::Setup(format!("getrandom uuid: {e}")))?;

    let mut st = state.lock().await;
    getrandom(&mut st.import_netkey)
        .map_err(|e| MeshTestError::Setup(format!("getrandom netkey: {e}")))?;
    getrandom(&mut st.import_devkey)
        .map_err(|e| MeshTestError::Setup(format!("getrandom devkey: {e}")))?;
    let devkey = st.import_devkey;
    let netkey = st.import_netkey;
    let ivi = st.iv_index;
    drop(st);

    let net_proxy =
        make_proxy(conn, BLUEZ_MESH_NAME, "/org/bluez/mesh", MESH_NETWORK_INTERFACE).await?;

    let path_val = ObjectPath::try_from(server_app.path)
        .map_err(|e| MeshTestError::Setup(format!("invalid path: {e}")))?;
    let uuid_vec: Vec<u8> = server_app.uuid.to_vec();
    let devkey_vec: Vec<u8> = devkey.to_vec();
    let netkey_vec: Vec<u8> = netkey.to_vec();

    let mut flags: HashMap<String, Value<'_>> = HashMap::new();
    flags.insert("IvUpdate".to_string(), Value::from(false));
    flags.insert("KeyRefresh".to_string(), Value::from(false));

    info!("Calling Import for {}", server_app.path);
    net_proxy
        .call_method(
            "Import",
            &(
                path_val,
                uuid_vec,
                devkey_vec,
                netkey_vec,
                IMPORT_NETKEY_IDX,
                flags,
                ivi,
                IMPORT_NODE_UNICAST,
            ),
        )
        .await
        .map_err(|e| {
            error!("Import failed: {e}");
            MeshTestError::DBus(e)
        })?;

    sleep(Duration::from_millis(500)).await;
    {
        let st = state.lock().await;
        if st.server_node.is_none() {
            return Err(MeshTestError::Setup(
                "Import: JoinComplete not received for server".to_string(),
            ));
        }
    }
    info!("Import completed successfully");
    Ok(())
}

/// Step 3: Attach — attaches the client node to get proxies.
async fn attach_node(
    conn: &Connection,
    client_app: &MeshCfgApp,
    state: &SharedState,
) -> Result<(), MeshTestError> {
    let token = {
        let st = state.lock().await;
        match &st.client_node {
            Some(node) => node.token,
            None => {
                return Err(MeshTestError::Setup("Attach: client node not available".to_string()));
            }
        }
    };

    let net_proxy =
        make_proxy(conn, BLUEZ_MESH_NAME, "/org/bluez/mesh", MESH_NETWORK_INTERFACE).await?;

    let path_val = ObjectPath::try_from(client_app.path)
        .map_err(|e| MeshTestError::Setup(format!("invalid path: {e}")))?;

    info!("Calling Attach for {} with token=0x{:016x}", client_app.path, token);

    let reply = net_proxy.call_method("Attach", &(path_val, token)).await.map_err(|e| {
        error!("Attach failed: {e}");
        MeshTestError::DBus(e)
    })?;

    // Parse the reply to extract the node object path.
    let body = reply.body();
    let attached_path: String = match body.deserialize::<(zbus::zvariant::OwnedObjectPath,)>() {
        Ok((p,)) => p.to_string(),
        Err(_) => match body.deserialize::<(String,)>() {
            Ok((s,)) => s,
            Err(e) => {
                warn!("Could not parse Attach reply: {e}");
                String::new()
            }
        },
    };

    info!("Attached with path: {}", attached_path);
    {
        let mut st = state.lock().await;
        if let Some(ref mut node) = st.client_node {
            node.path = attached_path;
        }
    }
    Ok(())
}

/// Step 4: ImportSubnet — imports the network key into the client node.
async fn import_subnet(conn: &Connection, state: &SharedState) -> Result<(), MeshTestError> {
    let (node_path, netkey) = {
        let st = state.lock().await;
        let path = st.client_node.as_ref().map(|n| n.path.clone()).unwrap_or_default();
        let key = st.import_netkey;
        (path, key)
    };
    if node_path.is_empty() {
        return Err(MeshTestError::Setup("ImportSubnet: client node path not set".to_string()));
    }

    let mgmt_proxy =
        make_proxy(conn, BLUEZ_MESH_NAME, &node_path, MESH_MANAGEMENT_INTERFACE).await?;

    let netkey_vec: Vec<u8> = netkey.to_vec();
    info!("Calling ImportSubnet idx=0x{:04x}", IMPORT_NETKEY_IDX);

    mgmt_proxy.call_method("ImportSubnet", &(IMPORT_NETKEY_IDX, netkey_vec)).await.map_err(
        |e| {
            error!("ImportSubnet failed: {e}");
            MeshTestError::DBus(e)
        },
    )?;

    info!("ImportSubnet completed successfully");
    Ok(())
}

/// Step 5: ImportRemoteNode — imports the server node info into client's mesh.
async fn import_remote(
    conn: &Connection,
    server_app: &MeshCfgApp,
    state: &SharedState,
) -> Result<(), MeshTestError> {
    let (node_path, devkey) = {
        let st = state.lock().await;
        let path = st.client_node.as_ref().map(|n| n.path.clone()).unwrap_or_default();
        let key = st.import_devkey;
        (path, key)
    };
    if node_path.is_empty() {
        return Err(MeshTestError::Setup("ImportRemoteNode: client node path not set".to_string()));
    }

    let mgmt_proxy =
        make_proxy(conn, BLUEZ_MESH_NAME, &node_path, MESH_MANAGEMENT_INTERFACE).await?;

    let devkey_vec: Vec<u8> = devkey.to_vec();
    info!(
        "Calling ImportRemoteNode unicast=0x{:04x} num_ele={}",
        IMPORT_NODE_UNICAST, server_app.num_ele
    );

    mgmt_proxy
        .call_method("ImportRemoteNode", &(IMPORT_NODE_UNICAST, server_app.num_ele, devkey_vec))
        .await
        .map_err(|e| {
            error!("ImportRemoteNode failed: {e}");
            MeshTestError::DBus(e)
        })?;

    info!("ImportRemoteNode completed successfully");
    Ok(())
}

/// Step 6: AddNetKey — sends add net key to the remote server node.
async fn add_netkey(conn: &Connection, state: &SharedState) -> Result<(), MeshTestError> {
    let node_path = {
        let st = state.lock().await;
        st.client_node.as_ref().map(|n| n.path.clone()).unwrap_or_default()
    };
    if node_path.is_empty() {
        return Err(MeshTestError::Setup("AddNetKey: client node path not set".to_string()));
    }

    let node_proxy = make_proxy(conn, BLUEZ_MESH_NAME, &node_path, MESH_NODE_INTERFACE).await?;
    let ele_path = ObjectPath::try_from(CLI_ELE_PATH_00)
        .map_err(|e| MeshTestError::Setup(format!("invalid path: {e}")))?;

    info!("Calling AddNetKey idx=0x{:04x}", IMPORT_NETKEY_IDX);
    node_proxy
        .call_method("AddNetKey", &(ele_path, 0x0001u16, IMPORT_NETKEY_IDX, 0x0000u16, false))
        .await
        .map_err(|e| {
            error!("AddNetKey failed: {e}");
            MeshTestError::DBus(e)
        })?;

    let result = wait_for_result(state, 10).await?;
    if !result {
        return Err(MeshTestError::Setup("AddNetKey: unexpected response".to_string()));
    }
    info!("AddNetKey completed successfully");
    Ok(())
}

/// Step 7: CreateAppKey — creates an app key on the management proxy.
async fn init_create_appkey(conn: &Connection, state: &SharedState) -> Result<(), MeshTestError> {
    let node_path = {
        let st = state.lock().await;
        st.client_node.as_ref().map(|n| n.path.clone()).unwrap_or_default()
    };
    if node_path.is_empty() {
        return Err(MeshTestError::Setup("CreateAppKey: client node path not set".to_string()));
    }

    let mgmt_proxy =
        make_proxy(conn, BLUEZ_MESH_NAME, &node_path, MESH_MANAGEMENT_INTERFACE).await?;
    info!("Calling CreateAppKey subnet=0x{:04x} idx=0x{:04x}", IMPORT_NETKEY_IDX, 0x001u16);

    mgmt_proxy.call_method("CreateAppKey", &(IMPORT_NETKEY_IDX, 0x001u16)).await.map_err(|e| {
        error!("CreateAppKey failed: {e}");
        MeshTestError::DBus(e)
    })?;

    info!("CreateAppKey completed successfully");
    Ok(())
}

/// Step 8: AddAppKey — sends add app key to the remote server node.
async fn init_add_appkey(conn: &Connection, state: &SharedState) -> Result<(), MeshTestError> {
    let node_path = {
        let st = state.lock().await;
        st.client_node.as_ref().map(|n| n.path.clone()).unwrap_or_default()
    };
    if node_path.is_empty() {
        return Err(MeshTestError::Setup("AddAppKey: client node path not set".to_string()));
    }

    let node_proxy = make_proxy(conn, BLUEZ_MESH_NAME, &node_path, MESH_NODE_INTERFACE).await?;
    let ele_path = ObjectPath::try_from(CLI_ELE_PATH_00)
        .map_err(|e| MeshTestError::Setup(format!("invalid path: {e}")))?;

    info!("Calling AddAppKey idx=0x{:04x}", 0x001u16);
    node_proxy
        .call_method(
            "AddAppKey",
            &(ele_path, IMPORT_NODE_UNICAST, 0x001u16, IMPORT_NETKEY_IDX, false),
        )
        .await
        .map_err(|e| {
            error!("AddAppKey failed: {e}");
            MeshTestError::DBus(e)
        })?;

    let result = wait_for_result(state, 10).await?;
    if !result {
        return Err(MeshTestError::Setup("AddAppKey: unexpected response".to_string()));
    }
    info!("AddAppKey completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// Test execution functions
// ---------------------------------------------------------------------------

/// Send a DevKeySend message with the given data payload.
async fn send_cfg_msg(
    conn: &Connection,
    state: &SharedState,
    msg: &MsgData,
) -> Result<(), MeshTestError> {
    let node_path = {
        let st = state.lock().await;
        st.client_node.as_ref().map(|n| n.path.clone()).unwrap_or_default()
    };

    let node_proxy = make_proxy(conn, BLUEZ_MESH_NAME, &node_path, MESH_NODE_INTERFACE).await?;
    let ele_path = ObjectPath::try_from(CLI_ELE_PATH_00)
        .map_err(|e| MeshTestError::Setup(format!("invalid path: {e}")))?;
    let data_vec: Vec<u8> = msg.data[..msg.len as usize].to_vec();
    let options: HashMap<String, Value<'_>> = HashMap::new();

    node_proxy
        .call_method(
            "DevKeySend",
            &(ele_path, IMPORT_NODE_UNICAST, true, IMPORT_NETKEY_IDX, options, data_vec),
        )
        .await
        .map_err(|e| {
            error!("DevKeySend failed: {e}");
            MeshTestError::DBus(e)
        })?;

    Ok(())
}

/// Execute the AppKey add test setup phase: create an app key on mgmt proxy.
async fn test_create_appkey(
    conn: &Connection,
    state: &SharedState,
    key_data: &KeyData,
) -> Result<(), MeshTestError> {
    let node_path = {
        let st = state.lock().await;
        st.client_node.as_ref().map(|n| n.path.clone()).unwrap_or_default()
    };
    if node_path.is_empty() {
        return Err(MeshTestError::Setup("test_create_appkey: node path not set".to_string()));
    }

    let mgmt_proxy =
        make_proxy(conn, BLUEZ_MESH_NAME, &node_path, MESH_MANAGEMENT_INTERFACE).await?;
    info!("Test setup: CreateAppKey subnet=0x{:04x} idx=0x{:04x}", IMPORT_NETKEY_IDX, key_data.idx);

    mgmt_proxy.call_method("CreateAppKey", &(IMPORT_NETKEY_IDX, key_data.idx)).await.map_err(
        |e| {
            error!("Test CreateAppKey failed: {e}");
            MeshTestError::DBus(e)
        },
    )?;

    Ok(())
}

/// Execute the AppKey add test: send AddAppKey to the node proxy.
async fn test_add_appkey(
    conn: &Connection,
    state: &SharedState,
    key_data: &KeyData,
) -> Result<(), MeshTestError> {
    let node_path = {
        let st = state.lock().await;
        st.client_node.as_ref().map(|n| n.path.clone()).unwrap_or_default()
    };

    let node_proxy = make_proxy(conn, BLUEZ_MESH_NAME, &node_path, MESH_NODE_INTERFACE).await?;
    let ele_path = ObjectPath::try_from(CLI_ELE_PATH_00)
        .map_err(|e| MeshTestError::Setup(format!("invalid path: {e}")))?;

    info!("Test: AddAppKey idx=0x{:04x}", key_data.idx);
    node_proxy
        .call_method(
            "AddAppKey",
            &(ele_path, IMPORT_NODE_UNICAST, key_data.idx, IMPORT_NETKEY_IDX, key_data.update),
        )
        .await
        .map_err(|e| {
            error!("Test AddAppKey failed: {e}");
            MeshTestError::DBus(e)
        })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Test orchestration
// ---------------------------------------------------------------------------

/// Run the full startup chain to prepare the mesh environment for testing.
async fn run_startup_chain(
    conn: &Connection,
    client_app: &mut MeshCfgApp,
    server_app: &mut MeshCfgApp,
    state: &SharedState,
) -> Result<(), MeshTestError> {
    info!("=== Starting startup chain ===");

    // Step 1: Create mesh network for the client
    create_network(conn, client_app, state).await?;

    // Step 2: Import the server node
    import_node(conn, server_app, state).await?;

    // Step 3: Attach the client node
    attach_node(conn, client_app, state).await?;

    // Step 4: Import subnet into the client node
    import_subnet(conn, state).await?;

    // Step 5: Import remote server node
    import_remote(conn, server_app, state).await?;

    // Step 6: Add network key
    add_netkey(conn, state).await?;

    // Step 7: Create app key (init)
    init_create_appkey(conn, state).await?;

    // Step 8: Add app key (init)
    init_add_appkey(conn, state).await?;

    {
        let mut st = state.lock().await;
        st.init_done = true;
    }

    info!("=== Startup chain completed successfully ===");
    Ok(())
}

/// Run all five test cases sequentially and return (passed, failed) counts.
async fn run_tests(conn: &Connection, state: &SharedState) -> (u32, u32) {
    let test_cases = build_test_cases();
    let total = test_cases.len() as u32;
    let mut passed = 0u32;
    let mut failed = 0u32;

    for (i, tc) in test_cases.iter().enumerate() {
        info!("--- Test {}/{}: {} ---", i + 1, total, tc.name);

        // Set the expected response for this test
        {
            let mut st = state.lock().await;
            st.current_expected = tc.expected.clone();
            st.last_test_result = None;
        }

        // Setup phase (only for AppKey Add test)
        if tc.has_setup {
            if let TestReqData::KeyOp(ref kd) = tc.req {
                match test_create_appkey(conn, state, kd).await {
                    Ok(()) => info!("  Setup completed"),
                    Err(e) => {
                        error!("  Setup FAILED: {e}");
                        failed += 1;
                        println!("  {} - FAILED (setup: {e})", tc.name);
                        continue;
                    }
                }
            }
        }

        // Test phase
        let send_result = match &tc.req {
            TestReqData::CfgMsg(msg) => send_cfg_msg(conn, state, msg).await,
            TestReqData::KeyOp(kd) => test_add_appkey(conn, state, kd).await,
        };

        if let Err(e) = send_result {
            error!("  Send FAILED: {e}");
            failed += 1;
            println!("  {} - FAILED (send: {e})", tc.name);
            continue;
        }

        // Wait for result from DevKeyMessageReceived
        match wait_for_result(state, 10).await {
            Ok(true) => {
                passed += 1;
                info!("  PASSED");
                println!("  {} - PASSED", tc.name);
            }
            Ok(false) => {
                failed += 1;
                error!("  FAILED: response mismatch");
                println!("  {} - FAILED (response mismatch)", tc.name);
            }
            Err(e) => {
                failed += 1;
                error!("  FAILED: {e}");
                println!("  {} - FAILED ({e})", tc.name);
            }
        }
    }

    (passed, failed)
}

// ---------------------------------------------------------------------------
// Test directory and daemon process management
// ---------------------------------------------------------------------------

/// Set up the test directory and resolve the bluetooth-meshd executable path.
/// Returns (test_dir, exe_path, io_string).
fn setup_test_dir() -> Result<(PathBuf, PathBuf, String), MeshTestError> {
    let test_dir = PathBuf::from("/tmp/mesh");

    // Clean up any leftover directory
    if test_dir.exists() {
        let _ = std::fs::remove_dir_all(&test_dir);
    }

    std::fs::create_dir_all(&test_dir).map_err(|e| {
        MeshTestError::Setup(format!("Failed to create {}: {e}", test_dir.display()))
    })?;

    // Resolve the bluetooth-meshd executable path relative to our own binary
    let self_exe = std::fs::read_link("/proc/self/exe")
        .map_err(|e| MeshTestError::Setup(format!("readlink /proc/self/exe: {e}")))?;
    let bluez_dir = self_exe
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| MeshTestError::Setup("Cannot determine bluez dir".to_string()))?;

    let exe_path = bluez_dir.join("mesh").join("bluetooth-meshd");
    let io_string = format!("unit:{}/test_sk", test_dir.display());

    info!("test_dir={} exe={} io={}", test_dir.display(), exe_path.display(), io_string);
    Ok((test_dir, exe_path, io_string))
}

/// Spawn the bluetooth-meshd process as a child.
async fn spawn_mesh_daemon(
    exe: &std::path::Path,
    io: &str,
    test_dir: &std::path::Path,
) -> Result<Child, MeshTestError> {
    info!("Spawning {} --io {} -s {}", exe.display(), io, test_dir.display());

    let child = Command::new(exe)
        .arg("--io")
        .arg(io)
        .arg("-s")
        .arg(test_dir)
        .spawn()
        .map_err(|e| MeshTestError::Setup(format!("Failed to spawn {}: {e}", exe.display())))?;

    // Give the daemon a moment to start up and register on D-Bus
    sleep(Duration::from_secs(1)).await;

    Ok(child)
}

// ---------------------------------------------------------------------------
// CLI option parsing
// ---------------------------------------------------------------------------

/// Parsed command-line options.
struct Options {
    list_only: bool,
    prefix: Option<String>,
    filter: Option<String>,
    version: bool,
}

fn parse_options() -> Options {
    let mut opts = Options { list_only: false, prefix: None, filter: None, version: false };

    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-v" | "--version" => {
                opts.version = true;
            }
            "-l" | "--list" => {
                opts.list_only = true;
            }
            "-p" | "--prefix" => {
                i += 1;
                if i < args.len() {
                    opts.prefix = Some(args[i].clone());
                }
            }
            "-s" | "--string" => {
                i += 1;
                if i < args.len() {
                    opts.filter = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    opts
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let options = parse_options();

    if options.version {
        println!("mesh-cfgtest 5.86");
        return Ok(());
    }

    // Build test cases for listing
    let test_cases = build_test_cases();

    if options.list_only {
        for (i, tc) in test_cases.iter().enumerate() {
            let show = match (&options.prefix, &options.filter) {
                (Some(p), _) => tc.name.starts_with(p.as_str()),
                (_, Some(s)) => tc.name.contains(s.as_str()),
                _ => true,
            };
            if show {
                println!("  Test {}: {}", i + 1, tc.name);
            }
        }
        return Ok(());
    }

    // Set up test directory and find daemon executable
    let (test_dir, exe_path, io_string) = setup_test_dir()?;

    // Spawn the mesh daemon child process
    let mut child = spawn_mesh_daemon(&exe_path, &io_string, &test_dir).await?;

    // Set up signal handling for graceful shutdown
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    // Create shared state
    let state: SharedState = Arc::new(Mutex::new(TestState::new()));

    // Connect to the session D-Bus (matching the C code's L_DBUS_SESSION_BUS)
    let conn = Builder::session()
        .map_err(MeshTestError::DBus)?
        .build()
        .await
        .map_err(MeshTestError::DBus)?;

    // Register application interfaces
    let mut client_app = make_client_app();
    let server_app_data = make_server_app();
    register_app(&conn, &client_app, &state, true).await?;
    register_app(&conn, &server_app_data, &state, false).await?;

    // Run the startup chain and tests, or handle signals
    let mut server_app = server_app_data;
    let status = tokio::select! {
        result = async {
            // Run startup chain
            if let Err(e) = run_startup_chain(&conn, &mut client_app, &mut server_app, &state).await {
                error!("Startup chain failed: {e}");
                return 1;
            }

            // Run tests
            let (passed, failed) = run_tests(&conn, &state).await;

            // Print summary
            println!("\n=== Test Summary ===");
            println!("Total: {}  Passed: {}  Failed: {}", passed + failed, passed, failed);

            if failed > 0 { 1 } else { 0 }
        } => result,
        _ = sigint.recv() => {
            info!("Received SIGINT, shutting down");
            1
        },
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down");
            1
        },
    };

    // Kill the mesh daemon child process
    info!("Killing mesh daemon child process");
    let _ = child.kill().await;

    // Clean up test directory
    let _ = std::fs::remove_dir_all(&test_dir);

    if status != 0 {
        std::process::exit(status);
    }

    Ok(())
}
