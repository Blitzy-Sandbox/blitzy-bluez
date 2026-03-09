// SPDX-License-Identifier: GPL-2.0-or-later
//
// End-to-end integration tests exercising cross-crate interactions.
// Corresponds to Verification Plan items 1 (smoke test) and 3 (mgmt-tester).

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Test 1: Emulator lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_emulator_lifecycle() {
    // Create an HciEmu instance, verify it initializes, tear down cleanly.
    let emu = bluez_emulator::hciemu::HciEmu::new(
        bluez_emulator::hciemu::HciEmuType::BredrLe,
    );

    // Verify the emulator has a client
    assert!(emu.get_client(0).is_some(), "first client must exist");
    assert!(emu.get_client(1).is_none(), "second client must not exist");

    // Verify we can get a formatted address
    let addr = emu.get_address();
    assert_eq!(addr.len(), 17, "address must be XX:XX:XX:XX:XX:XX");
    assert_eq!(
        addr.chars().filter(|c| *c == ':').count(),
        5,
        "address must contain 5 colons"
    );

    // Verify VHCI access
    let vhci = emu.get_vhci();
    assert!(!vhci.is_paused());

    // Drop emu — should tear down cleanly without panic
    drop(emu);
}

// ---------------------------------------------------------------------------
// Test 2: BtDev command/response
// ---------------------------------------------------------------------------

#[test]
fn test_btdev_command_response() {
    use bluez_emulator::btdev::{BtDev, BtDevType};

    let dev = BtDev::create(BtDevType::BredrLe, 0);
    let pkts: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

    let pkts_clone = pkts.clone();
    dev.set_send_handler(Box::new(move |data| {
        pkts_clone.lock().unwrap().push(data.to_vec());
    }));

    // Send HCI Reset command: H4_CMD(0x01) | opcode LE16(0x0c03) | param_len(0)
    let reset_cmd: Vec<u8> = vec![0x01, 0x03, 0x0c, 0x00];
    dev.receive_h4(&reset_cmd);

    let captured = pkts.lock().unwrap();
    assert!(!captured.is_empty(), "should receive at least one event");

    let pkt = &captured[0];
    // H4 event indicator
    assert_eq!(pkt[0], 0x04, "first byte must be H4 event type");
    // Command Complete event code
    assert_eq!(pkt[1], 0x0e, "event code must be Command Complete (0x0e)");
    // Status byte (after ncmd + opcode): pkt[6] for H4(1)+evt(1)+len(1)+ncmd(1)+opcode(2)
    assert_eq!(pkt[6], 0x00, "status must be success (0x00)");
}

// ---------------------------------------------------------------------------
// Test 3: BdAddr round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_shared_addr_round_trip() {
    use bluez_shared::addr::BdAddr;

    let original_str = "AA:BB:CC:DD:EE:FF";
    let addr: BdAddr = original_str.parse().unwrap();

    // Serialize to string
    let serialized = addr.to_string();
    assert_eq!(serialized, original_str);

    // Deserialize back
    let roundtripped: BdAddr = serialized.parse().unwrap();
    assert_eq!(roundtripped, addr);

    // Verify wire bytes are little-endian
    assert_eq!(addr.as_bytes(), &[0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]);

    // Verify OUI extraction
    assert_eq!(addr.oui(), "AA:BB:CC");

    // Verify swap
    let swapped = addr.swap();
    assert_eq!(swapped.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
}

// ---------------------------------------------------------------------------
// Test 4: UUID constants
// ---------------------------------------------------------------------------

#[test]
fn test_shared_uuid_constants() {
    use bluez_shared::uuid::{self, Uuid};

    // GAP UUID = 0x1800 per Bluetooth SIG
    let gap: Uuid = uuid::GAP_UUID.parse().unwrap();
    assert_eq!(gap, Uuid::Uuid16(0x1800));

    // GATT UUID = 0x1801
    let gatt: Uuid = uuid::GATT_UUID.parse().unwrap();
    assert_eq!(gatt, Uuid::Uuid16(0x1801));

    // Heart Rate UUID = 0x180D
    let hr: Uuid = uuid::HEART_RATE_UUID.parse().unwrap();
    assert_eq!(hr, Uuid::Uuid16(0x180D));

    // Battery Service UUID = 0x180F
    let battery: Uuid = uuid::BATTERY_UUID.parse().unwrap();
    assert_eq!(battery, Uuid::Uuid16(0x180F));

    // SPP UUID = 0x1101
    let spp: Uuid = uuid::SPP_UUID.parse().unwrap();
    assert_eq!(spp, Uuid::Uuid16(0x1101));

    // A2DP Source UUID = 0x110A
    let a2dp_src: Uuid = uuid::A2DP_SOURCE_UUID.parse().unwrap();
    assert_eq!(a2dp_src, Uuid::Uuid16(0x110A));

    // GATT Primary Service attribute type UUID (16-bit constant)
    assert_eq!(uuid::GATT_PRIM_SVC_UUID, 0x2800);
    assert_eq!(uuid::GATT_CHARAC_UUID, 0x2803);

    // Verify UUID16 → UUID128 expansion matches Bluetooth Base UUID
    let gap128 = gap.to_uuid128();
    let expected: [u8; 16] = [
        0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
    ];
    assert_eq!(gap128, expected);
}

// ---------------------------------------------------------------------------
// Test 5: Crypto SMP functions
// ---------------------------------------------------------------------------

#[test]
fn test_crypto_smp_functions() {
    use bluez_shared::crypto;

    // Test e() — AES-128 ECB with Bluetooth byte-order
    let key = [0u8; 16];
    let plaintext = [0u8; 16];
    let mut encrypted = [0u8; 16];
    assert!(crypto::bt_crypto_e(&key, &plaintext, &mut encrypted));
    // e(0, 0) should be deterministic and non-zero
    let mut encrypted2 = [0u8; 16];
    assert!(crypto::bt_crypto_e(&key, &plaintext, &mut encrypted2));
    assert_eq!(encrypted, encrypted2, "e() must be deterministic");

    // Test ah() — random address hash
    let k = [0u8; 16];
    let r = [0x01, 0x02, 0x03];
    let mut hash = [0u8; 3];
    assert!(crypto::bt_crypto_ah(&k, &r, &mut hash));
    // Deterministic: same inputs → same hash
    let mut hash2 = [0u8; 3];
    assert!(crypto::bt_crypto_ah(&k, &r, &mut hash2));
    assert_eq!(hash, hash2);

    // Test c1() — legacy pairing confirm value
    let c1_k = [0u8; 16];
    let c1_r = [0u8; 16];
    let pres = [0x01; 7];
    let preq = [0x02; 7];
    let ia = [0x03; 6];
    let ra = [0x04; 6];
    let mut c1_res = [0u8; 16];
    assert!(crypto::bt_crypto_c1(
        &c1_k, &c1_r, &pres, &preq, 0x00, &ia, 0x01, &ra, &mut c1_res
    ));
    // Verify deterministic
    let mut c1_res2 = [0u8; 16];
    assert!(crypto::bt_crypto_c1(
        &c1_k, &c1_r, &pres, &preq, 0x00, &ia, 0x01, &ra, &mut c1_res2
    ));
    assert_eq!(c1_res, c1_res2);

    // Test s1() — legacy pairing key generation
    let r1 = [0xAA; 16];
    let r2 = [0xBB; 16];
    let mut s1_res = [0u8; 16];
    assert!(crypto::bt_crypto_s1(&c1_k, &r1, &r2, &mut s1_res));
    let mut s1_res2 = [0u8; 16];
    assert!(crypto::bt_crypto_s1(&c1_k, &r1, &r2, &mut s1_res2));
    assert_eq!(s1_res, s1_res2);
}

// ---------------------------------------------------------------------------
// Test 6: GATT DB service hierarchy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_gatt_db_service_hierarchy() {
    use bluez_shared::gatt::db::GattDb;
    use bluez_shared::uuid::Uuid;

    let db = GattDb::new();

    // Add a primary service: Battery Service (0x180F) with 6 handles
    // (1 service decl + 1 char decl + 1 char value + 1 descriptor + 2 spare)
    let svc_handle = db
        .add_service(Uuid::from_u16(0x180F), true, 6)
        .await
        .expect("add_service must succeed");
    assert_eq!(svc_handle, 1, "first service starts at handle 1");

    // Add a characteristic: Battery Level (0x2A19), read + notify
    let char_handle = db
        .service_add_characteristic(
            svc_handle,
            Uuid::from_u16(0x2A19),
            0x01, // read permission
            0x02 | 0x10, // read + notify properties
            &[100], // initial value: 100%
        )
        .await
        .expect("add_characteristic must succeed");
    // Value handle = declaration handle + 1
    assert!(char_handle > svc_handle);

    // Add a CCC descriptor
    let desc_handle = db
        .service_add_ccc(svc_handle, 0x01)
        .await
        .expect("add_ccc must succeed");
    assert!(desc_handle > char_handle);

    // Verify handle lookup
    let attr = db.get_attribute(char_handle).await;
    assert!(attr.is_some(), "characteristic value must be findable");
    let attr = attr.unwrap();
    assert_eq!(attr.uuid, Uuid::from_u16(0x2A19));

    // Verify service lookup
    let svc = db.get_service(svc_handle).await;
    assert!(svc.is_some());
    let svc = svc.unwrap();
    assert!(svc.primary);
    assert_eq!(svc.uuid, Uuid::from_u16(0x180F));
    // Service should contain the declaration + characteristic + descriptor attributes
    assert!(
        svc.attributes.len() >= 3,
        "service must have at least 3 attributes (svc decl + char decl + char value), got {}",
        svc.attributes.len()
    );
}

// ---------------------------------------------------------------------------
// Test 7: IovBuf protocol encoding
// ---------------------------------------------------------------------------

#[test]
fn test_iov_buf_protocol_encoding() {
    use bluez_shared::util::IovBuf;

    // Encode an HCI command: opcode(u16 LE) + param_len(u8) + params
    let opcode: u16 = 0x0c03; // HCI Reset
    let mut buf = IovBuf::new();
    buf.push_le16(opcode);
    buf.push_u8(0x00); // no parameters

    assert_eq!(buf.len(), 3);
    assert_eq!(buf.as_slice(), &[0x03, 0x0c, 0x00]);

    // Decode it back
    let mut reader = IovBuf::from_slice(buf.as_slice());
    let decoded_opcode = reader.pull_le16().expect("pull_le16 must succeed");
    let decoded_param_len = reader.pull_u8().expect("pull_u8 must succeed");
    assert_eq!(decoded_opcode, opcode);
    assert_eq!(decoded_param_len, 0x00);
    assert_eq!(reader.remaining(), 0);

    // Test a more complex encoding: LE Set Advertising Data command
    let adv_opcode: u16 = 0x2008;
    let adv_data = [0x02, 0x01, 0x06, 0x03, 0x03, 0x0F, 0x18]; // flags + battery svc
    let mut cmd = IovBuf::new();
    cmd.push_le16(adv_opcode);
    cmd.push_u8(adv_data.len() as u8);
    cmd.push_mem(&adv_data);

    let mut reader = IovBuf::from_slice(cmd.as_slice());
    assert_eq!(reader.pull_le16().unwrap(), adv_opcode);
    let plen = reader.pull_u8().unwrap() as usize;
    assert_eq!(plen, adv_data.len());
    let params = reader.pull_mem(plen).unwrap();
    assert_eq!(params, &adv_data);
    assert_eq!(reader.remaining(), 0);
}

// ---------------------------------------------------------------------------
// Test 8: BTSnoop write/read
// ---------------------------------------------------------------------------

#[test]
fn test_btsnoop_write_read() {
    use bluez_shared::btsnoop::{
        BtSnoopReader, BtSnoopWriter, BTSNOOP_FLAG_CMD_EVT, BTSNOOP_FLAG_RECV,
        BTSNOOP_FLAG_SENT, BTSNOOP_TYPE_HCI_UART,
    };

    let mut output = Vec::new();

    // Write packets
    {
        let mut writer =
            BtSnoopWriter::new(&mut output, BTSNOOP_TYPE_HCI_UART).unwrap();

        // Packet 1: sent command
        let cmd_data = vec![0x01, 0x03, 0x0c, 0x00]; // HCI Reset
        writer
            .write_packet(&cmd_data, cmd_data.len() as u32, BTSNOOP_FLAG_SENT | BTSNOOP_FLAG_CMD_EVT, 0, 1000000)
            .unwrap();

        // Packet 2: received event
        let evt_data = vec![0x04, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00]; // Command Complete
        writer
            .write_packet(&evt_data, evt_data.len() as u32, BTSNOOP_FLAG_RECV | BTSNOOP_FLAG_CMD_EVT, 0, 2000000)
            .unwrap();

        writer.flush().unwrap();
    }

    // Read packets back
    let cursor = Cursor::new(&output);
    let mut reader = BtSnoopReader::new(cursor).unwrap();
    assert_eq!(reader.datalink_type, BTSNOOP_TYPE_HCI_UART);

    let pkt1 = reader.read_packet().unwrap().expect("packet 1 must exist");
    assert_eq!(pkt1.data, vec![0x01, 0x03, 0x0c, 0x00]);
    assert_eq!(pkt1.flags, BTSNOOP_FLAG_SENT | BTSNOOP_FLAG_CMD_EVT);
    assert_eq!(pkt1.timestamp, 1000000);
    assert_eq!(pkt1.original_len, 4);

    let pkt2 = reader.read_packet().unwrap().expect("packet 2 must exist");
    assert_eq!(pkt2.data, vec![0x04, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00]);
    assert_eq!(pkt2.flags, BTSNOOP_FLAG_RECV | BTSNOOP_FLAG_CMD_EVT);
    assert_eq!(pkt2.timestamp, 2000000);

    // No more packets
    assert!(reader.read_packet().unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Test 9: Config parse default
// ---------------------------------------------------------------------------

#[test]
fn test_config_parse_default() {
    use bluetoothd_lib::config::BtdConfig;

    let cfg = BtdConfig::default();

    // Verify key defaults from the C main.conf
    assert_eq!(cfg.name, "BlueZ");
    assert_eq!(cfg.class, 0x000000);
    assert!(cfg.pairable);
    assert_eq!(cfg.discovto, 180);
    assert_eq!(cfg.tmpto, 30);
    assert!(cfg.reverse_discovery);
    assert!(cfg.name_resolv);
    assert!(!cfg.debug_keys);
    assert!(!cfg.fast_conn);
    assert!(cfg.refresh_discovery);
    assert!(!cfg.experimental);
    assert!(!cfg.testing);
    assert!(cfg.filter_discoverable);
    assert_eq!(cfg.mode, bluetoothd_lib::config::BtMode::Dual);
    assert_eq!(cfg.gatt_cache, bluetoothd_lib::config::GattCache::Always);
    assert_eq!(cfg.gatt_mtu, 517); // BT_ATT_MAX_LE_MTU
    assert_eq!(cfg.gatt_channels, 1);
    assert!(cfg.gatt_client);
    assert_eq!(cfg.secure_conn, bluetoothd_lib::config::ScMode::On);
    assert_eq!(cfg.mps, bluetoothd_lib::config::MpsMode::Off);
    assert_eq!(cfg.jw_repairing, bluetoothd_lib::config::JwRepairing::Never);
    assert_eq!(cfg.did_source, 0x0002);
    assert_eq!(cfg.did_vendor, 0x1d6b);
    assert_eq!(cfg.did_product, 0x0246);
    assert_eq!(cfg.did_version, 0x0500);
}

// ---------------------------------------------------------------------------
// Test 10: Storage round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_storage_round_trip() {
    use bluetoothd_lib::storage::Storage;

    let tmp_dir = std::env::temp_dir().join("bluez-test-storage");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let storage = Storage::with_base(&tmp_dir, "00:11:22:33:44:55");

    // Write device info
    let device_addr = "AA:BB:CC:DD:EE:FF";
    let info_path = storage.device_info_path(device_addr);

    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut general = HashMap::new();
    general.insert("Name".to_string(), "TestDevice".to_string());
    general.insert("Alias".to_string(), "MyDevice".to_string());
    general.insert("Class".to_string(), "0x000104".to_string());
    general.insert("Paired".to_string(), "true".to_string());
    general.insert("Trusted".to_string(), "false".to_string());
    sections.insert("General".to_string(), general);

    let mut link_key = HashMap::new();
    link_key.insert("Key".to_string(), "AABBCCDD11223344AABBCCDD11223344".to_string());
    link_key.insert("Type".to_string(), "4".to_string());
    link_key.insert("PINLength".to_string(), "0".to_string());
    sections.insert("LinkKey".to_string(), link_key);

    Storage::write_info_file(&info_path, &sections).unwrap();

    // Read it back
    let loaded = Storage::read_info_file(&info_path).unwrap();

    let gen = loaded.get("General").expect("General section must exist");
    assert_eq!(gen.get("Name").unwrap(), "TestDevice");
    assert_eq!(gen.get("Alias").unwrap(), "MyDevice");
    assert_eq!(gen.get("Class").unwrap(), "0x000104");
    assert_eq!(gen.get("Paired").unwrap(), "true");
    assert_eq!(gen.get("Trusted").unwrap(), "false");

    let lk = loaded.get("LinkKey").expect("LinkKey section must exist");
    assert_eq!(lk.get("Key").unwrap(), "AABBCCDD11223344AABBCCDD11223344");
    assert_eq!(lk.get("Type").unwrap(), "4");
    assert_eq!(lk.get("PINLength").unwrap(), "0");

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ---------------------------------------------------------------------------
// Test 11: Plugin registration
// ---------------------------------------------------------------------------

#[test]
fn test_plugin_registration() {
    use bluetoothd_lib::plugin;

    // Force reference to the plugins module so inventory registrations fire.
    // The plugins are registered via inventory::submit! in each plugin module.
    // Referencing public items ensures the linker pulls in the modules.
    let _ = bluetoothd_lib::plugins::admin::ADMIN_POLICY_SET_INTERFACE;
    let _ = bluetoothd_lib::plugins::autopair::WII_IDS;

    // Initialize all plugins
    plugin::plugin_init(None, None);

    // Cleanup
    plugin::plugin_cleanup();
}

// ---------------------------------------------------------------------------
// Test 12: SDP service search
// ---------------------------------------------------------------------------

#[test]
fn test_sdp_service_search() {
    use bluetoothd_lib::sdpd::{SdpRecord, SdpServer};

    let mut server = SdpServer::new();
    assert!(server.start().is_ok());

    // Register SPP record
    let spp = SdpRecord {
        handle: 0,
        service_class_uuids: vec![0x1101],
        profile_descriptors: vec![(0x1101, 0x0100)],
        name: "Serial Port".to_string(),
        description: "SPP".to_string(),
        provider: "BlueZ".to_string(),
        attrs: HashMap::new(),
    };
    let spp_handle = server.register_record(spp);

    // Register OPP record
    let opp = SdpRecord {
        handle: 0,
        service_class_uuids: vec![0x1105],
        profile_descriptors: vec![(0x1105, 0x0100)],
        name: "Object Push".to_string(),
        description: "OPP".to_string(),
        provider: "BlueZ".to_string(),
        attrs: HashMap::new(),
    };
    let opp_handle = server.register_record(opp);

    // Register A2DP record with multiple UUIDs
    let a2dp = SdpRecord {
        handle: 0,
        service_class_uuids: vec![0x110A, 0x110D], // Source + Advanced Audio
        profile_descriptors: vec![(0x110D, 0x0103)],
        name: "Audio Source".to_string(),
        description: "A2DP".to_string(),
        provider: "BlueZ".to_string(),
        attrs: HashMap::new(),
    };
    let _a2dp_handle = server.register_record(a2dp);

    assert_eq!(server.record_count(), 3);

    // Search for SPP (0x1101)
    let results = server.search(0x1101);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Serial Port");

    // Search for Advanced Audio (0x110D) — should match A2DP
    let results = server.search(0x110D);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Audio Source");

    // Search for non-existent UUID
    let results = server.search(0xFFFF);
    assert!(results.is_empty());

    // Unregister SPP and verify
    assert!(server.unregister_record(spp_handle));
    assert_eq!(server.record_count(), 2);
    assert!(server.search(0x1101).is_empty());

    // OPP should still be searchable
    let opp_result = server.get_record(opp_handle);
    assert!(opp_result.is_some());
    assert_eq!(opp_result.unwrap().name, "Object Push");

    server.stop();
}

// ---------------------------------------------------------------------------
// Test 13: Mesh node provisioning flow
// ---------------------------------------------------------------------------

#[test]
fn test_mesh_node_provisioning_flow() {
    use bluetooth_meshd_lib::node::{MeshElement, MeshNode, NodeState};

    // Create an unprovisioned node with 2 elements
    let mut node = MeshNode::new(2);
    assert_eq!(node.state, NodeState::Unprovisioned);
    assert_eq!(node.unicast_addr, 0);

    // Add elements
    let elem0 = MeshElement::new(0, 0x0100); // Main element
    let elem1 = MeshElement::new(1, 0x0101); // Secondary element
    assert!(node.add_element(elem0).is_ok());
    assert!(node.add_element(elem1).is_ok());

    // Out-of-range element should fail
    let elem_bad = MeshElement::new(5, 0x0000);
    assert!(node.add_element(elem_bad).is_err());

    // Transition: Unprovisioned → Provisioning
    node.set_state(NodeState::Provisioning);
    assert_eq!(node.state, NodeState::Provisioning);

    // Simulate provisioning: assign address and device key
    node.set_unicast_addr(0x0100);
    let dev_key = [0xAA; 16];
    node.set_device_key(dev_key);

    // Transition: Provisioning → Provisioned
    node.set_state(NodeState::Provisioned);
    assert_eq!(node.state, NodeState::Provisioned);
    assert_eq!(node.unicast_addr, 0x0100);
    assert_eq!(node.device_key, dev_key);

    // Bind application keys
    node.bind_app_key(0);
    node.bind_app_key(1);
    assert_eq!(node.app_keys.len(), 2);

    // Duplicate bind should not add another entry
    node.bind_app_key(0);
    assert_eq!(node.app_keys.len(), 2);

    // Set TTL
    assert!(node.set_ttl(7).is_ok());
    assert!(node.set_ttl(1).is_err()); // TTL=1 is reserved
    assert!(node.set_ttl(128).is_err()); // TTL > 127

    // Transition: Provisioned → Configured
    node.set_state(NodeState::Configured);
    assert_eq!(node.state, NodeState::Configured);

    // Sequence number increments
    assert_eq!(node.next_sequence(), 0);
    assert_eq!(node.next_sequence(), 1);
    assert_eq!(node.current_sequence(), 2);

    // Verify element access
    assert!(node.get_element(0).is_some());
    assert!(node.get_element(1).is_some());
    assert!(node.get_element(2).is_none());

    // Unbind a key
    node.unbind_app_key(0);
    assert_eq!(node.app_keys.len(), 1);
}

// ---------------------------------------------------------------------------
// Test 14: OBEX packet encode/decode
// ---------------------------------------------------------------------------

#[test]
fn test_obex_packet_encode_decode() {
    use obexd_lib::gobex::{HeaderId, ObexHeader, ObexOpcode, ObexPacket};

    // Build a Connect packet with headers
    let mut pkt = ObexPacket::new(ObexOpcode::Connect, true);

    // Add a Target header (byte sequence)
    let target_uuid = vec![
        0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2,
        0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09,
    ];
    pkt.add_header(ObexHeader::new(HeaderId::Target, target_uuid.clone()));

    // Add a ConnectionId header (4-byte value)
    pkt.add_header(ObexHeader::new(
        HeaderId::ConnectionId,
        vec![0x00, 0x00, 0x00, 0x01],
    ));

    // Encode
    let encoded = pkt.encode();

    // Verify basic structure
    assert!(encoded.len() >= 3, "packet must be at least 3 bytes");
    // Opcode byte: Connect (0x80) with final bit set → 0x80
    assert_eq!(encoded[0], 0x80);
    // Length should match
    let pkt_len = u16::from_be_bytes([encoded[1], encoded[2]]) as usize;
    assert_eq!(pkt_len, encoded.len());

    // Decode
    let decoded = ObexPacket::decode(&encoded).expect("decode must succeed");
    assert!(decoded.final_bit);
    assert_eq!(decoded.headers.len(), 2);

    // Verify Target header
    assert_eq!(decoded.headers[0].id, HeaderId::Target);
    assert_eq!(decoded.headers[0].data, target_uuid);

    // Verify ConnectionId header
    assert_eq!(decoded.headers[1].id, HeaderId::ConnectionId);
    assert_eq!(decoded.headers[1].data, vec![0x00, 0x00, 0x00, 0x01]);
}
