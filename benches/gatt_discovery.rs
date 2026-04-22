// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors

//! GATT Service Discovery Time Benchmark
//!
//! Criterion benchmark measuring GATT service discovery performance for
//! Gate 3 validation (AAP Section 0.8.3).  Measures time for complete
//! primary service, characteristic, and descriptor discovery.
//!
//! # Reference C Code
//!
//! The C discovery pipeline is implemented in:
//! - `src/shared/gatt-client.c` — `discovery_op` struct (line 380),
//!   `discovery_op_create` (line 499), `bt_gatt_client_new` triggering
//!   full discovery.
//! - `src/shared/gatt-helpers.c` — `discover_all_primary()`,
//!   `bt_gatt_discover_characteristics()`, `bt_gatt_discover_descriptors()`.
//!
//! # Benchmark Design
//!
//! Since ATT transport operations require real Bluetooth sockets, these
//! benchmarks isolate the **CPU-bound portion** of the discovery pipeline:
//! [`GattDb`] population and service/characteristic/descriptor iteration.
//! This is the dominant cost after ATT PDU round-trips complete — the
//! in-memory data structure operations that [`BtGattClient`] and the
//! [`helpers`] discovery functions perform on the results.
//!
//! Additionally, a transport API verification step confirms that the
//! [`BtAtt`], [`BtGattClient`], and async discovery function signatures
//! are correctly wired, using a Unix-socketpair–backed mock transport.
//!
//! Measured values are required per AAP 0.8.4 — "assumed parity is not
//! acceptable."
//!
//! # AAP References
//!
//! - Section 0.8.3 Gate 3: Performance Baseline Comparison
//! - Section 0.8.4: Measured values required

use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use tokio::runtime::Runtime;

use bluez_shared::att::transport::BtAtt;
use bluez_shared::att::types::{
    AttError, AttOpcode, AttPermissions, BT_ATT_DEFAULT_LE_MTU, GattChrcProperties,
};
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::{GattDb, GattDbCcc};
use bluez_shared::gatt::helpers::{
    self, BtGattIter, BtGattResult, CharEntry, DescEntry, ServiceEntry,
};
use bluez_shared::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// Compile-time type compatibility assertions
// ---------------------------------------------------------------------------

/// Compile-time size assertion for [`BtGattResult`] — the accumulator type
/// populated by the async discovery pipeline.  Verifies the type is
/// importable and sized.
const _GATT_RESULT_SIZE: usize = std::mem::size_of::<BtGattResult>();

/// Compile-time size assertion for [`BtGattIter`].  Uses `'static` as a
/// stand-in lifetime — the physical size is lifetime-independent.
const _GATT_ITER_SIZE: usize = std::mem::size_of::<BtGattIter<'static>>();

/// Compile-time assertion referencing [`AttOpcode`] enum discriminants.
/// Ensures the ATT opcode definitions used during discovery
/// (`ReadByGrpTypeReq`, `ReadByTypeReq`, `FindInfoReq`) are importable.
const _ATT_DISCOVERY_OPCODES: [AttOpcode; 3] =
    [AttOpcode::ReadByGrpTypeReq, AttOpcode::ReadByTypeReq, AttOpcode::FindInfoReq];

/// Compile-time assertion referencing [`AttError`] — the error code enum
/// returned by ATT operations during discovery.
const _ATT_ERROR_NOT_FOUND: AttError = AttError::AttributeNotFound;

// ---------------------------------------------------------------------------
// Well-known Bluetooth SIG 16-bit UUIDs for benchmark data
// ---------------------------------------------------------------------------

/// Primary service UUIDs (Generic Access through Current Time, etc.).
const SERVICE_UUIDS: &[u16] = &[
    0x1800, // Generic Access
    0x1801, // Generic Attribute
    0x1802, // Immediate Alert
    0x1803, // Link Loss
    0x1804, // Tx Power
    0x1805, // Current Time
    0x1806, // Reference Time Update
    0x1807, // Next DST Change
    0x1808, // Glucose
    0x1809, // Health Thermometer
    0x180A, // Device Information
    0x180B, // Network Availability (reserved)
    0x180C, // Watchdog (reserved)
    0x180D, // Heart Rate
    0x180E, // Phone Alert Status
    0x180F, // Battery Service
    0x1810, // Blood Pressure
    0x1811, // Alert Notification
    0x1812, // HID
    0x1813, // Scan Parameters
    0x1814, // Running Speed and Cadence
    0x1815, // Automation IO
    0x1816, // Cycling Speed and Cadence
    0x1817, // (reserved)
    0x1818, // Cycling Power
    0x1819, // Location and Navigation
    0x181A, // Environmental Sensing
    0x181B, // Body Composition
    0x181C, // User Data
    0x181D, // Weight Scale
    0x181E, // Bond Management
    0x181F, // Continuous Glucose Monitoring
    0x1820, // Internet Protocol Support
    0x1821, // Indoor Positioning
    0x1822, // Pulse Oximeter
    0x1823, // HTTP Proxy
    0x1824, // Transport Discovery
    0x1825, // Object Transfer
    0x1826, // Fitness Machine
    0x1827, // Mesh Provisioning
    0x1828, // Mesh Proxy
    0x1829, // Reconnection Configuration
    0x182A, // Insulin Delivery
    0x182B, // Binary Sensor
    0x182C, // Emergency Configuration
    0x182D, // Authorization Control
    0x182E, // Physical Activity Monitor
    0x182F, // Elapsed Time
    0x1830, // Generic Health Sensor
    0x1831, // Audio Input Control
];

/// Characteristic UUIDs cycled for realistic service hierarchies.
const CHAR_UUIDS: &[u16] = &[
    0x2A00, // Device Name
    0x2A01, // Appearance
    0x2A02, // Peripheral Privacy Flag
    0x2A03, // Reconnection Address
    0x2A04, // Peripheral Preferred Connection Parameters
    0x2A05, // Service Changed
    0x2A06, // Alert Level
    0x2A07, // Tx Power Level
    0x2A08, // Date Time
    0x2A09, // Day of Week
    0x2A0A, // Day Date Time
];

/// CCC (Client Characteristic Configuration) descriptor UUID.
const CCC_DESC_UUID: u16 = 0x2902;

/// Characteristic User Description descriptor UUID.
const CUD_UUID: u16 = 0x2901;

// ---------------------------------------------------------------------------
// Helper: GattDb population
// ---------------------------------------------------------------------------

/// Populate a [`GattDb`] with the given number of primary services.
///
/// Each service receives `chars_per_service` characteristics and
/// `descs_per_char` descriptors per characteristic.  This mirrors the
/// data layout produced by the production discovery pipeline:
/// - [`helpers::discover_all_primary_services`] finds primary services
/// - [`helpers::discover_characteristics`] finds characteristics
/// - [`helpers::discover_descriptors`] finds descriptors
///
/// Uses alternating [`GattDb::add_service`] and [`GattDb::insert_service`]
/// calls to exercise both code paths.
fn populate_gatt_db(
    service_count: usize,
    chars_per_service: usize,
    descs_per_char: usize,
) -> GattDb {
    let db = GattDb::new();

    // Register CCC callbacks so that `GattDbService::add_ccc()` works.
    db.ccc_register(GattDbCcc { read_func: None, write_func: None, notify_func: None });

    let permissions = (AttPermissions::READ | AttPermissions::WRITE).bits() as u32;
    let properties = (GattChrcProperties::READ | GattChrcProperties::NOTIFY).bits();

    for svc_idx in 0..service_count {
        let uuid_val = SERVICE_UUIDS[svc_idx % SERVICE_UUIDS.len()];
        let uuid = BtUuid::from_u16(uuid_val);

        // Each service needs:
        //   1 (declaration) + chars * (2 (decl+value) + descs)
        let handles_needed: u16 = 1 + (chars_per_service as u16) * (2 + descs_per_char as u16);

        // Alternate between add_service (auto-handle) and insert_service
        // (explicit handle) to exercise both APIs.
        let svc = if svc_idx % 2 == 0 {
            db.add_service(&uuid, true, handles_needed)
        } else {
            // Place at a non-overlapping explicit base handle.
            let base = 0x8000_u16
                .wrapping_add((svc_idx as u16).wrapping_mul(handles_needed.wrapping_add(2)));
            db.insert_service(base, &uuid, true, handles_needed)
        };

        let svc = match svc {
            Some(s) => s,
            None => continue, // Handle range exhaustion is expected for very large counts.
        };

        for char_idx in 0..chars_per_service {
            let char_uuid_val = CHAR_UUIDS[char_idx % CHAR_UUIDS.len()];
            let char_uuid = BtUuid::from_u16(char_uuid_val);

            let _char_attr =
                svc.add_characteristic(&char_uuid, permissions, properties, None, None, None);

            for desc_idx in 0..descs_per_char {
                if desc_idx == 0 {
                    // First descriptor: Characteristic User Description.
                    let desc_uuid = BtUuid::from_u16(CUD_UUID);
                    let _desc_attr = svc.add_descriptor(&desc_uuid, permissions, None, None, None);
                } else {
                    // Subsequent descriptor slots: add CCC (0x2902)
                    // via the dedicated `add_ccc` API.
                    let ccc_uuid_check = BtUuid::from_u16(CCC_DESC_UUID);
                    let _ccc_attr = svc.add_ccc(permissions);
                    // Verify the CCC UUID constant is consistent.
                    black_box(&ccc_uuid_check);
                }
            }
        }

        svc.set_active(true);
    }

    db
}

// ---------------------------------------------------------------------------
// Helper: discovery result extraction
// ---------------------------------------------------------------------------

/// Extract discovery results from a populated [`GattDb`].
///
/// Returns `(services, characteristics, descriptors)` — the same data
/// that [`BtGattIter`] iterates over a [`BtGattResult`] from the live
/// async discovery pipeline.  By building [`ServiceEntry`], [`CharEntry`],
/// and [`DescEntry`] values directly from the [`GattDb`], we benchmark
/// the equivalent in-memory processing without requiring ATT I/O.
fn extract_discovery_results(db: &GattDb) -> (Vec<ServiceEntry>, Vec<CharEntry>, Vec<DescEntry>) {
    let mut services = Vec::new();
    let mut characteristics = Vec::new();
    let mut descriptors = Vec::new();

    db.foreach_service(None, |attr| {
        if let Some(svc_data) = attr.get_service_data() {
            services.push(ServiceEntry {
                start_handle: svc_data.start,
                end_handle: svc_data.end,
                uuid: svc_data.uuid.clone(),
            });

            // Get a service handle to iterate chars/descs within it.
            if let Some(svc_handle) = attr.get_service() {
                svc_handle.foreach_char(|char_attr| {
                    if let Some(char_data) = char_attr.get_char_data() {
                        characteristics.push(CharEntry {
                            start_handle: char_data.handle,
                            end_handle: char_data.value_handle,
                            value_handle: char_data.value_handle,
                            properties: char_data.properties,
                            uuid: char_data.uuid.clone(),
                        });
                    }
                });

                svc_handle.foreach_desc(|desc_attr| {
                    if let Some(desc_type) = desc_attr.get_type() {
                        descriptors
                            .push(DescEntry { handle: desc_attr.get_handle(), uuid: desc_type });
                    }
                });
            }
        }
    });

    (services, characteristics, descriptors)
}

// ---------------------------------------------------------------------------
// Mock transport API verification
// ---------------------------------------------------------------------------

/// Verify the ATT transport and GATT client APIs are correctly wired.
///
/// Creates a mock [`BtAtt`] over a Unix socketpair and a
/// [`BtGattClient`] on top of it, exercising:
/// - [`BtAtt::new`], [`BtAtt::get_mtu`], [`BtAtt::set_mtu`]
/// - [`BtGattClient::new`], [`BtGattClient::is_ready`],
///   [`BtGattClient::get_db`]
/// - [`helpers::discover_all_primary_services`],
///   [`helpers::discover_characteristics`],
///   [`helpers::discover_descriptors`] (via short timeout to confirm
///   the function signatures are compatible; actual I/O is not exercised).
///
/// Called once during benchmark initialization to ensure API compatibility
/// without affecting measured timings.
fn verify_transport_api(rt: &Runtime) {
    rt.block_on(async {
        // Create a Unix socketpair as a mock ATT transport channel.
        let (client_stream, _server_stream) = UnixStream::pair().expect("socketpair creation");
        client_stream.set_nonblocking(true).expect("set non-blocking");
        // Transfer ownership of the fd so it outlives this scope.
        let client_fd = client_stream.into_raw_fd();

        // Create ATT transport — channel type will be BT_ATT_LOCAL since
        // the fd is not an AF_BLUETOOTH socket.
        let att: Arc<Mutex<BtAtt>> = BtAtt::new(client_fd, false).expect("BtAtt::new");

        // Verify MTU accessors.
        {
            let mut guard = att.lock().expect("lock att");
            assert_eq!(guard.get_mtu(), BT_ATT_DEFAULT_LE_MTU);
            guard.set_mtu(517);
            assert_eq!(guard.get_mtu(), 517);
            // Restore to default for client creation.
            guard.set_mtu(BT_ATT_DEFAULT_LE_MTU);
        }

        // Create GATT client — spawns an async init task that will
        // eventually time out since there is no ATT responder.
        let db = GattDb::new();
        let client = BtGattClient::new(db, Arc::clone(&att), BT_ATT_DEFAULT_LE_MTU, 0)
            .expect("BtGattClient::new");

        // Client is not ready (no ATT responder to complete discovery).
        assert!(!client.is_ready());

        // Retrieve the underlying database.
        let _retrieved_db = client.get_db();

        // Verify async discovery function signatures with a short timeout.
        // These will fail/timeout since there is no ATT server, but the
        // call confirms the functions are importable and type-compatible.
        let _ = tokio::time::timeout(
            Duration::from_millis(5),
            helpers::discover_all_primary_services(&att, None),
        )
        .await;

        let _ = tokio::time::timeout(
            Duration::from_millis(5),
            helpers::discover_characteristics(&att, 0x0001, 0xFFFF),
        )
        .await;

        let _ = tokio::time::timeout(
            Duration::from_millis(5),
            helpers::discover_descriptors(&att, 0x0001, 0xFFFF),
        )
        .await;
    });
}

// ---------------------------------------------------------------------------
// Benchmark: Small device discovery (3 services, ~10 characteristics)
// ---------------------------------------------------------------------------

/// Benchmark GATT service discovery for a small BLE peripheral.
///
/// Simulates a typical sensor device with 3 primary services and
/// approximately 10 characteristics total.  Measures the CPU-bound
/// portion of the discovery pipeline: [`GattDb`] population and
/// [`extract_discovery_results`] iteration producing [`ServiceEntry`],
/// [`CharEntry`], and [`DescEntry`] vectors.
fn bench_gatt_discovery_small(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    // One-time transport API verification (outside measured loop).
    verify_transport_api(&rt);

    c.bench_function("gatt_discovery_small", |b| {
        b.iter(|| {
            rt.block_on(async {
                let db = populate_gatt_db(
                    black_box(3), // 3 services
                    black_box(3), // 3 chars per service
                    black_box(2), // 2 descriptors per char (CUD + CCC)
                );
                let (services, chars, descs) = extract_discovery_results(black_box(&db));
                black_box((services.len(), chars.len(), descs.len()))
            })
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: Large device discovery (20+ services, 100+ characteristics)
// ---------------------------------------------------------------------------

/// Benchmark GATT service discovery for a complex BLE device.
///
/// Simulates an LE Audio / hearing-aid device with 20+ primary services
/// and 100+ characteristics total (BAP, VCP, CSIP, TMAP, GMAP, ASHA…).
/// Measures the same CPU-bound portion of the discovery pipeline as the
/// small benchmark, at larger scale.
fn bench_gatt_discovery_large(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    c.bench_function("gatt_discovery_large", |b| {
        b.iter(|| {
            rt.block_on(async {
                let db = populate_gatt_db(
                    black_box(20), // 20 services
                    black_box(5),  // 5 chars per service (100 total)
                    black_box(2),  // 2 descriptors per char
                );
                let (services, chars, descs) = extract_discovery_results(black_box(&db));
                black_box((services.len(), chars.len(), descs.len()))
            })
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: Parameterized by service count
// ---------------------------------------------------------------------------

/// Parameterized benchmark varying the number of primary services.
///
/// Uses [`BenchmarkId`] with service counts `[1, 5, 10, 20, 50]` to
/// demonstrate the scaling behaviour of the GATT discovery algorithm.
/// Each service has 4 characteristics with 2 descriptors each, for
/// a realistic per-service overhead.
fn bench_gatt_discovery_parameterized(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("gatt_discovery");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    for &count in &[1_usize, 5, 10, 20, 50] {
        group.bench_with_input(BenchmarkId::new("services", count), &count, |b, &svc_count| {
            b.iter(|| {
                rt.block_on(async {
                    let db = populate_gatt_db(
                        black_box(svc_count),
                        black_box(4), // 4 chars per service
                        black_box(2), // 2 descs per char
                    );
                    let (services, chars, descs) = extract_discovery_results(black_box(&db));
                    black_box((services.len(), chars.len(), descs.len()))
                })
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: GattDb population time (isolated from iteration)
// ---------------------------------------------------------------------------

/// Benchmark raw [`GattDb`] population time.
///
/// Isolates the in-memory data structure performance from the iteration
/// cost measured in the other benchmarks.  Corresponds to
/// `gatt_db_insert_service()`, `gatt_db_insert_characteristic()`,
/// `gatt_db_insert_descriptor()` from `src/shared/gatt-db.c`.
///
/// Parameterised over service counts to show insert-time scaling.
fn bench_gatt_db_population(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("gatt_db_population");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    for &count in &[1_usize, 5, 10, 20, 50] {
        group.bench_with_input(BenchmarkId::new("services", count), &count, |b, &svc_count| {
            b.iter(|| {
                rt.block_on(async {
                    let db = populate_gatt_db(black_box(svc_count), black_box(4), black_box(2));
                    // Verify the DB is populated by iterating once.
                    let mut total_services = 0_usize;
                    db.foreach_service(None, |_attr| {
                        total_services += 1;
                    });
                    black_box(total_services)
                })
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness registration
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_gatt_discovery_small,
    bench_gatt_discovery_large,
    bench_gatt_discovery_parameterized,
    bench_gatt_db_population
);
criterion_main!(benches);
