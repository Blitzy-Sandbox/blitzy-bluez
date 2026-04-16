// SPDX-License-Identifier: GPL-2.0-or-later
//
// Criterion benchmarks for bluez_shared::gatt::db operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use bluez_shared::gatt::db::GattDb;
use bluez_shared::uuid::Uuid;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn bench_gatt_db_add_service(c: &mut Criterion) {
    let rt = rt();

    c.bench_function("gatt_db_add_100_services", |b| {
        b.iter(|| {
            rt.block_on(async {
                let db = GattDb::new();
                for i in 0u16..100 {
                    let uuid = Uuid::from_u16(0x1800 + i);
                    black_box(db.add_service(uuid, true, 4).await);
                }
                black_box(&db);
            });
        });
    });
}

fn bench_gatt_db_find_by_handle(c: &mut Criterion) {
    let rt = rt();

    // Pre-populate a database with 100 services, each with a characteristic
    let db = rt.block_on(async {
        let db = GattDb::new();
        for i in 0u16..100 {
            let uuid = Uuid::from_u16(0x1800 + i);
            let svc = db.add_service(uuid, true, 4).await.unwrap();
            db.set_service_active(svc, true).await;
            db.service_add_characteristic(
                svc,
                Uuid::from_u16(0x2A00 + i),
                0x01,
                0x02,
                &[i as u8],
            )
            .await;
        }
        db
    });

    c.bench_function("gatt_db_find_by_handle", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Look up attributes spread across the handle space
                for handle in [1u16, 50, 100, 200, 300, 399] {
                    black_box(db.get_attribute(handle).await);
                }
            });
        });
    });
}

fn bench_gatt_db_find_by_uuid(c: &mut Criterion) {
    let rt = rt();

    // Pre-populate a database
    let db = rt.block_on(async {
        let db = GattDb::new();
        for i in 0u16..100 {
            let uuid = Uuid::from_u16(0x1800 + i);
            let svc = db.add_service(uuid, true, 4).await.unwrap();
            db.set_service_active(svc, true).await;
            db.service_add_characteristic(
                svc,
                Uuid::from_u16(0x2A00 + i),
                0x01,
                0x02,
                &[i as u8],
            )
            .await;
        }
        db
    });

    c.bench_function("gatt_db_find_by_uuid", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Search by UUID across the full handle range
                let uuid = Uuid::from_u16(0x2A32); // characteristic in the middle
                black_box(db.read_by_type(0x0001, 0xFFFF, uuid).await);
            });
        });
    });
}

criterion_group!(
    benches,
    bench_gatt_db_add_service,
    bench_gatt_db_find_by_handle,
    bench_gatt_db_find_by_uuid
);
criterion_main!(benches);
