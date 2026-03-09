// SPDX-License-Identifier: GPL-2.0-or-later
//
// Criterion benchmarks for bluez_shared::crypto operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use bluez_shared::crypto;

fn bench_aes_cmac(c: &mut Criterion) {
    let key = [0x2bu8; 16];
    let plaintext = [0x6bu8; 16];

    c.bench_function("aes_cmac (bt_crypto_e)", |b| {
        b.iter(|| {
            let mut out = [0u8; 16];
            crypto::bt_crypto_e(black_box(&key), black_box(&plaintext), &mut out);
            black_box(out);
        });
    });
}

fn bench_smp_c1(c: &mut Criterion) {
    let k = [0x01u8; 16];
    let r = [0x02u8; 16];
    let pres = [0x03u8; 7];
    let preq = [0x04u8; 7];
    let ia = [0x05u8; 6];
    let ra = [0x06u8; 6];

    c.bench_function("smp_c1", |b| {
        b.iter(|| {
            let mut res = [0u8; 16];
            crypto::bt_crypto_c1(
                black_box(&k),
                black_box(&r),
                black_box(&pres),
                black_box(&preq),
                0,
                black_box(&ia),
                1,
                black_box(&ra),
                &mut res,
            );
            black_box(res);
        });
    });
}

fn bench_smp_s1(c: &mut Criterion) {
    let k = [0x01u8; 16];
    let r1 = [0x02u8; 16];
    let r2 = [0x03u8; 16];

    c.bench_function("smp_s1", |b| {
        b.iter(|| {
            let mut res = [0u8; 16];
            crypto::bt_crypto_s1(black_box(&k), black_box(&r1), black_box(&r2), &mut res);
            black_box(res);
        });
    });
}

fn bench_crypto_ah(c: &mut Criterion) {
    let k = [0xAAu8; 16];
    let r = [0xBBu8; 3];

    c.bench_function("crypto_ah", |b| {
        b.iter(|| {
            let mut hash = [0u8; 3];
            crypto::bt_crypto_ah(black_box(&k), black_box(&r), &mut hash);
            black_box(hash);
        });
    });
}

criterion_group!(benches, bench_aes_cmac, bench_smp_c1, bench_smp_s1, bench_crypto_ah);
criterion_main!(benches);
