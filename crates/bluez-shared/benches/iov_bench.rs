// SPDX-License-Identifier: GPL-2.0-or-later
//
// Criterion benchmarks for bluez_shared::util::IovBuf operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use bluez_shared::util::IovBuf;

fn bench_iov_push_le(c: &mut Criterion) {
    c.bench_function("iov_push_le_1000", |b| {
        b.iter(|| {
            let mut buf = IovBuf::with_capacity(8000);
            for i in 0u32..1000 {
                buf.push_le32(black_box(i));
            }
            black_box(buf.len());
        });
    });
}

fn bench_iov_pull_le(c: &mut Criterion) {
    // Pre-build a buffer with 1000 LE u32 values
    let mut source = IovBuf::with_capacity(4000);
    for i in 0u32..1000 {
        source.push_le32(i);
    }
    let data = source.as_slice().to_vec();

    c.bench_function("iov_pull_le_1000", |b| {
        b.iter(|| {
            let mut buf = IovBuf::from_slice(black_box(&data));
            let mut sum = 0u32;
            for _ in 0..1000 {
                sum = sum.wrapping_add(buf.pull_le32().unwrap());
            }
            black_box(sum);
        });
    });
}

fn bench_iov_extend(c: &mut Criterion) {
    let chunk = [0xAAu8; 64];

    c.bench_function("iov_extend_64B_x100", |b| {
        b.iter(|| {
            let mut buf = IovBuf::with_capacity(6400);
            for _ in 0..100 {
                buf.push_mem(black_box(&chunk));
            }
            black_box(buf.len());
        });
    });
}

criterion_group!(benches, bench_iov_push_le, bench_iov_pull_le, bench_iov_extend);
criterion_main!(benches);
