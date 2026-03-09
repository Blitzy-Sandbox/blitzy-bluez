#!/bin/bash
# Run all criterion benchmarks and report results
set -e
echo "=== BlueZ Rust Benchmark Suite ==="
echo "Running crypto benchmarks..."
cargo bench -p bluez-shared --bench crypto_bench
echo "Running GATT benchmarks..."
cargo bench -p bluez-shared --bench gatt_bench
echo "Running IovBuf benchmarks..."
cargo bench -p bluez-shared --bench iov_bench
echo "=== Benchmark results saved to target/criterion/ ==="
