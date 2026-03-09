#!/bin/bash
set -e
echo "Building BlueZ Rust release..."
RUSTFLAGS="-D warnings" cargo build --workspace --release

echo ""
echo "Release binaries:"
for bin in bluetoothd bluetoothctl bluetooth-meshd obexd btmon \
           mgmt-tester l2cap-tester sco-tester iso-tester \
           bnep-tester smp-tester gap-tester userchan-tester \
           hci-tester rfcomm-tester; do
    if [ -f "target/release/$bin" ]; then
        SIZE=$(du -h "target/release/$bin" | cut -f1)
        printf "  %-24s %s\n" "$bin" "$SIZE"
    fi
done

echo ""
echo "Build complete."
