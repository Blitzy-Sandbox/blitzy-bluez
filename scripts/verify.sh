#!/bin/bash
# BlueZ Rust Rewrite — Full Verification Suite
# Runs all verification plan checks
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
warn() { echo -e "${YELLOW}WARN${NC}: $1"; }

echo "==========================================="
echo " BlueZ Rust Rewrite — Verification Suite"
echo "==========================================="
echo ""

# 1. Build check (release mode, warnings as errors)
echo "--- Gate 1: Release Build ---"
if RUSTFLAGS="-D warnings" cargo build --workspace --release 2>&1; then
    pass "Release build clean"
else
    fail "Release build failed"
fi
echo ""

# 2. Clippy
echo "--- Gate 2: Clippy ---"
if RUSTFLAGS="-D warnings" cargo clippy --workspace -- -D clippy::all 2>&1; then
    pass "Clippy clean"
else
    fail "Clippy found issues"
fi
echo ""

# 3. Tests
echo "--- Gate 3: Test Suite ---"
TEST_OUTPUT=$(cargo test --workspace 2>&1)
FAILURES=$(echo "$TEST_OUTPUT" | grep "FAILED" | wc -l | tr -d ' ')
PASSED=$(echo "$TEST_OUTPUT" | grep -oE '[0-9]+ passed' | awk '{sum += $1} END {print sum+0}')
if [ "$FAILURES" -eq "0" ]; then
    pass "All tests passed ($PASSED total)"
else
    fail "$FAILURES test suites failed"
fi
echo ""

# 4. Unsafe audit
echo "--- Gate 4: Unsafe Audit ---"
UNSAFE_COUNT=$(grep -rn "unsafe {" crates/ --include="*.rs" 2>/dev/null | wc -l | tr -d ' ')
if [ "$UNSAFE_COUNT" -eq "0" ]; then
    pass "Zero unsafe blocks"
else
    warn "$UNSAFE_COUNT unsafe blocks found — review scripts/unsafe_audit.sh output"
fi
echo ""

# 5. Workspace structure check
echo "--- Gate 5: Workspace Structure ---"
EXPECTED_CRATES="bluez-shared bluez-emulator btmon bluetoothd bluetoothctl bluez-tools bluetooth-meshd obexd"
ALL_FOUND=true
for crate in $EXPECTED_CRATES; do
    if [ -d "crates/$crate" ]; then
        true
    else
        echo "  Missing: crates/$crate"
        ALL_FOUND=false
    fi
done
if $ALL_FOUND; then
    pass "All 8 crates present"
else
    fail "Missing crates"
fi
echo ""

# 6. Line count
echo "--- Gate 6: Codebase Metrics ---"
FILE_COUNT=$(find crates -name "*.rs" | wc -l | tr -d ' ')
LOC=$(find crates -name "*.rs" -exec cat {} + | wc -l | tr -d ' ')
echo "  Files: $FILE_COUNT"
echo "  Lines of Rust: $LOC"
pass "Metrics collected"
echo ""

# 7. Binary check
echo "--- Gate 7: Binary Targets ---"
BINARIES="bluetoothd bluetoothctl bluetooth-meshd obexd btmon mgmt-tester l2cap-tester"
for bin in $BINARIES; do
    if [ -f "target/release/$bin" ]; then
        SIZE=$(du -h "target/release/$bin" | cut -f1)
        echo "  $bin: $SIZE"
    else
        warn "$bin not found in target/release/"
    fi
done
echo ""

echo "==========================================="
echo " Verification Complete"
echo "==========================================="
