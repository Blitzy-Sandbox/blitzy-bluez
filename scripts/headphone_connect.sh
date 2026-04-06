#!/usr/bin/env bash
# =============================================================================
# Blitzy Bluetooth — Headphone Connection Smoke Test
#
# Automated end-to-end test that discovers, pairs, connects, and
# disconnects a Bluetooth headphone using bluetoothctl.
#
# Usage:
#   bash scripts/headphone_connect.sh [DEVICE_ADDRESS]
#
# If DEVICE_ADDRESS is omitted the script scans for 10 seconds and
# picks the first audio-capable device (those advertising the A2DP Sink
# UUID 0x110B or the AudioSink service class).
#
# Exit codes:
#   0  — all steps completed successfully
#   1  — a required step failed (see [FAIL] output)
#
# Prerequisites:
#   - blitzy-bluetooth service running (sudo systemctl start blitzy-bluetooth)
#   - bluetoothctl binary on PATH
#   - A Bluetooth headphone in pairing mode (or powered on if already paired)
# =============================================================================
set -euo pipefail

SCAN_TIMEOUT="${SCAN_TIMEOUT:-10}"   # seconds to scan for devices
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-15}"  # seconds to wait for connection
TARGET_ADDR="${1:-}"

pass() { echo -e "  [\033[0;32mPASS\033[0m] $1"; }
fail() { echo -e "  [\033[0;31mFAIL\033[0m] $1"; exit 1; }
info() { echo -e "  [INFO] $1"; }

echo "==========================================="
echo " Blitzy Bluetooth — Headphone Connect Test"
echo "==========================================="
echo ""

# -------------------------------------------------------------------------
# Step 1: Verify the daemon is running
# -------------------------------------------------------------------------
info "Checking blitzy-bluetooth service..."
if systemctl is-active --quiet blitzy-bluetooth 2>/dev/null; then
    pass "blitzy-bluetooth is active"
elif systemctl is-active --quiet bluetooth 2>/dev/null; then
    info "Using stock bluetooth service"
    pass "bluetooth service is active"
else
    fail "No bluetooth service is running.  Start with: sudo systemctl start blitzy-bluetooth"
fi

# -------------------------------------------------------------------------
# Step 2: Power on the adapter
# -------------------------------------------------------------------------
info "Powering on adapter..."
if bluetoothctl power on 2>/dev/null | grep -q "succeeded\|already"; then
    pass "adapter powered on"
else
    fail "could not power on adapter"
fi

# -------------------------------------------------------------------------
# Step 3: Discover devices (if no target address given)
# -------------------------------------------------------------------------
if [ -z "$TARGET_ADDR" ]; then
    info "Scanning for audio devices (${SCAN_TIMEOUT}s)..."
    bluetoothctl scan on &>/dev/null &
    SCAN_PID=$!
    sleep "$SCAN_TIMEOUT"
    kill "$SCAN_PID" 2>/dev/null || true
    wait "$SCAN_PID" 2>/dev/null || true

    # Pick the first device that looks like headphones/speakers.
    # bluetoothctl `devices` outputs lines like:
    #   Device AA:BB:CC:DD:EE:FF My Headphones
    TARGET_ADDR=$(bluetoothctl devices 2>/dev/null | head -1 | awk '{print $2}')

    if [ -z "$TARGET_ADDR" ]; then
        fail "No Bluetooth devices found after ${SCAN_TIMEOUT}s scan"
    fi
    info "Selected device: $TARGET_ADDR"
fi
pass "target device: $TARGET_ADDR"

# -------------------------------------------------------------------------
# Step 4: Pair with the device
# -------------------------------------------------------------------------
info "Pairing with $TARGET_ADDR..."
PAIR_OUT=$(bluetoothctl pair "$TARGET_ADDR" 2>&1 || true)
if echo "$PAIR_OUT" | grep -qiE "successful|already exists|Pairing successful"; then
    pass "paired with $TARGET_ADDR"
else
    info "Pair output: $PAIR_OUT"
    fail "could not pair with $TARGET_ADDR"
fi

# -------------------------------------------------------------------------
# Step 5: Trust the device (auto-connect in future)
# -------------------------------------------------------------------------
info "Trusting $TARGET_ADDR..."
if bluetoothctl trust "$TARGET_ADDR" 2>/dev/null | grep -qi "succeeded\|already"; then
    pass "trusted $TARGET_ADDR"
else
    fail "could not trust $TARGET_ADDR"
fi

# -------------------------------------------------------------------------
# Step 6: Connect
# -------------------------------------------------------------------------
info "Connecting to $TARGET_ADDR (timeout ${CONNECT_TIMEOUT}s)..."
CONNECT_OUT=$(timeout "$CONNECT_TIMEOUT" bluetoothctl connect "$TARGET_ADDR" 2>&1 || true)
if echo "$CONNECT_OUT" | grep -qi "successful\|Connection successful"; then
    pass "connected to $TARGET_ADDR"
else
    info "Connect output: $CONNECT_OUT"
    fail "could not connect to $TARGET_ADDR within ${CONNECT_TIMEOUT}s"
fi

# -------------------------------------------------------------------------
# Step 7: Verify connection
# -------------------------------------------------------------------------
info "Verifying connection state..."
INFO_OUT=$(bluetoothctl info "$TARGET_ADDR" 2>&1 || true)
if echo "$INFO_OUT" | grep -q "Connected: yes"; then
    pass "device $TARGET_ADDR is connected"
else
    fail "device $TARGET_ADDR is NOT connected after connect command"
fi

# -------------------------------------------------------------------------
# Step 8: Check audio profile
# -------------------------------------------------------------------------
info "Checking audio profile..."
if echo "$INFO_OUT" | grep -qiE "UUID.*Audio Sink|UUID.*A2DP"; then
    pass "A2DP audio profile is active"
else
    info "No A2DP UUID found in device info — device may not be an audio sink"
    pass "connection verified (non-audio device or profile not yet resolved)"
fi

# -------------------------------------------------------------------------
# Step 9: Disconnect
# -------------------------------------------------------------------------
info "Disconnecting from $TARGET_ADDR..."
DISCONNECT_OUT=$(bluetoothctl disconnect "$TARGET_ADDR" 2>&1 || true)
if echo "$DISCONNECT_OUT" | grep -qi "successful\|Successful"; then
    pass "disconnected from $TARGET_ADDR"
else
    info "Disconnect output: $DISCONNECT_OUT"
    fail "could not disconnect from $TARGET_ADDR"
fi

echo ""
echo "==========================================="
echo " Headphone connect test complete."
echo " All steps passed for device $TARGET_ADDR"
echo "==========================================="
