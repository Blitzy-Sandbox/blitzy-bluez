#!/usr/bin/env bash
# =============================================================================
# Blitzy Bluetooth — Uninstall Script
#
# Stops and disables the Blitzy bluetooth service, removes installed files,
# then re-enables and starts the system bluetooth service.
#
# Idempotent — safe to run even if partially or never installed.
# =============================================================================
set -euo pipefail

BINARY_DST="/usr/local/lib/bluetooth/bluetoothd"
DBUS_POLICY_DST="/etc/dbus-1/system.d/blitzy-bluetooth.conf"
SYSTEMD_DST="/etc/systemd/system/blitzy-bluetooth.service"
SERVICE_NAME="blitzy-bluetooth"
SYSTEM_SERVICE="bluetooth"

pass() { echo -e "  [\033[0;32mPASS\033[0m] $1"; }
fail() { echo -e "  [\033[0;31mFAIL\033[0m] $1"; exit 1; }
info() { echo -e "  [INFO] $1"; }

echo "==========================================="
echo " Blitzy Bluetooth — Uninstall"
echo "==========================================="
echo ""

# -------------------------------------------------------------------------
# Step 1: Stop and disable blitzy-bluetooth
# -------------------------------------------------------------------------
info "Stopping and disabling $SERVICE_NAME..."
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    sudo systemctl stop "$SERVICE_NAME" || true
fi
if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    sudo systemctl disable "$SERVICE_NAME" || true
fi
pass "stop & disable $SERVICE_NAME"

# -------------------------------------------------------------------------
# Step 2: Remove installed binary
# -------------------------------------------------------------------------
info "Removing $BINARY_DST..."
if [ -f "$BINARY_DST" ]; then
    sudo rm -f "$BINARY_DST"
    pass "removed $BINARY_DST"
else
    info "$BINARY_DST not found, skipping."
fi

# Remove the parent directory if empty.
BINARY_DIR="$(dirname "$BINARY_DST")"
if [ -d "$BINARY_DIR" ] && [ -z "$(ls -A "$BINARY_DIR")" ]; then
    sudo rmdir "$BINARY_DIR" 2>/dev/null || true
fi

# -------------------------------------------------------------------------
# Step 3: Remove D-Bus policy
# -------------------------------------------------------------------------
info "Removing $DBUS_POLICY_DST..."
if [ -f "$DBUS_POLICY_DST" ]; then
    sudo rm -f "$DBUS_POLICY_DST"
    pass "removed $DBUS_POLICY_DST"
else
    info "$DBUS_POLICY_DST not found, skipping."
fi

# -------------------------------------------------------------------------
# Step 4: Remove systemd service
# -------------------------------------------------------------------------
info "Removing $SYSTEMD_DST..."
if [ -f "$SYSTEMD_DST" ]; then
    sudo rm -f "$SYSTEMD_DST"
    pass "removed $SYSTEMD_DST"
else
    info "$SYSTEMD_DST not found, skipping."
fi

# -------------------------------------------------------------------------
# Step 5: Reload systemd
# -------------------------------------------------------------------------
info "Reloading systemd daemon..."
if sudo systemctl daemon-reload; then
    pass "systemctl daemon-reload"
else
    fail "systemctl daemon-reload"
fi

# -------------------------------------------------------------------------
# Step 6: Re-enable and start system bluetooth service
# -------------------------------------------------------------------------
info "Re-enabling and starting system $SYSTEM_SERVICE service..."
if systemctl list-unit-files "$SYSTEM_SERVICE.service" --no-pager 2>/dev/null | grep -q "$SYSTEM_SERVICE"; then
    sudo systemctl enable "$SYSTEM_SERVICE" 2>/dev/null || true
    sudo systemctl start "$SYSTEM_SERVICE" 2>/dev/null || true
    pass "enable & start $SYSTEM_SERVICE"
else
    info "System $SYSTEM_SERVICE service not found — nothing to re-enable."
fi

echo ""
echo "==========================================="
echo " Uninstall complete."
echo ""
echo " Verify with:"
echo "   bluetoothctl show"
echo "==========================================="
