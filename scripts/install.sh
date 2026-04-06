#!/usr/bin/env bash
# =============================================================================
# Blitzy Bluetooth — Install Script
#
# Builds the Rust bluetoothd daemon, installs the binary, D-Bus policy,
# and systemd service, then enables and starts the service.
#
# Idempotent — safe to run multiple times.
# Tested on Ubuntu 22.04 and 24.04.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY_SRC="$REPO_ROOT/target/release/bluetoothd"
BINARY_DST="/usr/local/lib/bluetooth/bluetoothd"
DBUS_POLICY_SRC="$REPO_ROOT/config/bluetooth.conf"
DBUS_POLICY_DST="/etc/dbus-1/system.d/blitzy-bluetooth.conf"
SYSTEMD_SRC="$REPO_ROOT/systemd/bluetooth.service"
SYSTEMD_DST="/etc/systemd/system/blitzy-bluetooth.service"
SERVICE_NAME="blitzy-bluetooth"
SYSTEM_SERVICE="bluetooth"

pass() { echo -e "  [\033[0;32mPASS\033[0m] $1"; }
fail() { echo -e "  [\033[0;31mFAIL\033[0m] $1"; exit 1; }
info() { echo -e "  [INFO] $1"; }

echo "==========================================="
echo " Blitzy Bluetooth — Installation"
echo "==========================================="
echo ""

# -------------------------------------------------------------------------
# Step 1: Build the release binary
# -------------------------------------------------------------------------
info "Building bluetoothd (release)..."
if (cd "$REPO_ROOT" && cargo build --release -p bluetoothd); then
    pass "cargo build --release -p bluetoothd"
else
    fail "cargo build --release -p bluetoothd"
fi

# -------------------------------------------------------------------------
# Step 2: Install binary
# -------------------------------------------------------------------------
info "Installing binary to $BINARY_DST..."
sudo mkdir -p "$(dirname "$BINARY_DST")"
if sudo install -m 755 "$BINARY_SRC" "$BINARY_DST"; then
    pass "install bluetoothd -> $BINARY_DST"
else
    fail "install bluetoothd -> $BINARY_DST"
fi

# -------------------------------------------------------------------------
# Step 3: Install D-Bus policy
# -------------------------------------------------------------------------
info "Installing D-Bus policy to $DBUS_POLICY_DST..."
# Generate a policy that allows root to own org.bluez AND the bluetooth
# group to send/receive, so non-root users (bluetoothctl, PipeWire,
# blueman) work without sudo.
DBUS_POLICY_CONTENT='<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>

  <!-- Allow root to own the org.bluez bus name -->
  <policy user="root">
    <allow own="org.bluez"/>
    <allow send_destination="org.bluez"/>
    <allow send_interface="org.bluez.Agent1"/>
    <allow send_interface="org.bluez.MediaEndpoint1"/>
    <allow send_interface="org.bluez.MediaPlayer1"/>
    <allow send_interface="org.bluez.Profile1"/>
    <allow send_interface="org.bluez.GattCharacteristic1"/>
    <allow send_interface="org.bluez.GattDescriptor1"/>
    <allow send_interface="org.bluez.LEAdvertisement1"/>
    <allow send_interface="org.bluez.AdvertisementMonitor1"/>
    <allow send_interface="org.bluez.BatteryProvider1"/>
    <allow send_interface="org.bluez.BatteryProviderManager1"/>
  </policy>

  <!-- Allow bluetooth group to interact with the daemon -->
  <policy group="bluetooth">
    <allow send_destination="org.bluez"/>
    <allow send_interface="org.freedesktop.DBus.ObjectManager"/>
    <allow send_interface="org.freedesktop.DBus.Properties"/>
  </policy>

  <!-- Allow anyone at_console to talk to BlueZ (for desktop sessions) -->
  <policy at_console="true">
    <allow send_destination="org.bluez"/>
  </policy>

  <!-- Deny everything else by default -->
  <policy context="default">
    <deny send_destination="org.bluez"/>
  </policy>

</busconfig>'

if echo "$DBUS_POLICY_CONTENT" | sudo tee "$DBUS_POLICY_DST" > /dev/null; then
    sudo chmod 644 "$DBUS_POLICY_DST"
    pass "install D-Bus policy -> $DBUS_POLICY_DST"
else
    fail "install D-Bus policy -> $DBUS_POLICY_DST"
fi

# -------------------------------------------------------------------------
# Step 4: Install systemd service
# -------------------------------------------------------------------------
info "Installing systemd service to $SYSTEMD_DST..."
if sudo install -m 644 "$SYSTEMD_SRC" "$SYSTEMD_DST"; then
    pass "install service -> $SYSTEMD_DST"
else
    fail "install service -> $SYSTEMD_DST"
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
# Step 6: Stop and disable system bluetooth service
# -------------------------------------------------------------------------
info "Stopping and disabling system bluetooth service..."
if systemctl is-active --quiet "$SYSTEM_SERVICE" 2>/dev/null; then
    sudo systemctl stop "$SYSTEM_SERVICE" || true
fi
if systemctl is-enabled --quiet "$SYSTEM_SERVICE" 2>/dev/null; then
    sudo systemctl disable "$SYSTEM_SERVICE" || true
fi

# Remove stale dbus-org.bluez.service alias symlink that systemd creates
# when the stock bluetooth.service is enabled.  If not removed, the
# subsequent `systemctl enable --now blitzy-bluetooth` fails with
# "Failed to enable unit: File /etc/systemd/system/dbus-org.bluez.service
# already exists".
STALE_ALIAS="/etc/systemd/system/dbus-org.bluez.service"
if [ -L "$STALE_ALIAS" ]; then
    info "Removing stale alias symlink $STALE_ALIAS..."
    sudo rm -f "$STALE_ALIAS"
    pass "remove stale alias symlink $STALE_ALIAS"
fi
pass "stop & disable $SYSTEM_SERVICE"

# -------------------------------------------------------------------------
# Step 7: Enable and start blitzy-bluetooth
# -------------------------------------------------------------------------
info "Enabling and starting $SERVICE_NAME..."
if sudo systemctl enable --now "$SERVICE_NAME"; then
    pass "enable --now $SERVICE_NAME"
else
    fail "enable --now $SERVICE_NAME"
fi

# -------------------------------------------------------------------------
# Step 8: Add current user to bluetooth group (if not already a member)
# -------------------------------------------------------------------------
CURRENT_USER="${SUDO_USER:-$USER}"
if id -nG "$CURRENT_USER" | grep -qw bluetooth; then
    info "User '$CURRENT_USER' is already in the bluetooth group."
else
    info "Adding user '$CURRENT_USER' to the bluetooth group..."
    # Ensure the bluetooth group exists (some minimal installs lack it).
    if ! getent group bluetooth > /dev/null 2>&1; then
        sudo groupadd bluetooth
    fi
    if sudo usermod -aG bluetooth "$CURRENT_USER"; then
        pass "usermod -aG bluetooth $CURRENT_USER"
        echo ""
        echo "  NOTE: Log out and log back in for group membership to take effect."
    else
        fail "usermod -aG bluetooth $CURRENT_USER"
    fi
fi

echo ""
echo "==========================================="
echo " Installation complete."
echo ""
echo " Verify with:"
echo "   systemctl status $SERVICE_NAME"
echo "   busctl tree org.bluez"
echo "   bluetoothctl show"
echo "==========================================="
