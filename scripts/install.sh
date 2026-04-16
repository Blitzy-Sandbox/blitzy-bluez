#!/bin/bash
set -e
PREFIX="${PREFIX:-/usr}"
LIBEXECDIR="${LIBEXECDIR:-$PREFIX/libexec/bluetooth}"
DBUSCONFDIR="${DBUSCONFDIR:-/etc/dbus-1/system.d}"
SYSTEMDDIR="${SYSTEMDDIR:-/usr/lib/systemd/system}"

echo "Installing BlueZ Rust to $PREFIX..."

# Build release
cargo build --workspace --release

# Install binaries
install -d "$LIBEXECDIR"
install -m 755 target/release/bluetoothd "$LIBEXECDIR/"
install -m 755 target/release/bluetooth-meshd "$LIBEXECDIR/"
install -m 755 target/release/obexd "$LIBEXECDIR/"
install -d "$PREFIX/bin"
install -m 755 target/release/bluetoothctl "$PREFIX/bin/"
install -m 755 target/release/btmon "$PREFIX/bin/"

# Install tester tools
for tool in mgmt-tester l2cap-tester sco-tester iso-tester bnep-tester smp-tester gap-tester userchan-tester hci-tester rfcomm-tester; do
    install -m 755 "target/release/$tool" "$PREFIX/bin/" 2>/dev/null || true
done

# Install D-Bus config
install -d "$DBUSCONFDIR"
install -m 644 scripts/dbus/org.bluez.conf "$DBUSCONFDIR/"
install -m 644 scripts/dbus/org.bluez.mesh.conf "$DBUSCONFDIR/" 2>/dev/null || true
install -m 644 scripts/dbus/org.bluez.obex.conf "$DBUSCONFDIR/" 2>/dev/null || true

# Install systemd units
install -d "$SYSTEMDDIR"
install -m 644 scripts/systemd/bluetooth.service "$SYSTEMDDIR/"
install -m 644 scripts/systemd/bluetooth-mesh.service "$SYSTEMDDIR/"
install -m 644 scripts/systemd/obex.service "$SYSTEMDDIR/"

echo "Installation complete."
echo "Run 'systemctl daemon-reload && systemctl restart bluetooth' to start."
