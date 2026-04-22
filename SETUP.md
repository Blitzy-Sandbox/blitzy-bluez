# Blitzy Bluetooth — Setup Guide

Drop-in replacement for the system BlueZ `bluetoothd` daemon, rewritten in Rust.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **OS** | Ubuntu 22.04 or 24.04 (other systemd-based distros should also work) |
| **Rust** | Stable toolchain via [rustup](https://rustup.rs): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| **System packages** | `sudo apt install -y build-essential pkg-config libdbus-1-dev libudev-dev libasound2-dev` |
| **Bluetooth adapter** | Physical USB or built-in Bluetooth adapter (`hciconfig` should list `hci0`) |
| **Kernel module** | `btusb` loaded — verify with `lsmod \| grep btusb`; load with `sudo modprobe btusb` if missing |

---

## Build & Install

```bash
bash scripts/install.sh
```

The script performs the following steps:

1. Builds `bluetoothd` in release mode (`cargo build --release -p bluetoothd`).
2. Installs the binary to `/usr/local/lib/bluetooth/bluetoothd`.
3. Installs a D-Bus policy to `/etc/dbus-1/system.d/blitzy-bluetooth.conf` allowing root ownership and bluetooth-group access.
4. Installs a systemd service to `/etc/systemd/system/blitzy-bluetooth.service`.
5. Reloads systemd, stops/disables the stock `bluetooth` service, and enables/starts `blitzy-bluetooth`.
6. Adds the current user to the `bluetooth` group if not already a member.

> **Important:** Log out and log back in after the first install so group membership takes effect.

---

## Verify

After installation, confirm the daemon is running and your adapter is visible:

```bash
# Service status
systemctl status blitzy-bluetooth

# D-Bus object tree — should show /org/bluez/hci0
busctl tree org.bluez

# Adapter info
bluetoothctl show

# Discover nearby devices
bluetoothctl scan on
```

Expected output from `busctl tree org.bluez`:

```
└─ /org/bluez
   └─ /org/bluez/hci0
```

---

## Connect a Device

1. Launch the interactive CLI:
   ```bash
   bluetoothctl
   ```

2. Start scanning:
   ```
   [bluetooth]# scan on
   ```

3. Wait for your device MAC address to appear (e.g., `AA:BB:CC:DD:EE:FF`).

4. Pair with the device:
   ```
   [bluetooth]# pair AA:BB:CC:DD:EE:FF
   ```

5. Connect:
   ```
   [bluetooth]# connect AA:BB:CC:DD:EE:FF
   ```

6. Trust the device (for automatic reconnection):
   ```
   [bluetooth]# trust AA:BB:CC:DD:EE:FF
   ```

7. Stop scanning and exit:
   ```
   [bluetooth]# scan off
   [bluetooth]# exit
   ```

---

## Uninstall

```bash
bash scripts/uninstall.sh
```

The script stops and disables `blitzy-bluetooth`, removes the installed binary, D-Bus policy, and systemd service, then re-enables and starts the stock `bluetooth` service.

---

## Troubleshooting

### D-Bus permission denied

**Symptom:** `bluetoothctl` or PipeWire reports permission errors connecting to `org.bluez`.

**Fix:**
1. Verify the policy file exists: `ls -l /etc/dbus-1/system.d/blitzy-bluetooth.conf`
2. Verify your user is in the `bluetooth` group: `groups`
3. If you just ran `install.sh`, log out and back in for group membership to take effect.
4. Reload the D-Bus daemon: `sudo systemctl reload dbus`

### Adapter not found

**Symptom:** `busctl tree org.bluez` shows only `/org/bluez` with no `hci0` child.

**Fix:**
1. Check the hardware: `hciconfig` or `lsusb | grep -i bluetooth`
2. Verify the kernel module: `lsmod | grep btusb` — if empty, load it: `sudo modprobe btusb`
3. Check the daemon logs: `journalctl -u blitzy-bluetooth -e --no-pager`

### Audio not routing after connect

**Symptom:** Bluetooth headphones connect but PulseAudio/PipeWire does not show the card.

**Fix:**
1. Verify the Bluetooth card is registered: `pactl list cards short`
2. If missing, restart PipeWire: `systemctl --user restart pipewire pipewire-pulse`
3. PipeWire requires an active BlueZ socket — ensure `blitzy-bluetooth` is running: `systemctl is-active blitzy-bluetooth`
4. Check PipeWire logs: `journalctl --user -u pipewire -e --no-pager`
