# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Refactoring Objective

Based on the prompt, the Blitzy platform understands that the refactoring objective is to perform a **complete language-level rewrite of BlueZ v5.86 from ANSI C to idiomatic Rust**, targeting the entire userspace Bluetooth protocol stack comprising 715 source files and approximately 522,547 lines of C code. This is not a partial modernization or incremental migration — it is a full tech-stack migration that replaces every C source file with an equivalent Rust implementation while preserving byte-identical external behavior at every interface boundary.

- **Refactoring type:** Tech stack migration (C → Rust)
- **Target repository:** New Cargo workspace within the same repository root — the Rust codebase is a standalone replacement, not a side-by-side coexistence
- **Behavioral fidelity mandate:** The Rust output MUST be a behavioral clone of the C original at every external interface boundary, verified through D-Bus introspection, HCI packet traces, and integration test suites

The following refactoring goals have been identified with enhanced clarity:

- **Replace all manual memory management** — Every `malloc`/`free`, GLib refcounting (`g_object_ref`/`g_object_unref`), and opaque struct pattern (`foo_new()`/`foo_free()`) must be replaced with Rust ownership semantics, `Box<T>`, `Vec<T>`, `Arc<T>`, and `impl Drop`
- **Eliminate the GLib/ELL event-loop dependency** — The `GMainLoop`, `g_io_add_watch`, `GIOChannel`, and ELL `l_main`/`l_io` event-driven I/O model must be replaced with `tokio::runtime` (multi-thread for `bluetoothd`, current-thread for `bluetooth-meshd`), `tokio::net`, `tokio::io`, `tokio::signal`, and `tokio::time`
- **Replace D-Bus stack** — The libdbus-1 + GLib `gdbus/` wrapper (6 files) and ELL `l_dbus` must be replaced with `zbus` 5.x using `#[zbus::interface]` proc macros, producing identical `org.bluez.*` interface contracts
- **Replace callback+user_data with idiomatic Rust** — All `callback_t fn + void *user_data` patterns must become `async fn`, `impl Fn` closures, or `tokio::sync::mpsc` channels
- **Replace plugin loading** — `BLUETOOTH_PLUGIN_DEFINE()` macro-based static registration must become `#[derive(inventory::collect)]` trait registration; `dlopen` external plugins must use `libloading::Library` + trait object cast
- **Consolidate 5 daemon binaries and shared infrastructure into 8 Cargo workspace crates** — Each binary maps to a specific crate, with two library crates (`bluez-shared`, `bluez-emulator`) providing shared foundations
- **Achieve zero `unsafe` outside designated FFI boundary modules** — All `unsafe` blocks must be confined to kernel socket creation, ioctl, uinput/uhid operations, and btsnoop parsing, with each site documented and tested

### 0.1.2 Technical Interpretation

This refactoring translates to the following technical transformation strategy:

**Current Architecture (C/GLib/ELL):**
- 5 independent binaries built via GNU Autotools with conditional compilation (`configure.ac`, `config.h`)
- Event-driven I/O via three interchangeable mainloop backends: GLib (`mainloop-glib.c`), ELL (`mainloop-ell.c`), and raw epoll (`mainloop.c`)
- D-Bus services via libdbus-1 wrapped by `gdbus/` (service side) and `l_dbus` (mesh daemon)
- Plugin architecture via linker-section descriptor tables and `dlopen`/`dlsym`
- Manual memory management with `malloc`/`free`, GLib containers (`GList`, `GSList`, `GHashTable`), and opaque struct lifecycle functions

**Target Architecture (Rust/tokio/zbus):**
- 8 Cargo workspace crates (6 binary, 2 library) built via `cargo build --workspace`
- Async I/O via `tokio::runtime` with `AsyncFd` for raw Bluetooth socket FDs
- D-Bus services via `zbus::Connection` + `#[zbus::interface]` proc macros with tokio backend
- Plugin architecture via `inventory` crate for built-in plugins and `libloading` for external `.so` plugins
- Rust ownership model with `Box`, `Vec`, `Arc`, `String`, and `impl Drop` replacing all manual allocation

**Implicit requirements surfaced from the specification:**
- The `AF_BLUETOOTH` socket family, `BTPROTO_*` constants, and kernel MGMT protocol structures defined in `lib/bluetooth/` must be re-declared in a `bluez-sys` FFI module — these are kernel ABI constants, not libbluetooth API
- The three mainloop backends (`mainloop-glib.c`, `mainloop-ell.c`, `mainloop.c`) collapse into a single `tokio::runtime` — no backend selection at compile time
- `GKeyFile` INI parsing in `src/main.c` for `main.conf` must be replaced with `rust-ini` preserving exact section/key semantics and default values
- The `src/shared/tester.c` GLib test harness used by `unit/test-*.c` must be replaced with Rust's built-in `#[test]` framework while preserving identical test coverage
- All 44 `unit/test-*.c` files must become `#[test]` functions achieving the same pass/fail matrix
- Configuration files (`main.conf`, `input.conf`, `network.conf`, `mesh-main.conf`) must parse identically — zero format changes
- Persistent storage format (`settings-storage.txt`) must be read/written identically for adapter and device state


## 0.2 Source Analysis

### 0.2.1 Comprehensive Source File Discovery

The BlueZ v5.86 C source repository contains 21 top-level directories with the following file distribution across all in-scope components:

**Core Daemon (`src/`)** — 57 files (.c/.h):
- `src/main.c`, `src/btd.h` — Daemon entry point, global configuration model (`struct btd_opts`)
- `src/adapter.c`, `src/adapter.h` — Controller abstraction, `org.bluez.Adapter1`, MGMT bring-up
- `src/device.c`, `src/device.h` — Peer device model, `org.bluez.Device1`, pairing/bonding
- `src/service.c`, `src/service.h` — Profile-instance state machine, dependency ordering
- `src/profile.c`, `src/profile.h` — Profile registry, `ProfileManager1`, SDP record generation
- `src/agent.c`, `src/agent.h` — `AgentManager1`, pairing/authorization prompts
- `src/plugin.c`, `src/plugin.h` — Plugin discovery, ordering, lifecycle (`BLUETOOTH_PLUGIN_DEFINE`)
- `src/advertising.c`, `src/advertising.h` — `LEAdvertisingManager1`, MGMT advertising
- `src/adv_monitor.c`, `src/adv_monitor.h` — `AdvertisementMonitorManager1`
- `src/battery.c`, `src/battery.h` — `Battery1`, `BatteryProviderManager1`
- `src/bearer.c`, `src/bearer.h` — `Bearer.BREDR1`/`Bearer.LE1`
- `src/set.c`, `src/set.h` — `DeviceSet1`, CSIP membership
- `src/gatt-database.c`, `src/gatt-database.h` — Local GATT DB, `GattManager1`
- `src/gatt-client.c`, `src/gatt-client.h` — Remote GATT export as D-Bus objects
- `src/settings.c`, `src/settings.h` — GATT DB persistence via `GKeyFile`
- `src/sdp-client.c`, `src/sdp-client.h` — Async SDP search helpers
- `src/sdp-xml.c`, `src/sdp-xml.h` — SDP record XML conversion
- `src/sdpd-server.c`, `src/sdpd-request.c`, `src/sdpd-database.c`, `src/sdpd-service.c`, `src/sdpd.h` — SDP daemon implementation
- `src/log.c`, `src/log.h` — Syslog + btmon logging
- `src/backtrace.c`, `src/backtrace.h` — Stack trace support
- `src/error.c`, `src/error.h` — D-Bus error reply mapping
- `src/dbus-common.c`, `src/dbus-common.h` — Dictionary helpers, connection cache
- `src/eir.c`, `src/eir.h` — EIR/AD blob parsing
- `src/storage.c`, `src/storage.h` — Legacy textfile persistence
- `src/textfile.c`, `src/textfile.h` — Key-value text file helpers
- `src/uuid-helper.c`, `src/uuid-helper.h` — UUID normalization
- `src/oui.c`, `src/oui.h` — Vendor OUI lookup
- `src/rfkill.c` — Radio-block state integration
- `src/bluetooth.conf` — D-Bus security policy
- `src/main.conf` — Default configuration template

**Shared Protocol Library (`src/shared/`)** — ~90 files (.c/.h):
- ATT/GATT: `att.c`, `att.h`, `att-types.h`, `gatt-db.c`, `gatt-db.h`, `gatt-client.c`, `gatt-client.h`, `gatt-server.c`, `gatt-server.h`, `gatt-helpers.c`, `gatt-helpers.h`
- Transport: `hci.c`, `hci.h`, `hci-crypto.c`, `hci-crypto.h`, `mgmt.c`, `mgmt.h`
- Event loop: `mainloop.c`, `mainloop.h`, `mainloop-glib.c`, `mainloop-ell.c`, `mainloop-notify.c`, `mainloop-notify.h`
- I/O: `io.h`, `io-mainloop.c`, `io-glib.c`, `io-ell.c`
- Timers: `timeout.h`, `timeout-mainloop.c`, `timeout-glib.c`, `timeout-ell.c`
- Containers: `queue.c`, `queue.h`, `ringbuf.c`, `ringbuf.h`
- Crypto: `crypto.c`, `crypto.h`, `ecc.c`, `ecc.h`
- LE Audio: `bap.c`, `bap.h`, `bap-defs.h`, `bap-debug.c`, `bap-debug.h`, `bass.c`, `bass.h`, `vcp.c`, `vcp.h`, `mcp.c`, `mcp.h`, `mcs.h`, `micp.c`, `micp.h`, `ccp.c`, `ccp.h`, `csip.c`, `csip.h`, `ascs.h`, `lc3.h`
- Profiles: `asha.c`, `asha.h`, `gap.c`, `gap.h`, `gmap.c`, `gmap.h`, `tmap.c`, `tmap.h`, `rap.c`, `rap.h`, `hfp.c`, `hfp.h`, `battery.c`, `battery.h`
- Utility: `util.c`, `util.h`, `ad.c`, `ad.h`, `btsnoop.c`, `btsnoop.h`, `pcap.c`, `pcap.h`, `log.c`, `log.h`, `shell.c`, `shell.h`, `tester.c`, `tester.h`, `btp.c`, `btp.h`, `uhid.c`, `uhid.h`, `uinput.c`, `uinput.h`, `tty.h`

**Profile Plugins (`profiles/`)** — ~60 files across 11 subdirectories:
- `profiles/audio/` — 37 files: A2DP, AVRCP, AVDTP, AVCTP, BAP, BASS, VCP, MICP, MCP, CCP, CSIP, TMAP, GMAP, ASHA, HFP, media, transport, player, telephony
- `profiles/battery/` — BAS client plugin
- `profiles/deviceinfo/` — DIS PnP ID reader
- `profiles/gap/` — GAP characteristic reader
- `profiles/iap/` — iAP helper daemon
- `profiles/input/` — HID host + HOGP, UHID integration, `input.conf`
- `profiles/midi/` — BLE-MIDI to ALSA bridge
- `profiles/network/` — PAN/BNEP implementation, `network.conf`
- `profiles/ranging/` — Experimental RAP/RAS plugin
- `profiles/scanparam/` — Scan Parameters client

**Daemon Plugins (`plugins/`)** — 6 files:
- `plugins/sixaxis.c` — PlayStation controller cable pairing
- `plugins/admin.c` — Admin policy allowlist
- `plugins/autopair.c` — Automatic PIN heuristics
- `plugins/hostname.c` — Hostname synchronization
- `plugins/neard.c` — NFC pairing bridge
- `plugins/policy.c` — Reconnection policy

**CLI Client (`client/`)** — 26 files:
- `client/main.c` — bluetoothctl entry point, D-Bus client, core commands
- Feature modules: `admin.c/h`, `adv_monitor.c/h`, `advertising.c/h`, `agent.c/h`, `assistant.c/h`, `gatt.c/h`, `hci.c/h`, `mgmt.c/h`, `player.c/h`, `telephony.c/h`
- UI utilities: `display.c/h`, `print.c/h`
- Subfolder: `client/btpclient/` — BTP client tooling

**Packet Monitor (`monitor/`)** — 50 files:
- Core: `main.c`, `control.c/h`, `packet.c/h`, `display.c/h`, `analyze.c/h`
- Protocol dissectors: `l2cap.c/h`, `att.c/h`, `sdp.c/h`, `rfcomm.c/h`, `bnep.c/h`, `avctp.c/h`, `avdtp.c/h`, `a2dp.c/h`, `ll.c/h`, `lmp.c/h`
- Vendor decoders: `intel.c/h`, `broadcom.c/h`, `msft.c/h`, `vendor.c/h`
- Backends: `hcidump.c/h`, `jlink.c/h`, `ellisys.c/h`, `hwdb.c/h`
- Utilities: `keys.c/h`, `crc.c/h`, `tty.h`, `bt.h`, `emulator.h`

**HCI Emulator (`emulator/`)** — 20 files:
- Core: `btdev.c/h`, `bthost.c/h`, `le.c/h`, `smp.c`
- Harness: `hciemu.c/h`, `vhci.c/h`, `server.c/h`, `serial.c/h`, `phy.c/h`
- Utilities: `main.c`, `b1ee.c`, `hfp.c`

**Mesh Daemon (`mesh/`)** — 56 files:
- Core: `main.c`, `mesh.c/h`, `node.c/h`, `model.c/h`, `net.c/h`, `net-keys.c/h`
- D-Bus: `dbus.c/h`, `bluetooth-mesh.conf`
- Security: `crypto.c/h`, `appkey.c/h`, `keyring.c/h`
- Provisioning: `pb-adv.c/h`, `prov-acceptor.c`, `prov-initiator.c`, `prov.h`, `provision.h`, `agent.c/h`
- Models: `cfgmod-server.c`, `cfgmod.h`, `friend.c/h`, `prvbeac-server.c`, `prv-beacon.h`, `remprv-server.c`, `remprv.h`
- I/O backends: `mesh-io.c/h`, `mesh-io-api.h`, `mesh-io-generic.c/h`, `mesh-io-mgmt.c/h`, `mesh-io-unit.c/h`
- Persistence: `mesh-config.h`, `mesh-config-json.c`
- Utilities: `util.c/h`, `rpl.c/h`, `mesh-mgmt.c/h`, `mesh-defs.h`, `mesh-main.conf`, `error.h`, `manager.c/h`

**OBEX Daemon (`obexd/`)** — ~40 files across 3 subdirectories:
- `obexd/src/` — Daemon core: entry point, session management, transport/service/MIME driver registries, plugin framework
- `obexd/plugins/` — Transport plugins (Bluetooth), service drivers (OPP, FTP, PBAP, MAP, IrMC, BIP), filesystem backends, phonebook providers
- `obexd/client/` — Client session/transfer stack, `org.bluez.obex.Client1`, profile-specific interfaces

**Legacy GATT (`attrib/`)** — 11 files:
- `att.c/h` — ATT PDU encode/decode
- `att-database.h` — Attribute record contract
- `gattrib.c/h` — GAttrib transport abstraction
- `gatt.c/h` — Client-side GATT procedures
- `gatttool.c`, `gatttool.h`, `interactive.c`, `utils.c` — gatttool utility

**Internal Libraries:**
- `btio/` — 2 files: `btio.c`, `btio.h` (GLib Bluetooth socket abstraction)
- `gdbus/` — 6 files: `gdbus.h`, `mainloop.c`, `watch.c`, `object.c`, `polkit.c`, `client.c`
- `gobex/` — 12 files: OBEX protocol library (packets, headers, app params, transfers)
- `lib/bluetooth/` — ~20 files: Public kernel-aligned ABI headers (`hci.h`, `l2cap.h`, `mgmt.h`, `sdp.h`, etc.)

**Unit Tests (`unit/`)** — ~50 files:
- Protocol engines: `avctp.c/h`, `avdtp.c/h`, `avrcp-lib.c/h`, `avrcp.c/h`
- 44 test executables: `test-avctp.c`, `test-avdtp.c`, `test-avrcp.c`, `test-bap.c`, `test-bass.c`, `test-battery.c`, `test-crc.c`, `test-crypto.c`, `test-ecc.c`, `test-eir.c`, `test-gatt.c`, `test-gattrib.c`, `test-gdbus-client.c`, `test-gmap.c`, `test-gobex.c`, `test-gobex-apparam.c`, `test-gobex-header.c`, `test-gobex-packet.c`, `test-gobex-transfer.c`, `test-hfp.c`, `test-hog.c`, `test-lib.c`, `test-mcp.c`, `test-mesh-crypto.c`, `test-mgmt.c`, `test-micp.c`, `test-midi.c`, `test-profile.c`, `test-queue.c`, `test-rap.c`, `test-ringbuf.c`, `test-sdp.c`, `test-tester.c`, `test-textfile.c`, `test-tmap.c`, `test-uhid.c`, `test-uuid.c`, `test-vcp.c`
- Stubs: `btd.c`, `util.c/h`

**Integration Testers (`tools/`)** — ~80 files (in-scope subset):
- Core testers: `mgmt-tester.c`, `l2cap-tester.c`, `iso-tester.c`, `sco-tester.c`, `hci-tester.c`, `mesh-tester.c`, `mesh-cfgtest.c`, `rfcomm-tester.c`, `bnep-tester.c`, `gap-tester.c`, `smp-tester.c`, `userchan-tester.c`, `ioctl-tester.c`, `6lowpan-tester.c`
- Support: `tester.h`, `test-runner.c`, `create-image.c`

**Documentation (`doc/`)** — ~90+ RST/TXT files defining D-Bus API contracts, protocol specs, and CLI manpages

### 0.2.2 Current Structure Mapping

```
Current BlueZ v5.86 Repository (C):
├── src/                          # Core bluetoothd daemon (~57 files)
│   ├── main.c                    # Entry point, config parsing
│   ├── adapter.c/h               # Adapter1 D-Bus, MGMT
│   ├── device.c/h                # Device1 D-Bus, pairing
│   ├── gatt-database.c/h         # GattManager1, local GATT
│   ├── gatt-client.c/h           # Remote GATT D-Bus export
│   ├── plugin.c/h                # Plugin framework
│   ├── profile.c/h               # Profile registry
│   ├── agent.c/h                 # Agent framework
│   ├── sdpd-*.c                  # SDP daemon
│   └── shared/                   # Shared protocol library (~90 files)
│       ├── att.c/h               # ATT transport
│       ├── gatt-db.c/h           # In-memory GATT DB
│       ├── gatt-client.c/h       # GATT client engine
│       ├── gatt-server.c/h       # GATT server engine
│       ├── mgmt.c/h              # Kernel MGMT client
│       ├── hci.c/h               # HCI socket transport
│       ├── bap.c/h               # BAP state machine
│       ├── crypto.c/h            # BT crypto (AF_ALG)
│       ├── mainloop*.c           # Event loop backends (3)
│       ├── io-*.c                # I/O backends (3)
│       └── timeout-*.c           # Timer backends (3)
├── profiles/                     # Profile plugins (~60 files)
│   ├── audio/                    # A2DP/AVRCP/BAP/VCP/HFP (37 files)
│   ├── input/                    # HID/HOGP
│   ├── network/                  # PAN/BNEP
│   └── ...                       # battery, gap, midi, etc.
├── plugins/                      # Daemon plugins (6 files)
├── client/                       # bluetoothctl (26 files)
├── monitor/                      # btmon (50 files)
├── emulator/                     # HCI emulator (20 files)
├── mesh/                         # bluetooth-meshd (56 files)
├── obexd/                        # OBEX daemon (~40 files)
├── attrib/                       # Legacy GATT (11 files)
├── btio/                         # BtIO socket abstraction (2 files)
├── gdbus/                        # D-Bus helper library (6 files)
├── gobex/                        # OBEX protocol library (12 files)
├── lib/bluetooth/                # Kernel ABI headers (~20 files)
├── unit/                         # Unit tests (~50 files)
├── tools/                        # Integration testers + tools (~80 files)
└── doc/                          # API documentation (~90 files)
```


## 0.3 Scope Boundaries

### 0.3.1 Exhaustively In Scope

**Source Transformations (all C source files requiring Rust rewrite):**
- `src/*.c`, `src/*.h` — All core daemon files (adapter, device, service, profile, agent, plugin, GATT, SDP, advertising, battery, bearer, set, storage, logging, error handling, EIR, UUID helpers, rfkill)
- `src/shared/*.c`, `src/shared/*.h` — All shared protocol library modules (ATT, GATT, mgmt, HCI, BAP, VCP, MCP, MICP, CCP, CSIP, BASS, TMAP, GMAP, ASHA, RAP, HFP, crypto, ECC, mainloop, I/O, timers, queue, ringbuf, btsnoop, pcap, shell, tester, BTP, uhid, uinput, utility)
- `profiles/audio/*.c`, `profiles/audio/*.h` — All audio profile implementations (A2DP, AVRCP, AVDTP, AVCTP, BAP, BASS, VCP, MICP, MCP, CCP, CSIP, TMAP, GMAP, ASHA, HFP, media, transport, player, telephony, control, sink, source)
- `profiles/battery/*.c`, `profiles/battery/*.h` — BAS client
- `profiles/deviceinfo/*.c`, `profiles/deviceinfo/*.h` — DIS reader
- `profiles/gap/*.c` — GAP characteristics reader
- `profiles/iap/*.c` — iAP helper daemon
- `profiles/input/*.c`, `profiles/input/*.h` — HID host, HOGP, UHID
- `profiles/midi/*.c`, `profiles/midi/*.h` — BLE-MIDI bridge
- `profiles/network/*.c`, `profiles/network/*.h` — PAN/BNEP
- `profiles/ranging/*.c` — RAP/RAS plugin
- `profiles/scanparam/*.c`, `profiles/scanparam/*.h` — Scan Parameters
- `plugins/*.c` — All 6 daemon plugins (sixaxis, admin, autopair, hostname, neard, policy)
- `client/*.c`, `client/*.h` — All bluetoothctl modules (main, admin, advertising, adv_monitor, agent, assistant, display, gatt, hci, mgmt, player, print, telephony)
- `monitor/*.c`, `monitor/*.h` — All btmon files (control, packet, display, analyze, all protocol dissectors, vendor decoders, capture backends)
- `emulator/*.c`, `emulator/*.h` — All emulator files (btdev, bthost, le, smp, hciemu, vhci, server, serial, phy, main, b1ee, hfp)
- `mesh/*.c`, `mesh/*.h` — All mesh daemon files (main, mesh, node, model, net, net-keys, crypto, appkey, keyring, provisioning, I/O backends, config, friend, models, dbus, util, rpl)
- `obexd/src/*.c`, `obexd/src/*.h` — OBEX daemon core
- `obexd/plugins/*.c`, `obexd/plugins/*.h` — OBEX service/transport plugins
- `obexd/client/*.c`, `obexd/client/*.h` — OBEX client subsystem
- `attrib/*.c`, `attrib/*.h` — Legacy ATT/GATT stack (att, gatt, gattrib, gatttool, interactive, utils)
- `btio/*.c`, `btio/*.h` — BtIO socket abstraction
- `gdbus/*.c`, `gdbus/*.h` — D-Bus helper library
- `gobex/*.c`, `gobex/*.h` — OBEX protocol library

**Kernel ABI Re-declarations (constants/structs only, not library rewrite):**
- `lib/bluetooth/*.h` — Protocol constants, socket address structures, MGMT definitions, HCI definitions — re-declared in `bluez-sys` module within `bluez-shared` crate

**Test Rewrites:**
- `unit/test-*.c` — All 44 unit test files converted to `#[test]` functions
- `unit/avctp.c`, `unit/avdtp.c`, `unit/avrcp-lib.c`, `unit/avrcp.c` — Protocol engines used by tests
- `unit/btd.c`, `unit/util.c`, `unit/util.h` — Test stubs and helpers
- `tools/mgmt-tester.c`, `tools/l2cap-tester.c`, `tools/iso-tester.c`, `tools/sco-tester.c` — Core integration testers
- `tools/hci-tester.c`, `tools/mesh-tester.c`, `tools/mesh-cfgtest.c` — Additional integration testers
- `tools/tester.h`, `tools/test-runner.c` — Test infrastructure

**Configuration Preservation:**
- `src/main.conf` — Main configuration template (INI format, parsed identically)
- `src/bluetooth.conf` — D-Bus policy (preserved as-is, not rewritten)
- `profiles/input/input.conf` — HID input configuration
- `profiles/network/network.conf` — Network/PAN configuration
- `mesh/mesh-main.conf` — Mesh daemon configuration
- `mesh/bluetooth-mesh.conf` — Mesh D-Bus policy

**Documentation Updates:**
- `doc/*.rst` — API reference docs (reviewed for accuracy, no format changes needed since they describe interface contracts that are preserved)
- `doc/settings-storage.txt` — Storage format specification (reference, unchanged)

### 0.3.2 Explicitly Out of Scope

Per the user's explicit directives, the following items are NOT part of this rewrite:

- **`lib/libbluetooth.so` public C library ABI** — NOT rewritten. If third-party callers need it, a separate C-compatible FFI shim crate may be provided, but this is NOT a deliverable
- **Deprecated CLI tools** — `hcitool`, `hciconfig`, `rfcomm`, `ciptool`, `hcidump`, `sdptool`, `gatttool` (standalone), `rctest`, `l2test`, `scotest`, `l2ping` are NOT rewritten
- **`tools/parser/`** — Legacy protocol parsers (used by deprecated `hcidump`)
- **`tools/mesh-gatt/`** — Legacy mesh GATT tooling
- **Python test scripts in `test/`** — `test/agent.py`, `test/bluezutils.py`, `test/dbusdef.py` and other Python D-Bus utilities
- **CUPS printer backend (`profiles/cups/`)** — Printing support is excluded
- **Build system migration details beyond Cargo workspace** — No GNU Autotools preservation (`configure.ac`, `Makefile.am`)
- **`.github/` CI workflows** — GitHub Actions pipeline definitions are not rewritten (new CI would be Cargo-native)
- **`.checkpatch.conf`, `.editorconfig`** — C-specific style enforcement files
- **`peripheral/`** — Standalone LE peripheral daemon (separate utility, not part of core stack)
- **Non-tester tools** — `tools/hciattach*.c`, `tools/btattach.c`, `tools/bluemoon.c`, `tools/hex2hcd.c`, `tools/bdaddr.c`, `tools/hwdb.c`, `tools/btproxy.c`, `tools/btsnoop.c`, `tools/btmon-logger.c`, `tools/avinfo.c`, `tools/avtest.c`, `tools/btgatt-client.c`, `tools/btgatt-server.c`, `tools/gatt-service.c`, `tools/obexctl.c`, `tools/mpris-proxy.c`, `tools/bluetooth-player.c`, and similar standalone utilities
- **External feature libraries** — `libical`, `ALSA`, `libudev`, `PolicyKit`, `libelf`, `liblc3`, `libjlinkarm` — these are consumed via conditional compilation; Rust equivalents may be used where needed but are not rewrite targets


## 0.4 Target Design

### 0.4.1 Refactored Structure Planning

The target Rust architecture consolidates the C codebase into a Cargo workspace of 8 crates with clear module boundaries. Every source file is comprehensively listed:

```
Target Cargo Workspace:
├── Cargo.toml                          # Workspace manifest
├── Cargo.lock                          # Dependency lock file
├── rust-toolchain.toml                 # Rust 2024 edition, stable toolchain
├── clippy.toml                         # Workspace-wide clippy configuration
├── rustfmt.toml                        # Formatting configuration
│
├── crates/
│   ├── bluez-shared/                   # lib crate (replaces src/shared/ + lib/bluetooth/)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # Crate root, module declarations
│   │       ├── sys/                    # FFI boundary module (unsafe allowed here)
│   │       │   ├── mod.rs
│   │       │   ├── bluetooth.rs        # AF_BLUETOOTH constants, bdaddr_t, socket addrs
│   │       │   ├── hci.rs              # HCI packet structs, opcodes, socket options
│   │       │   ├── l2cap.rs            # L2CAP socket addr, options, signaling structs
│   │       │   ├── rfcomm.rs           # RFCOMM socket addr, ioctls
│   │       │   ├── sco.rs              # SCO socket addr, options
│   │       │   ├── iso.rs              # ISO socket addr, BIS structures
│   │       │   ├── bnep.rs             # BNEP constants, ioctls
│   │       │   ├── hidp.rs             # HIDP ioctl structures
│   │       │   ├── cmtp.rs             # CMTP ioctl structures
│   │       │   └── mgmt.rs             # MGMT protocol opcodes, events, TLV structures
│   │       ├── socket/                 # Bluetooth socket abstraction
│   │       │   ├── mod.rs
│   │       │   └── bluetooth_socket.rs # BluetoothSocket wrapping nix + AsyncFd
│   │       ├── att/                    # ATT protocol
│   │       │   ├── mod.rs
│   │       │   ├── types.rs            # Opcodes, errors, permissions
│   │       │   └── transport.rs        # bt_att equivalent with EATT
│   │       ├── gatt/                   # GATT engines
│   │       │   ├── mod.rs
│   │       │   ├── db.rs               # gatt_db equivalent
│   │       │   ├── client.rs           # bt_gatt_client equivalent
│   │       │   ├── server.rs           # GATT server over ATT
│   │       │   └── helpers.rs          # Discovery/read utilities
│   │       ├── mgmt/                   # Kernel MGMT client
│   │       │   ├── mod.rs
│   │       │   └── client.rs           # MgmtSocket with typed enums
│   │       ├── hci/                    # HCI transport
│   │       │   ├── mod.rs
│   │       │   ├── transport.rs        # HCI socket + command queue
│   │       │   └── crypto.rs           # HCI-assisted LE crypto
│   │       ├── audio/                  # LE Audio state machines
│   │       │   ├── mod.rs
│   │       │   ├── bap.rs              # BAP (streams, PAC, ASE)
│   │       │   ├── bass.rs             # BASS (broadcast assistant)
│   │       │   ├── vcp.rs              # VCS/VOCS/AICS
│   │       │   ├── mcp.rs              # MCS/GMCS
│   │       │   ├── micp.rs             # MICS
│   │       │   ├── ccp.rs              # GTBS/CCP
│   │       │   ├── csip.rs             # CSIS/CSIP
│   │       │   ├── tmap.rs             # TMAS
│   │       │   ├── gmap.rs             # GMAS
│   │       │   └── asha.rs             # ASHA hearing aids
│   │       ├── profiles/               # Profile protocols
│   │       │   ├── mod.rs
│   │       │   ├── gap.rs              # GAP mgmt probe
│   │       │   ├── hfp.rs              # HFP AT engine
│   │       │   ├── battery.rs          # Battery service
│   │       │   └── rap.rs              # RAS skeleton
│   │       ├── crypto/                 # Bluetooth crypto
│   │       │   ├── mod.rs
│   │       │   ├── aes_cmac.rs         # AES/CMAC via ring
│   │       │   └── ecc.rs              # P-256 keygen/ECDH
│   │       ├── util/                   # Utilities
│   │       │   ├── mod.rs
│   │       │   ├── queue.rs            # Vec/VecDeque wrappers
│   │       │   ├── ringbuf.rs          # Ring buffer
│   │       │   ├── ad.rs               # Advertising data
│   │       │   ├── eir.rs              # EIR parsing
│   │       │   ├── uuid.rs             # UUID normalization
│   │       │   └── endian.rs           # Endianness helpers
│   │       ├── capture/                # Capture formats
│   │       │   ├── mod.rs
│   │       │   ├── btsnoop.rs          # BTSnoop read/write
│   │       │   └── pcap.rs             # PCAP parsing
│   │       ├── device/                 # Linux device helpers
│   │       │   ├── mod.rs
│   │       │   ├── uhid.rs             # UHID device creation (unsafe)
│   │       │   └── uinput.rs           # uinput device creation (unsafe)
│   │       ├── shell.rs                # Interactive shell (rustyline)
│   │       ├── tester.rs               # Test harness framework
│   │       └── log.rs                  # Structured logging via tracing
│   │
│   ├── bluetoothd/                     # bin crate (replaces src/ + profiles/ + plugins/ + gdbus/ + btio/ + attrib/)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                 # Daemon entry, config, D-Bus name acquisition
│   │       ├── config.rs               # main.conf parsing via rust-ini
│   │       ├── adapter.rs              # Adapter1 D-Bus interface
│   │       ├── device.rs               # Device1 D-Bus interface
│   │       ├── service.rs              # Profile-instance state machine
│   │       ├── profile.rs              # Profile registry + ProfileManager1
│   │       ├── agent.rs                # AgentManager1 + agent brokerage
│   │       ├── plugin.rs               # Plugin framework (inventory + libloading)
│   │       ├── advertising.rs          # LEAdvertisingManager1
│   │       ├── adv_monitor.rs          # AdvertisementMonitorManager1
│   │       ├── battery.rs              # Battery1 + BatteryProviderManager1
│   │       ├── bearer.rs               # Bearer.BREDR1/LE1
│   │       ├── set.rs                  # DeviceSet1
│   │       ├── gatt/                   # GATT subsystem
│   │       │   ├── mod.rs
│   │       │   ├── database.rs         # GattManager1 + local GATT DB
│   │       │   ├── client.rs           # Remote GATT D-Bus export
│   │       │   └── settings.rs         # GATT persistence
│   │       ├── sdp/                    # SDP subsystem
│   │       │   ├── mod.rs
│   │       │   ├── client.rs           # Async SDP search
│   │       │   ├── server.rs           # SDP daemon
│   │       │   ├── database.rs         # SDP record store
│   │       │   └── xml.rs              # SDP XML conversion
│   │       ├── profiles/               # Profile plugin implementations
│   │       │   ├── mod.rs
│   │       │   ├── audio/              # Audio profiles (A2DP, AVRCP, BAP, etc.)
│   │       │   │   ├── mod.rs
│   │       │   │   ├── a2dp.rs
│   │       │   │   ├── avdtp.rs
│   │       │   │   ├── avctp.rs
│   │       │   │   ├── avrcp.rs
│   │       │   │   ├── media.rs
│   │       │   │   ├── transport.rs
│   │       │   │   ├── player.rs
│   │       │   │   ├── bap.rs
│   │       │   │   ├── bass.rs
│   │       │   │   ├── vcp.rs
│   │       │   │   ├── micp.rs
│   │       │   │   ├── mcp.rs
│   │       │   │   ├── ccp.rs
│   │       │   │   ├── csip.rs
│   │       │   │   ├── tmap.rs
│   │       │   │   ├── gmap.rs
│   │       │   │   ├── asha.rs
│   │       │   │   ├── hfp.rs
│   │       │   │   ├── telephony.rs
│   │       │   │   ├── sink.rs
│   │       │   │   ├── source.rs
│   │       │   │   └── control.rs
│   │       │   ├── input.rs            # HID/HOGP
│   │       │   ├── network.rs          # PAN/BNEP
│   │       │   ├── battery.rs          # BAS client
│   │       │   ├── deviceinfo.rs       # DIS reader
│   │       │   ├── gap.rs              # GAP chars
│   │       │   ├── midi.rs             # BLE-MIDI
│   │       │   ├── ranging.rs          # RAP/RAS
│   │       │   └── scanparam.rs        # Scan Parameters
│   │       ├── plugins/                # Daemon plugins
│   │       │   ├── mod.rs
│   │       │   ├── sixaxis.rs
│   │       │   ├── admin.rs
│   │       │   ├── autopair.rs
│   │       │   ├── hostname.rs
│   │       │   ├── neard.rs
│   │       │   └── policy.rs
│   │       ├── legacy_gatt/            # Legacy ATT/GATT (from attrib/)
│   │       │   ├── mod.rs
│   │       │   ├── att.rs
│   │       │   ├── gatt.rs
│   │       │   └── gattrib.rs
│   │       ├── storage.rs              # Persistent storage (textfile format)
│   │       ├── dbus_common.rs          # D-Bus utility helpers
│   │       ├── error.rs                # D-Bus error mapping
│   │       ├── rfkill.rs               # rfkill integration
│   │       └── log.rs                  # Daemon logging
│   │
│   ├── bluetoothctl/                   # bin crate (replaces client/)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                 # CLI entry, D-Bus client, core commands
│   │       ├── admin.rs
│   │       ├── advertising.rs
│   │       ├── adv_monitor.rs
│   │       ├── agent.rs
│   │       ├── assistant.rs
│   │       ├── display.rs
│   │       ├── gatt.rs
│   │       ├── hci.rs
│   │       ├── mgmt.rs
│   │       ├── player.rs
│   │       ├── print.rs
│   │       └── telephony.rs
│   │
│   ├── btmon/                          # bin crate (replaces monitor/)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── control.rs
│   │       ├── packet.rs
│   │       ├── display.rs
│   │       ├── analyze.rs
│   │       ├── dissectors/
│   │       │   ├── mod.rs
│   │       │   ├── l2cap.rs
│   │       │   ├── att.rs
│   │       │   ├── sdp.rs
│   │       │   ├── rfcomm.rs
│   │       │   ├── bnep.rs
│   │       │   ├── avctp.rs
│   │       │   ├── avdtp.rs
│   │       │   ├── a2dp.rs
│   │       │   ├── ll.rs
│   │       │   └── lmp.rs
│   │       ├── vendor/
│   │       │   ├── mod.rs
│   │       │   ├── intel.rs
│   │       │   ├── broadcom.rs
│   │       │   └── msft.rs
│   │       ├── backends/
│   │       │   ├── mod.rs
│   │       │   ├── hcidump.rs
│   │       │   ├── jlink.rs
│   │       │   └── ellisys.rs
│   │       ├── hwdb.rs
│   │       ├── keys.rs
│   │       └── crc.rs
│   │
│   ├── bluetooth-meshd/                # bin crate (replaces mesh/)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── mesh.rs
│   │       ├── node.rs
│   │       ├── model.rs
│   │       ├── net.rs
│   │       ├── net_keys.rs
│   │       ├── crypto.rs
│   │       ├── appkey.rs
│   │       ├── keyring.rs
│   │       ├── dbus.rs
│   │       ├── agent.rs
│   │       ├── provisioning/
│   │       │   ├── mod.rs
│   │       │   ├── pb_adv.rs
│   │       │   ├── acceptor.rs
│   │       │   └── initiator.rs
│   │       ├── models/
│   │       │   ├── mod.rs
│   │       │   ├── config_server.rs
│   │       │   ├── friend.rs
│   │       │   ├── prv_beacon.rs
│   │       │   └── remote_prov.rs
│   │       ├── io/
│   │       │   ├── mod.rs
│   │       │   ├── generic.rs
│   │       │   ├── mgmt.rs
│   │       │   └── unit.rs
│   │       ├── config/
│   │       │   ├── mod.rs
│   │       │   └── json.rs
│   │       ├── rpl.rs
│   │       ├── manager.rs
│   │       └── util.rs
│   │
│   ├── obexd/                          # bin crate (replaces obexd/ + gobex/)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── obex/                   # OBEX protocol (from gobex/)
│   │       │   ├── mod.rs
│   │       │   ├── packet.rs
│   │       │   ├── header.rs
│   │       │   ├── apparam.rs
│   │       │   ├── transfer.rs
│   │       │   └── session.rs
│   │       ├── server/                 # Server-side daemon
│   │       │   ├── mod.rs
│   │       │   ├── transport.rs
│   │       │   └── service.rs
│   │       ├── plugins/                # Service/transport plugins
│   │       │   ├── mod.rs
│   │       │   ├── bluetooth.rs
│   │       │   ├── ftp.rs
│   │       │   ├── opp.rs
│   │       │   ├── pbap.rs
│   │       │   ├── map.rs
│   │       │   ├── sync.rs
│   │       │   └── filesystem.rs
│   │       └── client/                 # Client subsystem
│   │           ├── mod.rs
│   │           ├── session.rs
│   │           ├── transfer.rs
│   │           └── profiles.rs
│   │
│   ├── bluez-emulator/                 # lib crate (replaces emulator/)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── btdev.rs
│   │       ├── bthost.rs
│   │       ├── le.rs
│   │       ├── smp.rs
│   │       ├── hciemu.rs
│   │       ├── vhci.rs
│   │       ├── server.rs
│   │       ├── serial.rs
│   │       └── phy.rs
│   │
│   └── bluez-tools/                    # bin(multi) crate (replaces tools/*-tester.c)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs                  # Shared tester infrastructure
│           └── bin/
│               ├── mgmt_tester.rs
│               ├── l2cap_tester.rs
│               ├── iso_tester.rs
│               ├── sco_tester.rs
│               ├── hci_tester.rs
│               ├── mesh_tester.rs
│               ├── mesh_cfgtest.rs
│               ├── rfcomm_tester.rs
│               ├── bnep_tester.rs
│               ├── gap_tester.rs
│               ├── smp_tester.rs
│               └── userchan_tester.rs
│
├── tests/                              # Workspace-level integration tests
│   ├── unit/                           # Converted from unit/test-*.c (44 tests)
│   │   ├── test_att.rs
│   │   ├── test_gatt.rs
│   │   ├── test_mgmt.rs
│   │   ├── test_crypto.rs
│   │   ├── test_ecc.rs
│   │   ├── test_bap.rs
│   │   ├── test_vcp.rs
│   │   └── ...                         # (all 44 test files)
│   └── integration/                    # End-to-end tests
│       ├── dbus_contract_test.rs
│       ├── smoke_test.rs
│       └── btsnoop_replay_test.rs
│
├── benches/                            # Criterion benchmarks
│   ├── startup.rs
│   ├── mgmt_latency.rs
│   ├── gatt_discovery.rs
│   └── btmon_throughput.rs
│
└── config/                             # Configuration files (preserved exactly)
    ├── main.conf
    ├── input.conf
    ├── network.conf
    ├── mesh-main.conf
    ├── bluetooth.conf                  # D-Bus policy
    └── bluetooth-mesh.conf             # Mesh D-Bus policy
```

### 0.4.2 Design Pattern Applications

- **Ownership and RAII** — All opaque struct patterns (`foo_new()`/`foo_free()`) become `pub struct Foo` with `impl Drop` where needed, eliminating manual memory management entirely
- **Trait-based polymorphism** — Plugin interfaces use `trait BluetoothPlugin` registered via `inventory::collect!`, replacing `BLUETOOTH_PLUGIN_DEFINE()` macro + linker sections
- **Async I/O via tokio** — `GMainLoop`/`l_main` event loops become `tokio::runtime::Runtime`; `GIOChannel` becomes `AsyncFd` wrapping raw Bluetooth socket FDs; `g_timeout_add` becomes `tokio::time::sleep`/`tokio::time::interval`
- **Typed enums for protocol messages** — HCI commands/events, MGMT opcodes, and ATT opcodes become Rust enums with `From<&[u8]>` validation, replacing raw byte packing with `zerocopy` or manual deserialization
- **Channel-based communication** — `callback_t fn + void *user_data` patterns become `tokio::sync::mpsc` channels or `async fn` closures, eliminating raw function pointer + user data pairs
- **Error handling** — `errno`-style returns and `GError` become `Result<T, E>` with typed error enums mapping to D-Bus error names exactly

### 0.4.3 User Interface Design

Not applicable — BlueZ is a headless system daemon with no graphical UI. The `bluetoothctl` CLI uses `rustyline` (replacing `readline`) with the same interactive shell command structure. The `btmon` terminal output must produce byte-identical human-readable protocol decoding.


## 0.5 Transformation Mapping

### 0.5.1 File-by-File Transformation Plan

All transformations execute in a single phase. Every target file is mapped to its C source origin.

**bluez-shared crate** — Protocol library and FFI foundations:

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| crates/bluez-shared/Cargo.toml | CREATE | — | Workspace lib crate with tokio, nix, libc, ring, serde, rust-ini, rustyline, tracing deps |
| crates/bluez-shared/src/lib.rs | CREATE | — | Module declarations for all sub-modules |
| crates/bluez-shared/src/sys/mod.rs | CREATE | lib/bluetooth/*.h | FFI boundary: re-declare kernel ABI constants, packed structs, socket addresses |
| crates/bluez-shared/src/sys/bluetooth.rs | CREATE | lib/bluetooth/bluetooth.h | bdaddr_t, BTPROTO_*, SOL_BT, endian helpers, address utilities |
| crates/bluez-shared/src/sys/hci.rs | CREATE | lib/bluetooth/hci.h, lib/bluetooth/hci_lib.h | HCI packet structs, opcodes, event codes, socket options |
| crates/bluez-shared/src/sys/l2cap.rs | CREATE | lib/bluetooth/l2cap.h | sockaddr_l2, SOL_L2CAP, signaling structs |
| crates/bluez-shared/src/sys/rfcomm.rs | CREATE | lib/bluetooth/rfcomm.h | sockaddr_rc, RFCOMM ioctls |
| crates/bluez-shared/src/sys/sco.rs | CREATE | lib/bluetooth/sco.h | sockaddr_sco, SCO options |
| crates/bluez-shared/src/sys/iso.rs | CREATE | lib/bluetooth/iso.h | sockaddr_iso, BIS structures |
| crates/bluez-shared/src/sys/bnep.rs | CREATE | lib/bluetooth/bnep.h | BNEP constants, ioctls |
| crates/bluez-shared/src/sys/hidp.rs | CREATE | lib/bluetooth/hidp.h | HIDP ioctl structures |
| crates/bluez-shared/src/sys/cmtp.rs | CREATE | lib/bluetooth/cmtp.h | CMTP ioctl structures |
| crates/bluez-shared/src/sys/mgmt.rs | CREATE | lib/bluetooth/mgmt.h | MGMT opcodes, events, TLV structs — typed Rust enums |
| crates/bluez-shared/src/socket/bluetooth_socket.rs | CREATE | btio/btio.c, btio/btio.h | BluetoothSocket wrapping nix::sys::socket + AsyncFd for L2CAP/RFCOMM/SCO/ISO |
| crates/bluez-shared/src/att/types.rs | CREATE | src/shared/att-types.h | ATT opcodes, errors, permissions as Rust enums |
| crates/bluez-shared/src/att/transport.rs | CREATE | src/shared/att.c, src/shared/att.h | bt_att equivalent: async send/recv, EATT channels, request matching |
| crates/bluez-shared/src/gatt/db.rs | CREATE | src/shared/gatt-db.c, src/shared/gatt-db.h | gatt_db: in-memory service/char/desc model, CCC, DB hash |
| crates/bluez-shared/src/gatt/client.rs | CREATE | src/shared/gatt-client.c, src/shared/gatt-client.h | bt_gatt_client: async discovery, robust caching, Service Changed |
| crates/bluez-shared/src/gatt/server.rs | CREATE | src/shared/gatt-server.c, src/shared/gatt-server.h | GATT server: ATT handler dispatch, permissions, notifications |
| crates/bluez-shared/src/gatt/helpers.rs | CREATE | src/shared/gatt-helpers.c, src/shared/gatt-helpers.h | Discovery/read utilities, result iterators |
| crates/bluez-shared/src/mgmt/client.rs | CREATE | src/shared/mgmt.c, src/shared/mgmt.h | MgmtSocket: async command/reply, event notify, TLV utilities |
| crates/bluez-shared/src/hci/transport.rs | CREATE | src/shared/hci.c, src/shared/hci.h | HCI socket transport with command queues, response correlation |
| crates/bluez-shared/src/hci/crypto.rs | CREATE | src/shared/hci-crypto.c, src/shared/hci-crypto.h | LE Encrypt/Rand wrappers via HCI |
| crates/bluez-shared/src/audio/bap.rs | CREATE | src/shared/bap.c, src/shared/bap.h, src/shared/bap-defs.h, src/shared/bap-debug.c, src/shared/bap-debug.h, src/shared/ascs.h | BAP state machine: PAC/ASE/stream management |
| crates/bluez-shared/src/audio/bass.rs | CREATE | src/shared/bass.c, src/shared/bass.h | BASS broadcast assistant |
| crates/bluez-shared/src/audio/vcp.rs | CREATE | src/shared/vcp.c, src/shared/vcp.h | VCS/VOCS/AICS server + VCP client |
| crates/bluez-shared/src/audio/mcp.rs | CREATE | src/shared/mcp.c, src/shared/mcp.h, src/shared/mcs.h | MCS/GMCS server + MCP client |
| crates/bluez-shared/src/audio/micp.rs | CREATE | src/shared/micp.c, src/shared/micp.h | MICS mute server + client |
| crates/bluez-shared/src/audio/ccp.rs | CREATE | src/shared/ccp.c, src/shared/ccp.h | GTBS/CCP scaffold |
| crates/bluez-shared/src/audio/csip.rs | CREATE | src/shared/csip.c, src/shared/csip.h | CSIS set member service + discovery |
| crates/bluez-shared/src/audio/tmap.rs | CREATE | src/shared/tmap.c, src/shared/tmap.h | TMAS role client+server |
| crates/bluez-shared/src/audio/gmap.rs | CREATE | src/shared/gmap.c, src/shared/gmap.h | GMAS role/feature |
| crates/bluez-shared/src/audio/asha.rs | CREATE | src/shared/asha.c, src/shared/asha.h | ASHA hearing aids client |
| crates/bluez-shared/src/profiles/gap.rs | CREATE | src/shared/gap.c, src/shared/gap.h | GAP mgmt capability probe |
| crates/bluez-shared/src/profiles/hfp.rs | CREATE | src/shared/hfp.c, src/shared/hfp.h | HFP AT command engine |
| crates/bluez-shared/src/profiles/battery.rs | CREATE | src/shared/battery.c, src/shared/battery.h | Battery service state machine |
| crates/bluez-shared/src/profiles/rap.rs | CREATE | src/shared/rap.c, src/shared/rap.h | RAS skeleton |
| crates/bluez-shared/src/crypto/aes_cmac.rs | CREATE | src/shared/crypto.c, src/shared/crypto.h | AES/CMAC via ring (replacing AF_ALG) |
| crates/bluez-shared/src/crypto/ecc.rs | CREATE | src/shared/ecc.c, src/shared/ecc.h | P-256 via ring (replacing software ECC) |
| crates/bluez-shared/src/util/queue.rs | CREATE | src/shared/queue.c, src/shared/queue.h | Vec/VecDeque-based queue |
| crates/bluez-shared/src/util/ringbuf.rs | CREATE | src/shared/ringbuf.c, src/shared/ringbuf.h | Ring buffer |
| crates/bluez-shared/src/util/ad.rs | CREATE | src/shared/ad.c, src/shared/ad.h | Advertising data builder/parser |
| crates/bluez-shared/src/capture/btsnoop.rs | CREATE | src/shared/btsnoop.c, src/shared/btsnoop.h | BTSnoop read/write with Apple PacketLogger |
| crates/bluez-shared/src/capture/pcap.rs | CREATE | src/shared/pcap.c, src/shared/pcap.h | PCAP + PPI parsing |
| crates/bluez-shared/src/device/uhid.rs | CREATE | src/shared/uhid.c, src/shared/uhid.h | UHID device creation (unsafe FFI) |
| crates/bluez-shared/src/device/uinput.rs | CREATE | src/shared/uinput.c, src/shared/uinput.h | uinput device creation (unsafe FFI) |
| crates/bluez-shared/src/shell.rs | CREATE | src/shared/shell.c, src/shared/shell.h | Interactive shell using rustyline |
| crates/bluez-shared/src/tester.rs | CREATE | src/shared/tester.c, src/shared/tester.h | Test harness framework (Rust #[test] compatible) |
| crates/bluez-shared/src/log.rs | CREATE | src/shared/log.c, src/shared/log.h | Structured logging via tracing |

**bluetoothd crate** — Core daemon:

| Target File | Transformation | Source File(s) | Key Changes |
|---|---|---|---|
| crates/bluetoothd/Cargo.toml | CREATE | — | Binary crate depending on bluez-shared, zbus, tokio, inventory, libloading |
| crates/bluetoothd/src/main.rs | CREATE | src/main.c | tokio::main, rust-ini config, zbus name acquisition, plugin init |
| crates/bluetoothd/src/config.rs | CREATE | src/main.c, src/btd.h | btd_opts struct, main.conf parsing via rust-ini |
| crates/bluetoothd/src/adapter.rs | CREATE | src/adapter.c, src/adapter.h | Adapter1 via #[zbus::interface], MGMT integration |
| crates/bluetoothd/src/device.rs | CREATE | src/device.c, src/device.h | Device1 via #[zbus::interface], pairing/bonding |
| crates/bluetoothd/src/service.rs | CREATE | src/service.c, src/service.h | Profile-instance state machine |
| crates/bluetoothd/src/profile.rs | CREATE | src/profile.c, src/profile.h | ProfileManager1, SDP record generation |
| crates/bluetoothd/src/agent.rs | CREATE | src/agent.c, src/agent.h | AgentManager1, pairing prompts |
| crates/bluetoothd/src/plugin.rs | CREATE | src/plugin.c, src/plugin.h | inventory + libloading plugin framework |
| crates/bluetoothd/src/advertising.rs | CREATE | src/advertising.c, src/advertising.h | LEAdvertisingManager1, MGMT ext adv |
| crates/bluetoothd/src/adv_monitor.rs | CREATE | src/adv_monitor.c, src/adv_monitor.h | AdvertisementMonitorManager1 |
| crates/bluetoothd/src/battery.rs | CREATE | src/battery.c, src/battery.h | Battery1 + BatteryProviderManager1 |
| crates/bluetoothd/src/bearer.rs | CREATE | src/bearer.c, src/bearer.h | Bearer.BREDR1/LE1 |
| crates/bluetoothd/src/set.rs | CREATE | src/set.c, src/set.h | DeviceSet1 |
| crates/bluetoothd/src/gatt/database.rs | CREATE | src/gatt-database.c, src/gatt-database.h | GattManager1 |
| crates/bluetoothd/src/gatt/client.rs | CREATE | src/gatt-client.c, src/gatt-client.h | Remote GATT D-Bus export |
| crates/bluetoothd/src/gatt/settings.rs | CREATE | src/settings.c, src/settings.h | GATT DB persistence |
| crates/bluetoothd/src/sdp/*.rs | CREATE | src/sdpd-*.c, src/sdp-*.c | SDP daemon + client + XML |
| crates/bluetoothd/src/profiles/audio/*.rs | CREATE | profiles/audio/*.c | All audio profiles (A2DP, AVRCP, BAP, HFP, etc.) |
| crates/bluetoothd/src/profiles/input.rs | CREATE | profiles/input/*.c | HID/HOGP |
| crates/bluetoothd/src/profiles/network.rs | CREATE | profiles/network/*.c | PAN/BNEP |
| crates/bluetoothd/src/profiles/battery.rs | CREATE | profiles/battery/*.c | BAS client |
| crates/bluetoothd/src/profiles/deviceinfo.rs | CREATE | profiles/deviceinfo/*.c | DIS |
| crates/bluetoothd/src/profiles/gap.rs | CREATE | profiles/gap/*.c | GAP |
| crates/bluetoothd/src/profiles/midi.rs | CREATE | profiles/midi/*.c | BLE-MIDI |
| crates/bluetoothd/src/profiles/ranging.rs | CREATE | profiles/ranging/*.c | RAP/RAS |
| crates/bluetoothd/src/profiles/scanparam.rs | CREATE | profiles/scanparam/*.c | Scan Parameters |
| crates/bluetoothd/src/plugins/*.rs | CREATE | plugins/*.c | All 6 daemon plugins |
| crates/bluetoothd/src/legacy_gatt/*.rs | CREATE | attrib/*.c | Legacy ATT/GATT client stack |
| crates/bluetoothd/src/storage.rs | CREATE | src/storage.c, src/textfile.c | Persistent storage (identical format) |
| crates/bluetoothd/src/error.rs | CREATE | src/error.c, src/error.h | D-Bus error reply mapping |
| crates/bluetoothd/src/dbus_common.rs | CREATE | src/dbus-common.c, src/dbus-common.h | D-Bus utilities |
| crates/bluetoothd/src/rfkill.rs | CREATE | src/rfkill.c | rfkill integration |

**Remaining binary crates** (summary — each follows same CREATE pattern):

| Target Crate | Source Directory | Key Source Files |
|---|---|---|
| crates/bluetoothctl/src/*.rs | client/ | main.c, admin.c, advertising.c, agent.c, assistant.c, display.c, gatt.c, hci.c, mgmt.c, player.c, print.c, telephony.c |
| crates/btmon/src/*.rs | monitor/ | main.c, control.c, packet.c, display.c, analyze.c, all dissectors, all vendor decoders, all backends |
| crates/bluetooth-meshd/src/*.rs | mesh/ | main.c, mesh.c, node.c, model.c, net.c, crypto.c, all provisioning, all models, all I/O backends |
| crates/obexd/src/*.rs | obexd/ + gobex/ | All obexd/src, obexd/plugins, obexd/client files + all gobex/ files |
| crates/bluez-emulator/src/*.rs | emulator/ | btdev.c, bthost.c, le.c, smp.c, hciemu.c, vhci.c, server.c, serial.c, phy.c |
| crates/bluez-tools/src/*.rs | tools/*-tester.c | mgmt-tester.c, l2cap-tester.c, iso-tester.c, sco-tester.c, hci-tester.c, mesh-tester.c |

### 0.5.2 Cross-File Dependencies

**Import transformation rules:**
- FROM: `#include "src/shared/att.h"` → TO: `use bluez_shared::att::transport::BtAtt;`
- FROM: `#include "src/shared/gatt-db.h"` → TO: `use bluez_shared::gatt::db::GattDb;`
- FROM: `#include "src/shared/mgmt.h"` → TO: `use bluez_shared::mgmt::client::MgmtSocket;`
- FROM: `#include "gdbus/gdbus.h"` → TO: `use zbus::{Connection, interface};`
- FROM: `#include "btio/btio.h"` → TO: `use bluez_shared::socket::BluetoothSocket;`
- FROM: `#include "lib/bluetooth/mgmt.h"` → TO: `use bluez_shared::sys::mgmt::*;`
- FROM: `#include <glib.h>` → Removed entirely; replaced by std collections, tokio, Arc

**Configuration file updates:**
- `config/main.conf` — Identical INI format, parsed by `rust-ini` instead of `GKeyFile`
- `config/bluetooth.conf` — D-Bus policy XML, preserved verbatim
- `config/bluetooth-mesh.conf` — Mesh D-Bus policy XML, preserved verbatim

### 0.5.3 One-Phase Execution

The entire refactoring executes as a single phase. All 8 crates, all test files, all configuration files, and all workspace-level infrastructure are created simultaneously. There is no multi-phase split — the Cargo workspace must build and pass all tests in one delivery.


## 0.6 Dependency Inventory

### 0.6.1 Key Private and Public Packages

All packages listed below use exact names and versions as specified by the user or verified from public registries.

| Registry | Package | Version | Purpose |
|---|---|---|---|
| crates.io | tokio | 1.50 | Async runtime: multi-thread for bluetoothd, current_thread for bluetooth-meshd. Features: full |
| crates.io | zbus | 5.12 | D-Bus service/client. Features: tokio (disable default async-io). Replaces gdbus/ + libdbus-1 + l_dbus |
| crates.io | nix | 0.29 | POSIX syscalls: socket(), bind(), connect(), ioctl(), sendmsg(), recvmsg(). Features: socket, ioctl, net |
| crates.io | libc | 0.2 | Raw C type definitions for AF_BLUETOOTH, sockaddr structs, ioctl numbers |
| crates.io | rust-ini | 0.21 | INI configuration parsing preserving identical section/key semantics. Replaces GKeyFile |
| crates.io | serde | 1.0 | Internal data serialization (NOT for config format change). Features: derive |
| crates.io | tracing | 0.1 | Structured logging replacing syslog + btmon HCI_CHANNEL_LOGGING |
| crates.io | tracing-subscriber | 0.3 | Log output formatting and filtering |
| crates.io | rustyline | 14 | Interactive CLI shell replacing GNU readline |
| crates.io | inventory | 0.3 | Plugin registration via trait collection. Replaces BLUETOOTH_PLUGIN_DEFINE + linker sections |
| crates.io | libloading | 0.8 | External plugin loading via dlopen/dlsym equivalent |
| crates.io | ring | 0.17 | Cryptographic primitives: AES-128, CMAC, P-256 ECC/ECDH. Replaces AF_ALG + software ECC |
| crates.io | criterion | 0.5 | Microbenchmark framework for performance gate validation |
| crates.io | zerocopy | 0.8 | Zero-copy byte-level struct conversion for HCI/MGMT packed structures |
| crates.io | bitflags | 2.6 | Type-safe bitfield definitions for BT flags, permissions, capabilities |
| crates.io | bytes | 1.7 | Efficient byte buffer management for protocol packet handling |
| crates.io | thiserror | 2.0 | Derive macro for Error trait implementations on typed error enums |
| crates.io | tokio-stream | 0.1 | Stream utilities for async event processing |
| crates.io | futures | 0.3 | Future combinators and stream extensions |

**Workspace-internal dependencies:**

| Crate | Depends On | Purpose |
|---|---|---|
| bluetoothd | bluez-shared | Protocol engines, socket abstraction, crypto, utilities |
| bluetoothctl | bluez-shared | Shell framework, MGMT client, HCI transport |
| btmon | bluez-shared | BTSnoop/PCAP parsing, protocol constants, utility functions |
| bluetooth-meshd | bluez-shared | Crypto, MGMT client, mesh protocol primitives |
| obexd | bluez-shared | Socket abstraction, utility functions |
| bluez-emulator | bluez-shared | HCI protocol structures, crypto, socket types |
| bluez-tools | bluez-shared, bluez-emulator | Tester framework, emulator harness, protocol engines |

### 0.6.2 Dependency Updates

**Import refactoring — files requiring import updates:**
- `crates/bluez-shared/src/**/*.rs` — Internal module imports using Rust `use` declarations
- `crates/bluetoothd/src/**/*.rs` — Import `bluez_shared::*` modules + `zbus::*` for D-Bus
- `crates/bluetoothctl/src/**/*.rs` — Import `bluez_shared::*` + `zbus::proxy` for D-Bus client
- `crates/btmon/src/**/*.rs` — Import `bluez_shared::capture::*`, `bluez_shared::sys::*`
- `crates/bluetooth-meshd/src/**/*.rs` — Import `bluez_shared::crypto::*`, `bluez_shared::mgmt::*`
- `crates/obexd/src/**/*.rs` — Import `bluez_shared::socket::*`, `zbus::*`
- `crates/bluez-emulator/src/**/*.rs` — Import `bluez_shared::sys::*`, `bluez_shared::hci::*`
- `crates/bluez-tools/src/**/*.rs` — Import `bluez_shared::tester::*`, `bluez_emulator::*`

**Import transformation rules:**
- Old: `#include "src/shared/gatt-db.h"` / `#include <glib.h>`
- New: `use bluez_shared::gatt::db::GattDb;` / removed (std types)
- Apply to: All `.rs` files in workspace

**External reference updates:**
- `Cargo.toml` (workspace root) — Workspace members, shared dependency versions
- `crates/*/Cargo.toml` — Per-crate dependencies, features, binary targets
- `rust-toolchain.toml` — Rust edition 2024, stable channel
- `clippy.toml` — Workspace-wide lint configuration
- `rustfmt.toml` — Formatting standards

**Build system changes:**
- `configure.ac`, `Makefile.am` — Replaced entirely by Cargo workspace (out of scope, not preserved)
- `config.h` / `HAVE_*` macros — Replaced by Cargo features for conditional compilation


## 0.7 Special Analysis

### 0.7.1 Event Loop Unification Strategy

The C codebase maintains three interchangeable mainloop backends in `src/shared/`:

- **GLib backend** (`mainloop-glib.c`) — Used by `bluetoothd` and `obexd`. Wraps `GMainLoop`, `g_io_add_watch`, `g_timeout_add`. The `struct io` wrapper (`io-glib.c`) bridges `GIOChannel` with the generic `io.h` API.
- **ELL backend** (`mainloop-ell.c`) — Used by `bluetooth-meshd`. Wraps `l_main_run`, `l_io`, `l_timeout`. The ELL variant (`io-ell.c`) provides the same `io.h` contract over ELL primitives.
- **Raw epoll backend** (`mainloop.c`, `mainloop-notify.c`) — The native implementation using `epoll_create1`, `epoll_ctl`, `epoll_wait`, `timerfd_create`, `signalfd`. The matching `io-mainloop.c` directly interfaces with this epoll dispatcher.

All three backends conform to identical API contracts defined in `mainloop.h` (lifecycle: `mainloop_init`/`mainloop_run`/`mainloop_quit`; I/O: `mainloop_add_fd`/`mainloop_modify_fd`/`mainloop_remove_fd`; timers: `mainloop_add_timeout`/`mainloop_modify_timeout`/`mainloop_remove_timeout`; signals: `mainloop_set_signal`, `mainloop_run_with_signal`) and `io.h` (opaque `struct io` with `io_new`/`io_destroy`, read/write/disconnect handler registration via `io_set_read_handler`/`io_set_write_handler`/`io_set_disconnect_handler`, and scatter-gather `io_send`).

**Rust unification approach:**

All three backends collapse into a single `tokio::runtime::Runtime`:
- `bluetoothd`, `obexd`, `bluez-tools` — `tokio::runtime::Builder::new_multi_thread()`
- `bluetooth-meshd` — `tokio::runtime::Builder::new_current_thread()` (preserving the single-threaded model mesh requires)
- `btmon`, `bluetoothctl` — `tokio::runtime::Builder::new_current_thread()`

The `io.h` API translates to a Rust `BluetoothIo` struct wrapping `tokio::io::unix::AsyncFd<RawFd>` with:
- `set_read_handler` → `AsyncFd::readable()` awaited in a spawned task, invoking the registered callback
- `set_write_handler` → `AsyncFd::writable()` awaited in a spawned task
- `set_disconnect_handler` → HUP/ERR detection via `epoll_events` through `AsyncFd::ready()`
- `io_send` with `iovec` → `nix::sys::uio::writev` called within the writable guard

The `mainloop.h` timers translate to `tokio::time::sleep` / `tokio::time::interval` wrapped in `tokio::spawn` tasks, with cancellation via `tokio::task::JoinHandle::abort()`.

Signal handling via `mainloop_run_with_signal` / `mainloop_set_signal` becomes `tokio::signal::unix::signal(SignalKind::*)`, awaited in a dedicated signal-watcher task.

The `mainloop_sd_notify` systemd notification translates to a direct `nix::sys::socket::sendto` on the `NOTIFY_SOCKET` environment variable path.

### 0.7.2 Plugin Architecture Migration Strategy

The C plugin system operates through three mechanisms discovered in `src/plugin.h` and `src/plugin.c`:

- **Builtin plugins** — Each plugin file invokes `BLUETOOTH_PLUGIN_DEFINE(name, version, priority, init, exit)`, which emits a `const struct bluetooth_plugin_desc` named `__bluetooth_builtin_<name>`. At build time, a generated `src/builtin.h` collects all these descriptors into the `__bluetooth_builtin[]` array. At runtime, `plugin_init()` iterates this array, applies enable/disable glob filters, sorts by priority, and calls `desc->init()`.
- **External plugins** — When `EXTERNAL_PLUGINS` is defined, `external_plugin_init()` scans `PLUGINDIR` for `.so` files (excluding `lib*` prefixed names), `dlopen()`s each with `RTLD_NOW`, resolves the `bluetooth_plugin_desc` symbol via `dlsym()`, enforces a version match, and registers the plugin.
- **Priority ordering** — `BLUETOOTH_PLUGIN_PRIORITY_LOW (-100)`, `DEFAULT (0)`, `HIGH (100)` control initialization order.

**Rust migration approach:**

Builtin plugins use the `inventory` crate:
```rust
#[derive(inventory::collect)]
struct PluginDesc { /* name, priority, init, exit */ }
```

External plugins use `libloading`:
```rust
let lib = unsafe { libloading::Library::new(path)? };
let desc: libloading::Symbol<*const PluginDesc> =
    unsafe { lib.get(b"bluetooth_plugin_desc")? };
```

The `plugin_init()` function becomes:
- Collect all `inventory::iter::<PluginDesc>()` entries into a `Vec`
- Apply enable/disable glob patterns (using the `glob` crate or manual matching)
- Sort by priority (descending)
- Call `desc.init()` for each, tracking success/failure
- Scan external plugin directory if configured, using `libloading` with version enforcement

This is one of the designated `unsafe` boundary sites — the `libloading::Library::new` and `lib.get` calls require `unsafe` blocks with documented safety invariants.

### 0.7.3 D-Bus Interface Contract Migration

The C codebase uses `gdbus/` — a custom wrapper over `libdbus-1` with GLib integration. The `gdbus.h` header defines:
- Table-driven interface description (`GDBusMethodTable`, `GDBusSignalTable`, `GDBusPropertyTable`) using initializer macros (`GDBUS_METHOD`, `GDBUS_SIGNAL`, etc.)
- Service-side registration via `g_dbus_register_interface` / `g_dbus_unregister_interface`
- Signal emission via `g_dbus_emit_signal`, `g_dbus_emit_property_changed`
- Client-side proxy via `GDBusClient` / `GDBusProxy` with property caching
- ObjectManager support via `g_dbus_attach_object_manager`

**Rust migration approach using `zbus 5.x`:**

Service-side interfaces use `#[zbus::interface]` proc macros:
```rust
#[zbus::interface(name = "org.bluez.Adapter1")]
impl AdapterInterface { /* methods, properties, signals */ }
```

Key translation patterns:
- `GDBusMethodTable` entries → `#[zbus::interface]` method annotations
- `GDBusPropertyTable` entries → `#[zbus::interface]` `#[zbus(property)]` annotations
- `GDBusSignalTable` entries → `#[zbus::interface]` `#[zbus(signal)]` annotations
- `g_dbus_register_interface(conn, path, iface, methods, signals, props, data, destroy)` → `conn.object_server().at(path, iface_impl).await?`
- `g_dbus_emit_signal` → `iface_ref.signal_name(&ctxt).await?`
- `g_dbus_emit_property_changed` → `iface_ref.property_name_changed(&ctxt).await?`
- `GDBusClient` / `GDBusProxy` → `zbus::proxy::Proxy` or custom `#[zbus::proxy]` trait

**Contract verification:** The D-Bus introspection XML output from the Rust daemon is diffed against the C daemon's output to ensure byte-identical interface definitions. Every `org.bluez.*` interface documented in `doc/org.bluez.*.rst` is individually verified.

### 0.7.4 Unsafe Code Boundary Inventory

The user specifies ~80-120 `unsafe` sites, all confined to designated FFI boundary modules. Based on repository analysis, the expected `unsafe` categories and their locations in the target Rust code are:

| Category | Target Module(s) | Estimated Sites | Safety Invariant |
|---|---|---|---|
| `kernel_socket` | `bluez-shared/src/sys/socket.rs` | 15-20 | `AF_BLUETOOTH` socket creation via `libc::socket`, `bind`, `connect`, `getsockopt`, `setsockopt` with validated sockaddr structs |
| `ioctl` | `bluez-shared/src/sys/ioctl.rs` | 10-15 | HCI ioctl calls (`HCIGETDEVINFO`, `HCIGETDEVLIST`, etc.) with pre-validated buffer sizes |
| `mgmt_socket` | `bluez-shared/src/mgmt/transport.rs` | 5-8 | `HCI_CHANNEL_CONTROL` socket operations with typed command/event buffers |
| `uinput` | `bluetoothd/src/profiles/input/uinput.rs` | 5-8 | `/dev/uinput` ioctl calls (`UI_SET_EVBIT`, `UI_DEV_CREATE`, etc.) with validated `uinput_setup` structs |
| `uhid` | `bluetoothd/src/profiles/input/uhid.rs` | 5-8 | `/dev/uhid` write of `uhid_event` union with tag-checked variant selection |
| `vhci` | `bluez-emulator/src/vhci.rs` | 3-5 | `/dev/vhci` open/ioctl for virtual controller creation |
| `raw_hci` | `bluez-shared/src/sys/hci.rs` | 8-12 | Raw HCI channel socket I/O with validated packet buffers |
| `ffi_callback` | `bluetoothd/src/plugin/external.rs` | 3-5 | `libloading::Library::new` and symbol resolution with version-checked descriptors |
| `btsnoop_parsing` | `bluez-shared/src/capture/btsnoop.rs` | 3-5 | Memory-mapped file access with validated header magic and record bounds |
| `signal_handling` | `bluez-shared/src/sys/signal.rs` | 2-3 | `sigprocmask` / `sigaction` setup before tokio signal handlers take over |
| **Total** | | **~80-120** | |

Each `unsafe` block requires:
- A `// SAFETY:` comment explaining the invariant
- A corresponding `#[test]` that exercises the unsafe path
- Confinement to `sys/` or explicitly marked FFI boundary modules
- No `#[allow(...)]` annotations except `non_camel_case_types` / `non_upper_case_globals` for kernel struct compatibility in `bluez-shared/src/sys/` modules

### 0.7.5 Bluetooth Socket Abstraction Migration

The `btio/btio.h` and `btio/btio.c` provide a GLib-integrated socket abstraction using variadic option-driven configuration (`BtIOOption` enum with 30+ tokens covering address, PSM, CID, MTU, security level, mode, QoS, ISO broadcast parameters). The API surfaces:
- `bt_io_connect` — Async outgoing connection with `BtIOConnect` callback
- `bt_io_listen` — Listening socket with optional `BtIOConfirm` callback
- `bt_io_accept` — Accept and arm connection
- `bt_io_set` / `bt_io_get` — Runtime option configuration/query

This translates to a `BluetoothSocket` struct in `bluez-shared/src/sys/socket.rs`:
```rust
pub struct BluetoothSocket {
    inner: AsyncFd<OwnedFd>,
    /* socket type, addressing metadata */
}
```

Key design decisions:
- The variadic `BtIOOption` enum becomes a Rust builder pattern: `BluetoothSocket::builder().psm(1).sec_level(SecLevel::Medium).connect().await?`
- `GIOChannel` integration is replaced by `tokio::io::unix::AsyncFd` wrapping the raw Bluetooth socket fd
- Security level (`BtIOSecLevel`) becomes a Rust enum `SecLevel { Sdp, Low, Medium, High }`
- L2CAP modes (`BtIOMode`) become `enum L2capMode { Basic, Ertm, Streaming, LeFlowctl, ExtFlowctl, Iso }`
- ISO broadcast parameters (`BT_IO_OPT_QOS`, `BT_IO_OPT_BASE`, `BT_IO_OPT_ISO_BC_*`) become structured types rather than variadic arguments

### 0.7.6 Management API Async Migration

The `src/shared/mgmt.h` / `mgmt.c` provide an opaque `struct mgmt` handle with callback-based async command/event handling:
- `mgmt_send(mgmt, opcode, index, length, param, callback, user_data, destroy)` — sends a command, delivers response via callback
- `mgmt_register(mgmt, event, index, callback, user_data, destroy)` — subscribes to events
- Reference-counted via `mgmt_ref` / `mgmt_unref`
- TLV construction utilities for extended command parameters

**Rust migration approach:**

```rust
pub struct MgmtSocket {
    fd: AsyncFd<OwnedFd>,
    pending: HashMap<u16, oneshot::Sender<MgmtResponse>>,
}
```

Key transformations:
- `mgmt_send` with callback → `mgmt.send_command(opcode, index, &params).await? -> MgmtResponse`
- `mgmt_register` with callback → `mgmt.subscribe(event, index) -> mpsc::Receiver<MgmtEvent>`
- Reference counting (`mgmt_ref`/`mgmt_unref`) → `Arc<MgmtSocket>` shared ownership
- TLV utilities → Typed `MgmtTlvList` with `serde`-like serialization
- All 200+ MGMT opcodes from `lib/bluetooth/mgmt.h` become Rust enums with `#[repr(u16)]`
- All event codes become a parallel `MgmtEvent` enum
- Command parameter structs use `zerocopy::AsBytes` / `zerocopy::FromBytes` for wire-compatible serialization

### 0.7.7 HCI Emulator Architecture Migration

The `emulator/hciemu.h` defines the test infrastructure used by all integration testers. Key characteristics:
- Opaque `struct hciemu` and `struct hciemu_client` with ref-counting (`hciemu_ref`/`hciemu_unref`)
- Controller type selection via `enum hciemu_type` (dual-mode, BR/EDR-only, LE-only, versioned 5.0/5.2/6.0)
- Hook system (`hciemu_hook_type`: pre/post command, pre/post event) for packet interception
- VHCI-backed virtual controller with BD_ADDR configuration
- `btdev` virtual device implementation and `bthost` model for protocol emulation

**Rust migration approach:**

- `struct hciemu` → `pub struct HciEmulator` with `Arc`-based sharing (replacing ref-counting)
- `struct hciemu_client` → `pub struct EmulatorClient` embedded within the emulator
- Hook callbacks → Rust closures stored as `Box<dyn Fn(&[u8]) -> bool + Send + Sync>`
- `btdev` → Async task processing HCI commands and generating events via `tokio::sync::mpsc` channels
- `bthost` → State machine with typed HCI/L2CAP/ATT protocol handlers
- VHCI bridge → `unsafe` fd operations in `bluez-emulator/src/vhci.rs` wrapped in `AsyncFd`
- Controller type enum preserved identically as `#[repr(u8)] enum EmulatorType`

The tester framework (`src/shared/tester.c`) becomes a Rust test harness using standard `#[test]` + a custom `TesterContext` providing emulator setup/teardown, with `tokio::test` for async test execution.

### 0.7.8 GLib Type and Container Removal

The C codebase uses GLib container types pervasively. A systematic removal strategy is required:

| GLib Type | Occurrences (estimated) | Rust Replacement | Notes |
|---|---|---|---|
| `GList` (doubly-linked) | ~200+ | `Vec<T>` | Stable iteration order, O(1) append |
| `GSList` (singly-linked) | ~150+ | `Vec<T>` | Most usages are simple collections |
| `GHashTable` | ~100+ | `HashMap<K, V>` or `BTreeMap<K, V>` | Hash-based for general use, BTree where ordered iteration needed |
| `GString` | ~50+ | `String` | Owned UTF-8 string |
| `GMainLoop` | ~5 (per daemon) | `tokio::runtime::Runtime` | See section 0.7.1 |
| `GIOChannel` | ~30+ | `AsyncFd<OwnedFd>` | See section 0.7.5 |
| `GKeyFile` | ~10 | `rust_ini::Ini` | INI config parser, identical section/key semantics |
| `GDir` | ~5 | `std::fs::read_dir` | Directory iteration |
| `GError` | ~100+ | `Result<T, E>` with `thiserror` | Error propagation |
| `g_malloc`/`g_free` | pervasive | Owned types (`Box`, `Vec`, `String`) | Zero manual allocation |
| `g_try_new0` | ~50+ | `Box::new(T::default())` or direct construction | Zero-initialized allocation |
| `g_strdup`/`g_strndup` | ~200+ | `String::from` / `.to_owned()` / `.clone()` | Owned string copies |
| `g_idle_add`/`g_timeout_add` | ~30+ | `tokio::spawn` / `tokio::time::sleep` | Deferred/timed execution |

For `bluetooth-meshd`, ELL types follow the same pattern — `l_queue` → `Vec<T>`, `l_hashmap` → `HashMap<K, V>`, `l_io` → `AsyncFd`, `l_timeout` → `tokio::time::sleep`.

### 0.7.9 Configuration Preservation Analysis

Three configuration files must parse identically:

- **`main.conf`** — Parsed by `src/main.c` using `GKeyFile`. Sections: `[General]`, `[BR]`, `[LE]`, `[Policy]`, `[GATT]`, `[CSIS]`, `[AVDTP]`, `[AdvMon]`. Keys include `Name`, `Class`, `DiscoverableTimeout`, `PairableTimeout`, `AutoEnable`, `Privacy`, `FastConnectable`, `ControllerMode`, `MultiProfile`, `JustWorksRepairing`, `TemporaryTimeout`, `Experimental`, plus section-specific keys.
- **`input.conf`** — Parsed by `profiles/input/device.c`. Section: `[General]`. Keys: `IdleTimeout`, `ClassicBondedOnly`, `LEAutoSecurity`.
- **`network.conf`** — Parsed by `profiles/network/server.c`. Section: `[General]`. Keys: specific to PAN/BNEP configuration.

The `rust-ini` crate preserves INI semantics — sections, keys, comments, multiline values — identically. The Rust implementation must:
- Parse the same config files from `/etc/bluetooth/`
- Apply identical default values when keys are absent
- Expose identical runtime behavior observable via D-Bus properties
- Preserve comment handling for round-trip editing

### 0.7.10 Persistent Storage Format Preservation

The `settings-storage.txt` format (used in `src/storage.c` and related files) stores adapter and device state in INI-like files under `/var/lib/bluetooth/<adapter>/<device>/info`. Key structures:

- Adapter storage: `settings` file with `[General]` section containing `Discoverable`, `Pairable`, `Alias`, `Class`
- Device storage: `info` file with sections `[General]`, `[DeviceID]`, `[LinkKey]`, `[LongTermKey]`, `[SlaveLongTermKey]`, `[IdentityResolvingKey]`, `[ConnectionParameters]`, `[Attributes]`
- Cache files: `cache/<device>` with discovered service/attribute data

All file paths, section names, key names, and value formats must remain byte-identical to ensure existing Bluetooth pairings and device data survive the daemon replacement without re-pairing.


## 0.8 Refactoring Rules

### 0.8.1 Refactoring-Specific Rules

The following rules are explicitly mandated by the user and are non-negotiable:

- **Behavioral clone mandate** — The Rust output MUST be a behavioral clone of the C original at every external interface boundary. Functional equivalence is the sole completion metric.
- **All 5 binaries build and run** — `bluetoothd`, `bluetoothctl`, `btmon`, `bluetooth-meshd`, `obexd` must build and run on Linux with identical external behavior.
- **D-Bus interface identity** — `busctl introspect org.bluez /org/bluez` output MUST match the C original exactly — interface names, method signatures, property types, object paths.
- **Integration test parity** — `mgmt-tester`, `l2cap-tester`, `iso-tester`, `sco-tester` integration test suites MUST achieve the same pass rate as the C original when run against the HCI emulator.
- **Unit test parity** — All 44 unit test equivalents MUST pass as `#[test]` functions.
- **btmon decode fidelity** — `btmon` MUST decode the same packet captures identically to the C version.
- **Zero compiler warnings** — `RUSTFLAGS="-D warnings"` must produce zero warnings.
- **Zero clippy warnings** — `cargo clippy --workspace -- -D clippy::all` must produce zero warnings.
- **Zero unsafe outside FFI** — Zero `unsafe` blocks outside of designated FFI boundary modules.
- **No `#[allow(...)]` annotations** — Except on FFI boundary modules where `non_camel_case_types` or `non_upper_case_globals` are required for kernel struct compatibility.

### 0.8.2 Interface Contract Preservation

- NEVER introduce new D-Bus interfaces, methods, properties, or signals not present in the C original.
- NEVER change the Management API command set or add custom kernel interactions.
- NEVER alter wire protocol encoding for any Bluetooth protocol layer.
- NEVER change configuration key names, section names, or default values in `main.conf`, `input.conf`, or `network.conf`.
- NEVER add features, optimizations, or behavioral changes beyond what the C code does.
- Preserve all error codes, error messages, and D-Bus error names exactly.
- Preserve all object paths (`/org/bluez`, `/org/bluez/hci0`, `/org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX`).
- Preserve the persistent storage format (`settings-storage.txt`, adapter/device `info` files) to ensure existing Bluetooth pairings and device data survive daemon replacement.

### 0.8.3 Validation Gates

Eight mandatory validation gates are defined. All gates must pass before the deliverable is accepted:

**Gate 1 — End-to-End Boundary Verification:**
- Rust `bluetoothd` boots, registers on D-Bus as `org.bluez`, responds to `busctl introspect`, completes full adapter power-on sequence via Management API against HCI emulator.
- Verification artifact: `bluetoothd` running against `bluez-emulator`, with `bluetoothctl` successfully executing `power on`, `scan on`, `devices`, `power off`.

**Gate 2 — Zero-Warning Build Enforcement:**
- `RUSTFLAGS="-D warnings" cargo build --workspace --release` must succeed.
- `cargo clippy --workspace -- -D clippy::all` must succeed.

**Gate 3 — Performance Baseline Comparison:**
- `criterion` microbenchmarks and `hyperfine` binary-level benchmarks for: startup time, MGMT round-trip latency, GATT discovery time, btmon decode throughput.
- Thresholds: startup ≤ 1.5× C original, latency ≤ 1.1×, throughput ≥ 0.9×.

**Gate 4 — Named Real-World Validation Artifacts:**
- btmon capture replay: byte-identical human-readable output vs. C btmon for the same btsnoop capture file.
- mgmt-tester full suite: same pass/fail matrix as C versions.

**Gate 5 — API/Interface Contract Verification:**
- `busctl introspect` XML diff (C vs Rust) for all `org.bluez.*` interfaces — must be zero diff.
- Management API opcode coverage verified by `mgmt-tester`.
- `main.conf` parsing identity verified by comparing runtime property values.
- `bluetoothctl` CLI command set verified — every shell command present with identical names and argument parsing.

**Gate 6 — Unsafe/Low-Level Code Audit:**
- Document every `unsafe` block with: file path, line number, reason category, safety invariant comment.
- Each `unsafe` site must have a corresponding test exercising the unsafe path.
- Formal audit mandatory (count exceeds 50 threshold).

**Gate 7 — Extended Specification Tier Confirmation:**
- All 8 gates mandatory and fully specified per the complexity of this multi-subsystem daemon rewrite.

**Gate 8 — Integration Sign-Off Checklist:**
- Live smoke test: power on, scan, pair, connect, disconnect, power off — all 6 operations without error.
- API contract verification: busctl introspect XML diff — zero diff.
- Performance baseline: within specified thresholds.
- Unsafe audit: 100% coverage, all safety comments present.

### 0.8.4 Special Instructions and Constraints

- **Implementation phasing** — Recommended order: `bluez-shared` → `bluez-emulator` → `btmon` → `bluetoothd` → `bluetoothctl` → `bluez-tools` → `bluetooth-meshd` → `obexd`. Each phase must produce a building, warning-free, test-passing artifact.
- **One-phase Blitzy execution** — Despite phasing recommendations, the entire refactoring deliverable is produced in a single Blitzy execution phase. All 8 crates are built and tested together.
- **Workspace structure** — Single Cargo workspace with 8 crates. All inter-crate dependencies resolved within the workspace.
- **Rust edition** — 2024 edition, stable toolchain. No nightly features permitted.
- **Async runtime** — `tokio` is the sole async runtime. The `zbus` crate must use tokio feature (not default `async-io`).
- **bluetooth-meshd threading** — Must use `tokio::runtime::Builder::new_current_thread()` to preserve the single-threaded execution model required by the mesh stack.
- **Self-certification not accepted** — Real D-Bus clients (`busctl`, `dbus-monitor`, `bluetoothctl`) must exercise each interface. Unit test mocking does not satisfy boundary verification.
- **Measured values required** — Performance thresholds require measured values; assumed parity is not acceptable.

### 0.8.5 Out-of-Scope Exclusions (User-Specified)

- `lib/libbluetooth.so` public C library ABI — NOT rewritten. If third-party callers need it, a separate C-compatible FFI shim crate may be provided, but this is NOT a deliverable.
- Deprecated CLI tools: `hcitool`, `hciconfig`, `rfcomm`, `ciptool`, `hcidump`, `sdptool`, `gatttool` (standalone), `rctest`, `l2test`, `scotest`, `l2ping`.
- `tools/parser/` legacy protocol parsers.
- `tools/mesh-gatt/` legacy mesh GATT.
- Python test scripts in `test/`.
- CUPS printer backend (`profiles/cups/`).
- Build system migration details beyond Cargo workspace — no autotools preservation.


## 0.9 References

### 0.9.1 Codebase Files and Folders Searched

The following files and folders were systematically inspected to derive all conclusions in this Agent Action Plan:

**Top-Level Repository Structure (21 directories explored):**

| Path | Type | Purpose |
|---|---|---|
| `src/` | folder | Core daemon source (57 files) — main.c, adapter, device, service, profile, agent, plugin, GATT, SDP, advertising, battery, bearer, storage, logging, error handling |
| `src/shared/` | folder | Shared protocol library (~90 files) — ATT/GATT engines, MGMT/HCI transports, mainloop/IO/timeout backends (GLib, ELL, epoll), crypto, containers, LE Audio profiles, HFP, ASHA, utility/shell/tester |
| `profiles/` | folder | Bluetooth profile plugins (11 subdirectories, ~60 files) — audio, battery, cups, deviceinfo, gap, iap, input, midi, network, ranging, scanparam |
| `profiles/audio/` | folder | Audio profile stack (37 files) — A2DP, AVDTP, AVCTP, AVRCP, BAP, BASS, VCP, MICP, MCP, CCP, CSIP, TMAP, GMAP, ASHA, HFP, media, transport, player, telephony |
| `plugins/` | folder | Daemon plugins (6 files) — sixaxis.c, admin.c, autopair.c, hostname.c, neard.c, policy.c |
| `client/` | folder | bluetoothctl CLI source (26 files) — main.c, admin, advertising, adv_monitor, agent, assistant, gatt, hci, mgmt, player, telephony, display/print utilities |
| `monitor/` | folder | btmon packet monitor (50 files) — control hub, packet decoder, protocol dissectors (L2CAP, ATT, SDP, RFCOMM, BNEP, AVCTP, AVDTP, A2DP, LL, LMP), vendor decoders |
| `emulator/` | folder | HCI emulator (20 files) — btdev, bthost, LE emulator, SMP, hciemu harness, VHCI bridge, server, serial, PHY |
| `mesh/` | folder | bluetooth-meshd source (56 files) — mesh coordinator, node/model/net stack, crypto, provisioning, configuration server, friend, I/O backends, JSON persistence |
| `obexd/` | folder | OBEX daemon (~40 files) — src (core runtime), plugins (transport, OPP/FTP/PBAP/MAP services), client (session/transfer) |
| `attrib/` | folder | Legacy ATT/GATT client (11 files) — att encode/decode, gattrib transport, gatt procedures, gatttool |
| `btio/` | folder | Bluetooth socket abstraction (2 files) — btio.h API, btio.c implementation |
| `gdbus/` | folder | D-Bus helper library (6 files) — gdbus.h, mainloop integration, watch, object export, PolicyKit, client/proxy |
| `gobex/` | folder | OBEX protocol library (12 files) — session engine, packets, headers, app params, transfers, debug |
| `lib/` | folder | Kernel ABI header library — single child `lib/bluetooth/` |
| `lib/bluetooth/` | folder | Kernel-aligned ABI headers (~20 files) — HCI, L2CAP, RFCOMM, SCO, ISO, BNEP, HIDP, CMTP, MGMT, SDP, bluetooth.h |
| `unit/` | folder | Unit tests (~50 files) — 44 test executables + protocol engine libs + stubs |
| `tools/` | folder | Tool binaries and testers (~80 files) — controller CLIs, capture utilities, 14+ integration testers, test-runner |
| `doc/` | folder | Documentation (~90+ files) — RST manpages for D-Bus APIs, CLI tools, protocol references |
| `test/` | folder | Python test scripts (out of scope) |
| `peripheral/` | folder | Peripheral sample code (out of scope) |
| `.github/` | folder | CI workflows (out of scope) |

**Individual files inspected for detailed analysis:**

| File Path | Analysis Purpose |
|---|---|
| `src/shared/mainloop.h` | Event loop API contract — lifecycle, I/O, timers, signals |
| `src/shared/io.h` | Generic I/O wrapper API — opaque struct io, read/write/disconnect handlers |
| `src/plugin.h` | Plugin descriptor structure, priority enum, BLUETOOTH_PLUGIN_DEFINE macro |
| `src/plugin.c` | Plugin loader implementation — builtin collection, external dlopen, priority sorting |
| `gdbus/gdbus.h` | D-Bus helper library API — interface tables, service registration, signal emission, client/proxy |
| `src/shared/mgmt.h` | Management API client — opaque struct mgmt, async command/event, TLV utilities |
| `btio/btio.h` | Bluetooth socket abstraction — BtIOOption enum, security levels, L2CAP modes, connect/listen/accept |
| `emulator/hciemu.h` | HCI emulator API — emulator types, hook system, VHCI bridge, client management |

### 0.9.2 Technical Specification Sections Retrieved

| Section | Key Information Extracted |
|---|---|
| 1.1 Executive Summary | Project identity (BlueZ v5.86, GPL-2.0-or-later), business problem, stakeholders, value proposition |
| 1.2 System Overview | Integration architecture (D-Bus, kernel MGMT, systemd, PipeWire), 10 primary capabilities, major components table, core technical approach |
| 3.1 Programming Languages | ANSI C with GNU extensions throughout production code, support languages (Python, Shell, Perl, RST, YAML, XML) |
| 3.2 Frameworks & Libraries | GLib (primary for bluetoothd/obexd), ELL (bluetooth-meshd), libdbus-1, json-c, readline, ALSA, libical, libudev, internal libraries (BtIO, GDBus, GOBeX, src/shared/) |

### 0.9.3 User-Provided Attachments

No file attachments were provided for this project. All specifications were communicated via the user prompt text.

No Figma URLs or design assets were referenced — this is a headless daemon stack with no graphical user interface.

### 0.9.4 External Resources Referenced

| Resource | Purpose |
|---|---|
| BlueZ v5.86 source repository | Primary source codebase for C-to-Rust migration analysis |
| Cargo workspace documentation | Rust workspace structure and inter-crate dependency management |
| tokio crate documentation | Async runtime API for event loop unification |
| zbus 5.x crate documentation | D-Bus service/client implementation via proc macros |
| inventory crate documentation | Compile-time plugin registration via trait collection |
| libloading crate documentation | Runtime shared object loading (dlopen equivalent) |
| ring crate documentation | Cryptographic primitives (AES, CMAC, ECC) |
| nix crate documentation | POSIX syscall wrappers for socket, ioctl, signal operations |
| rust-ini crate documentation | INI configuration file parsing with GKeyFile-compatible semantics |
| zerocopy crate documentation | Zero-copy byte-level struct conversion for HCI/MGMT packed structures |
| rustyline crate documentation | Interactive CLI shell (readline replacement) |
| criterion crate documentation | Microbenchmark framework for performance gate validation |


