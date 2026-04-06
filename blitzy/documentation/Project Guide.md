# Blitzy Project Guide — BlueZ v5.86 C-to-Rust Rewrite

---

## 1. Executive Summary

### 1.1 Project Overview

This project performs a complete language-level rewrite of the BlueZ v5.86 userspace Bluetooth protocol stack from ANSI C to idiomatic Rust. The target is the entire daemon ecosystem — `bluetoothd`, `bluetoothctl`, `btmon`, `bluetooth-meshd`, and `obexd` — comprising 715 original C source files (~522,547 lines). The Rust replacement is organized as a Cargo workspace of 8 crates producing 6 binaries and 2 libraries, achieving behavioral fidelity at every external interface boundary (D-Bus, HCI/MGMT kernel API, Bluetooth wire protocols, configuration formats, and persistent storage). The rewrite replaces GLib/ELL event loops with tokio, libdbus-1/gdbus with zbus, and manual memory management with Rust ownership semantics.

### 1.2 Completion Status

```mermaid
pie title Project Completion
    "Completed (650h)" : 650
    "Remaining (112h)" : 112
```

| Metric | Value |
|--------|-------|
| **Total Project Hours** | **762** |
| **Completed Hours (AI)** | **650** |
| **Remaining Hours** | **112** |
| **Completion Percentage** | **85.3%** |

**Calculation:** 650 completed hours / (650 + 112) total hours = 650 / 762 = **85.3% complete**

### 1.3 Key Accomplishments

- ✅ All 8 Cargo workspace crates created and fully populated (253 source files, 325,161 LoC in crates)
- ✅ All 44 unit test files converted from C `test-*.c` to Rust `#[test]` (1,283 test functions, 47,807 LoC)
- ✅ 3 integration test files and 4 Criterion benchmarks created
- ✅ **ZERO-WARNING BUILD**: `RUSTFLAGS="-D warnings" cargo build --workspace` succeeds with zero errors and zero warnings
- ✅ **4,175 tests pass**, 0 failures, 27 hardware-dependent tests ignored
- ✅ **ZERO clippy warnings**: `cargo clippy --workspace` completely clean
- ✅ **ZERO formatting issues**: `cargo fmt --all -- --check` completely clean
- ✅ 701 C source files removed from all in-scope directories (only `peripheral/` out-of-scope C remains)
- ✅ Full `adapter_init()` implementation with MGMT enumeration, hotplug events, D-Bus registration
- ✅ All 6 configuration files preserved with identical INI format (`main.conf`, `input.conf`, `network.conf`, `mesh-main.conf`, `bluetooth.conf`, `bluetooth-mesh.conf`)
- ✅ Deployment infrastructure: systemd service file, install/uninstall scripts, SETUP.md
- ✅ 272 `unsafe` blocks confined to FFI boundary modules with 451 SAFETY comments
- ✅ 336 commits of iterative development, testing, and validation

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| Live D-Bus boundary verification not performed (Gate 1) | Cannot confirm runtime behavioral fidelity of daemon on real system | Human Developer | 2-3 days |
| Performance baseline comparison not run (Gate 3) | No measured evidence Rust meets ≤1.5× startup, ≤1.1× latency thresholds | Human Developer | 1-2 days |
| btmon capture replay not verified (Gate 4) | Cannot confirm byte-identical decode output vs C btmon | Human Developer | 1 day |
| busctl introspect XML diff not run (Gate 5) | D-Bus interface contract identity unverified against C daemon | Human Developer | 1-2 days |
| Formal unsafe audit document not produced (Gate 6) | 272 unsafe blocks documented inline but no standalone audit report | Human Developer | 1 day |
| Integration sign-off on real hardware not performed (Gate 7/8) | Full power-on/scan/pair/connect/disconnect cycle untested on hardware | Human Developer | 2-3 days |

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|----------------|---------------|-------------------|-------------------|-------|
| Linux system with Bluetooth HW | Hardware access | Validation gates 1, 3, 4, 5, 7, 8 require a Linux system with a physical or virtual HCI controller | Unresolved — CI environment lacks BT hardware | Human Developer |
| D-Bus system bus | System privilege | Running `bluetoothd` on system bus requires root or `bluetooth` group membership | Documented in install.sh — needs manual verification | Human Developer |
| VHCI kernel module | Kernel module | Integration tests need `/dev/vhci` for virtual HCI controller — requires `hci_vhci` module | Not loaded in CI environment | Human Developer |

### 1.6 Recommended Next Steps

1. **[High]** Set up a Linux test environment with Bluetooth hardware (or VHCI) and run the full Gate 1 boundary verification — boot `bluetoothd`, verify `busctl introspect org.bluez /org/bluez` matches C output
2. **[High]** Run Gate 5 API contract verification — diff `busctl introspect` XML output from both C and Rust daemons for all `org.bluez.*` interfaces
3. **[High]** Execute Gate 7/8 integration sign-off — perform live power on → scan → pair → connect → disconnect → power off cycle
4. **[Medium]** Run Gate 3 performance baselines — build C BlueZ, run `hyperfine` and `criterion` benchmarks, compare against Rust
5. **[Medium]** Produce Gate 6 formal unsafe audit report — enumerate all 272 unsafe blocks with file/line/category/safety-invariant
6. **[Medium]** Set up CI/CD pipeline with Cargo-native workflows for automated build, test, clippy, and format checks

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|-----------|-------|-------------|
| bluez-shared — FFI/sys module | 18 | 13 kernel ABI re-declaration files (bluetooth, hci, l2cap, rfcomm, sco, iso, bnep, hidp, cmtp, mgmt, ffi_helpers, mod) |
| bluez-shared — Socket abstraction | 6 | BluetoothSocket wrapping nix + AsyncFd for L2CAP/RFCOMM/SCO/ISO |
| bluez-shared — ATT/GATT engines | 22 | att/types, att/transport, gatt/db (2,121 LoC), gatt/client, gatt/server, gatt/helpers |
| bluez-shared — MGMT client | 8 | Async MGMT command/reply/event with typed enums (1,392 LoC) |
| bluez-shared — HCI transport + crypto | 8 | HCI socket transport, command queues, LE crypto wrappers |
| bluez-shared — Audio profiles | 24 | BAP, BASS, VCP, MCP, MICP, CCP, CSIP, TMAP, GMAP, ASHA (10 files, 16,809 LoC) |
| bluez-shared — Profile protocols | 6 | GAP, HFP AT engine, Battery service, RAP skeleton |
| bluez-shared — Crypto | 6 | AES-CMAC via aes+cmac crates, P-256 ECC via p256 crate |
| bluez-shared — Utilities | 10 | queue, ringbuf, ad, eir, uuid, endian, crc (7 files) |
| bluez-shared — Capture formats | 4 | BTSnoop read/write with Apple PacketLogger, PCAP + PPI parsing |
| bluez-shared — Device helpers | 6 | UHID device creation, uinput device creation (unsafe FFI) |
| bluez-shared — Shell, tester, log | 6 | Interactive shell (rustyline), test harness framework, structured logging (tracing) |
| bluetoothd — Main + config | 10 | Daemon entry point (tokio::main, D-Bus name acquisition), main.conf parsing via rust-ini |
| bluetoothd — Adapter | 20 | Adapter1 D-Bus interface (3,632 LoC), MGMT integration, adapter_init with hotplug |
| bluetoothd — Device | 14 | Device1 D-Bus interface (2,319 LoC), pairing/bonding state machine |
| bluetoothd — Core framework | 20 | service.rs, profile.rs (ProfileManager1), agent.rs (AgentManager1), plugin.rs (inventory + libloading) |
| bluetoothd — D-Bus interfaces | 12 | advertising.rs, adv_monitor.rs, battery.rs, bearer.rs, set.rs |
| bluetoothd — GATT subsystem | 14 | GattManager1 database (4,343 LoC), remote GATT client D-Bus export, GATT DB persistence |
| bluetoothd — SDP subsystem | 16 | SDP client, server, database, XML conversion (7,762 LoC) |
| bluetoothd — Audio profiles | 48 | All 22 audio modules: A2DP, AVDTP, AVCTP, AVRCP, BAP, BASS, VCP, MICP, MCP, CCP, CSIP, TMAP, GMAP, ASHA, HFP, media, transport, player, telephony, sink, source, control (31,077 LoC) |
| bluetoothd — Other profiles | 16 | input (HID/HOGP), network (PAN/BNEP), battery (BAS), deviceinfo (DIS), gap, midi, ranging, scanparam |
| bluetoothd — Daemon plugins | 12 | sixaxis, admin, autopair, hostname, neard, policy (6,972 LoC) |
| bluetoothd — Legacy GATT | 6 | ATT encode/decode, GATT procedures, GAttrib transport (from attrib/) |
| bluetoothd — Infrastructure | 8 | storage.rs, error.rs, dbus_common.rs, rfkill.rs, log.rs |
| bluetoothctl crate | 30 | 13 modules (21,794 LoC): main, admin, advertising, adv_monitor, agent, assistant, display, gatt, hci, mgmt, player, print, telephony |
| btmon crate | 48 | 30 modules (34,577 LoC): control, packet, display, analyze, 10 dissectors, 3 vendor decoders, 3 backends, hwdb, keys, crc |
| bluetooth-meshd crate | 52 | 29 modules (38,459 LoC): mesh core, node, model, net, crypto, provisioning, config models, I/O backends, JSON persistence |
| obexd crate | 36 | 23 modules (25,434 LoC): OBEX protocol (packet/header/apparam/transfer/session), server, 7 service plugins, client subsystem |
| bluez-emulator crate | 22 | 10 modules (16,345 LoC): btdev, bthost, LE emulator, SMP, hciemu, vhci, server, serial, phy |
| bluez-tools crate | 32 | 13 modules (31,666 LoC): shared tester infrastructure + 12 integration tester binaries |
| Unit tests (44 files) | 56 | 1,283 #[test] functions (47,807 LoC) converting all unit/test-*.c files |
| Integration tests + benchmarks | 10 | 3 integration tests (smoke, D-Bus contract, btsnoop replay) + 4 Criterion benchmarks (2,062 LoC) |
| Workspace infrastructure | 8 | Cargo.toml (workspace), 8 per-crate Cargo.toml, rust-toolchain.toml, clippy.toml, rustfmt.toml, Cargo.lock |
| Configuration preservation | 4 | 6 config files: main.conf, input.conf, network.conf, mesh-main.conf, bluetooth.conf, bluetooth-mesh.conf |
| Deployment infrastructure | 4 | systemd/bluetooth.service, scripts/install.sh, scripts/uninstall.sh, SETUP.md |
| Validation & QA fixes | 28 | 336 commits of iterative bug fixing, clippy compliance, formatting, deadlock resolution, adapter_init implementation |
| **Total Completed** | **650** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|----------|-------|----------|
| Gate 1 — Live D-Bus boundary verification (boot daemon, busctl introspect, adapter power-on sequence) | 16 | High |
| Gate 5 — API contract verification (busctl introspect XML diff for all org.bluez.* interfaces, main.conf property comparison) | 12 | High |
| Gate 7/8 — Integration sign-off testing (live smoke test: power on, scan, pair, connect, disconnect, power off on real HW) | 16 | High |
| Gate 3 — Performance baseline comparison (build C original, run hyperfine + criterion benchmarks, verify thresholds) | 12 | Medium |
| Gate 4 — btmon capture replay verification (run same btsnoop captures through C and Rust btmon, diff output) | 8 | Medium |
| Gate 6 — Formal unsafe code audit (document all 272 unsafe blocks: file, line, category, safety invariant) | 8 | Medium |
| Storage format compatibility testing (test existing Bluetooth pairings/device data survive daemon replacement) | 6 | Medium |
| CI/CD pipeline setup (Cargo-native GitHub Actions workflows for build, test, clippy, fmt, release artifacts) | 8 | Medium |
| Documentation review (verify doc/*.rst accuracy against Rust implementation, update as needed) | 6 | Low |
| Real-world hardening (error recovery under load, edge cases, race conditions, multi-device scenarios) | 12 | Low |
| Production environment testing (systemd integration on multiple distros, D-Bus policy verification, SELinux/AppArmor) | 8 | Low |
| **Total Remaining** | **112** | |

---

## 3. Test Results

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---------------|-----------|-------------|--------|--------|------------|-------|
| Unit Tests — bluez-shared | Rust #[test] | 824 | 824 | 0 | — | Protocol engines, crypto, utilities |
| Unit Tests — bluetoothd | Rust #[test] | 426 | 426 | 0 | — | Daemon core, D-Bus interfaces, plugins |
| Unit Tests — btmon | Rust #[test] | 4 | 4 | 0 | — | CRC, dissector helpers |
| Unit Tests — bluetooth-meshd | Rust #[test] | 11 | 11 | 0 | — | Mesh crypto, provisioning |
| Unit Tests — obexd | Rust #[test] | 16 | 16 | 0 | — | OBEX packet, header, apparam |
| Unit Tests — bluez-emulator | Rust #[test] | 0 | 0 | 0 | — | Hardware-dependent (6 ignored) |
| Unit Tests — bluez-tools | Rust #[test] | 0 | 0 | 0 | — | Requires VHCI (3 ignored) |
| Workspace Unit Tests (test_att … test_vcp) | Rust #[test] | 2,825 | 2,825 | 0 | — | 44 converted test suites from unit/test-*.c |
| Integration Tests | Rust #[tokio::test] | 38 | 38 | 0 | — | Smoke test, D-Bus contract, btsnoop replay |
| Doc Tests | Rust doctest | 31 | 31 | 0 | — | Inline code examples in documentation |
| Compilation Gate | RUSTFLAGS="-D warnings" | 8 crates | 8 | 0 | 100% | Zero warnings across all crates |
| Clippy Lint Gate | cargo clippy | 8 crates | 8 | 0 | 100% | Zero clippy warnings |
| Format Gate | cargo fmt --check | All files | Pass | 0 | 100% | Zero formatting issues |
| **Totals** | | **4,175 + 27 ignored** | **4,175** | **0** | | **100% pass rate on executable tests** |

*Note: 27 tests are `#[ignore]` due to hardware dependencies (VHCI kernel module, /dev/uhid, ALSA sequencer) — these are expected to pass on a properly configured Linux system with Bluetooth hardware.*

---

## 4. Runtime Validation & UI Verification

### Runtime Health

- ✅ `cargo build --workspace` — All 8 crates compile successfully
- ✅ `RUSTFLAGS="-D warnings" cargo build --workspace` — Zero warnings enforcement passes
- ✅ `cargo test --workspace --exclude bluetoothctl` — 4,175 tests pass, 0 failures
- ✅ `cargo clippy --workspace` — Zero lint warnings
- ✅ `cargo fmt --all -- --check` — Zero formatting deviations
- ✅ Configuration files parse correctly (INI format preserved)
- ✅ Workspace dependency resolution — all inter-crate dependencies resolve correctly
- ⚠️ Daemon runtime not verified — requires Linux with D-Bus system bus and Bluetooth hardware
- ⚠️ `bluetoothctl` excluded from test suite — requires TTY/readline interaction

### UI Verification (CLI — bluetoothctl)

- ✅ `bluetoothctl` binary compiles as part of workspace build
- ✅ 13 command modules implemented (admin, advertising, adv_monitor, agent, assistant, gatt, hci, mgmt, player, telephony, display, print)
- ✅ Shell framework uses `rustyline` (replacing GNU readline)
- ⚠️ Interactive CLI testing requires manual verification on a live system
- ❌ No automated CLI regression tests (would require PTY-based testing)

### API Integration

- ✅ D-Bus interfaces implemented via `zbus 5.x` `#[zbus::interface]` proc macros
- ✅ All `org.bluez.*` interface names, method signatures, and property types match AAP specification
- ✅ `org.bluez.Adapter1`, `Device1`, `GattManager1`, `LEAdvertisingManager1`, `AgentManager1`, etc. all present
- ⚠️ `busctl introspect` XML diff not performed — requires running daemon on system D-Bus
- ⚠️ ObjectManager integration not verified at runtime

---

## 5. Compliance & Quality Review

| AAP Requirement | Status | Evidence | Notes |
|----------------|--------|----------|-------|
| 8 Cargo workspace crates (6 bin, 2 lib) | ✅ Pass | `crates/` directory with 8 subdirectories, Cargo.toml workspace members | All crates present per AAP §0.4.1 |
| bluez-shared protocol library | ✅ Pass | 64 files, 67,550 LoC covering sys/, socket/, att/, gatt/, mgmt/, hci/, audio/, profiles/, crypto/, util/, capture/, device/, shell, tester, log | Matches AAP §0.5.1 file-by-file mapping |
| bluetoothd core daemon | ✅ Pass | 71 files, 89,336 LoC with main, adapter, device, service, profile, agent, plugin, GATT, SDP, all profiles, all plugins | All AAP-specified modules present |
| bluetoothctl CLI client | ✅ Pass | 13 files, 21,794 LoC with all command modules | Matches AAP client/ file list |
| btmon packet monitor | ✅ Pass | 30 files, 34,577 LoC with all dissectors, vendor decoders, backends | Matches AAP monitor/ mapping |
| bluetooth-meshd mesh daemon | ✅ Pass | 29 files, 38,459 LoC with mesh core, provisioning, models, I/O backends | Matches AAP mesh/ mapping |
| obexd OBEX daemon | ✅ Pass | 23 files, 25,434 LoC with OBEX protocol, server, plugins, client | Matches AAP obexd/ + gobex/ mapping |
| bluez-emulator HCI emulator | ✅ Pass | 10 files, 16,345 LoC | Matches AAP emulator/ mapping |
| bluez-tools integration testers | ✅ Pass | 13 files, 31,666 LoC with 12 tester binaries | All AAP-specified testers present |
| 44 unit test conversions | ✅ Pass | tests/unit/test_*.rs — 44 files, 1,283 #[test] functions | Matches AAP unit/test-*.c list |
| Zero compiler warnings (Gate 2) | ✅ Pass | `RUSTFLAGS="-D warnings"` build succeeds | Verified in validation |
| Zero clippy warnings (Gate 2) | ✅ Pass | `cargo clippy --workspace` clean | Verified in validation |
| Configuration file preservation | ✅ Pass | config/ directory with all 6 files | INI format identical |
| GLib/ELL removal | ✅ Pass | No GLib or ELL dependencies in Cargo.toml | tokio replaces all event loops |
| D-Bus via zbus 5.x | ✅ Pass | `#[zbus::interface]` proc macros used throughout | Replaces gdbus/ + libdbus-1 |
| Plugin framework (inventory + libloading) | ✅ Pass | crates/bluetoothd/src/plugin.rs | Replaces BLUETOOTH_PLUGIN_DEFINE |
| Unsafe confinement to FFI modules | ✅ Pass | 272 unsafe blocks, 451 SAFETY comments, all in sys/, device/, socket/ modules | Per AAP §0.7.4 |
| E2E boundary verification (Gate 1) | ⚠️ Partial | Code implemented, adapter_init works | Needs live D-Bus + HCI testing |
| Performance baseline (Gate 3) | ⚠️ Partial | Benchmarks created but no C comparison | Needs measured values |
| btmon replay fidelity (Gate 4) | ⚠️ Partial | btsnoop module implemented | Needs byte-identical output diff |
| API contract diff (Gate 5) | ⚠️ Partial | D-Bus interfaces present | Needs busctl introspect XML diff |
| Unsafe formal audit (Gate 6) | ⚠️ Partial | Inline SAFETY comments present | Needs standalone audit document |
| Integration sign-off (Gate 7/8) | ❌ Not verified | Smoke test written but not executed on hardware | Requires Linux + BT HW |

### Fixes Applied During Validation

- Resolved adapter driver deadlock by changing `BtdAdapterDriver` trait to accept `Arc<tokio::sync::Mutex<BtdAdapter>>` instead of `&BtdAdapter`
- Updated 5 driver implementations (admin, autopair, hostname, policy, a2dp) for new trait signatures
- Fixed nested runtime panics in obexd by wrapping `block_on` calls with `block_in_place`
- Resolved 37 QA findings for documentation accuracy and D-Bus interface parity
- Fixed 7 QA findings from unsafe code audit
- Applied rustfmt formatting across entire workspace
- Implemented full `adapter_init()` with MGMT READ_INDEX_LIST, hotplug subscription, and D-Bus registration

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|------------|--------|
| D-Bus interface contract mismatch (method signatures, property types, or object paths differ from C daemon) | Technical | High | Medium | Run busctl introspect XML diff on live system; automated D-Bus contract test exists in tests/integration/dbus_contract_test.rs | Open — needs live verification |
| Behavioral divergence in MGMT API handling (event ordering, error code mapping) | Technical | High | Medium | Run mgmt-tester full suite against VHCI; compare pass/fail matrix with C version | Open — needs VHCI environment |
| Performance regression exceeding AAP thresholds (startup >1.5×, latency >1.1×) | Technical | Medium | Low | Criterion benchmarks created; compare against C baseline with hyperfine | Open — needs baseline measurement |
| Unsafe code soundness issues (memory safety in FFI boundary) | Security | High | Low | 272 unsafe blocks all have SAFETY comments; confined to sys/, device/, socket/ modules; formal audit pending | Open — needs formal audit |
| Missing error paths in D-Bus method handlers (unhandled Result variants) | Technical | Medium | Low | All D-Bus methods return Result<T, zbus::fwError>; comprehensive error mapping in error.rs | Mitigated — code reviewed |
| Persistent storage format incompatibility (existing pairings lost on daemon replacement) | Operational | High | Medium | storage.rs preserves textfile format; needs testing with real /var/lib/bluetooth/ data | Open — needs testing |
| Configuration parsing edge cases (main.conf keys with whitespace, comments, multiline values) | Technical | Medium | Low | rust-ini handles standard INI semantics; main.conf test coverage in unit tests | Partially mitigated |
| VHCI kernel module unavailability in CI/CD environments | Integration | Medium | High | Integration tests gracefully skip (27 ignored); requires manual gate validation | Known limitation |
| External plugin loading via libloading (ABI compatibility with C plugin descriptors) | Integration | Medium | Low | Version checking enforced in plugin.rs; libloading safety documented | Mitigated — needs testing |
| tokio runtime configuration mismatch (multi-thread vs current-thread for mesh daemon) | Technical | Medium | Low | bluetooth-meshd uses new_current_thread() per AAP §0.7.1; bluetoothd uses multi-thread | Mitigated |
| systemd service conflicts with stock BlueZ bluetooth.service | Operational | Medium | Medium | Conflicts=bluetooth.service in unit file; install.sh disables stock service | Mitigated — needs distro testing |
| Missing ALSA integration for BLE-MIDI bridge profile | Integration | Low | Medium | alsa crate dependency present; actual ALSA sequencer interaction needs testing | Open |

---

## 7. Visual Project Status

```mermaid
pie title Project Hours Breakdown
    "Completed Work" : 650
    "Remaining Work" : 112
```

### Remaining Hours by Category

| Category | Hours |
|----------|-------|
| Gate 1 — D-Bus boundary verification | 16 |
| Gate 5 — API contract verification | 12 |
| Gate 7/8 — Integration sign-off | 16 |
| Gate 3 — Performance baseline | 12 |
| Gate 4 — btmon capture replay | 8 |
| Gate 6 — Unsafe formal audit | 8 |
| Storage format compatibility | 6 |
| CI/CD pipeline setup | 8 |
| Documentation review | 6 |
| Real-world hardening | 12 |
| Production environment testing | 8 |
| **Total** | **112** |

### Priority Distribution

```mermaid
pie title Remaining Work by Priority
    "High Priority" : 44
    "Medium Priority" : 42
    "Low Priority" : 26
```

---

## 8. Summary & Recommendations

### Achievement Summary

The BlueZ v5.86 C-to-Rust rewrite has achieved **85.3% completion** (650 hours completed out of 762 total project hours). The autonomous agents produced a fully compilable Cargo workspace of 8 crates containing 253 Rust source files (325,161 lines of code) plus 44 unit test files (47,807 LoC), 3 integration tests, and 4 benchmarks. All 701 in-scope C source files have been deleted and replaced. The build produces zero warnings, zero clippy violations, and zero formatting issues. A total of 4,175 tests pass with zero failures.

### Remaining Gaps

The primary remaining work (112 hours) centers on **runtime behavioral verification** — the AAP's fundamental requirement that the Rust output be a "behavioral clone at every external interface boundary." While all code is written and compiles, the following gates remain unverified due to the need for a Linux environment with Bluetooth hardware (or VHCI kernel module):

1. **Live D-Bus boundary verification** (Gate 1) — 16h
2. **API contract XML diffing** (Gate 5) — 12h
3. **Integration sign-off on real hardware** (Gate 7/8) — 16h
4. **Performance baseline comparison** (Gate 3) — 12h
5. **btmon decode fidelity** (Gate 4) — 8h
6. **Formal unsafe audit** (Gate 6) — 8h

### Critical Path to Production

1. Provision a Linux test environment with Bluetooth hardware and VHCI kernel module
2. Execute Gates 1 and 5 — boot daemon, run busctl introspect diff
3. Execute Gates 7/8 — full smoke test lifecycle
4. Execute Gate 3 — measure and compare performance against C baseline
5. Execute Gates 4 and 6 — btmon replay and unsafe audit
6. Test storage format compatibility with existing paired devices
7. Set up CI/CD pipeline and deploy to staging

### Production Readiness Assessment

The codebase is **structurally complete and quality-verified** at the build/test/lint level. The path to production requires approximately 112 hours of human-led validation, primarily in environments with Bluetooth hardware access that was unavailable to the autonomous agents. The code quality (zero warnings, zero clippy issues, 4,175 passing tests) provides a strong foundation for the remaining verification work.

---

## 9. Development Guide

### System Prerequisites

- **Operating System:** Linux (kernel 5.x+ with `CONFIG_BT`, `CONFIG_BT_HCIBTUSB`, `CONFIG_BT_HCIVHCI`)
- **Rust Toolchain:** Stable (Rust 2024 edition) — managed via `rust-toolchain.toml`
- **System Libraries:**
  - `libasound2-dev` (ALSA headers for BLE-MIDI)
  - `libdbus-1-dev` (D-Bus headers for zbus build)
  - `pkg-config`
- **Optional:**
  - Bluetooth hardware (USB dongle or integrated) for live testing
  - `hci_vhci` kernel module for virtual controller testing

### Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd blitzy-bluez

# Install Rust toolchain (if not present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Install system dependencies (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y libasound2-dev libdbus-1-dev pkg-config

# Verify Rust version (should be 1.85+ stable)
rustc --version
cargo --version
```

### Build

```bash
# Debug build (all 8 crates)
cargo build --workspace

# Release build with zero-warning enforcement
RUSTFLAGS="-D warnings" cargo build --workspace --release

# Build specific crate
cargo build -p bluetoothd --release
```

### Run Tests

```bash
# Run all tests (excluding bluetoothctl which needs TTY)
cargo test --workspace --exclude bluetoothctl --no-fail-fast

# Run specific test suite
cargo test --test test_gatt
cargo test --test test_crypto
cargo test --test test_sdp

# Run clippy lint check
cargo clippy --workspace

# Run format check
cargo fmt --all -- --check
```

### Run Benchmarks

```bash
# Run all Criterion benchmarks
cargo bench --workspace

# Run specific benchmark
cargo bench --bench startup
cargo bench --bench mgmt_latency
cargo bench --bench gatt_discovery
cargo bench --bench btmon_throughput
```

### Install and Run Daemon

```bash
# Build release binary
cargo build -p bluetoothd --release

# Install (requires root)
sudo ./scripts/install.sh

# Verify service is running
systemctl status blitzy-bluetooth
busctl introspect org.bluez /org/bluez

# Uninstall
sudo ./scripts/uninstall.sh
```

### Verification Steps

```bash
# 1. Verify build succeeds with zero warnings
RUSTFLAGS="-D warnings" cargo build --workspace --release
# Expected: "Finished `release` profile..."

# 2. Verify all tests pass
cargo test --workspace --exclude bluetoothctl --no-fail-fast 2>&1 | grep "test result"
# Expected: All lines show "ok. N passed; 0 failed"

# 3. Verify clippy is clean
cargo clippy --workspace
# Expected: No warnings output

# 4. Verify daemon boots (requires D-Bus and BT hardware)
sudo target/release/bluetoothd &
busctl introspect org.bluez /org/bluez
# Expected: Adapter1, AgentManager1, etc. interfaces listed
```

### Troubleshooting

| Issue | Resolution |
|-------|-----------|
| `error: linker 'cc' not found` | Install build-essential: `sudo apt-get install -y build-essential` |
| `alsa-sys build fails` | Install ALSA dev headers: `sudo apt-get install -y libasound2-dev` |
| `zbus build fails with dbus error` | Install D-Bus dev headers: `sudo apt-get install -y libdbus-1-dev pkg-config` |
| `27 tests ignored` | These require hardware (VHCI, /dev/uhid, ALSA) — expected in CI |
| `bluetoothctl tests excluded` | Requires interactive TTY — test manually |
| `Permission denied` on daemon start | Run as root or add user to `bluetooth` group |
| `Adapter not found` | Verify Bluetooth hardware: `hciconfig` or `rfkill list bluetooth` |

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---------|---------|
| `cargo build --workspace` | Build all 8 crates (debug) |
| `RUSTFLAGS="-D warnings" cargo build --workspace --release` | Release build with zero-warning enforcement |
| `cargo test --workspace --exclude bluetoothctl --no-fail-fast` | Run all tests |
| `cargo test --test test_gatt` | Run specific test suite |
| `cargo clippy --workspace` | Lint check |
| `cargo fmt --all -- --check` | Format check |
| `cargo bench --workspace` | Run all benchmarks |
| `cargo build -p bluetoothd --release` | Build daemon only |
| `sudo ./scripts/install.sh` | Install daemon as systemd service |
| `sudo ./scripts/uninstall.sh` | Uninstall daemon |

### B. Port Reference

| Service | Port/Socket | Description |
|---------|-------------|-------------|
| bluetoothd | D-Bus system bus (`org.bluez`) | Bluetooth daemon D-Bus service |
| bluetooth-meshd | D-Bus system bus (`org.bluez.mesh`) | Mesh daemon D-Bus service |
| obexd | D-Bus session bus (`org.bluez.obex`) | OBEX daemon D-Bus service |
| btmon | HCI monitor channel | Bluetooth packet monitor |
| bluetoothctl | D-Bus client | Interactive CLI client |

### C. Key File Locations

| Path | Description |
|------|-------------|
| `Cargo.toml` | Workspace manifest with all members and shared deps |
| `crates/bluez-shared/` | Shared protocol library (64 .rs files) |
| `crates/bluetoothd/` | Core Bluetooth daemon (71 .rs files) |
| `crates/bluetoothctl/` | Interactive CLI client (13 .rs files) |
| `crates/btmon/` | Packet monitor (30 .rs files) |
| `crates/bluetooth-meshd/` | Mesh daemon (29 .rs files) |
| `crates/obexd/` | OBEX daemon (23 .rs files) |
| `crates/bluez-emulator/` | HCI emulator library (10 .rs files) |
| `crates/bluez-tools/` | Integration testers (13 .rs files) |
| `tests/unit/` | 44 unit test files |
| `tests/integration/` | 3 integration test files |
| `benches/` | 4 Criterion benchmark files |
| `config/` | 6 configuration files (main.conf, input.conf, etc.) |
| `systemd/bluetooth.service` | systemd unit file |
| `scripts/install.sh` | Installation script |
| `scripts/uninstall.sh` | Uninstallation script |

### D. Technology Versions

| Technology | Version | Purpose |
|------------|---------|---------|
| Rust | Stable (2024 edition) | Primary language |
| tokio | 1.50 | Async runtime |
| zbus | 5.12 | D-Bus service/client |
| nix | 0.29 | POSIX syscalls |
| libc | 0.2 | C type definitions |
| ring | 0.17 | Cryptographic primitives |
| rust-ini | 0.21 | INI config parsing |
| serde | 1.0 | Serialization |
| tracing | 0.1 | Structured logging |
| rustyline | 14 | Interactive shell |
| inventory | 0.3 | Plugin registration |
| libloading | 0.8 | External plugin loading |
| criterion | 0.5 | Benchmarking |
| zerocopy | 0.8 | Zero-copy struct conversion |
| bitflags | 2.6 | Type-safe bitfields |
| bytes | 1.7 | Byte buffer management |
| thiserror | 2.0 | Error derive macro |
| aes | 0.8 | AES-ECB block cipher |
| cmac | 0.7 | AES-CMAC |
| ccm | 0.5 | AES-CCM for mesh |
| p256 | 0.13 | P-256 ECC/ECDH |
| alsa | 0.9 | ALSA sequencer |

### E. Environment Variable Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `RUSTFLAGS` | (none) | Set to `-D warnings` for zero-warning enforcement |
| `BLUETOOTH_SYSTEM_BUS_ADDRESS` | (system default) | Override D-Bus system bus address |
| `NOTIFY_SOCKET` | (set by systemd) | systemd notification socket path |
| `STORAGEDIR` | `/var/lib/bluetooth` | Persistent storage directory for adapter/device data |
| `CONFIGDIR` | `/etc/bluetooth` | Configuration directory for main.conf, input.conf, etc. |

### F. Developer Tools Guide

| Tool | Command | Purpose |
|------|---------|---------|
| `cargo build` | `cargo build --workspace` | Compile all crates |
| `cargo test` | `cargo test --workspace --exclude bluetoothctl` | Run test suite |
| `cargo clippy` | `cargo clippy --workspace` | Lint analysis |
| `cargo fmt` | `cargo fmt --all -- --check` | Format verification |
| `cargo bench` | `cargo bench --workspace` | Performance benchmarks |
| `cargo doc` | `cargo doc --workspace --no-deps` | Generate API documentation |
| `busctl` | `busctl introspect org.bluez /org/bluez` | D-Bus interface inspection |
| `dbus-monitor` | `dbus-monitor --system "sender='org.bluez'"` | D-Bus traffic monitoring |
| `btmon` | `target/release/btmon` | Bluetooth packet monitor |

### G. Glossary

| Term | Definition |
|------|-----------|
| AAP | Agent Action Plan — the specification driving this rewrite |
| ATT | Attribute Protocol — low-level Bluetooth LE data transport |
| BAP | Basic Audio Profile — LE Audio stream management |
| GATT | Generic Attribute Profile — Bluetooth LE service discovery |
| HCI | Host Controller Interface — kernel-level Bluetooth command protocol |
| MGMT | Management API — Linux kernel Bluetooth management interface |
| VHCI | Virtual HCI — kernel module for virtual Bluetooth controllers |
| UHID | User-space HID — kernel interface for virtual HID devices |
| AVDTP | Audio/Video Distribution Transport Protocol |
| AVRCP | Audio/Video Remote Control Profile |
| CSIP | Coordinated Set Identification Profile |
| OBEX | Object Exchange — file/data transfer protocol |
| PAN | Personal Area Networking — Bluetooth network profile |
| SDP | Service Discovery Protocol |
| zbus | Rust D-Bus library using proc macros |
| tokio | Rust asynchronous runtime |