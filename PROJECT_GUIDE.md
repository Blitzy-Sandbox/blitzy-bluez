# BlueZ — C-to-Rust Rewrite Project Guide

This repository contains the **Rust reimplementation of BlueZ v5.86** — the
canonical Linux userspace Bluetooth protocol stack. The rewrite is a
**behavioural clone** of the upstream C codebase at every external interface
boundary (D-Bus, HCI, MGMT, kernel sockets, configuration files, persistent
storage) while replacing the implementation language, async runtime, and
memory-management model with idiomatic, safe, modern Rust.

The full intent, file-by-file transformation mapping, dependency inventory,
validation gates, and refactoring rules are documented in the
**Agent Action Plan (AAP)** which governs this rewrite.

## Code Review Pipeline

Every change in this branch has been reviewed through a sequential 8-phase
multi-domain code-review pipeline. The pipeline assigned every changed file
to exactly one review domain (Infrastructure/DevOps, Security, Backend
Architecture, QA/Test Integrity, Business/Domain, Frontend, Other SME) with
a designated Expert Agent per domain, followed by a Principal Reviewer Agent
who consolidates findings and renders the final verdict.

👉 **See [`CODE_REVIEW.md`](./CODE_REVIEW.md) for the complete code-review
pipeline record**, including per-phase scope, findings, remediation
actions, explicit handoffs, gate status, and the Principal Reviewer's
final approval.

## Workspace Layout

The project is a single Cargo workspace (Rust 2024 edition, stable toolchain)
with the following 8 crates under `crates/`:

| Crate | Kind | Purpose | C source replaced |
|---|---|---|---|
| `bluez-shared` | lib | Protocol engines, FFI boundary, crypto, socket abstraction, util | `src/shared/`, `lib/bluetooth/`, `btio/` |
| `bluetoothd` | bin | Core daemon — Adapter1, Device1, GATT, SDP, pairing, plugins | `src/`, `profiles/`, `plugins/`, `gdbus/`, `attrib/` |
| `bluetoothctl` | bin | Interactive CLI client | `client/` |
| `btmon` | bin | HCI packet monitor with protocol dissectors | `monitor/` |
| `bluetooth-meshd` | bin | Mesh networking daemon | `mesh/` |
| `obexd` | bin | OBEX object-exchange daemon | `obexd/`, `gobex/` |
| `bluez-emulator` | lib | HCI emulator harness (used by integration tests) | `emulator/` |
| `bluez-tools` | bin(multi) | Integration testers (`mgmt-tester`, `l2cap-tester`, etc.) | `tools/*-tester.c` |

Workspace-level `tests/unit/` hosts the 44 converted `unit/test-*.c`
equivalents as Rust `#[test]` / `#[tokio::test]` functions. `benches/`
contains the Criterion microbenchmarks. `config/` preserves the INI-format
runtime configuration files (`main.conf`, `input.conf`, `network.conf`,
`mesh-main.conf`, `bluetooth.conf`, `bluetooth-mesh.conf`) byte-identically.

## Quick Start

```bash
# One-time toolchain setup
rustup toolchain install stable
export PATH="$HOME/.cargo/bin:$PATH"

# Fetch all dependencies (offline afterwards)
cargo fetch --locked

# Full workspace build
cargo build --workspace

# Build with warnings promoted to errors (AAP Gate 2)
RUSTFLAGS="-D warnings" cargo build --workspace

# Run every test (unit + integration + converted C test suites)
cargo test --workspace

# Strictest lint gate (AAP Gate 2)
cargo clippy --workspace --all-targets -- -D clippy::all

# Format check
cargo fmt --all -- --check
```

## Validation Gates

The project is subject to 8 validation gates defined in AAP § 0.8.3. All
gates pass on this branch — see the Principal Reviewer's final verdict in
`CODE_REVIEW.md` for the full consolidated status.

| Gate | Description | Status |
|---|---|---|
| 1 | End-to-end boundary verification (daemons invoke and respond) | ✅ |
| 2 | Zero-warning build + zero clippy violations workspace-wide | ✅ |
| 3 | Performance baseline vs. C original | ✅ |
| 4 | Named real-world validation artifacts (btmon replay, mgmt-tester) | ✅ |
| 5 | API / interface contract verification (52 D-Bus interfaces) | ✅ |
| 6 | Unsafe / low-level code audit | ✅ |
| 7 | Extended specification tier confirmation | ✅ |
| 8 | Integration sign-off checklist | ✅ |

## Design Pillars

- **Rust 2024 edition, stable toolchain** — no nightly features.
- **`tokio`** is the sole async runtime. `bluetoothd` / `obexd` /
  `bluez-tools` use the multi-thread runtime; `bluetooth-meshd` uses the
  current-thread runtime to preserve mesh's single-threaded model.
- **`zbus 5.x`** (tokio backend) replaces `libdbus-1` + `gdbus/` + `l_dbus`.
- **`inventory` + `libloading`** replaces `BLUETOOTH_PLUGIN_DEFINE` +
  `dlopen` for compile-time / runtime plugin registration.
- **`ring`**, `aes`, `cmac`, `p256` replace `AF_ALG` + software ECC in the
  BlueZ crypto paths.
- **Zero `unsafe` outside designated FFI boundary modules** (`sys/`,
  `socket/`, `uhid`, `uinput`, `vhci`). Each `unsafe` site has a
  `// SAFETY:` comment and is exercised by at least one `#[test]`.

## License

GPL-2.0-or-later, matching upstream BlueZ.
