// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux

//! # `bluez-shared` — Shared Bluetooth Protocol Library
//!
//! Foundational protocol library for the BlueZ Rust workspace.  This crate is
//! the shared dependency of **all** other 7 crates in the workspace
//! (`bluetoothd`, `bluetoothctl`, `btmon`, `bluetooth-meshd`, `obexd`,
//! `bluez-emulator`, `bluez-tools`).
//!
//! ## What This Crate Replaces
//!
//! This crate is a complete Rust rewrite of three C source trees from
//! BlueZ v5.86:
//!
//! - **`src/shared/`** (~90 C files) — Protocol engines (ATT, GATT, MGMT,
//!   HCI), LE Audio state machines (BAP, BASS, VCP, MCP, MICP, CCP, CSIP,
//!   TMAP, GMAP, ASHA), cryptographic primitives, containers, mainloop/I/O
//!   backends, shell framework, test harness, and utility functions.
//!
//! - **`lib/bluetooth/`** (~20 header files) — Linux kernel Bluetooth ABI
//!   constants, packed structures, and socket address definitions
//!   (`AF_BLUETOOTH`, `bdaddr_t`, `BTPROTO_*`, HCI/L2CAP/RFCOMM/SCO/ISO/
//!   BNEP/HIDP/CMTP/MGMT definitions).
//!
//! - **`btio/`** (2 C files) — GLib-integrated Bluetooth socket abstraction
//!   (`bt_io_connect`, `bt_io_listen`, `bt_io_accept`).
//!
//! ## Key Architectural Decisions
//!
//! - **Event loop unification** — The three interchangeable C mainloop
//!   backends (GLib `mainloop-glib.c`, ELL `mainloop-ell.c`, raw epoll
//!   `mainloop.c`) are **collapsed** into a single `tokio::runtime::Runtime`.
//!   All I/O, timers, and signals are managed through tokio's async
//!   primitives.
//!
//! - **GLib container removal** — `GList` → [`Vec`], `GSList` → [`Vec`],
//!   `GHashTable` → [`HashMap`](std::collections::HashMap)/
//!   [`BTreeMap`](std::collections::BTreeMap), `GString` → [`String`],
//!   `GKeyFile` → `rust-ini`, `GMainLoop` → `tokio::runtime::Runtime`.
//!
//! - **Callback elimination** — All `callback_t fn + void *user_data`
//!   patterns are replaced with `async fn`, `impl Fn` closures, or
//!   `tokio::sync::mpsc` channels.
//!
//! - **Ownership and RAII** — All opaque struct patterns
//!   (`foo_new()`/`foo_free()`) become Rust structs with `impl Drop` where
//!   needed, eliminating manual memory management entirely.  Reference
//!   counting (`foo_ref()`/`foo_unref()`) becomes `Arc<T>`.
//!
//! - **Typed enums** — Raw `#define` integer constants for HCI
//!   commands/events, MGMT opcodes, and ATT opcodes become Rust enums with
//!   `TryFrom<u8>` validation for safe wire-format parsing.
//!
//! - **Zero unsafe outside FFI boundaries** — All `unsafe` blocks are
//!   confined to the [`sys`] module (kernel socket creation, ioctl, MGMT
//!   protocol) and the [`device`] module (UHID, uinput operations).  Each
//!   `unsafe` site has a documented `// SAFETY:` comment.
//!
//! ## Module Organization
//!
//! | Module       | Purpose                                              |
//! |-------------|-------------------------------------------------------|
//! | [`sys`]      | FFI boundary: kernel ABI constants, packed structs    |
//! | [`socket`]   | Async Bluetooth socket abstraction (AsyncFd-based)    |
//! | [`att`]      | ATT protocol: opcodes, errors, async transport        |
//! | [`gatt`]     | GATT engines: in-memory DB, client, server, helpers   |
//! | [`mgmt`]     | Kernel Management API async client                    |
//! | [`hci`]      | HCI socket transport and LE crypto                    |
//! | [`audio`]    | LE Audio: BAP, BASS, VCP, MCP, MICP, CCP, CSIP, …    |
//! | [`profiles`] | Profile protocols: GAP, HFP, Battery, RAP             |
//! | [`crypto`]   | Bluetooth crypto: AES-CMAC, P-256 ECC/ECDH            |
//! | [`util`]     | Utilities: queue, ringbuf, AD, EIR, UUID, endian      |
//! | [`capture`]  | Capture formats: BTSnoop, PCAP                        |
//! | [`device`]   | Linux device helpers: UHID, uinput (unsafe FFI)       |
//! | [`shell`]    | Interactive CLI shell (rustyline-based)                |
//! | [`tester`]   | Test harness framework (`#[test]` compatible)         |
//! | [`log`]      | Structured logging via tracing + HCI log channel      |
//!
//! ## Crate-Level Re-exports
//!
//! The most frequently used types are re-exported at the crate root for
//! ergonomic access by dependent crates:
//!
//! ```rust,ignore
//! use bluez_shared::BdAddr;           // Bluetooth device address
//! use bluez_shared::BluetoothSocket;  // Async transport socket
//! use bluez_shared::BtAtt;            // ATT transport
//! use bluez_shared::GattDb;           // GATT attribute database
//! use bluez_shared::BtGattClient;     // GATT client engine
//! use bluez_shared::MgmtSocket;       // Management API client
//! ```

// ===========================================================================
// Sub-module directory declarations (12 directories)
// ===========================================================================

/// FFI boundary module — Linux kernel Bluetooth ABI constants, packed
/// structures, and socket address types.
///
/// Contains sub-modules for each protocol family: [`sys::bluetooth`],
/// [`sys::hci`], [`sys::l2cap`], [`sys::rfcomm`], [`sys::sco`], [`sys::iso`],
/// [`sys::bnep`], [`sys::hidp`], [`sys::cmtp`], [`sys::mgmt`].
///
/// This is a designated `unsafe` boundary — kernel socket creation and ioctl
/// calls require `unsafe` blocks with documented safety invariants.
/// `#[allow(non_camel_case_types)]` and `#[allow(non_upper_case_globals)]`
/// are permitted only within `sys/` modules (AAP Section 0.7.4).
pub mod sys;

/// Async Bluetooth socket abstraction wrapping `nix::sys::socket` and
/// `tokio::io::unix::AsyncFd` for L2CAP, RFCOMM, SCO, and ISO transports.
///
/// Replaces the GLib-based `btio/` C library with a type-safe builder
/// pattern.  The variadic `BtIOOption` enum from C becomes
/// [`socket::SocketBuilder`].
pub mod socket;

/// ATT (Attribute Protocol) layer — opcodes, error types, permission
/// bitflags, packed PDU structures, and the async ATT transport with
/// EATT (Enhanced ATT) multi-channel support.
///
/// Sub-modules: [`att::types`] (protocol constants), [`att::transport`]
/// (async transport with request/response matching).
pub mod att;

/// GATT (Generic Attribute Profile) engines — in-memory attribute database,
/// async GATT client with robust caching and Service Changed support,
/// GATT server for local attribute handling, and discovery utility iterators.
///
/// Sub-modules: [`gatt::db`], [`gatt::client`], [`gatt::server`],
/// [`gatt::helpers`].
pub mod gatt;

/// Kernel Bluetooth Management API client — async command/reply with typed
/// enums and event subscription via `mpsc` channels over
/// `HCI_CHANNEL_CONTROL`.
///
/// Sub-module: [`mgmt::client`] providing [`MgmtSocket`].
pub mod mgmt;

/// HCI (Host Controller Interface) transport — async socket communication
/// with command queuing and response correlation, plus HCI-assisted LE
/// cryptographic functions.
///
/// Sub-modules: [`hci::transport`] (socket I/O), [`hci::crypto`]
/// (LE Encrypt/Rand wrappers).
pub mod hci;

/// LE Audio state machines and protocol engines.
///
/// Sub-modules: [`audio::bap`] (BAP streams/PAC/ASE), [`audio::bass`]
/// (broadcast assistant), [`audio::vcp`] (volume), [`audio::mcp`] (media),
/// [`audio::micp`] (microphone), [`audio::ccp`] (call control),
/// [`audio::csip`] (coordinated sets), [`audio::tmap`] (telephony/media
/// roles), [`audio::gmap`] (gaming audio), [`audio::asha`] (hearing aids).
pub mod audio;

/// Bluetooth profile protocol modules — GAP (management capability probe),
/// HFP (AT command engine for audio gateway and hands-free), Battery
/// (charge fluctuation smoother), RAP (ranging service skeleton).
///
/// Sub-modules: [`profiles::gap`], [`profiles::hfp`],
/// [`profiles::battery`], [`profiles::rap`].
pub mod profiles;

/// Bluetooth cryptographic primitives — AES-CMAC for LE pairing, key
/// derivation, ATT signing, and GATT database hashing; P-256 ECC/ECDH
/// for LE Secure Connections key exchange.
///
/// Sub-modules: [`crypto::aes_cmac`], [`crypto::ecc`].
pub mod crypto;

/// Utility modules — [`util::queue`] (`Vec`/`VecDeque`-based queue),
/// [`util::ringbuf`] (ring buffer), [`util::ad`] (advertising data
/// builder/parser), [`util::eir`] (EIR parsing), [`util::uuid`]
/// (UUID normalization with SIG-assigned lookup tables), [`util::endian`]
/// (endianness helpers and I/O buffer), [`util::crc`] (CRC-24).
pub mod util;

/// Capture file format parsers — [`capture::btsnoop`] (BTSnoop read/write
/// with Apple PacketLogger support) and [`capture::pcap`] (PCAP + PPI
/// parsing).  Used primarily by `btmon` for packet capture and replay.
pub mod capture;

/// Linux virtual input/HID device creation helpers — [`device::uhid`]
/// (UHID for HID-over-GATT) and [`device::uinput`] (uinput for HID host
/// input injection).
///
/// This is a designated `unsafe` boundary — raw character device I/O and
/// ioctl calls require `unsafe` blocks with documented safety invariants.
pub mod device;

// ===========================================================================
// Standalone module declarations (3 modules)
// ===========================================================================

/// Interactive command shell framework using `rustyline`.
///
/// Provides command registration, tab completion, history persistence, and
/// prompt management for `bluetoothctl` and `btmon` CLIs.  Replaces the
/// GNU `readline`-based `src/shared/shell.c`.
pub mod shell;

/// Test harness framework — sequential test execution with lifecycle phases
/// (pre-setup → setup → run → teardown → post-teardown), per-test timeout
/// enforcement via `tokio::time`, ANSI-colored progress output, I/O
/// simulation via AF_UNIX SOCK_SEQPACKET socketpairs, and structured traffic
/// monitoring through the HCI logging channel.
///
/// Compatible with Rust's standard `#[test]` and `#[tokio::test]`
/// frameworks.  Used by all 44 unit tests and integration testers.
pub mod tester;

/// Structured logging via `tracing` with HCI Logging Channel transport
/// for `btmon` compatibility.
///
/// Provides two complementary logging paths: (1) `tracing` subscriber for
/// daemon console/journal output replacing C `syslog`, and (2) HCI logging
/// channel socket transport producing wire-identical datagrams to the C
/// implementation for seamless `btmon` integration.
pub mod log;

// ===========================================================================
// Crate-level re-exports — frequently used types for ergonomic access
// ===========================================================================
//
// These re-exports allow downstream crates to import commonly used types
// directly from the crate root:
//
//   use bluez_shared::BdAddr;
//   use bluez_shared::BluetoothSocket;
//   use bluez_shared::MgmtSocket;
//
// The fully qualified paths (e.g. `bluez_shared::sys::bluetooth::BdAddr`)
// remain accessible for disambiguation.

/// Bluetooth device address — the fundamental 6-byte address type used
/// throughout the entire stack for identifying controllers and remote
/// devices.
///
/// Re-exported from [`sys::bluetooth::BdAddr`].
pub use sys::bluetooth::BdAddr;

/// Async Bluetooth socket — the primary transport type for L2CAP, RFCOMM,
/// SCO, and ISO protocol connections.
///
/// Re-exported from [`socket::BluetoothSocket`].
pub use socket::BluetoothSocket;

/// ATT transport — the core Attribute Protocol transport engine supporting
/// both legacy ATT and Enhanced ATT (EATT) multi-channel bearers.
///
/// Re-exported from [`att::transport::BtAtt`].
pub use att::transport::BtAtt;

/// GATT database — in-memory service/characteristic/descriptor model with
/// CCC tracking and database hash computation.
///
/// Re-exported from [`gatt::db::GattDb`].
pub use gatt::db::GattDb;

/// GATT client engine — async service discovery with robust caching,
/// characteristic read/write operations, notification registration, and
/// Service Changed indication handling.
///
/// Re-exported from [`gatt::client::BtGattClient`].
pub use gatt::client::BtGattClient;

/// Management API socket — async command/reply interface for controlling
/// the kernel Bluetooth subsystem via `HCI_CHANNEL_CONTROL`.
///
/// Re-exported from [`mgmt::client::MgmtSocket`].
pub use mgmt::client::MgmtSocket;
