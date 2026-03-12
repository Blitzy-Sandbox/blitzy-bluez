// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux

//! Bluetooth ATT (Attribute Protocol) layer.
//!
//! This module is a complete Rust rewrite of the following C sources from
//! BlueZ v5.86:
//!
//! - `src/shared/att-types.h` — protocol constants, opcodes, error codes,
//!   permission bitflags, GATT property bitflags, and packed PDU structures.
//! - `src/shared/att.h` — public ATT transport API declarations.
//! - `src/shared/att.c` — ATT transport implementation (opaque ref-counted
//!   `struct bt_att` / `struct bt_att_chan`).
//!
//! # Sub-modules
//!
//! - [`types`] — All ATT protocol constants, typed opcode and error enums,
//!   permission/property bitflags (via the `bitflags` crate), packed PDU
//!   structures, and security-level definitions.
//! - [`transport`] — The async ATT transport layer ([`BtAtt`]) and per-bearer
//!   channel struct ([`BtAttChan`]) with full EATT (Enhanced ATT) support.
//!
//! # Key Architectural Changes from C
//!
//! - **Ref-counting → `Arc`**: The opaque `bt_att_ref`/`bt_att_unref` pattern
//!   is replaced by `Arc<Mutex<BtAtt>>` for shared ownership.
//! - **Callbacks + `void *user_data` → async / closures / channels**: All
//!   `callback_t fn + void *user_data` pairs are replaced by boxed Rust
//!   closures (`Box<dyn Fn(…)>`) or `tokio::sync::mpsc` channels.
//! - **GLib / ELL mainloop → tokio**: `GIOChannel`, `io.h`, `timeout.h`, and
//!   `mainloop.h` are replaced by `tokio::io::unix::AsyncFd`, `tokio::time`,
//!   and spawned `tokio` tasks.
//! - **GLib containers → std**: `queue`, `GList`, `GSList` are replaced by
//!   `Vec` and `VecDeque`.
//! - **Typed enums**: Raw `#define` integer constants are complemented by
//!   Rust enums (`AttOpcode`, `AttError`, `AttSecurityLevel`) with
//!   `TryFrom<u8>` conversion for safe wire-format parsing.

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

pub mod transport;
pub mod types;

// ---------------------------------------------------------------------------
// Re-exports from `types` — protocol constants, enums, bitflags, PDU structs
// ---------------------------------------------------------------------------

pub use types::AttError;
pub use types::AttOpcode;
pub use types::AttPermissions;
pub use types::AttSecurityLevel;
pub use types::BtAttPduErrorRsp;
pub use types::GattChrcExtProperties;
pub use types::GattChrcProperties;
pub use types::GattClientFeatures;
pub use types::GattServerFeatures;

// Core protocol constants.
pub use types::BT_ATT_ALL_REQUESTS;
pub use types::BT_ATT_CID;
pub use types::BT_ATT_DEFAULT_LE_MTU;
pub use types::BT_ATT_EATT_PSM;
pub use types::BT_ATT_MAX_LE_MTU;
pub use types::BT_ATT_MAX_VALUE_LEN;
pub use types::BT_ATT_PSM;

// ---------------------------------------------------------------------------
// Re-exports from `transport` — async ATT transport and channel types
// ---------------------------------------------------------------------------

pub use transport::BtAtt;
pub use transport::BtAttChan;
