// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux

//! ATT (Attribute Protocol) module.
//!
//! This module implements the Bluetooth ATT layer, providing protocol
//! constants, opcodes, error codes, permission bitflags, and transport
//! abstractions. It is a complete Rust rewrite of the C sources:
//! `src/shared/att-types.h`, `src/shared/att.h`, and `src/shared/att.c`.

pub mod types;
