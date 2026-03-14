// SPDX-License-Identifier: GPL-2.0-or-later
//
//! OBEX daemon library crate — exposes protocol modules for workspace-level tests.
//!
//! This library target exists alongside the `obexd` binary target to allow
//! workspace-level integration tests (in `tests/unit/`) to exercise OBEX
//! protocol primitives such as application parameter TLV encoding/decoding,
//! header handling, and packet construction without running the full daemon.
//!
//! The binary entry point remains in `main.rs`.

pub mod client;
pub mod obex;
pub mod server;
