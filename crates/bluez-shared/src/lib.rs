// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ shared protocol library — Rust implementation
//
// This crate provides the foundational protocol types, FFI definitions,
// transport abstractions, and utility functions shared across all BlueZ
// workspace crates.

pub mod att;
pub mod capture;
pub mod crypto;
pub mod device;
pub mod log;
pub mod profiles;
pub mod socket;
pub mod sys;
pub mod util;
