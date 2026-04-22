//! # btmon System FFI Boundary
//!
//! Designated unsafe FFI boundary modules for btmon. All `unsafe` code in the
//! btmon crate is confined to modules within this `sys` namespace, with each
//! site documented with safety invariants and corresponding tests.
//!
//! ## Designated Sites
//!
//! - `terminal.rs` — Terminal I/O (ioctl TIOCGWINSZ, dup2/close for pager
//!   management). Category: `kernel_ioctl` + `process_control`.

pub mod terminal;
