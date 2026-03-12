// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ shared utility module — Rust implementation
//
// Provides endianness helpers, IoBuf buffer abstraction, LTV helpers,
// string utilities, and general-purpose functions used across the stack.

pub mod crc;
pub mod eir;
pub mod endian;
pub mod queue;
pub mod ringbuf;
pub mod uuid;

pub use self::ringbuf::RingBuf;
