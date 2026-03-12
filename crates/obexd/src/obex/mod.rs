// SPDX-License-Identifier: GPL-2.0-or-later
//
//! OBEX protocol engine — Rust rewrite of the BlueZ GOBeX library.
//!
//! This module implements the complete OBEX (Object Exchange) protocol:
//! - Header management with 4 encoding types (Unicode, ByteSequence, U8, U32)
//! - Application parameter TLV container
//!
//! Wire format and protocol behavior are byte-identical to the C GOBeX
//! implementation to ensure interoperability.

pub mod apparam;
pub mod header;
pub mod packet;
pub mod session;
