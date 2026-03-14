// SPDX-License-Identifier: GPL-2.0-or-later
//
//! OBEX protocol engine — Rust rewrite of the BlueZ GOBeX library.
//!
//! This module implements the complete OBEX (Object Exchange) protocol:
//! - Packet encoding/decoding with opcode and response code definitions
//! - Header management with 4 encoding types (Unicode, ByteSequence, U8, U32)
//! - Application parameter TLV container
//! - Transfer lifecycle management for streaming PUT/GET operations
//! - Session runtime engine with async I/O, SRM, and authentication
//!
//! Wire format and protocol behavior are byte-identical to the C GOBeX
//! implementation to ensure interoperability.
//!
//! # Module Structure
//!
//! The OBEX engine is split across five sub-modules, each replacing a specific
//! C header/source pair from `gobex/`:
//!
//! | Rust Module   | C Origin                               | Responsibility              |
//! |---------------|----------------------------------------|-----------------------------|
//! | [`packet`]    | `gobex-packet.{c,h}`                   | Wire-format encode/decode   |
//! | [`header`]    | `gobex-header.{c,h}`                   | Header types and constants  |
//! | [`apparam`]   | `gobex-apparam.{c,h}`                  | Application parameter TLVs  |
//! | [`transfer`]  | `gobex-transfer.c`                     | PUT/GET streaming lifecycle |
//! | [`session`]   | `gobex.{c,h}`, `gobex-defs.{c,h}`, `gobex-debug.h` | Session runtime engine |
//!
//! All core types are re-exported at this module level for convenient access
//! by the rest of the `obexd` crate (server, client, and plugins modules).

// ---------------------------------------------------------------------------
// Sub-module declarations
// ---------------------------------------------------------------------------

pub mod apparam;
pub mod header;
pub mod packet;
pub mod session;
pub mod transfer;

// ---------------------------------------------------------------------------
// Re-exports: packet types and constants
// ---------------------------------------------------------------------------

pub use packet::ObexPacket;

// Request opcode constants (matching C G_OBEX_OP_*)
pub use packet::OP_ABORT;
pub use packet::OP_ACTION;
pub use packet::OP_CONNECT;
pub use packet::OP_DISCONNECT;
pub use packet::OP_GET;
pub use packet::OP_PUT;
pub use packet::OP_SESSION;
pub use packet::OP_SETPATH;

// FINAL bit constant
pub use packet::PACKET_FINAL;

// Response code constants (matching C G_OBEX_RSP_*)
pub use packet::RSP_CONTINUE;
pub use packet::RSP_SUCCESS;

// ---------------------------------------------------------------------------
// Re-exports: header types and constants
// ---------------------------------------------------------------------------

pub use header::ObexHeader;

// Header ID constants (matching C G_OBEX_HDR_*)
pub use header::HDR_ACTION;
pub use header::HDR_APPARAM;
pub use header::HDR_AUTHCHAL;
pub use header::HDR_AUTHRESP;
pub use header::HDR_BODY;
pub use header::HDR_BODY_END;
pub use header::HDR_CONNECTION;
pub use header::HDR_LENGTH;
pub use header::HDR_NAME;
pub use header::HDR_SRM;
pub use header::HDR_SRMP;
pub use header::HDR_TARGET;
pub use header::HDR_TYPE;
pub use header::HDR_WHO;

// ---------------------------------------------------------------------------
// Re-exports: application parameters
// ---------------------------------------------------------------------------

pub use apparam::ObexApparam;

// ---------------------------------------------------------------------------
// Re-exports: transfer types
// ---------------------------------------------------------------------------

pub use transfer::CompleteFunc;
pub use transfer::DataConsumer;
pub use transfer::DataProducer;
pub use transfer::ObexTransfer;

// ---------------------------------------------------------------------------
// Re-exports: session types
// ---------------------------------------------------------------------------

pub use session::DataPolicy;
pub use session::ObexError;
pub use session::ObexSession;
pub use session::TransportType;
