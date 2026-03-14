// SPDX-License-Identifier: GPL-2.0-or-later
//
//! OBEX server-side daemon core.
//!
//! This module provides the transport/service driver registries,
//! OBEX session engine, and server lifecycle management for the BlueZ
//! OBEX daemon.
//!
//! ## Sub-modules
//! - **transport** — Transport driver registry, `ObexServer` struct, connection acceptance
//! - **service** — Service driver registry, MIME type driver registry, OBEX session engine
//!   (placeholder — created by a separate agent)

pub mod service;
pub mod transport;
