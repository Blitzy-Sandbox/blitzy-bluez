// SPDX-License-Identifier: GPL-2.0-or-later

//! Capture backend modules for btmon.
//!
//! Provides alternative HCI packet capture sources beyond the primary
//! `HCI_CHANNEL_MONITOR` kernel socket managed by `control.rs`:
//!
//! - `hcidump` — Legacy raw HCI socket tracing fallback
//! - `jlink` — SEGGER J-Link RTT (Real-Time Transfer) backend
//! - `ellisys` — Ellisys Bluetooth Analyzer UDP injection

pub mod ellisys;
pub mod hcidump;
pub mod jlink;
