// SPDX-License-Identifier: GPL-2.0-or-later
//
// btmon — Bluetooth packet monitor and analyzer
//
// Replaces the C monitor/ directory (~47K LOC).
// Captures HCI traffic from the Linux Bluetooth kernel subsystem
// and displays it in human-readable format with protocol-specific decoding.

pub mod analyze;
pub mod control;
pub mod display;
pub mod keys;
pub mod packet;
pub mod vendor;
