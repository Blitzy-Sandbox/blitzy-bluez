// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Kernel ABI type re-declarations for Bluetooth protocol constants,
// packed structures, and socket addresses. This module serves as the
// FFI boundary layer between the Rust codebase and the Linux kernel
// Bluetooth subsystem.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub mod bluetooth;
pub mod bnep;
