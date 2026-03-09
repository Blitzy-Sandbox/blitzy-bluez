// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Rust rewrite
//
// Shared library crate: protocol definitions, types, and utilities.

pub mod ad;
pub mod addr;
pub mod att;
pub mod bap;
pub mod bass;
pub mod btsnoop;
pub mod crypto;
pub mod csip;
pub mod error;
pub mod gap;
pub mod gatt;
pub mod gmap;
pub mod hci;
pub mod hfp;
pub mod io;
pub mod iso;
pub mod l2cap;
pub mod mainloop;
pub mod mcp;
pub mod mgmt;
pub mod micp;
pub mod pcap;
pub mod rfcomm;
pub mod ringbuf;
pub mod sco;
pub mod shell;
pub mod tester;
pub mod timeout;
pub mod tmap;
pub mod uuid;
pub mod util;
pub mod vcp;

// Re-export primary types at crate root for convenience
pub use addr::{BdAddr, BdAddrType};
pub use error::{AttError, Error, HciError, MgmtStatus};
pub use uuid::Uuid;
