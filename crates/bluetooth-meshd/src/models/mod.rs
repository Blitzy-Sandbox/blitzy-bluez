//! Bluetooth Mesh model implementations.
//!
//! Sub-modules:
//! - `config_server` — Configuration Server model (opcodes, dispatcher, init)
//! - `friend` — Friend role (LPN support, message caching, subscription lists)
//! - `prv_beacon` — Private Beacon Server/Client model IDs and server init
//! - `remote_prov` — Remote Provisioning Server/Client models

pub mod config_server;
pub mod friend;
pub mod prv_beacon;
pub mod remote_prov;
