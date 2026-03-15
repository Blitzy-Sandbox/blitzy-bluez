//! Bluetooth Mesh model server implementations.
//!
//! Contains the Configuration Server (SIG Model 0x0000), Friend role,
//! Private Beacon Server (SIG Model 0x0008), and Remote Provisioning Server
//! (SIG Model 0x0004). All models register via the `MeshModelOps` trait
//! from `crate::model`.

pub mod config_server;
pub mod friend;
pub mod prv_beacon;
pub mod remote_prov;

// Re-export Configuration Server model ID constants and initializer.
pub use config_server::{CONFIG_CLI_MODEL, CONFIG_SRV_MODEL, cfgmod_server_init};

// Re-export Friend role public API functions.
pub use friend::{
    friend_clear, friend_clear_confirm, friend_poll, friend_request, friend_sub_add, friend_sub_del,
};

// Re-export Private Beacon Server model ID constants and initializer.
pub use prv_beacon::{PRV_BEACON_CLI_MODEL, PRV_BEACON_SRV_MODEL, prv_beacon_server_init};

// Re-export Remote Provisioning Server/Client model ID constants, initializers,
// and NPPI acceptor registration.
pub use remote_prov::{
    REM_PROV_CLI_MODEL, REM_PROV_SRV_MODEL, register_nppi_acceptor, remote_prov_client_init,
    remote_prov_server_init,
};
