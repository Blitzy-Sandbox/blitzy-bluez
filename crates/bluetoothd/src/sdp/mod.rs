//! SDP (Service Discovery Protocol) subsystem.
//!
//! This module provides SDP record management including XML
//! serialisation/deserialisation, SDP server, client, and database.

pub mod client;
pub mod database;
pub mod server;
pub mod xml;

// Re-export the primary XML conversion API.
pub use xml::{SdpData, SdpRecord, XmlError, parse_record, record_to_xml};

// Re-export the SDP database and registration API.
pub use database::{
    SdpDatabase, add_record_to_server, remove_record_from_server, service_register_req,
    service_remove_req, service_update_req,
};
