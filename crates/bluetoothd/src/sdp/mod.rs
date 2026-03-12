//! SDP (Service Discovery Protocol) subsystem.
//!
//! This module provides SDP record management including XML
//! serialisation/deserialisation, SDP server, client, and database.

pub mod client;
pub mod xml;

// Re-export the primary XML conversion API.
pub use xml::{SdpData, SdpRecord, XmlError, parse_record, record_to_xml};
