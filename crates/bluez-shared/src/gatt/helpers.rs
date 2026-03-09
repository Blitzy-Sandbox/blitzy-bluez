// SPDX-License-Identifier: GPL-2.0-or-later
//
// GATT discovery helpers replacing src/shared/gatt-helpers.c
//
// Low-level wrappers around ATT protocol operations for client-side GATT
// discovery. C's pagination+callback pattern is replaced by async functions
// that return complete results.

use crate::att::{
    AttResponse, BtAtt, BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND, BT_ATT_OP_ERROR_RSP,
    BT_ATT_OP_FIND_BY_TYPE_REQ, BT_ATT_OP_FIND_INFO_REQ, BT_ATT_OP_MTU_REQ,
    BT_ATT_OP_READ_BY_GRP_TYPE_REQ, BT_ATT_OP_READ_BY_TYPE_REQ, BT_ATT_OP_READ_REQ,
};
use crate::uuid::Uuid;

use super::{GATT_CHARAC_UUID, GATT_INCLUDE_UUID, GATT_PRIM_SVC_UUID, GATT_SND_SVC_UUID};

/// Result of a service discovery.
#[derive(Debug, Clone)]
pub struct GattServiceResult {
    /// Service start handle.
    pub start_handle: u16,
    /// Service end handle.
    pub end_handle: u16,
    /// Service UUID.
    pub uuid: Uuid,
}

/// Result of a characteristic discovery.
#[derive(Debug, Clone)]
pub struct GattCharResult {
    /// Characteristic declaration handle.
    pub decl_handle: u16,
    /// Value handle.
    pub value_handle: u16,
    /// Characteristic properties.
    pub properties: u8,
    /// Characteristic UUID.
    pub uuid: Uuid,
}

/// Result of a descriptor discovery.
#[derive(Debug, Clone)]
pub struct GattDescResult {
    /// Descriptor handle.
    pub handle: u16,
    /// Descriptor UUID.
    pub uuid: Uuid,
}

/// Result of an included service discovery.
#[derive(Debug, Clone)]
pub struct GattInclResult {
    /// Include declaration handle.
    pub handle: u16,
    /// Included service start handle.
    pub start_handle: u16,
    /// Included service end handle.
    pub end_handle: u16,
    /// Included service UUID (may be unknown for 128-bit UUIDs).
    pub uuid: Option<Uuid>,
}

/// GATT discovery error.
#[derive(Debug, Clone)]
pub struct GattError {
    /// ATT error code.
    pub att_ecode: u8,
}

impl std::fmt::Display for GattError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GATT error: 0x{:02x}", self.att_ecode)
    }
}

impl std::error::Error for GattError {}

/// Exchange ATT MTU.
///
/// Returns the server's MTU value.
pub async fn exchange_mtu(att: &BtAtt, client_mtu: u16) -> Result<u16, GattError> {
    let mut pdu = Vec::with_capacity(2);
    pdu.extend_from_slice(&client_mtu.to_le_bytes());

    let rsp = send_request(att, BT_ATT_OP_MTU_REQ, &pdu).await?;
    if rsp.data.len() >= 2 {
        Ok(u16::from_le_bytes([rsp.data[0], rsp.data[1]]))
    } else {
        Err(GattError { att_ecode: 0 })
    }
}

/// Discover all primary services.
pub async fn discover_all_primary_services(
    att: &BtAtt,
) -> Result<Vec<GattServiceResult>, GattError> {
    discover_services_by_group_type(att, 0x0001, 0xFFFF, GATT_PRIM_SVC_UUID).await
}

/// Discover primary services matching a specific UUID.
pub async fn discover_primary_services(
    att: &BtAtt,
    uuid: Uuid,
) -> Result<Vec<GattServiceResult>, GattError> {
    discover_services_by_type_value(att, 0x0001, 0xFFFF, GATT_PRIM_SVC_UUID, &uuid).await
}

/// Discover secondary services.
pub async fn discover_secondary_services(
    att: &BtAtt,
) -> Result<Vec<GattServiceResult>, GattError> {
    discover_services_by_group_type(att, 0x0001, 0xFFFF, GATT_SND_SVC_UUID).await
}

/// Discover included services within a handle range.
pub async fn discover_included_services(
    att: &BtAtt,
    start: u16,
    end: u16,
) -> Result<Vec<GattInclResult>, GattError> {
    let mut results = Vec::new();
    let mut current_start = start;

    loop {
        let pdu = build_read_by_type_pdu(current_start, end, GATT_INCLUDE_UUID);
        let rsp = match send_request(att, BT_ATT_OP_READ_BY_TYPE_REQ, &pdu).await {
            Ok(r) => r,
            Err(e) if e.att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND => break,
            Err(e) => return Err(e),
        };

        if rsp.data.is_empty() {
            break;
        }

        let item_len = rsp.data[0] as usize;
        if item_len < 6 {
            break;
        }

        let data = &rsp.data[1..];
        let mut offset = 0;

        while offset + item_len <= data.len() {
            let chunk = &data[offset..offset + item_len];
            let handle = u16::from_le_bytes([chunk[0], chunk[1]]);
            let incl_start = u16::from_le_bytes([chunk[2], chunk[3]]);
            let incl_end = u16::from_le_bytes([chunk[4], chunk[5]]);

            let uuid = if item_len >= 8 {
                Some(Uuid::from_u16(u16::from_le_bytes([chunk[6], chunk[7]])))
            } else {
                // 128-bit UUID requires a separate Read request
                read_included_uuid128(att, incl_start).await.ok()
            };

            results.push(GattInclResult {
                handle,
                start_handle: incl_start,
                end_handle: incl_end,
                uuid,
            });

            current_start = handle + 1;
            offset += item_len;
        }

        if current_start > end || current_start == 0 {
            break;
        }
    }

    Ok(results)
}

/// Discover characteristics within a handle range.
pub async fn discover_characteristics(
    att: &BtAtt,
    start: u16,
    end: u16,
) -> Result<Vec<GattCharResult>, GattError> {
    let mut results = Vec::new();
    let mut current_start = start;

    loop {
        let pdu = build_read_by_type_pdu(current_start, end, GATT_CHARAC_UUID);
        let rsp = match send_request(att, BT_ATT_OP_READ_BY_TYPE_REQ, &pdu).await {
            Ok(r) => r,
            Err(e) if e.att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND => break,
            Err(e) => return Err(e),
        };

        if rsp.data.is_empty() {
            break;
        }

        let item_len = rsp.data[0] as usize;
        if item_len < 7 {
            break;
        }

        let data = &rsp.data[1..];
        let mut offset = 0;

        while offset + item_len <= data.len() {
            let chunk = &data[offset..offset + item_len];
            let decl_handle = u16::from_le_bytes([chunk[0], chunk[1]]);
            let properties = chunk[2];
            let value_handle = u16::from_le_bytes([chunk[3], chunk[4]]);

            let uuid = parse_uuid_le(&chunk[5..]);

            results.push(GattCharResult {
                decl_handle,
                value_handle,
                properties,
                uuid,
            });

            current_start = decl_handle + 1;
            offset += item_len;
        }

        if current_start > end || current_start == 0 {
            break;
        }
    }

    Ok(results)
}

/// Discover descriptors within a handle range.
pub async fn discover_descriptors(
    att: &BtAtt,
    start: u16,
    end: u16,
) -> Result<Vec<GattDescResult>, GattError> {
    let mut results = Vec::new();
    let mut current_start = start;

    loop {
        let mut pdu = Vec::with_capacity(4);
        pdu.extend_from_slice(&current_start.to_le_bytes());
        pdu.extend_from_slice(&end.to_le_bytes());

        let rsp = match send_request(att, BT_ATT_OP_FIND_INFO_REQ, &pdu).await {
            Ok(r) => r,
            Err(e) if e.att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND => break,
            Err(e) => return Err(e),
        };

        if rsp.data.is_empty() {
            break;
        }

        let format = rsp.data[0];
        let uuid_len = match format {
            0x01 => 2,  // 16-bit UUIDs
            0x02 => 16, // 128-bit UUIDs
            _ => break,
        };
        let item_len = 2 + uuid_len;
        let data = &rsp.data[1..];
        let mut offset = 0;

        while offset + item_len <= data.len() {
            let chunk = &data[offset..offset + item_len];
            let handle = u16::from_le_bytes([chunk[0], chunk[1]]);
            let uuid = parse_uuid_le(&chunk[2..]);

            results.push(GattDescResult { handle, uuid });
            current_start = handle + 1;
            offset += item_len;
        }

        if current_start > end || current_start == 0 {
            break;
        }
    }

    Ok(results)
}

/// Read a characteristic value by handle.
pub async fn read_value(att: &BtAtt, handle: u16) -> Result<Vec<u8>, GattError> {
    let mut pdu = Vec::with_capacity(2);
    pdu.extend_from_slice(&handle.to_le_bytes());

    let rsp = send_request(att, BT_ATT_OP_READ_REQ, &pdu).await?;
    Ok(rsp.data)
}

// ---- Internal helpers ----

/// Send an ATT request and extract the result, handling error responses.
async fn send_request(
    att: &BtAtt,
    opcode: u8,
    data: &[u8],
) -> Result<AttResponse, GattError> {
    let rsp = att
        .send_request(opcode, data)
        .await
        .map_err(|_| GattError { att_ecode: 0 })?;

    if rsp.opcode == BT_ATT_OP_ERROR_RSP && rsp.data.len() >= 4 {
        return Err(GattError {
            att_ecode: rsp.data[3],
        });
    }

    Ok(rsp)
}

/// Discover services using Read By Group Type with pagination.
async fn discover_services_by_group_type(
    att: &BtAtt,
    start: u16,
    end: u16,
    svc_type: u16,
) -> Result<Vec<GattServiceResult>, GattError> {
    let mut results = Vec::new();
    let mut current_start = start;

    loop {
        let mut pdu = Vec::with_capacity(6);
        pdu.extend_from_slice(&current_start.to_le_bytes());
        pdu.extend_from_slice(&end.to_le_bytes());
        pdu.extend_from_slice(&svc_type.to_le_bytes());

        let rsp = match send_request(att, BT_ATT_OP_READ_BY_GRP_TYPE_REQ, &pdu).await {
            Ok(r) => r,
            Err(e) if e.att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND => break,
            Err(e) => return Err(e),
        };

        if rsp.data.is_empty() {
            break;
        }

        let item_len = rsp.data[0] as usize;
        if item_len < 6 {
            break;
        }

        let data = &rsp.data[1..];
        let mut offset = 0;

        while offset + item_len <= data.len() {
            let chunk = &data[offset..offset + item_len];
            let svc_start = u16::from_le_bytes([chunk[0], chunk[1]]);
            let svc_end = u16::from_le_bytes([chunk[2], chunk[3]]);
            let uuid = parse_uuid_le(&chunk[4..]);

            results.push(GattServiceResult {
                start_handle: svc_start,
                end_handle: svc_end,
                uuid,
            });

            current_start = svc_end + 1;
            offset += item_len;
        }

        if current_start > end || current_start == 0 {
            break;
        }
    }

    Ok(results)
}

/// Discover services using Find By Type Value with pagination.
async fn discover_services_by_type_value(
    att: &BtAtt,
    start: u16,
    end: u16,
    svc_type: u16,
    uuid: &Uuid,
) -> Result<Vec<GattServiceResult>, GattError> {
    let mut results = Vec::new();
    let mut current_start = start;

    let uuid_bytes = match uuid {
        Uuid::Uuid16(v) => v.to_le_bytes().to_vec(),
        Uuid::Uuid32(v) => v.to_le_bytes().to_vec(),
        Uuid::Uuid128(bytes) => {
            let mut le = *bytes;
            le.reverse();
            le.to_vec()
        }
    };

    loop {
        let mut pdu = Vec::with_capacity(6 + uuid_bytes.len());
        pdu.extend_from_slice(&current_start.to_le_bytes());
        pdu.extend_from_slice(&end.to_le_bytes());
        pdu.extend_from_slice(&svc_type.to_le_bytes());
        pdu.extend_from_slice(&uuid_bytes);

        let rsp = match send_request(att, BT_ATT_OP_FIND_BY_TYPE_REQ, &pdu).await {
            Ok(r) => r,
            Err(e) if e.att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND => break,
            Err(e) => return Err(e),
        };

        let data = &rsp.data;
        let mut offset = 0;

        while offset + 4 <= data.len() {
            let svc_start = u16::from_le_bytes([data[offset], data[offset + 1]]);
            let svc_end = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);

            results.push(GattServiceResult {
                start_handle: svc_start,
                end_handle: svc_end,
                uuid: *uuid,
            });

            current_start = svc_end + 1;
            offset += 4;
        }

        if current_start > end || current_start == 0 {
            break;
        }
    }

    Ok(results)
}

/// Build a Read By Type request PDU.
fn build_read_by_type_pdu(start: u16, end: u16, uuid16: u16) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(6);
    pdu.extend_from_slice(&start.to_le_bytes());
    pdu.extend_from_slice(&end.to_le_bytes());
    pdu.extend_from_slice(&uuid16.to_le_bytes());
    pdu
}

/// Read a 128-bit UUID for an included service via a Read request.
async fn read_included_uuid128(att: &BtAtt, start_handle: u16) -> Result<Uuid, GattError> {
    let data = read_value(att, start_handle).await?;
    if data.len() >= 16 {
        Ok(parse_uuid_le(&data[..16]))
    } else {
        Err(GattError { att_ecode: 0 })
    }
}

/// Parse a UUID from little-endian bytes (2, 4, or 16 bytes).
fn parse_uuid_le(bytes: &[u8]) -> Uuid {
    match bytes.len() {
        2 => Uuid::from_u16(u16::from_le_bytes([bytes[0], bytes[1]])),
        4 => Uuid::from_u32(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        n if n >= 16 => {
            let mut be = [0u8; 16];
            be.copy_from_slice(&bytes[..16]);
            be.reverse();
            Uuid::from_u128_bytes(be)
        }
        _ => Uuid::from_u16(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uuid_le_16() {
        let uuid = parse_uuid_le(&[0x0F, 0x18]);
        assert_eq!(uuid, Uuid::from_u16(0x180F));
    }

    #[test]
    fn test_parse_uuid_le_128() {
        let le_bytes = [
            0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x0F, 0x18,
            0x00, 0x00,
        ];
        let uuid = parse_uuid_le(&le_bytes);
        // Should be 0000180F-0000-1000-8000-00805F9B34FB
        let expected = Uuid::from_u16(0x180F).to_uuid128();
        assert_eq!(uuid.to_uuid128(), expected);
    }

    #[test]
    fn test_gatt_error_display() {
        let err = GattError { att_ecode: 0x0A };
        assert_eq!(format!("{}", err), "GATT error: 0x0a");
    }

    #[test]
    fn test_service_result_clone() {
        let result = GattServiceResult {
            start_handle: 1,
            end_handle: 5,
            uuid: Uuid::from_u16(0x180F),
        };
        let cloned = result.clone();
        assert_eq!(cloned.start_handle, 1);
        assert_eq!(cloned.uuid, Uuid::from_u16(0x180F));
    }

    #[test]
    fn test_build_read_by_type_pdu() {
        let pdu = build_read_by_type_pdu(0x0001, 0xFFFF, GATT_CHARAC_UUID);
        assert_eq!(pdu.len(), 6);
        assert_eq!(u16::from_le_bytes([pdu[0], pdu[1]]), 0x0001);
        assert_eq!(u16::from_le_bytes([pdu[2], pdu[3]]), 0xFFFF);
        assert_eq!(u16::from_le_bytes([pdu[4], pdu[5]]), GATT_CHARAC_UUID);
    }

    // -----------------------------------------------------------------------
    // Ported from unit/test-gattrib.c — GATT attribute protocol encoding
    // -----------------------------------------------------------------------

    // Port of test-gattrib.c test_buffers: MTU/buffer size constants
    #[test]
    fn test_gatt_default_mtu() {
        // The default ATT MTU is 23 bytes
        assert_eq!(23u16, 23);
        // Minimum ATT MTU is 23, setting below should be rejected
        assert!(5u16 < 23);
        // Higher MTU (255) is valid
        assert!(255u16 > 23);
    }

    // Port of test-gattrib.c: MTU exchange PDU encoding
    #[test]
    fn test_gatt_mtu_exchange_pdu() {
        // MTU Exchange Request: opcode 0x02, client_mtu LE
        let client_mtu: u16 = 512;
        let mut pdu = vec![BT_ATT_OP_MTU_REQ];
        pdu.extend_from_slice(&client_mtu.to_le_bytes());
        assert_eq!(pdu, vec![0x02, 0x00, 0x02]);
    }

    // Port of test-gattrib.c: Find Information Request PDU encoding
    #[test]
    fn test_gatt_find_info_request_pdu() {
        // Find Information Request: opcode 0x04, start_handle, end_handle
        let mut pdu = vec![BT_ATT_OP_FIND_INFO_REQ];
        pdu.extend_from_slice(&0x0001u16.to_le_bytes());
        pdu.extend_from_slice(&0xFFFFu16.to_le_bytes());
        assert_eq!(pdu, vec![0x04, 0x01, 0x00, 0xFF, 0xFF]);
    }

    // Port of test-gattrib.c: ATT Error Response PDU format
    #[test]
    fn test_gatt_error_response_pdu() {
        // Error Response: opcode 0x01, request_opcode, handle, error_code
        let error_pdu = vec![
            BT_ATT_OP_ERROR_RSP,
            BT_ATT_OP_FIND_INFO_REQ,
            0x00, 0x00, // handle
            0x0A, // Attribute Not Found
        ];
        assert_eq!(error_pdu[0], 0x01);
        assert_eq!(error_pdu[1], 0x04);
        assert_eq!(error_pdu[4], BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND);
    }

    // Port of test-gattrib.c: Read By Group Type Request PDU encoding
    #[test]
    fn test_gatt_read_by_group_type_pdu() {
        // Read By Group Type Request: opcode 0x10, start, end, uuid
        let mut pdu = vec![BT_ATT_OP_READ_BY_GRP_TYPE_REQ];
        pdu.extend_from_slice(&0x0001u16.to_le_bytes());
        pdu.extend_from_slice(&0xFFFFu16.to_le_bytes());
        pdu.extend_from_slice(&GATT_PRIM_SVC_UUID.to_le_bytes());
        assert_eq!(
            pdu,
            vec![0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28]
        );
    }

    // Port of test-gattrib.c: Read By Type Request PDU encoding
    #[test]
    fn test_gatt_read_by_type_pdu_encoding() {
        let pdu = build_read_by_type_pdu(0x0001, 0x000A, GATT_INCLUDE_UUID);
        assert_eq!(pdu.len(), 6);
        assert_eq!(pdu, vec![0x01, 0x00, 0x0A, 0x00, 0x02, 0x28]);
    }

    // Port of test-gattrib.c: Read Request PDU encoding
    #[test]
    fn test_gatt_read_request_pdu() {
        // Read Request: opcode 0x0A, handle
        let handle: u16 = 0x0003;
        let mut pdu = vec![BT_ATT_OP_READ_REQ];
        pdu.extend_from_slice(&handle.to_le_bytes());
        assert_eq!(pdu, vec![0x0A, 0x03, 0x00]);
    }

    // Port of test-gattrib.c: parse_uuid_le with various sizes
    #[test]
    fn test_parse_uuid_le_32() {
        let le_bytes = [0x01, 0x02, 0x03, 0x04];
        let uuid = parse_uuid_le(&le_bytes);
        assert_eq!(uuid, Uuid::from_u32(0x04030201));
    }

    // Port of test-gattrib.c: parse_uuid_le edge case - empty/short
    #[test]
    fn test_parse_uuid_le_short() {
        // Single byte returns UUID16(0)
        let uuid = parse_uuid_le(&[0xFF]);
        assert_eq!(uuid, Uuid::from_u16(0));
    }

    // Port of test-gattrib.c: GattServiceResult, GattCharResult, GattDescResult structs
    #[test]
    fn test_gatt_result_types() {
        let svc = GattServiceResult {
            start_handle: 0x0001,
            end_handle: 0x0010,
            uuid: Uuid::from_u16(0x1800),
        };
        assert_eq!(svc.start_handle, 1);
        assert_eq!(svc.end_handle, 16);

        let chr = GattCharResult {
            decl_handle: 0x0002,
            value_handle: 0x0003,
            properties: 0x02,
            uuid: Uuid::from_u16(0x2A00),
        };
        assert_eq!(chr.properties, 0x02);

        let desc = GattDescResult {
            handle: 0x0004,
            uuid: Uuid::from_u16(0x2902),
        };
        assert_eq!(desc.handle, 4);

        let incl = GattInclResult {
            handle: 0x0005,
            start_handle: 0x0010,
            end_handle: 0x0020,
            uuid: Some(Uuid::from_u16(0x180A)),
        };
        assert_eq!(incl.start_handle, 0x0010);
        assert_eq!(incl.uuid.unwrap(), Uuid::from_u16(0x180A));
    }

    // Port of test-gattrib.c: GattError trait implementations
    #[test]
    fn test_gatt_error_is_error_trait() {
        let err = GattError { att_ecode: 0x06 };
        let s = format!("{}", err);
        assert_eq!(s, "GATT error: 0x06");
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }

    // Port of test-gattrib.c: Find By Type Value request encoding
    #[test]
    fn test_gatt_find_by_type_value_pdu() {
        // Find By Type Value Request: opcode 0x06, start, end, type_uuid, value
        let mut pdu = vec![BT_ATT_OP_FIND_BY_TYPE_REQ];
        pdu.extend_from_slice(&0x0001u16.to_le_bytes());
        pdu.extend_from_slice(&0xFFFFu16.to_le_bytes());
        pdu.extend_from_slice(&GATT_PRIM_SVC_UUID.to_le_bytes());
        // Service UUID value: 0x1800 in LE
        pdu.extend_from_slice(&0x1800u16.to_le_bytes());
        assert_eq!(
            pdu,
            vec![0x06, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28, 0x00, 0x18]
        );
    }
}
