// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Legacy client-side GATT procedures
//
// Copyright 2024 BlueZ Project
//
// Rust rewrite of `attrib/gatt.c` (1250 lines) + `attrib/gatt.h` (110 lines).
// Implements the legacy client-side GATT procedure layer: discovery of primary
// services, included services, characteristics, and descriptors; read/write
// operations (single, long, prepared, reliable, signed); MTU exchange; and SDP
// record parsing for GATT. This is the legacy GATT API used by bluetoothd
// profile plugins that still use the GAttrib transport path.

use std::sync::{Arc, Mutex};

use bitflags::bitflags;

use super::att::{
    ATT_ECODE_ATTR_NOT_FOUND, ATT_ECODE_INSUFF_RESOURCES, ATT_ECODE_INVALID_PDU, ATT_ECODE_IO,
    ATT_ECODE_UNLIKELY, ATT_FIND_INFO_RESP_FMT_16BIT, ATT_FIND_INFO_RESP_FMT_128BIT,
    ATT_WRITE_ALL_PREP_WRITES, AttRange, dec_find_by_type_resp, dec_find_info_resp,
    dec_read_by_grp_resp, dec_read_by_type_resp, enc_exec_write_req, enc_find_by_type_req,
    enc_find_info_req, enc_mtu_req, enc_prep_write_req, enc_read_blob_req, enc_read_by_grp_req,
    enc_read_by_type_req, enc_read_req, enc_signed_write_cmd, enc_write_cmd, enc_write_req,
};
// Callers of gatt_execute_write use ATT_CANCEL_ALL_PREP_WRITES from att module
pub use super::att::ATT_CANCEL_ALL_PREP_WRITES;
use super::gattrib::{AttribResultFn, GAttrib};
use crate::sdp::{
    L2CAP_UUID, SDP_ATTR_PROTO_DESC_LIST, SDP_ATTR_SVCLASS_ID_LIST, SdpData, SdpRecord,
};
use bluez_shared::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// GATT UUID Constants
// ---------------------------------------------------------------------------

/// GATT Primary Service Declaration UUID (0x2800).
pub const GATT_PRIM_SVC_UUID: u16 = 0x2800;

/// GATT Include Declaration UUID (0x2802).
pub const GATT_INCLUDE_UUID: u16 = 0x2802;

/// GATT Characteristic Declaration UUID (0x2803).
pub const GATT_CHARAC_UUID: u16 = 0x2803;

/// GATT Client Characteristic Configuration Descriptor UUID (0x2902).
pub const GATT_CLIENT_CHARAC_CFG_UUID: u16 = 0x2902;

/// ATT service UUID used in SDP protocol descriptors.
const ATT_UUID: u16 = 0x0007;

// ---------------------------------------------------------------------------
// Characteristic Property Bitflags
// ---------------------------------------------------------------------------

bitflags! {
    /// GATT Characteristic Property bits.
    ///
    /// Reference: Core SPEC 4.1, Table 3.5: Characteristic Properties bit field.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CharProperties: u8 {
        /// Characteristic supports broadcasting.
        const BROADCAST         = 0x01;
        /// Characteristic is readable.
        const READ              = 0x02;
        /// Characteristic supports Write Without Response.
        const WRITE_WITHOUT_RESP = 0x04;
        /// Characteristic supports Write Request.
        const WRITE             = 0x08;
        /// Characteristic supports Notification.
        const NOTIFY            = 0x10;
        /// Characteristic supports Indication.
        const INDICATE          = 0x20;
        /// Characteristic supports Authenticated Signed Writes.
        const AUTH              = 0x40;
        /// Characteristic has Extended Properties.
        const EXT_PROP          = 0x80;
    }
}

// ---------------------------------------------------------------------------
// CCCD Configuration Bitflags
// ---------------------------------------------------------------------------

bitflags! {
    /// Client Characteristic Configuration Descriptor bits.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CccdConfig: u16 {
        /// Enable notifications.
        const NOTIFICATION = 0x0001;
        /// Enable indications.
        const INDICATION   = 0x0002;
    }
}

// ---------------------------------------------------------------------------
// Result Structs
// ---------------------------------------------------------------------------

/// Discovered primary service information.
///
/// Replaces C `struct gatt_primary`.
#[derive(Debug, Clone)]
pub struct GattPrimary {
    /// Service UUID as a string.
    pub uuid: String,
    /// Whether the service has changed (Service Changed indication).
    pub changed: bool,
    /// Attribute handle range of the service.
    pub range: AttRange,
}

/// Discovered included service information.
///
/// Replaces C `struct gatt_included`.
#[derive(Debug, Clone)]
pub struct GattIncluded {
    /// Included service UUID as a string.
    pub uuid: String,
    /// Handle of the include declaration.
    pub handle: u16,
    /// Attribute handle range of the included service.
    pub range: AttRange,
}

/// Discovered characteristic information.
///
/// Replaces C `struct gatt_char`.
#[derive(Debug, Clone)]
pub struct GattChar {
    /// Characteristic UUID as a string.
    pub uuid: String,
    /// Handle of the characteristic declaration.
    pub handle: u16,
    /// Characteristic property bits.
    pub properties: CharProperties,
    /// Handle of the characteristic value.
    pub value_handle: u16,
}

/// Discovered descriptor information.
///
/// Replaces C `struct gatt_desc`.
#[derive(Debug, Clone)]
pub struct GattDesc {
    /// Descriptor UUID as a string.
    pub uuid: String,
    /// Handle of the descriptor.
    pub handle: u16,
    /// 16-bit UUID value if the descriptor has a UUID16, otherwise 0.
    pub uuid16: u16,
}

// ---------------------------------------------------------------------------
// Callback Type
// ---------------------------------------------------------------------------

/// Generic GATT discovery callback.
///
/// Replaces C `gatt_cb_t = fn(u8, *GSList, *void)`.
/// The status is 0 on success, or an ATT error code on failure.
/// The second parameter is a slice of discovered results.
pub type GattCbFn<T> = Box<dyn FnOnce(u8, &[T]) + Send>;

// ---------------------------------------------------------------------------
// Internal UUID type constants matching the C BT_UUID16/BT_UUID128 values
// ---------------------------------------------------------------------------

/// Marker value for 16-bit UUIDs in decoded response parsing.
const UUID_TYPE_16: u8 = 16;
/// Marker value for 128-bit UUIDs in decoded response parsing.
const UUID_TYPE_128: u8 = 128;

// ---------------------------------------------------------------------------
// Internal UUID Helpers
// ---------------------------------------------------------------------------

/// Writes a UUID in little-endian wire format.
///
/// For UUID16: writes 2 bytes, returns 2.
/// For UUID128: copies 16 bytes, returns 16.
/// For UUID32: expands to UUID128 then writes 16 bytes, returns 16.
fn put_uuid_le(uuid: &BtUuid, dst: &mut [u8]) -> usize {
    match uuid {
        BtUuid::Uuid16(val) => {
            dst[..2].copy_from_slice(&val.to_le_bytes());
            2
        }
        BtUuid::Uuid32(_) | BtUuid::Uuid128(_) => {
            let bytes = uuid.to_uuid128_bytes();
            dst[..16].copy_from_slice(&bytes);
            16
        }
    }
}

/// Constructs a BtUuid from raw wire bytes, promoting to UUID128.
///
/// When `uuid_type` is `UUID_TYPE_16`, reads 2 bytes as a UUID16 value,
/// then promotes it to a UUID128 (by embedding in the Bluetooth SIG base UUID).
/// Otherwise reads 16 bytes as UUID128.
///
/// This mirrors the C `get_uuid128()` function which always produces a
/// 128-bit UUID for consistent string formatting.
fn get_uuid128(uuid_type: u8, val: &[u8]) -> BtUuid {
    if uuid_type == UUID_TYPE_16 {
        let u16_val = u16::from_le_bytes([val[0], val[1]]);
        // Promote UUID16 to UUID128 via Bluetooth SIG base
        let uuid16 = BtUuid::from_u16(u16_val);
        BtUuid::from_bytes(&uuid16.to_uuid128_bytes())
    } else {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&val[..16]);
        BtUuid::from_bytes(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Primary Service Discovery
// ---------------------------------------------------------------------------

/// Internal context for primary service discovery.
struct DiscoverPrimary {
    attrib: GAttrib,
    id: u32,
    uuid: Option<BtUuid>,
    start: u16,
    primaries: Vec<GattPrimary>,
    cb: Option<GattCbFn<GattPrimary>>,
}

/// Encodes an ATT PDU for primary service discovery.
///
/// If `uuid` is `None`, encodes a Read By Group Type Request (discover all
/// primary services). If `uuid` is `Some`, encodes a Find By Type Value
/// Request (discover by specific UUID).
fn encode_discover_primary(start: u16, end: u16, uuid: Option<&BtUuid>, buf: &mut [u8]) -> usize {
    let prim = BtUuid::from_u16(GATT_PRIM_SVC_UUID);

    match uuid {
        None => {
            // Discover all primary services
            enc_read_by_grp_req(start, end, &prim, buf)
        }
        Some(u) => {
            // Discover primary service by UUID
            let mut value = [0u8; 16];
            let vlen = put_uuid_le(u, &mut value);
            enc_find_by_type_req(start, end, &prim, &value[..vlen], buf)
        }
    }
}

/// Callback for Find By Type Value responses during primary-by-UUID discovery.
///
/// Accumulates `AttRange` entries as `GattPrimary` with the searched UUID.
/// Pages forward if `range.end < 0xFFFF`. Includes infinite-loop protection.
fn primary_by_uuid_cb(dp: &mut Arc<Mutex<DiscoverPrimary>>, status: u8, pdu: &[u8], _plen: u16) {
    let mut dp_guard = dp.lock().expect("DiscoverPrimary lock poisoned");

    if status != 0 {
        let err = if status == ATT_ECODE_ATTR_NOT_FOUND { 0 } else { status };
        fire_primary_cb(&mut dp_guard, err);
        return;
    }

    let list = match dec_find_by_type_resp(pdu) {
        Some(l) => l,
        None => {
            fire_primary_cb(&mut dp_guard, 0);
            return;
        }
    };

    // The C code uses dec_find_by_type_resp which returns a GSList of AttRange.
    // Our decoder returns an AttDataList with 4-byte entries (start_handle,
    // end_handle).
    let mut last_end: u16 = 0;
    for i in 0..list.num() as usize {
        if let Some(data) = list.get(i) {
            if data.len() < 4 {
                continue;
            }
            let range_start = u16::from_le_bytes([data[0], data[1]]);
            let range_end = u16::from_le_bytes([data[2], data[3]]);

            let uuid_str = dp_guard.uuid.as_ref().map(|u| u.to_string()).unwrap_or_default();

            dp_guard.primaries.push(GattPrimary {
                uuid: uuid_str,
                changed: false,
                range: AttRange { start: range_start, end: range_end },
            });
            last_end = range_end;
        }
    }

    if last_end == 0xFFFF {
        fire_primary_cb(&mut dp_guard, 0);
        return;
    }

    // Infinite loop protection
    if last_end < dp_guard.start {
        fire_primary_cb(&mut dp_guard, ATT_ECODE_UNLIKELY);
        return;
    }

    dp_guard.start = last_end + 1;
    let new_start = dp_guard.start;
    let uuid_clone = dp_guard.uuid.clone();
    let attrib_clone = dp_guard.attrib.clone();
    let id = dp_guard.id;

    let (mut buf, _buflen) = attrib_clone.get_buffer_with_len();
    let oplen = encode_discover_primary(new_start, 0xFFFF, uuid_clone.as_ref(), &mut buf);

    if oplen == 0 {
        fire_primary_cb(&mut dp_guard, 0);
        return;
    }

    let dp_arc = Arc::clone(dp);
    drop(dp_guard);

    let send_id = attrib_clone.send(
        id,
        &buf[..oplen],
        Some(Box::new(move |s, p, l| {
            primary_by_uuid_cb(&mut Arc::clone(&dp_arc), s, p, l);
        })),
        None,
    );

    if send_id == 0 {
        let mut dp_guard = dp.lock().expect("DiscoverPrimary lock poisoned");
        fire_primary_cb(&mut dp_guard, ATT_ECODE_IO);
    }
}

/// Callback for Read By Group Type responses during discover-all-primary.
///
/// Determines UUID type from `list.len` (6=UUID16, 20=UUID128), accumulates
/// `GattPrimary` entries. Pages forward if `end < 0xFFFF`.
fn primary_all_cb(dp: &mut Arc<Mutex<DiscoverPrimary>>, status: u8, pdu: &[u8], _plen: u16) {
    let mut dp_guard = dp.lock().expect("DiscoverPrimary lock poisoned");

    if status != 0 {
        let err = if status == ATT_ECODE_ATTR_NOT_FOUND { 0 } else { status };
        fire_primary_cb(&mut dp_guard, err);
        return;
    }

    let list = match dec_read_by_grp_resp(pdu) {
        Some(l) => l,
        None => {
            fire_primary_cb(&mut dp_guard, ATT_ECODE_IO);
            return;
        }
    };

    let uuid_type = match list.len() {
        6 => UUID_TYPE_16,
        20 => UUID_TYPE_128,
        _ => {
            fire_primary_cb(&mut dp_guard, ATT_ECODE_INVALID_PDU);
            return;
        }
    };

    let mut end: u16 = 0;
    for i in 0..list.num() as usize {
        if let Some(data) = list.get(i) {
            if data.len() < 4 {
                continue;
            }
            let start = u16::from_le_bytes([data[0], data[1]]);
            end = u16::from_le_bytes([data[2], data[3]]);

            let uuid128 = get_uuid128(uuid_type, &data[4..]);
            let uuid_str = uuid128.to_string();

            // Check that we can accommodate the new entry (mirrors C
            // g_try_new0 allocation failure guard)
            if dp_guard.primaries.try_reserve(1).is_err() {
                fire_primary_cb(&mut dp_guard, ATT_ECODE_INSUFF_RESOURCES);
                return;
            }

            dp_guard.primaries.push(GattPrimary {
                uuid: uuid_str,
                changed: false,
                range: AttRange { start, end },
            });
        }
    }

    // Infinite loop protection
    if end < dp_guard.start {
        fire_primary_cb(&mut dp_guard, ATT_ECODE_UNLIKELY);
        return;
    }

    dp_guard.start = end + 1;

    if end != 0xFFFF {
        let new_start = dp_guard.start;
        let attrib_clone = dp_guard.attrib.clone();
        let id = dp_guard.id;

        let (mut buf, _buflen) = attrib_clone.get_buffer_with_len();
        let oplen = encode_discover_primary(new_start, 0xFFFF, None, &mut buf);

        if oplen == 0 {
            fire_primary_cb(&mut dp_guard, 0);
            return;
        }

        let dp_arc = Arc::clone(dp);
        drop(dp_guard);

        attrib_clone.send(
            id,
            &buf[..oplen],
            Some(Box::new(move |s, p, l| {
                primary_all_cb(&mut Arc::clone(&dp_arc), s, p, l);
            })),
            None,
        );
        return;
    }

    fire_primary_cb(&mut dp_guard, 0);
}

/// Fires the primary discovery callback and consumes it.
fn fire_primary_cb(dp: &mut DiscoverPrimary, err: u8) {
    if let Some(cb) = dp.cb.take() {
        cb(err, &dp.primaries);
    }
}

/// Discovers primary services on a remote GATT server.
///
/// If `uuid` is `Some`, discovers only services matching that UUID.
/// If `uuid` is `None`, discovers all primary services.
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_discover_primary(
    attrib: &GAttrib,
    uuid: Option<&BtUuid>,
    func: GattCbFn<GattPrimary>,
) -> u32 {
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = encode_discover_primary(0x0001, 0xFFFF, uuid, &mut buf);
    if plen == 0 {
        return 0;
    }

    let dp = Arc::new(Mutex::new(DiscoverPrimary {
        attrib: attrib.clone(),
        id: 0,
        uuid: uuid.cloned(),
        start: 0x0001,
        primaries: Vec::new(),
        cb: Some(func),
    }));

    let cb: AttribResultFn = if uuid.is_some() {
        let dp_arc = Arc::clone(&dp);
        Box::new(move |s, p, l| {
            primary_by_uuid_cb(&mut Arc::clone(&dp_arc), s, p, l);
        })
    } else {
        let dp_arc = Arc::clone(&dp);
        Box::new(move |s, p, l| {
            primary_all_cb(&mut Arc::clone(&dp_arc), s, p, l);
        })
    };

    let id = attrib.send(0, &buf[..plen], Some(cb), None);

    if id != 0 {
        let mut dp_guard = dp.lock().expect("DiscoverPrimary lock poisoned");
        dp_guard.id = id;
    }

    id
}

// ---------------------------------------------------------------------------
// Included Service Discovery
// ---------------------------------------------------------------------------

/// Internal context for included service discovery.
struct IncludedDiscovery {
    attrib: GAttrib,
    id: u32,
    end_handle: u16,
    includes: Vec<GattIncluded>,
    err: u8,
    cb: Option<GattCbFn<GattIncluded>>,
}

/// Context for resolving the UUID of an included service whose UUID128 is
/// not directly available from the include declaration (data length == 6).
struct IncludedUuidQuery {
    isd: Arc<Mutex<IncludedDiscovery>>,
    included: GattIncluded,
}

/// Callback for Read Response when resolving a 128-bit included-service UUID.
fn resolve_included_uuid_cb(query: &mut IncludedUuidQuery, status: u8, pdu: &[u8], _plen: u16) {
    let mut isd = query.isd.lock().expect("IncludedDiscovery lock poisoned");

    if status != 0 {
        isd.err = status;
        fire_included_cb(&mut isd);
        return;
    }

    // The Read Response PDU: [opcode (1 byte)] [value (N bytes)]
    if pdu.len() < 17 {
        isd.err = ATT_ECODE_INVALID_PDU;
        fire_included_cb(&mut isd);
        return;
    }

    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&pdu[1..17]);
    let uuid = BtUuid::from_bytes(&uuid_bytes);
    query.included.uuid = uuid.to_string();

    isd.includes.push(query.included.clone());

    let next_start = query.included.handle + 1;
    if next_start > isd.end_handle {
        fire_included_cb(&mut isd);
        return;
    }

    let attrib_clone = isd.attrib.clone();
    let end = isd.end_handle;
    let id = isd.id;
    let isd_arc = Arc::clone(&query.isd);
    drop(isd);

    find_included_internal(&isd_arc, &attrib_clone, id, next_start, end);
}

/// Sends a Read Request to resolve the 128-bit UUID for an included service.
fn resolve_included_uuid(query: IncludedUuidQuery) {
    let isd = query.isd.lock().expect("IncludedDiscovery lock poisoned");
    let attrib_clone = isd.attrib.clone();
    let (mut buf, _buflen) = attrib_clone.get_buffer_with_len();
    let oplen = enc_read_req(query.included.range.start, &mut buf);
    if oplen == 0 {
        drop(isd);
        return;
    }

    drop(isd);

    let mut query_boxed = query;
    attrib_clone.send(
        0,
        &buf[..oplen],
        Some(Box::new(move |s, p, l| {
            resolve_included_uuid_cb(&mut query_boxed, s, p, l);
        })),
        None,
    );
}

/// Parses an included service entry from a Read By Type Response value.
fn included_from_buf(handle: u16, data: &[u8]) -> GattIncluded {
    let start = u16::from_le_bytes([data[0], data[1]]);
    let end = u16::from_le_bytes([data[2], data[3]]);
    let uuid_str = if data.len() >= 6 {
        let uuid = get_uuid128(UUID_TYPE_16, &data[4..]);
        uuid.to_string()
    } else {
        String::new()
    };

    GattIncluded { uuid: uuid_str, handle, range: AttRange { start, end } }
}

/// Callback for Read By Type responses during included service discovery.
fn find_included_cb(isd: &mut Arc<Mutex<IncludedDiscovery>>, status: u8, pdu: &[u8], _plen: u16) {
    let mut isd_guard = isd.lock().expect("IncludedDiscovery lock poisoned");

    if status != 0 {
        let err = if status == ATT_ECODE_ATTR_NOT_FOUND { 0 } else { status };
        isd_guard.err = err;
        fire_included_cb(&mut isd_guard);
        return;
    }

    let list = match dec_read_by_type_resp(pdu) {
        Some(l) => l,
        None => {
            isd_guard.err = ATT_ECODE_IO;
            fire_included_cb(&mut isd_guard);
            return;
        }
    };

    let entry_len = list.len() as usize;
    let end_handle = isd_guard.end_handle;

    for i in 0..list.num() as usize {
        if let Some(data) = list.get(i) {
            if data.len() < 4 {
                continue;
            }
            let handle = u16::from_le_bytes([data[0], data[1]]);

            if entry_len == 8 && data.len() >= 8 {
                let included = included_from_buf(handle, &data[2..]);
                isd_guard.includes.push(included);
            } else if entry_len == 6 && data.len() >= 6 {
                let included = GattIncluded {
                    uuid: String::new(),
                    handle,
                    range: AttRange {
                        start: u16::from_le_bytes([data[2], data[3]]),
                        end: u16::from_le_bytes([data[4], data[5]]),
                    },
                };

                let query = IncludedUuidQuery { isd: Arc::clone(isd), included };

                drop(isd_guard);
                resolve_included_uuid(query);
                return;
            }
        }
    }

    let last_handle = isd_guard.includes.last().map(|inc| inc.handle).unwrap_or(0);
    if last_handle != 0 && last_handle < end_handle {
        let next_start = last_handle + 1;

        if next_start <= last_handle {
            fire_included_cb(&mut isd_guard);
            return;
        }

        let attrib_clone = isd_guard.attrib.clone();
        let id = isd_guard.id;
        let isd_arc = Arc::clone(isd);
        drop(isd_guard);

        find_included_internal(&isd_arc, &attrib_clone, id, next_start, end_handle);
    } else {
        fire_included_cb(&mut isd_guard);
    }
}

/// Internal helper that sends a Read By Type Request for included services.
fn find_included_internal(
    isd: &Arc<Mutex<IncludedDiscovery>>,
    attrib: &GAttrib,
    id: u32,
    start: u16,
    end: u16,
) {
    let include_uuid = BtUuid::from_u16(GATT_INCLUDE_UUID);
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let oplen = enc_read_by_type_req(start, end, &include_uuid, &mut buf);

    if oplen == 0 {
        let mut isd_guard = isd.lock().expect("IncludedDiscovery lock poisoned");
        fire_included_cb(&mut isd_guard);
        return;
    }

    let isd_arc = Arc::clone(isd);
    attrib.send(
        id,
        &buf[..oplen],
        Some(Box::new(move |s, p, l| {
            find_included_cb(&mut Arc::clone(&isd_arc), s, p, l);
        })),
        None,
    );
}

/// Fires the included service discovery callback.
fn fire_included_cb(isd: &mut IncludedDiscovery) {
    if let Some(cb) = isd.cb.take() {
        cb(isd.err, &isd.includes);
    }
}

/// Discovers included services within a given handle range.
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_find_included(
    attrib: &GAttrib,
    start: u16,
    end: u16,
    func: GattCbFn<GattIncluded>,
) -> u32 {
    let include_uuid = BtUuid::from_u16(GATT_INCLUDE_UUID);
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = enc_read_by_type_req(start, end, &include_uuid, &mut buf);
    if plen == 0 {
        return 0;
    }

    let isd = Arc::new(Mutex::new(IncludedDiscovery {
        attrib: attrib.clone(),
        id: 0,
        end_handle: end,
        includes: Vec::new(),
        err: 0,
        cb: Some(func),
    }));

    let isd_arc = Arc::clone(&isd);
    let id = attrib.send(
        0,
        &buf[..plen],
        Some(Box::new(move |s, p, l| {
            find_included_cb(&mut Arc::clone(&isd_arc), s, p, l);
        })),
        None,
    );

    if id != 0 {
        let mut isd_guard = isd.lock().expect("IncludedDiscovery lock poisoned");
        isd_guard.id = id;
    }

    id
}

// ---------------------------------------------------------------------------
// Characteristic Discovery
// ---------------------------------------------------------------------------

/// Internal context for characteristic discovery.
struct DiscoverChar {
    attrib: GAttrib,
    id: u32,
    uuid: Option<BtUuid>,
    start: u16,
    end: u16,
    chars: Vec<GattChar>,
    cb: Option<GattCbFn<GattChar>>,
}

/// Callback for Read By Type responses during characteristic discovery.
///
/// Determines UUID type from `list.len` (7=UUID16, otherwise UUID128).
/// Extracts handle, properties, value_handle, and UUID.
/// Applies optional UUID filter.
fn char_discovered_cb(dc: &mut Arc<Mutex<DiscoverChar>>, status: u8, pdu: &[u8], _plen: u16) {
    let mut dc_guard = dc.lock().expect("DiscoverChar lock poisoned");

    if status != 0 {
        let err = if status == ATT_ECODE_ATTR_NOT_FOUND && !dc_guard.chars.is_empty() {
            0
        } else {
            status
        };
        fire_char_cb(&mut dc_guard, err);
        return;
    }

    let list = match dec_read_by_type_resp(pdu) {
        Some(l) => l,
        None => {
            fire_char_cb(&mut dc_guard, ATT_ECODE_IO);
            return;
        }
    };

    let uuid_type = if list.len() == 7 { UUID_TYPE_16 } else { UUID_TYPE_128 };

    let mut last: u16 = 0;
    for i in 0..list.num() as usize {
        if let Some(data) = list.get(i) {
            // data format: [handle_lo, handle_hi, properties, value_handle_lo,
            //               value_handle_hi, uuid...]
            if data.len() < 5 {
                continue;
            }
            let handle = u16::from_le_bytes([data[0], data[1]]);
            let properties = CharProperties::from_bits_truncate(data[2]);
            let value_handle = u16::from_le_bytes([data[3], data[4]]);

            let uuid128 = get_uuid128(uuid_type, &data[5..]);

            // Apply optional UUID filter
            if let Some(ref filter_uuid) = dc_guard.uuid {
                let filter_128 = BtUuid::from_bytes(&filter_uuid.to_uuid128_bytes());
                let found_128 = BtUuid::from_bytes(&uuid128.to_uuid128_bytes());
                if filter_128 != found_128 {
                    last = handle;
                    continue;
                }
            }

            dc_guard.chars.push(GattChar {
                uuid: uuid128.to_string(),
                handle,
                properties,
                value_handle,
            });

            last = handle;
        }
    }

    // If we haven't reached the end, page forward
    if last != 0 && last < dc_guard.end {
        let next = last + 1;

        // Infinite loop protection
        if next <= dc_guard.start {
            fire_char_cb(&mut dc_guard, ATT_ECODE_UNLIKELY);
            return;
        }
        dc_guard.start = next;

        let charac_uuid = BtUuid::from_u16(GATT_CHARAC_UUID);
        let attrib_clone = dc_guard.attrib.clone();
        let end = dc_guard.end;
        let id = dc_guard.id;

        let (mut buf, _buflen) = attrib_clone.get_buffer_with_len();
        let oplen = enc_read_by_type_req(next, end, &charac_uuid, &mut buf);

        if oplen == 0 {
            fire_char_cb(&mut dc_guard, 0);
            return;
        }

        let dc_arc = Arc::clone(dc);
        drop(dc_guard);

        attrib_clone.send(
            id,
            &buf[..oplen],
            Some(Box::new(move |s, p, l| {
                char_discovered_cb(&mut Arc::clone(&dc_arc), s, p, l);
            })),
            None,
        );
        return;
    }

    fire_char_cb(&mut dc_guard, 0);
}

/// Fires the characteristic discovery callback.
fn fire_char_cb(dc: &mut DiscoverChar, err: u8) {
    if let Some(cb) = dc.cb.take() {
        cb(err, &dc.chars);
    }
}

/// Discovers characteristics within a given handle range.
///
/// If `uuid` is `Some`, only characteristics matching the filter UUID are
/// returned (post-discovery filtering).
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_discover_char(
    attrib: &GAttrib,
    start: u16,
    end: u16,
    uuid: Option<&BtUuid>,
    func: GattCbFn<GattChar>,
) -> u32 {
    let charac_uuid = BtUuid::from_u16(GATT_CHARAC_UUID);
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = enc_read_by_type_req(start, end, &charac_uuid, &mut buf);
    if plen == 0 {
        return 0;
    }

    let dc = Arc::new(Mutex::new(DiscoverChar {
        attrib: attrib.clone(),
        id: 0,
        uuid: uuid.cloned(),
        start,
        end,
        chars: Vec::new(),
        cb: Some(func),
    }));

    let dc_arc = Arc::clone(&dc);
    let id = attrib.send(
        0,
        &buf[..plen],
        Some(Box::new(move |s, p, l| {
            char_discovered_cb(&mut Arc::clone(&dc_arc), s, p, l);
        })),
        None,
    );

    if id != 0 {
        let mut dc_guard = dc.lock().expect("DiscoverChar lock poisoned");
        dc_guard.id = id;
    }

    id
}

// ---------------------------------------------------------------------------
// Descriptor Discovery
// ---------------------------------------------------------------------------

/// Internal context for descriptor discovery.
struct DiscoverDesc {
    attrib: GAttrib,
    id: u32,
    uuid: Option<BtUuid>,
    start: u16,
    end: u16,
    descs: Vec<GattDesc>,
    cb: Option<GattCbFn<GattDesc>>,
}

/// Callback for Find Information responses during descriptor discovery.
///
/// The format byte determines UUID size:
/// - `ATT_FIND_INFO_RESP_FMT_16BIT` (0x01): 2-byte UUID handles
/// - `ATT_FIND_INFO_RESP_FMT_128BIT` (0x02): 16-byte UUID handles
///
/// Applies optional UUID filter with early exit on match.
fn desc_discovered_cb(dd: &mut Arc<Mutex<DiscoverDesc>>, status: u8, pdu: &[u8], _plen: u16) {
    let mut dd_guard = dd.lock().expect("DiscoverDesc lock poisoned");

    if status != 0 {
        let err = if status == ATT_ECODE_ATTR_NOT_FOUND { 0 } else { status };
        fire_desc_cb(&mut dd_guard, err);
        return;
    }

    let (format, list) = match dec_find_info_resp(pdu) {
        Some((f, l)) => (f, l),
        None => {
            fire_desc_cb(&mut dd_guard, ATT_ECODE_IO);
            return;
        }
    };

    let uuid_type = if format == ATT_FIND_INFO_RESP_FMT_16BIT {
        UUID_TYPE_16
    } else if format == ATT_FIND_INFO_RESP_FMT_128BIT {
        UUID_TYPE_128
    } else {
        fire_desc_cb(&mut dd_guard, ATT_ECODE_INVALID_PDU);
        return;
    };

    let mut last: u16 = 0;
    for i in 0..list.num() as usize {
        if let Some(data) = list.get(i) {
            if data.len() < 2 {
                continue;
            }
            let handle = u16::from_le_bytes([data[0], data[1]]);

            let uuid16_val = if uuid_type == UUID_TYPE_16 && data.len() >= 4 {
                u16::from_le_bytes([data[2], data[3]])
            } else {
                0u16
            };

            let uuid128 = get_uuid128(uuid_type, &data[2..]);

            // Apply optional UUID filter
            if let Some(ref filter_uuid) = dd_guard.uuid {
                let filter_128 = BtUuid::from_bytes(&filter_uuid.to_uuid128_bytes());
                let found_128 = BtUuid::from_bytes(&uuid128.to_uuid128_bytes());
                if filter_128 == found_128 {
                    dd_guard.descs.push(GattDesc {
                        uuid: uuid128.to_string(),
                        handle,
                        uuid16: uuid16_val,
                    });
                    fire_desc_cb(&mut dd_guard, 0);
                    return;
                }
            } else {
                dd_guard.descs.push(GattDesc {
                    uuid: uuid128.to_string(),
                    handle,
                    uuid16: uuid16_val,
                });
            }

            last = handle;
        }
    }

    // Check if we need to page forward
    if last != 0 && last < dd_guard.end && last != 0xFFFF {
        let next = last + 1;

        // Infinite loop protection
        if next <= dd_guard.start {
            fire_desc_cb(&mut dd_guard, ATT_ECODE_UNLIKELY);
            return;
        }
        dd_guard.start = next;

        let attrib_clone = dd_guard.attrib.clone();
        let end = dd_guard.end;
        let id = dd_guard.id;

        let (mut buf, _buflen) = attrib_clone.get_buffer_with_len();
        let oplen = enc_find_info_req(next, end, &mut buf);

        if oplen == 0 {
            fire_desc_cb(&mut dd_guard, 0);
            return;
        }

        let dd_arc = Arc::clone(dd);
        drop(dd_guard);

        attrib_clone.send(
            id,
            &buf[..oplen],
            Some(Box::new(move |s, p, l| {
                desc_discovered_cb(&mut Arc::clone(&dd_arc), s, p, l);
            })),
            None,
        );
        return;
    }

    fire_desc_cb(&mut dd_guard, 0);
}

/// Fires the descriptor discovery callback.
fn fire_desc_cb(dd: &mut DiscoverDesc, err: u8) {
    if let Some(cb) = dd.cb.take() {
        cb(err, &dd.descs);
    }
}

/// Discovers descriptors within a given handle range.
///
/// If `uuid` is `Some`, returns only the first descriptor matching that UUID
/// (early exit on match).
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_discover_desc(
    attrib: &GAttrib,
    start: u16,
    end: u16,
    uuid: Option<&BtUuid>,
    func: GattCbFn<GattDesc>,
) -> u32 {
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = enc_find_info_req(start, end, &mut buf);
    if plen == 0 {
        return 0;
    }

    let dd = Arc::new(Mutex::new(DiscoverDesc {
        attrib: attrib.clone(),
        id: 0,
        uuid: uuid.cloned(),
        start,
        end,
        descs: Vec::new(),
        cb: Some(func),
    }));

    let dd_arc = Arc::clone(&dd);
    let id = attrib.send(
        0,
        &buf[..plen],
        Some(Box::new(move |s, p, l| {
            desc_discovered_cb(&mut Arc::clone(&dd_arc), s, p, l);
        })),
        None,
    );

    if id != 0 {
        let mut dd_guard = dd.lock().expect("DiscoverDesc lock poisoned");
        dd_guard.id = id;
    }

    id
}

// ---------------------------------------------------------------------------
// Read Operations
// ---------------------------------------------------------------------------

/// Callback type for raw ATT response data (status, data bytes).
///
/// Used for read and write operations where callers receive the raw value
/// bytes rather than parsed structures.
pub type GattRawCbFn = Box<dyn FnOnce(u8, &[u8]) + Send>;

/// Internal context for long read operations (Read Blob).
struct ReadLongData {
    attrib: GAttrib,
    func: Option<GattRawCbFn>,
    buffer: Vec<u8>,
    handle: u16,
    id: u32,
    offset: u16,
}

/// Callback for Read Blob responses during long read operations.
///
/// Appends received data to the accumulated buffer and pages forward
/// until a short read indicates the value is complete.
fn read_blob_helper(rld: &mut Arc<Mutex<ReadLongData>>, status: u8, pdu: &[u8], _plen: u16) {
    let mut rld_guard = rld.lock().expect("ReadLongData lock poisoned");

    if status != 0 {
        fire_raw_cb(&mut rld_guard, status);
        return;
    }

    if pdu.is_empty() {
        fire_raw_cb(&mut rld_guard, ATT_ECODE_INVALID_PDU);
        return;
    }

    // Read Blob Response PDU: [opcode (1)] [value (N)]
    let value = &pdu[1..];

    rld_guard.buffer.extend_from_slice(value);
    rld_guard.offset += value.len() as u16;

    // Check the attrib buffer size to determine if we should page
    let (_, buflen) = rld_guard.attrib.get_buffer_with_len();

    // If the response value fills the available MTU, there may be more data
    if value.len() + 1 >= buflen {
        let attrib_clone = rld_guard.attrib.clone();
        let handle = rld_guard.handle;
        let offset = rld_guard.offset;

        let (mut buf, _buflen) = attrib_clone.get_buffer_with_len();
        let oplen = enc_read_blob_req(handle, offset, &mut buf);

        if oplen == 0 {
            fire_raw_cb(&mut rld_guard, ATT_ECODE_IO);
            return;
        }

        let rld_arc = Arc::clone(rld);
        drop(rld_guard);

        attrib_clone.send(
            0,
            &buf[..oplen],
            Some(Box::new(move |s, p, l| {
                read_blob_helper(&mut Arc::clone(&rld_arc), s, p, l);
            })),
            None,
        );
        return;
    }

    // Short read — value complete
    fire_raw_cb(&mut rld_guard, 0);
}

/// Callback for the initial Read Response during a read characteristic
/// operation.
///
/// If the response value fills the MTU, initiates a Read Blob sequence.
/// Otherwise, delivers the value immediately.
fn read_char_helper(rld: &mut Arc<Mutex<ReadLongData>>, status: u8, pdu: &[u8], _plen: u16) {
    let mut rld_guard = rld.lock().expect("ReadLongData lock poisoned");

    if status != 0 {
        fire_raw_cb(&mut rld_guard, status);
        return;
    }

    if pdu.is_empty() {
        fire_raw_cb(&mut rld_guard, ATT_ECODE_INVALID_PDU);
        return;
    }

    // Read Response PDU: [opcode (1)] [value (N)]
    let value = &pdu[1..];

    rld_guard.buffer.extend_from_slice(value);
    rld_guard.offset = value.len() as u16;

    // Check the attrib buffer size to determine if we need long read
    let (_, buflen) = rld_guard.attrib.get_buffer_with_len();

    // If the response fills the available MTU, initiate Read Blob sequence
    if value.len() + 1 >= buflen {
        let attrib_clone = rld_guard.attrib.clone();
        let handle = rld_guard.handle;
        let offset = rld_guard.offset;

        let (mut buf, _buflen) = attrib_clone.get_buffer_with_len();
        let oplen = enc_read_blob_req(handle, offset, &mut buf);

        if oplen == 0 {
            fire_raw_cb(&mut rld_guard, ATT_ECODE_IO);
            return;
        }

        let rld_arc = Arc::clone(rld);
        drop(rld_guard);

        attrib_clone.send(
            0,
            &buf[..oplen],
            Some(Box::new(move |s, p, l| {
                read_blob_helper(&mut Arc::clone(&rld_arc), s, p, l);
            })),
            None,
        );
        return;
    }

    // Short read — value complete
    fire_raw_cb(&mut rld_guard, 0);
}

/// Fires the raw read callback with the accumulated data.
fn fire_raw_cb(rld: &mut ReadLongData, status: u8) {
    if let Some(cb) = rld.func.take() {
        cb(status, &rld.buffer);
    }
}

/// Reads a characteristic value by handle, automatically handling long reads.
///
/// If the initial Read Response fills the MTU, a Read Blob sequence is
/// initiated to retrieve the complete value.
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_read_char(attrib: &GAttrib, handle: u16, func: GattRawCbFn) -> u32 {
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = enc_read_req(handle, &mut buf);
    if plen == 0 {
        return 0;
    }

    let rld = Arc::new(Mutex::new(ReadLongData {
        attrib: attrib.clone(),
        func: Some(func),
        buffer: Vec::new(),
        handle,
        id: 0,
        offset: 0,
    }));

    let rld_arc = Arc::clone(&rld);
    let id = attrib.send(
        0,
        &buf[..plen],
        Some(Box::new(move |s, p, l| {
            read_char_helper(&mut Arc::clone(&rld_arc), s, p, l);
        })),
        None,
    );

    if id != 0 {
        let mut rld_guard = rld.lock().expect("ReadLongData lock poisoned");
        rld_guard.id = id;
    }

    id
}

/// Reads a characteristic by UUID (Read By Type Request).
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_read_char_by_uuid(
    attrib: &GAttrib,
    start: u16,
    end: u16,
    uuid: &BtUuid,
    func: AttribResultFn,
) -> u32 {
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = enc_read_by_type_req(start, end, uuid, &mut buf);
    if plen == 0 {
        return 0;
    }

    attrib.send(0, &buf[..plen], Some(func), None)
}

// ---------------------------------------------------------------------------
// Write Operations
// ---------------------------------------------------------------------------

/// Internal context for long write operations (Prepare Write).
struct WriteLongData {
    attrib: GAttrib,
    func: Option<GattRawCbFn>,
    handle: u16,
    offset: u16,
    value: Vec<u8>,
}

/// Sends a Prepare Write Request for the current offset chunk.
///
/// Returns the request ID (> 0) on success, or 0 on failure.
fn prepare_write(wld: &Arc<Mutex<WriteLongData>>) -> u32 {
    let wld_guard = wld.lock().expect("WriteLongData lock poisoned");
    let attrib_clone = wld_guard.attrib.clone();
    let handle = wld_guard.handle;
    let offset = wld_guard.offset;

    let (_, buflen) = attrib_clone.get_buffer_with_len();

    // Max payload per Prepare Write = buflen - 5 (opcode + handle + offset)
    let max_chunk = buflen.saturating_sub(5);
    if max_chunk == 0 {
        drop(wld_guard);
        return 0;
    }

    let remaining = if (offset as usize) < wld_guard.value.len() {
        &wld_guard.value[offset as usize..]
    } else {
        &[]
    };

    let chunk_len = remaining.len().min(max_chunk);
    let chunk = remaining[..chunk_len].to_vec();

    let (mut buf, _buflen) = attrib_clone.get_buffer_with_len();
    let oplen = enc_prep_write_req(handle, offset, &chunk, &mut buf);

    if oplen == 0 {
        drop(wld_guard);
        return 0;
    }

    let wld_arc = Arc::clone(wld);
    drop(wld_guard);

    attrib_clone.send(
        0,
        &buf[..oplen],
        Some(Box::new(move |s, p, l| {
            prepare_write_cb(&wld_arc, s, p, l);
        })),
        None,
    )
}

/// Callback for Prepare Write Response.
///
/// Advances offset by the amount written and chains the next Prepare Write,
/// or calls Execute Write when the complete value has been sent.
fn prepare_write_cb(wld: &Arc<Mutex<WriteLongData>>, status: u8, pdu: &[u8], _plen: u16) {
    let mut wld_guard = wld.lock().expect("WriteLongData lock poisoned");

    if status != 0 {
        fire_write_cb(&mut wld_guard, status);
        return;
    }

    // Prepare Write Response PDU: [opcode (1)] [handle (2)] [offset (2)]
    //                              [value (N)]
    if pdu.len() < 5 {
        fire_write_cb(&mut wld_guard, ATT_ECODE_INVALID_PDU);
        return;
    }

    // Advance offset by the length of data confirmed (pdu_len - 5)
    let written = (pdu.len() - 5) as u16;
    wld_guard.offset += written;

    // Check if there is more data to write
    if (wld_guard.offset as usize) < wld_guard.value.len() {
        let wld_arc = Arc::clone(wld);
        drop(wld_guard);

        let id = prepare_write(wld);
        if id == 0 {
            let mut wld_guard = wld_arc.lock().expect("WriteLongData lock poisoned");
            fire_write_cb(&mut wld_guard, ATT_ECODE_IO);
        }
        return;
    }

    // All data sent — execute write
    let attrib_clone = wld_guard.attrib.clone();
    let func = wld_guard.func.take();
    drop(wld_guard);

    let (mut buf, _buflen) = attrib_clone.get_buffer_with_len();
    let oplen = enc_exec_write_req(ATT_WRITE_ALL_PREP_WRITES, &mut buf);

    if oplen == 0 {
        if let Some(cb) = func {
            cb(ATT_ECODE_IO, &[]);
        }
        return;
    }

    attrib_clone.send(
        0,
        &buf[..oplen],
        func.map(|f| -> AttribResultFn {
            Box::new(move |s, p, _l| {
                let data = if p.len() > 1 { &p[1..] } else { &[] };
                f(s, data);
            })
        }),
        None,
    );
}

/// Fires the write callback.
fn fire_write_cb(wld: &mut WriteLongData, status: u8) {
    if let Some(cb) = wld.func.take() {
        cb(status, &[]);
    }
}

/// Writes a characteristic value.
///
/// For short values (≤ buflen - 3), uses a simple Write Request.
/// For longer values, uses a Prepare Write chain followed by Execute Write.
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_write_char(attrib: &GAttrib, handle: u16, value: &[u8], func: GattRawCbFn) -> u32 {
    let (mut buf, buflen) = attrib.get_buffer_with_len();

    // Simple Write Request if value fits (overhead: opcode + handle = 3 bytes)
    if value.len() + 3 <= buflen {
        let plen = enc_write_req(handle, value, &mut buf);
        if plen == 0 {
            return 0;
        }

        return attrib.send(
            0,
            &buf[..plen],
            Some(Box::new(move |s, p, _l| {
                let data = if p.len() > 1 { &p[1..] } else { &[] };
                func(s, data);
            })),
            None,
        );
    }

    // Long Write via Prepare Write chain
    let wld = Arc::new(Mutex::new(WriteLongData {
        attrib: attrib.clone(),
        func: Some(func),
        handle,
        offset: 0,
        value: value.to_vec(),
    }));

    let id = prepare_write(&wld);
    if id == 0 {
        let mut wld_guard = wld.lock().expect("WriteLongData lock poisoned");
        fire_write_cb(&mut wld_guard, ATT_ECODE_IO);
        return 0;
    }

    id
}

/// Sends an Execute Write Request.
///
/// The `flags` parameter controls execution:
/// - `ATT_WRITE_ALL_PREP_WRITES` (0x01): Execute all prepared writes.
/// - `ATT_CANCEL_ALL_PREP_WRITES` (0x00): Cancel all prepared writes.
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_execute_write(attrib: &GAttrib, flags: u8, func: GattRawCbFn) -> u32 {
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = enc_exec_write_req(flags, &mut buf);
    if plen == 0 {
        return 0;
    }

    attrib.send(
        0,
        &buf[..plen],
        Some(Box::new(move |s, p, _l| {
            let data = if p.len() > 1 { &p[1..] } else { &[] };
            func(s, data);
        })),
        None,
    )
}

/// Sends a single Prepare Write Request (Reliable Write).
///
/// Unlike `gatt_write_char`, this does NOT automatically chain multiple
/// Prepare Writes or call Execute Write. The caller is responsible for
/// invoking `gatt_execute_write` afterwards.
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_reliable_write_char(
    attrib: &GAttrib,
    handle: u16,
    value: &[u8],
    func: GattRawCbFn,
) -> u32 {
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = enc_prep_write_req(handle, 0, value, &mut buf);
    if plen == 0 {
        return 0;
    }

    attrib.send(
        0,
        &buf[..plen],
        Some(Box::new(move |s, p, _l| {
            let data = if p.len() > 1 { &p[1..] } else { &[] };
            func(s, data);
        })),
        None,
    )
}

/// Sends a Write Without Response (Write Command).
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_write_cmd(attrib: &GAttrib, handle: u16, value: &[u8]) -> u32 {
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = enc_write_cmd(handle, value, &mut buf);
    if plen == 0 {
        return 0;
    }

    attrib.send(0, &buf[..plen], None, None)
}

/// Sends a Signed Write Without Response (Signed Write Command).
///
/// The CSRK and sign counter are used to compute a CMAC signature that is
/// appended to the PDU.
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_signed_write_cmd(
    attrib: &GAttrib,
    handle: u16,
    value: &[u8],
    csrk: &[u8; 16],
    sign_cnt: u32,
) -> u32 {
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = enc_signed_write_cmd(handle, value, csrk, sign_cnt, &mut buf);
    if plen == 0 {
        return 0;
    }

    attrib.send(0, &buf[..plen], None, None)
}

// ---------------------------------------------------------------------------
// MTU Exchange
// ---------------------------------------------------------------------------

/// Sends an ATT Exchange MTU Request.
///
/// Returns the request ID (> 0) on success, or 0 on failure.
pub fn gatt_exchange_mtu(attrib: &GAttrib, mtu: u16, func: AttribResultFn) -> u32 {
    let (mut buf, _buflen) = attrib.get_buffer_with_len();
    let plen = enc_mtu_req(mtu, &mut buf);
    if plen == 0 {
        return 0;
    }

    attrib.send(0, &buf[..plen], Some(func), None)
}

// ---------------------------------------------------------------------------
// SDP Record Parsing
// ---------------------------------------------------------------------------

/// Finds the ATT protocol entry in an SDP protocol descriptor list.
///
/// Traverses the SDP Sequence looking for a nested Sequence that starts with
/// ATT_UUID (0x0007). Returns the matching inner Sequence if found.
fn proto_seq_find_att(proto_list: &[SdpData]) -> Option<&Vec<SdpData>> {
    for item in proto_list {
        if let SdpData::Sequence(inner) = item {
            // Check if first element is ATT_UUID
            if let Some(first) = inner.first() {
                match first {
                    SdpData::Uuid16(uuid) if *uuid == ATT_UUID => {
                        return Some(inner);
                    }
                    SdpData::Uuid32(uuid) if *uuid == ATT_UUID as u32 => {
                        return Some(inner);
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

/// Extracts L2CAP PSM, start handle, and end handle from an SDP protocol
/// descriptor list.
///
/// The protocol descriptor list is expected to be a Sequence of Sequences,
/// where the L2CAP entry contains PSM and the ATT entry contains the start
/// and end handles.
fn parse_proto_params(
    proto_list: &[SdpData],
    psm: &mut u16,
    start: &mut u16,
    end: &mut u16,
) -> bool {
    // Find L2CAP entry for PSM
    for item in proto_list {
        if let SdpData::Sequence(inner) = item {
            if let Some(first) = inner.first() {
                let is_l2cap = match first {
                    SdpData::Uuid16(uuid) => *uuid == L2CAP_UUID,
                    _ => false,
                };
                if is_l2cap {
                    // PSM is the second element if present
                    if let Some(SdpData::UInt16(p)) = inner.get(1) {
                        *psm = *p;
                    }
                }
            }
        }
    }

    // Find ATT entry for start and end handles
    if let Some(att_entry) = proto_seq_find_att(proto_list) {
        // ATT Sequence: [ATT_UUID, start_handle, end_handle]
        if let Some(SdpData::UInt16(s)) = att_entry.get(1) {
            *start = *s;
        }
        if let Some(SdpData::UInt16(e)) = att_entry.get(2) {
            *end = *e;
        }
        return true;
    }

    false
}

/// Parses an SDP record to extract GATT service parameters.
///
/// Extracts the primary service UUID from `SDP_ATTR_SVCLASS_ID_LIST`, then
/// traverses `SDP_ATTR_PROTO_DESC_LIST` to find the ATT protocol entry and
/// extract L2CAP PSM, start handle, and end handle.
///
/// Returns `true` if the record was successfully parsed as a GATT service,
/// setting all output parameters. Returns `false` if the record does not
/// contain valid GATT service information.
///
/// # Arguments
/// * `record` — The SDP record to parse.
/// * `prim_uuid` — Output: receives the primary service UUID.
/// * `psm` — Output: receives the L2CAP PSM.
/// * `start` — Output: receives the start handle.
/// * `end` — Output: receives the end handle.
pub fn gatt_parse_record(
    record: &SdpRecord,
    prim_uuid: &mut Option<BtUuid>,
    psm: &mut u16,
    start: &mut u16,
    end: &mut u16,
) -> bool {
    // Initialize outputs
    *psm = 0;
    *start = 0;
    *end = 0;
    *prim_uuid = None;

    // Extract primary service UUID from SDP_ATTR_SVCLASS_ID_LIST (0x0001)
    if let Some(SdpData::Sequence(classes)) = record.attrs.get(&SDP_ATTR_SVCLASS_ID_LIST) {
        for class in classes {
            match class {
                SdpData::Uuid16(uuid) => {
                    *prim_uuid = Some(BtUuid::from_u16(*uuid));
                    break;
                }
                SdpData::Uuid128(bytes) => {
                    *prim_uuid = Some(BtUuid::from_bytes(bytes));
                    break;
                }
                _ => {}
            }
        }
    }

    if prim_uuid.is_none() {
        return false;
    }

    // Extract protocol parameters from SDP_ATTR_PROTO_DESC_LIST (0x0004)
    if let Some(SdpData::Sequence(proto_list)) = record.attrs.get(&SDP_ATTR_PROTO_DESC_LIST) {
        return parse_proto_params(proto_list, psm, start, end);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdp::{
        L2CAP_UUID, SDP_ATTR_PROTO_DESC_LIST, SDP_ATTR_SVCLASS_ID_LIST, SdpData, SdpRecord,
    };

    #[test]
    fn test_char_properties_bitflags() {
        assert_eq!(CharProperties::BROADCAST.bits(), 0x01);
        assert_eq!(CharProperties::READ.bits(), 0x02);
        assert_eq!(CharProperties::WRITE_WITHOUT_RESP.bits(), 0x04);
        assert_eq!(CharProperties::WRITE.bits(), 0x08);
        assert_eq!(CharProperties::NOTIFY.bits(), 0x10);
        assert_eq!(CharProperties::INDICATE.bits(), 0x20);
        assert_eq!(CharProperties::AUTH.bits(), 0x40);
        assert_eq!(CharProperties::EXT_PROP.bits(), 0x80);

        let props = CharProperties::READ | CharProperties::WRITE | CharProperties::NOTIFY;
        assert!(props.contains(CharProperties::READ));
        assert!(props.contains(CharProperties::WRITE));
        assert!(props.contains(CharProperties::NOTIFY));
        assert!(!props.contains(CharProperties::BROADCAST));

        let all = CharProperties::all();
        assert_eq!(all.bits(), 0xFF);
    }

    #[test]
    fn test_cccd_config_bitflags() {
        assert_eq!(CccdConfig::NOTIFICATION.bits(), 0x0001);
        assert_eq!(CccdConfig::INDICATION.bits(), 0x0002);

        let both = CccdConfig::NOTIFICATION | CccdConfig::INDICATION;
        assert!(both.contains(CccdConfig::NOTIFICATION));
        assert!(both.contains(CccdConfig::INDICATION));
    }

    #[test]
    fn test_gatt_constants() {
        assert_eq!(GATT_PRIM_SVC_UUID, 0x2800);
        assert_eq!(GATT_INCLUDE_UUID, 0x2802);
        assert_eq!(GATT_CHARAC_UUID, 0x2803);
        assert_eq!(GATT_CLIENT_CHARAC_CFG_UUID, 0x2902);
        assert_eq!(ATT_CANCEL_ALL_PREP_WRITES, 0x00);
    }

    #[test]
    fn test_gatt_primary_struct() {
        let primary = GattPrimary {
            uuid: "00001800-0000-1000-8000-00805f9b34fb".to_string(),
            changed: false,
            range: AttRange { start: 0x0001, end: 0x000F },
        };
        assert_eq!(primary.uuid, "00001800-0000-1000-8000-00805f9b34fb");
        assert!(!primary.changed);
        assert_eq!(primary.range.start, 0x0001);
        assert_eq!(primary.range.end, 0x000F);
    }

    #[test]
    fn test_gatt_included_struct() {
        let included = GattIncluded {
            uuid: "0000180a-0000-1000-8000-00805f9b34fb".to_string(),
            handle: 0x0010,
            range: AttRange { start: 0x0020, end: 0x002F },
        };
        assert_eq!(included.handle, 0x0010);
        assert_eq!(included.range.start, 0x0020);
        assert_eq!(included.range.end, 0x002F);
    }

    #[test]
    fn test_gatt_char_struct() {
        let chr = GattChar {
            uuid: "00002a00-0000-1000-8000-00805f9b34fb".to_string(),
            handle: 0x0002,
            properties: CharProperties::READ | CharProperties::WRITE,
            value_handle: 0x0003,
        };
        assert!(chr.properties.contains(CharProperties::READ));
        assert!(chr.properties.contains(CharProperties::WRITE));
        assert!(!chr.properties.contains(CharProperties::NOTIFY));
        assert_eq!(chr.value_handle, 0x0003);
    }

    #[test]
    fn test_gatt_desc_struct() {
        let desc = GattDesc {
            uuid: "00002902-0000-1000-8000-00805f9b34fb".to_string(),
            handle: 0x0004,
            uuid16: 0x2902,
        };
        assert_eq!(desc.uuid16, GATT_CLIENT_CHARAC_CFG_UUID);
    }

    #[test]
    fn test_gatt_parse_record_empty() {
        let record = SdpRecord::new(0);
        let mut prim_uuid = None;
        let mut psm = 0u16;
        let mut start = 0u16;
        let mut end = 0u16;

        let result = gatt_parse_record(&record, &mut prim_uuid, &mut psm, &mut start, &mut end);
        assert!(!result);
        assert!(prim_uuid.is_none());
    }

    #[test]
    fn test_gatt_parse_record_service_class_only() {
        let mut record = SdpRecord::new(1);
        record
            .attrs
            .insert(SDP_ATTR_SVCLASS_ID_LIST, SdpData::Sequence(vec![SdpData::Uuid16(0x1800)]));

        let mut prim_uuid = None;
        let mut psm = 0u16;
        let mut start = 0u16;
        let mut end = 0u16;

        let result = gatt_parse_record(&record, &mut prim_uuid, &mut psm, &mut start, &mut end);
        assert!(!result);
        assert!(prim_uuid.is_some());
    }

    #[test]
    fn test_gatt_parse_record_full() {
        let mut record = SdpRecord::new(2);
        record
            .attrs
            .insert(SDP_ATTR_SVCLASS_ID_LIST, SdpData::Sequence(vec![SdpData::Uuid16(0x1800)]));
        record.attrs.insert(
            SDP_ATTR_PROTO_DESC_LIST,
            SdpData::Sequence(vec![
                SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID), SdpData::UInt16(25)]),
                SdpData::Sequence(vec![
                    SdpData::Uuid16(0x0007), // ATT_UUID
                    SdpData::UInt16(1),
                    SdpData::UInt16(10),
                ]),
            ]),
        );

        let mut prim_uuid = None;
        let mut psm = 0u16;
        let mut start = 0u16;
        let mut end = 0u16;

        let result = gatt_parse_record(&record, &mut prim_uuid, &mut psm, &mut start, &mut end);
        assert!(result);
        assert!(prim_uuid.is_some());
        assert_eq!(psm, 25);
        assert_eq!(start, 1);
        assert_eq!(end, 10);
    }

    #[test]
    fn test_put_uuid_le_uuid16() {
        let uuid = BtUuid::from_u16(0x2800);
        let mut buf = [0u8; 16];
        let len = put_uuid_le(&uuid, &mut buf);
        assert_eq!(len, 2);
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[1], 0x28);
    }

    #[test]
    fn test_get_uuid128_from_16() {
        let val = [0x00u8, 0x28]; // 0x2800 in LE
        let uuid = get_uuid128(UUID_TYPE_16, &val);
        let s = uuid.to_string();
        assert!(s.contains("2800"));
    }

    #[test]
    fn test_get_uuid128_from_128() {
        let val = [
            0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x18,
            0x00, 0x00,
        ];
        let uuid = get_uuid128(UUID_TYPE_128, &val);
        let s = uuid.to_string();
        assert!(!s.is_empty());
    }

    #[test]
    fn test_callback_type_is_send() {
        let cb: GattCbFn<GattPrimary> = Box::new(|_status, _primaries| {});
        fn assert_send<T: Send>(_: &T) {}
        assert_send(&cb);
    }

    #[test]
    fn test_encode_discover_primary_all() {
        let mut buf = vec![0u8; 64];
        let len = encode_discover_primary(0x0001, 0xFFFF, None, &mut buf);
        assert!(len > 0, "encode_discover_primary should produce non-zero length PDU");
    }

    #[test]
    fn test_encode_discover_primary_by_uuid() {
        let uuid = BtUuid::from_u16(0x1800);
        let mut buf = vec![0u8; 64];
        let len = encode_discover_primary(0x0001, 0xFFFF, Some(&uuid), &mut buf);
        assert!(len > 0, "encode_discover_primary by UUID should produce non-zero length PDU");
    }
}
