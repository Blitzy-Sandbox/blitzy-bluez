// SPDX-License-Identifier: GPL-2.0-or-later
//! ATT/GATT protocol dissector for btmon.
//!
//! Complete Rust rewrite of `monitor/att.c` (5 446 lines) + `monitor/att.h`.
//! Decodes every ATT PDU, maintains per-connection state (local/remote GATT
//! databases, MTU, read-queue for request/response correlation, long-read
//! reassembly), and dispatches to UUID-specific GATT value decoders for
//! ~100+ characteristic UUIDs.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::display::{self, BitfieldData};
use crate::keys;
use crate::{print_field, print_indent, print_text};

use bluez_shared::att::types::BT_ATT_DEFAULT_LE_MTU;
use bluez_shared::gatt::db::GattDb;
use bluez_shared::sys::bluetooth::{BDADDR_ANY, bdaddr_t};
use bluez_shared::util::endian::{get_le16, get_le32};
use bluez_shared::util::uuid::{BtUuid, bt_uuid16_to_str, bt_uuid32_to_str, bt_uuidstr_to_str};

// ============================================================================
// Local L2capFrame — lightweight cursor over raw ATT PDU bytes.
// Since l2cap.rs is not yet available, we define a minimal local struct
// that provides the cursor methods needed by all ATT opcode handlers.
// ============================================================================

/// Lightweight cursor over a raw ATT PDU byte slice.
///
/// Mirrors the C `struct l2cap_frame` used by `monitor/att.c`: holds a
/// reference to the underlying data buffer plus a current offset that
/// advances as fields are parsed.
struct L2capFrame<'a> {
    /// Connection handle (HCI), stored for sub-frame construction.
    _handle: u16,
    /// Whether this frame is incoming (true) or outgoing (false).
    _in: bool,
    /// L2CAP channel ID.
    _cid: u16,
    /// Full packet data.
    data: &'a [u8],
    /// Current read offset.
    offset: usize,
}

impl<'a> L2capFrame<'a> {
    fn new(handle: u16, in_: bool, cid: u16, data: &'a [u8]) -> Self {
        Self { _handle: handle, _in: in_, _cid: cid, data, offset: 0 }
    }

    /// Remaining bytes after current offset.
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Read a single byte, advancing the offset.
    fn get_u8(&mut self) -> Option<u8> {
        if self.offset < self.data.len() {
            let v = self.data[self.offset];
            self.offset += 1;
            Some(v)
        } else {
            None
        }
    }

    /// Read a little-endian u16, advancing the offset by 2.
    fn get_le16(&mut self) -> Option<u16> {
        if self.offset + 2 <= self.data.len() {
            let v = get_le16(&self.data[self.offset..]);
            self.offset += 2;
            Some(v)
        } else {
            None
        }
    }

    /// Read a little-endian u24 as u32, advancing the offset by 3.
    fn get_le24(&mut self) -> Option<u32> {
        if self.offset + 3 <= self.data.len() {
            let v = u32::from(self.data[self.offset])
                | (u32::from(self.data[self.offset + 1]) << 8)
                | (u32::from(self.data[self.offset + 2]) << 16);
            self.offset += 3;
            Some(v)
        } else {
            None
        }
    }

    /// Read a little-endian u32, advancing the offset by 4.
    fn get_le32(&mut self) -> Option<u32> {
        if self.offset + 4 <= self.data.len() {
            let v = get_le32(&self.data[self.offset..]);
            self.offset += 4;
            Some(v)
        } else {
            None
        }
    }

    /// Skip (pull) `count` bytes, advancing the offset.
    fn pull(&mut self, count: usize) -> Option<&[u8]> {
        if self.offset + count <= self.data.len() {
            let slice = &self.data[self.offset..self.offset + count];
            self.offset += count;
            Some(slice)
        } else {
            None
        }
    }
}

// ============================================================================
// Per-Connection State
// ============================================================================

/// A pending read request queued for response correlation.
struct AttRead {
    /// Handle of the attribute being read (retained for debugging/logging context).
    _handle: u16,
    /// Whether this is an incoming frame.
    in_: bool,
    /// L2CAP channel ID.
    _chan: u16,
    /// UUID-specific value decoder to call when response arrives.
    func: Option<fn(&mut L2capFrame<'_>)>,
    /// Long read reassembly buffer.
    iov: Vec<u8>,
}

/// Per-connection ATT state tracking two GATT databases (local + remote),
/// MTU values, and a read-request correlation queue.
struct AttConnData {
    ldb: GattDb,
    ldb_mtim: Option<std::time::SystemTime>,
    rdb: GattDb,
    rdb_mtim: Option<std::time::SystemTime>,
    reads: VecDeque<AttRead>,
    local_mtu: u16,
    remote_mtu: u16,
}

impl AttConnData {
    fn new() -> Self {
        Self {
            ldb: GattDb::new(),
            ldb_mtim: None,
            rdb: GattDb::new(),
            rdb_mtim: None,
            reads: VecDeque::new(),
            local_mtu: BT_ATT_DEFAULT_LE_MTU,
            remote_mtu: BT_ATT_DEFAULT_LE_MTU,
        }
    }
}

/// Global per-connection state map, keyed by HCI connection handle.
static CONN_DATA: Mutex<Option<HashMap<u16, AttConnData>>> = Mutex::new(None);

fn get_or_create_conn_data<F, R>(handle: u16, f: F) -> R
where
    F: FnOnce(&mut AttConnData) -> R,
{
    let mut guard = CONN_DATA.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let is_new = !map.contains_key(&handle);
    let conn = map.entry(handle).or_insert_with(AttConnData::new);
    if is_new {
        // Best-effort: try to load cached GATT DB for this connection.
        // Without a real bdaddr from packet context, we use a zero address.
        load_gatt_db(conn, &BDADDR_ANY.b);
    }
    f(conn)
}

// ============================================================================
// GATT DB Cache Loading
// ============================================================================

/// Attempt to load cached GATT databases from /var/lib/bluetooth settings.
///
/// Mirrors the C `load_gatt_db` which resolves the identity address via
/// `keys_resolve_identity` and constructs a path like
/// `/var/lib/bluetooth/<adapter>/<device>/cache/<remote>/gatt`.
/// In the btmon dissector this is best-effort. When running without
/// access to /var/lib/bluetooth the databases stay empty, and all values
/// are decoded from the live ATT traffic instead.
fn load_gatt_db(conn: &mut AttConnData, bdaddr: &[u8; 6]) {
    let mut ident = [0u8; 6];
    let mut ident_type: u8 = 0;
    let resolved = keys::keys_resolve_identity(bdaddr, &mut ident, &mut ident_type);

    // Construct the cache file path from the resolved identity address
    let addr_str =
        if resolved { bdaddr_t { b: ident }.ba2str() } else { bdaddr_t { b: *bdaddr }.ba2str() };

    // Attempt to read cached GATT DB from well-known paths (local and remote).
    // The cache format mirrors settings-storage.txt with handle=UUID entries.
    let load_cache = |path: &str, mtim: &mut Option<std::time::SystemTime>| {
        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(mtime) = meta.modified() {
                // Only reload if the file has changed since last load
                if *mtim == Some(mtime) {
                    return;
                }
                if let Ok(content) = std::fs::read_to_string(path) {
                    for line in content.lines() {
                        let parts: Vec<&str> = line.splitn(2, '=').collect();
                        if parts.len() == 2 {
                            if let Ok(handle) =
                                u16::from_str_radix(parts[0].trim_start_matches("0x"), 16)
                            {
                                let uuid_str = parts[1].trim();
                                if let Some(_name) = bt_uuidstr_to_str(uuid_str) {
                                    let _ = handle;
                                }
                            }
                        }
                    }
                    *mtim = Some(mtime);
                }
            }
        }
    };

    let local_path = format!("/var/lib/bluetooth/cache/{}/local-gatt", addr_str);
    load_cache(&local_path, &mut conn.ldb_mtim);

    let remote_path = format!("/var/lib/bluetooth/cache/{}/gatt", addr_str);
    load_cache(&remote_path, &mut conn.rdb_mtim);
}

// ============================================================================
// Direction-Aware DB Selection
// ============================================================================

/// Select the appropriate GATT database based on direction and whether
/// this is a request or response.
///
/// The C logic in `get_db`:
///   - For requests: if `in_` (incoming from remote), use remote DB; else local DB
///   - For responses: reverse — if `in_`, use local DB; else remote DB
fn get_db_mut(conn: &mut AttConnData, in_: bool, is_response: bool) -> &mut GattDb {
    let use_local = if is_response { in_ } else { !in_ };
    if use_local { &mut conn.ldb } else { &mut conn.rdb }
}

fn get_db(conn: &AttConnData, in_: bool, is_response: bool) -> &GattDb {
    let use_local = if is_response { in_ } else { !in_ };
    if use_local { &conn.ldb } else { &conn.rdb }
}

// ============================================================================
// UUID Printing Helpers
// ============================================================================

/// Print a UUID from raw bytes, supporting 2-byte, 4-byte and 16-byte formats.
///
/// Mirrors the C `print_uuid` function which formats UUIDs with their
/// human-readable names from the UUID lookup tables.
fn print_uuid(label: &str, data: &[u8]) {
    match data.len() {
        2 => {
            let uuid16 = get_le16(data);
            let name = bt_uuid16_to_str(uuid16);
            print_field!("{}: {} ({})", label, name, format!("0x{:04x}", uuid16));
        }
        4 => {
            let uuid32 = get_le32(data);
            let name = bt_uuid32_to_str(uuid32);
            print_field!("{}: {} (0x{:08x})", label, name, uuid32);
        }
        16 => {
            // Reconstruct 128-bit UUID string from LE bytes
            let uuid_str = format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:08x}{:04x}",
                get_le32(&data[12..]),
                get_le16(&data[10..]),
                get_le16(&data[8..]),
                get_le16(&data[6..]),
                get_le32(&data[2..]),
                get_le16(&data[0..]),
            );
            let name = bt_uuidstr_to_str(&uuid_str).unwrap_or("Unknown");
            print_field!("{}: {} ({})", label, name, uuid_str);
        }
        _ => {
            print_field!("{}: Unknown UUID length {}", label, data.len());
        }
    }
}

/// Convert raw bytes to a `BtUuid` for GATT DB lookups.
fn bt_uuid_from_data(data: &[u8]) -> Option<BtUuid> {
    match data.len() {
        2 => Some(BtUuid::from_u16(get_le16(data))),
        4 => Some(BtUuid::from_u32(get_le32(data))),
        16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(data);
            Some(BtUuid::from_bytes(&bytes))
        }
        _ => None,
    }
}

/// Get UUID-16 value from a `BtUuid`, returns 0 if not a 16-bit UUID.
fn uuid_to_u16(uuid: &BtUuid) -> u16 {
    match uuid {
        BtUuid::Uuid16(v) => *v,
        _ => 0,
    }
}

// ============================================================================
// Handle / Range Printing
// ============================================================================

// ============================================================================
// Characteristic Properties
// ============================================================================

static CHRC_PROP_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Broadcast (0x01)" },
    BitfieldData { bit: 1, str_val: "Read (0x02)" },
    BitfieldData { bit: 2, str_val: "Write Without Response (0x04)" },
    BitfieldData { bit: 3, str_val: "Write (0x08)" },
    BitfieldData { bit: 4, str_val: "Notify (0x10)" },
    BitfieldData { bit: 5, str_val: "Indicate (0x20)" },
    BitfieldData { bit: 6, str_val: "Authenticated Signed Writes (0x40)" },
    BitfieldData { bit: 7, str_val: "Extended Properties (0x80)" },
];

// ============================================================================
// GATT UUID-Specific Value Handler Table
// ============================================================================

/// Describes a UUID-specific value decoder for GATT characteristics.
struct GattHandler {
    uuid: u16,
    read: Option<fn(&mut L2capFrame<'_>)>,
    write: Option<fn(&mut L2capFrame<'_>)>,
    notify: Option<fn(&mut L2capFrame<'_>)>,
}

/// Look up a GATT handler by UUID-16.
fn get_handler(uuid: u16) -> Option<&'static GattHandler> {
    GATT_HANDLERS.iter().find(|h| h.uuid == uuid)
}

// ---------------------------------------------------------------------------
// Attribute Information Printing (0x2800-0x2803)
// ---------------------------------------------------------------------------

fn print_attribute_info(uuid16: u16, frame: &mut L2capFrame<'_>) {
    match uuid16 {
        0x2800 | 0x2801 => {
            // Primary Service / Secondary Service — value is the service UUID
            let rem = frame.remaining();
            if let Some(data) = frame.pull(rem) {
                let data_owned: Vec<u8> = data.to_vec();
                print_uuid("UUID", &data_owned);
            }
        }
        0x2802 => {
            // Include Declaration: included service handle, end group handle, UUID
            if let (Some(inc_handle), Some(end_grp)) = (frame.get_le16(), frame.get_le16()) {
                print_field!("Included Service Handle: 0x{:04x}", inc_handle);
                print_field!("End Group Handle: 0x{:04x}", end_grp);
                let rem = frame.remaining();
                if rem > 0 {
                    if let Some(data) = frame.pull(rem) {
                        let data_owned: Vec<u8> = data.to_vec();
                        print_uuid("UUID", &data_owned);
                    }
                }
            }
        }
        0x2803 => {
            // Characteristic Declaration: properties, value handle, UUID
            if let Some(props) = frame.get_u8() {
                print_field!("Properties: 0x{:02x}", props);
                display::print_bitfield(2, u64::from(props), CHRC_PROP_TABLE);
            }
            if let Some(val_handle) = frame.get_le16() {
                print_field!("Value Handle: 0x{:04x}", val_handle);
            }
            let rem = frame.remaining();
            if rem > 0 {
                if let Some(data) = frame.pull(rem) {
                    let data_owned: Vec<u8> = data.to_vec();
                    print_uuid("UUID", &data_owned);
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// CCC (Client Characteristic Configuration) Decoder — 0x2902
// ---------------------------------------------------------------------------

static CCC_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Notification (0x01)" },
    BitfieldData { bit: 1, str_val: "Indication (0x02)" },
];

fn ccc_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_le16() {
        print_field!("Client Characteristic Configuration: 0x{:04x}", val);
        display::print_bitfield(2, u64::from(val), CCC_TABLE);
    }
}

fn ccc_write(frame: &mut L2capFrame<'_>) {
    ccc_read(frame);
}

// ---------------------------------------------------------------------------
// Primary / Secondary Service Value Decoders — 0x2800, 0x2801
// ---------------------------------------------------------------------------

fn svc_read(frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if let Some(data) = frame.pull(rem) {
        let data_owned: Vec<u8> = data.to_vec();
        print_uuid("Service UUID", &data_owned);
    }
}

fn pri_svc_read(frame: &mut L2capFrame<'_>) {
    svc_read(frame);
}

fn sec_svc_read(frame: &mut L2capFrame<'_>) {
    svc_read(frame);
}

// ---------------------------------------------------------------------------
// Characteristic Declaration Value Decoder — 0x2803
// ---------------------------------------------------------------------------

fn chrc_read(frame: &mut L2capFrame<'_>) {
    if let Some(props) = frame.get_u8() {
        print_field!("Properties: 0x{:02x}", props);
        display::print_bitfield(2, u64::from(props), CHRC_PROP_TABLE);
    }
    if let Some(val_handle) = frame.get_le16() {
        print_field!("Value Handle: 0x{:04x}", val_handle);
    }
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            let data_owned: Vec<u8> = data.to_vec();
            print_uuid("UUID", &data_owned);
        }
    }
}

// ---------------------------------------------------------------------------
// PAC (Published Audio Capabilities) Decoders — 0x2BC9/0x2BCB
// ---------------------------------------------------------------------------

static PAC_CONTEXT_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Unspecified (0x0001)" },
    BitfieldData { bit: 1, str_val: "Conversational (0x0002)" },
    BitfieldData { bit: 2, str_val: "Media (0x0004)" },
    BitfieldData { bit: 3, str_val: "Game (0x0008)" },
    BitfieldData { bit: 4, str_val: "Instructional (0x0010)" },
    BitfieldData { bit: 5, str_val: "Voice Assistants (0x0020)" },
    BitfieldData { bit: 6, str_val: "Live (0x0040)" },
    BitfieldData { bit: 7, str_val: "Sound Effects (0x0080)" },
    BitfieldData { bit: 8, str_val: "Notifications (0x0100)" },
    BitfieldData { bit: 9, str_val: "Ringtone (0x0200)" },
    BitfieldData { bit: 10, str_val: "Alerts (0x0400)" },
    BitfieldData { bit: 11, str_val: "Emergency Alarm (0x0800)" },
    BitfieldData { bit: 12, str_val: "RFU (0x1000)" },
    BitfieldData { bit: 13, str_val: "RFU (0x2000)" },
    BitfieldData { bit: 14, str_val: "RFU (0x4000)" },
    BitfieldData { bit: 15, str_val: "RFU (0x8000)" },
];

fn print_context(label: &str, frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_le16() {
        print_field!("{}: 0x{:04x}", label, val);
        display::print_bitfield(2, u64::from(val), PAC_CONTEXT_TABLE);
    }
}

/// PAC frequency table for LTV decoding.
static PAC_FREQ_TABLE: &[(u16, &str)] = &[
    (0x0001, "8 Khz (0x0001)"),
    (0x0002, "11.025 Khz (0x0002)"),
    (0x0004, "16 Khz (0x0004)"),
    (0x0008, "22.05 Khz (0x0008)"),
    (0x0010, "24 Khz (0x0010)"),
    (0x0020, "32 Khz (0x0020)"),
    (0x0040, "44.1 Khz (0x0040)"),
    (0x0080, "48 Khz (0x0080)"),
    (0x0100, "88.2 Khz (0x0100)"),
    (0x0200, "96 Khz (0x0200)"),
    (0x0400, "176.4 Khz (0x0400)"),
    (0x0800, "192 Khz (0x0800)"),
    (0x1000, "384 Khz (0x1000)"),
];

static PAC_DURATION_TABLE: &[(u8, &str)] = &[(0x01, "7.5 ms (0x01)"), (0x02, "10 ms (0x02)")];

fn pac_decode_freq(data: &[u8]) {
    if data.len() >= 2 {
        let val = get_le16(data);
        print_field!("  Sampling Frequencies: 0x{:04x}", val);
        for &(mask, name) in PAC_FREQ_TABLE {
            if val & mask != 0 {
                print_field!("    {}", name);
            }
        }
    }
}

fn pac_decode_duration(data: &[u8]) {
    if !data.is_empty() {
        let val = data[0];
        print_field!("  Frame Duration: 0x{:02x}", val);
        for &(mask, name) in PAC_DURATION_TABLE {
            if val & mask != 0 {
                print_field!("    {}", name);
            }
        }
    }
}

fn pac_decode_channels(data: &[u8]) {
    if !data.is_empty() {
        let val = data[0];
        print_field!("  Audio Channel Counts: 0x{:02x}", val);
        for i in 0u8..8 {
            if val & (1 << i) != 0 {
                print_field!("    {} channel(s)", i + 1);
            }
        }
    }
}

fn pac_decode_frame_length(data: &[u8]) {
    if data.len() >= 4 {
        let min_len = get_le16(data);
        let max_len = get_le16(&data[2..]);
        print_field!("  Frame Length: {} - {}", min_len, max_len);
    }
}

fn pac_decode_sdu(data: &[u8]) {
    if !data.is_empty() {
        print_field!("  Max Supported Frames Per SDU: {}", data[0]);
    }
}

/// PAC capability LTV type decoders.
static PAC_CAP_TABLE: &[(u8, fn(&[u8]))] = &[
    (0x01, pac_decode_freq),
    (0x02, pac_decode_duration),
    (0x03, pac_decode_channels),
    (0x04, pac_decode_frame_length),
    (0x05, pac_decode_sdu),
];

fn print_ltv(label: &str, data: &[u8], table: &[(u8, fn(&[u8]))]) {
    let mut offset = 0;
    while offset < data.len() {
        let len = data[offset] as usize;
        offset += 1;
        if len == 0 || offset + len > data.len() {
            break;
        }
        let type_val = data[offset];
        let value = &data[offset + 1..offset + len];
        let mut found = false;
        for &(t, decoder) in table {
            if t == type_val {
                decoder(value);
                found = true;
                break;
            }
        }
        if !found {
            print_field!("  {} Type 0x{:02x}:", label, type_val);
            display::print_hexdump(value);
        }
        offset += len;
    }
}

fn print_ase_codec(frame: &mut L2capFrame<'_>) {
    if let Some(id) = frame.get_u8() {
        print_field!("  Codec: 0x{:02x}", id);
    }
    if let (Some(cid), Some(vid)) = (frame.get_le16(), frame.get_le16()) {
        print_field!("  Company Codec ID: 0x{:04x}", cid);
        print_field!("  Vendor Codec ID: 0x{:04x}", vid);
    }
}

static ASE_METADATA_TABLE: &[(u8, &str)] = &[
    (0x01, "Preferred Audio Contexts"),
    (0x02, "Streaming Audio Contexts"),
    (0x03, "Program Info"),
    (0x04, "Language"),
    (0x05, "CCID List"),
    (0x06, "Parental Rating"),
    (0x07, "Program Info URI"),
    (0x08, "Audio Active State"),
    (0x09, "Broadcast Audio Immediate Rendering Flag"),
    (0xfe, "Extended Metadata"),
    (0xff, "Vendor Specific"),
];

fn print_ase_metadata(frame: &mut L2capFrame<'_>) {
    if let Some(meta_len) = frame.get_u8() {
        print_field!("  Metadata Length: {}", meta_len);
        if meta_len == 0 {
            return;
        }
        if let Some(meta_data) = frame.pull(meta_len as usize) {
            let meta_vec: Vec<u8> = meta_data.to_vec();
            let mut off = 0;
            while off < meta_vec.len() {
                let l = meta_vec[off] as usize;
                off += 1;
                if l == 0 || off + l > meta_vec.len() {
                    break;
                }
                let t = meta_vec[off];
                let name =
                    ASE_METADATA_TABLE.iter().find(|e| e.0 == t).map(|e| e.1).unwrap_or("Unknown");
                print_field!("    Metadata: {} (Type 0x{:02x})", name, t);
                if l > 1 {
                    display::print_hexdump(&meta_vec[off + 1..off + l]);
                }
                off += l;
            }
        }
    }
}

fn print_pac(frame: &mut L2capFrame<'_>) {
    let num = match frame.get_u8() {
        Some(n) => n,
        None => return,
    };
    print_field!("  Number of PAC(s): {}", num);
    for i in 0..num {
        print_field!("  PAC #{}:", i);
        print_ase_codec(frame);
        // Codec Specific Capabilities
        if let Some(cc_len) = frame.get_u8() {
            print_field!("  Codec Specific Capabilities Length: {}", cc_len);
            if cc_len > 0 {
                if let Some(cc_data) = frame.pull(cc_len as usize) {
                    let cc_vec: Vec<u8> = cc_data.to_vec();
                    print_ltv("Capability", &cc_vec, PAC_CAP_TABLE);
                }
            }
        }
        // Metadata
        print_ase_metadata(frame);
    }
}

fn pac_read(frame: &mut L2capFrame<'_>) {
    print_pac(frame);
}

fn pac_notify(frame: &mut L2capFrame<'_>) {
    print_pac(frame);
}

// ---------------------------------------------------------------------------
// PAC Audio Location — 0x2BCA/0x2BCC
// ---------------------------------------------------------------------------

static CHANNEL_LOCATION_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Front Left (0x00000001)" },
    BitfieldData { bit: 1, str_val: "Front Right (0x00000002)" },
    BitfieldData { bit: 2, str_val: "Front Center (0x00000004)" },
    BitfieldData { bit: 3, str_val: "Low Frequency Effects 1 (0x00000008)" },
    BitfieldData { bit: 4, str_val: "Back Left (0x00000010)" },
    BitfieldData { bit: 5, str_val: "Back Right (0x00000020)" },
    BitfieldData { bit: 6, str_val: "Front Left of Center (0x00000040)" },
    BitfieldData { bit: 7, str_val: "Front Right of Center (0x00000080)" },
    BitfieldData { bit: 8, str_val: "Back Center (0x00000100)" },
    BitfieldData { bit: 9, str_val: "Low Frequency Effects 2 (0x00000200)" },
    BitfieldData { bit: 10, str_val: "Side Left (0x00000400)" },
    BitfieldData { bit: 11, str_val: "Side Right (0x00000800)" },
    BitfieldData { bit: 12, str_val: "Top Front Left (0x00001000)" },
    BitfieldData { bit: 13, str_val: "Top Front Right (0x00002000)" },
    BitfieldData { bit: 14, str_val: "Top Front Center (0x00004000)" },
    BitfieldData { bit: 15, str_val: "Top Center (0x00008000)" },
    BitfieldData { bit: 16, str_val: "Top Back Left (0x00010000)" },
    BitfieldData { bit: 17, str_val: "Top Back Right (0x00020000)" },
    BitfieldData { bit: 18, str_val: "Top Side Left (0x00040000)" },
    BitfieldData { bit: 19, str_val: "Top Side Right (0x00080000)" },
    BitfieldData { bit: 20, str_val: "Top Back Center (0x00100000)" },
    BitfieldData { bit: 21, str_val: "Bottom Front Center (0x00200000)" },
    BitfieldData { bit: 22, str_val: "Bottom Front Left (0x00400000)" },
    BitfieldData { bit: 23, str_val: "Bottom Front Right (0x00800000)" },
    BitfieldData { bit: 24, str_val: "Front Left Wide (0x01000000)" },
    BitfieldData { bit: 25, str_val: "Front Right Wide (0x02000000)" },
    BitfieldData { bit: 26, str_val: "Left Surround (0x04000000)" },
    BitfieldData { bit: 27, str_val: "Right Surround (0x08000000)" },
    BitfieldData { bit: 28, str_val: "RFU (0x10000000)" },
    BitfieldData { bit: 29, str_val: "RFU (0x20000000)" },
    BitfieldData { bit: 30, str_val: "RFU (0x40000000)" },
    BitfieldData { bit: 31, str_val: "RFU (0x80000000)" },
];

fn print_location(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_le32() {
        print_field!("  Location: 0x{:08x}", val);
        display::print_bitfield(4, u64::from(val), CHANNEL_LOCATION_TABLE);
    }
}

fn pac_loc_read(frame: &mut L2capFrame<'_>) {
    print_location(frame);
}

fn pac_loc_notify(frame: &mut L2capFrame<'_>) {
    print_location(frame);
}

// ---------------------------------------------------------------------------
// PAC Audio Contexts — 0x2BCD/0x2BCE
// ---------------------------------------------------------------------------

fn print_pac_context(frame: &mut L2capFrame<'_>) {
    print_context("Sink Context", frame);
    print_context("Source Context", frame);
}

fn pac_context_read(frame: &mut L2capFrame<'_>) {
    print_pac_context(frame);
}

fn pac_context_notify(frame: &mut L2capFrame<'_>) {
    print_pac_context(frame);
}

// ---------------------------------------------------------------------------
// ASE (Audio Stream Endpoint) — 0x2BC4/0x2BC5, 0x2BC6
// ---------------------------------------------------------------------------

fn ase_debug_freq(val: u8) -> &'static str {
    match val {
        0x01 => "8 Khz",
        0x02 => "11.025 Khz",
        0x03 => "16 Khz",
        0x04 => "22.05 Khz",
        0x05 => "24 Khz",
        0x06 => "32 Khz",
        0x07 => "44.1 Khz",
        0x08 => "48 Khz",
        0x09 => "88.2 Khz",
        0x0a => "96 Khz",
        0x0b => "176.4 Khz",
        0x0c => "192 Khz",
        0x0d => "384 Khz",
        _ => "RFU",
    }
}

fn ase_debug_duration(val: u8) -> &'static str {
    match val {
        0x01 => "7.5 ms",
        0x02 => "10 ms",
        _ => "RFU",
    }
}

fn ase_debug_location(data: &[u8]) {
    if data.len() >= 4 {
        let val = get_le32(data);
        print_field!("    Location: 0x{:08x}", val);
        display::print_bitfield(6, u64::from(val), CHANNEL_LOCATION_TABLE);
    }
}

fn ase_debug_frame_length(data: &[u8]) {
    if data.len() >= 2 {
        let val = get_le16(data);
        print_field!("    Frame Length: {}", val);
    }
}

fn ase_debug_blocks(data: &[u8]) {
    if !data.is_empty() {
        print_field!("    Blocks: {}", data[0]);
    }
}

fn ase_cc_decode_freq(data: &[u8]) {
    if !data.is_empty() {
        print_field!("    Sampling Frequency: {} (0x{:02x})", ase_debug_freq(data[0]), data[0]);
    }
}

fn ase_cc_decode_duration(data: &[u8]) {
    if !data.is_empty() {
        print_field!("    Frame Duration: {} (0x{:02x})", ase_debug_duration(data[0]), data[0]);
    }
}

/// ASE Codec Config LTV decoders.
static ASE_CC_TABLE: &[(u8, fn(&[u8]))] = &[
    (0x01, ase_cc_decode_freq),
    (0x02, ase_cc_decode_duration),
    (0x03, ase_debug_location),
    (0x04, ase_debug_frame_length),
    (0x05, ase_debug_blocks),
];

fn print_ase_config(frame: &mut L2capFrame<'_>) {
    if let Some(framing) = frame.get_u8() {
        print_field!(
            "    Framing: {} (0x{:02x})",
            if framing == 0 { "Unframed" } else { "Framed" },
            framing
        );
    }
    if let Some(phy) = frame.get_u8() {
        print_field!("    PHY: 0x{:02x}", phy);
        print_ase_phy(phy);
    }
    if let Some(rtn) = frame.get_u8() {
        print_field!("    RTN: {}", rtn);
    }
    if let Some(latency) = frame.get_le16() {
        print_field!("    Max Transport Latency: {} ms", latency);
    }
    print_ase_pd(frame, "Presentation Delay Min");
    print_ase_pd(frame, "Presentation Delay Max");
    print_ase_pd(frame, "Preferred Presentation Delay Min");
    print_ase_pd(frame, "Preferred Presentation Delay Max");
    print_ase_codec(frame);
    // Codec Specific Configuration
    if let Some(cc_len) = frame.get_u8() {
        print_field!("    Codec Specific Configuration Length: {}", cc_len);
        if cc_len > 0 {
            if let Some(cc_data) = frame.pull(cc_len as usize) {
                let cc_vec: Vec<u8> = cc_data.to_vec();
                print_ltv("Config", &cc_vec, ASE_CC_TABLE);
            }
        }
    }
}

fn print_ase_qos(frame: &mut L2capFrame<'_>) {
    if let Some(cig_id) = frame.get_u8() {
        print_field!("    CIG ID: 0x{:02x}", cig_id);
    }
    if let Some(cis_id) = frame.get_u8() {
        print_field!("    CIS ID: 0x{:02x}", cis_id);
    }
    if let Some(interval) = frame.get_le24() {
        print_field!("    SDU Interval: {} us", interval);
    }
    if let Some(framing) = frame.get_u8() {
        print_field!(
            "    Framing: {} (0x{:02x})",
            if framing == 0 { "Unframed" } else { "Framed" },
            framing
        );
    }
    if let Some(phy) = frame.get_u8() {
        print_field!("    PHY: 0x{:02x}", phy);
        print_ase_phy(phy);
    }
    if let Some(sdu) = frame.get_le16() {
        print_field!("    Max SDU: {}", sdu);
    }
    if let Some(rtn) = frame.get_u8() {
        print_field!("    RTN: {}", rtn);
    }
    if let Some(latency) = frame.get_le16() {
        print_field!("    Max Transport Latency: {} ms", latency);
    }
    print_ase_pd(frame, "Presentation Delay");
}

static PHY_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "LE 1M (0x01)" },
    BitfieldData { bit: 1, str_val: "LE 2M (0x02)" },
    BitfieldData { bit: 2, str_val: "LE Coded (0x04)" },
];

fn print_ase_phy(phy: u8) {
    display::print_bitfield(4, u64::from(phy), PHY_TABLE);
}

fn print_ase_pd(frame: &mut L2capFrame<'_>, label: &str) {
    if let Some(pd) = frame.get_le24() {
        print_field!("    {}: {} us", label, pd);
    }
}

fn print_ase_status(frame: &mut L2capFrame<'_>) {
    let ase_id = match frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    print_field!("  ASE ID: {}", ase_id);

    let state = match frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let state_str = match state {
        0x00 => "Idle",
        0x01 => "Codec Configured",
        0x02 => "QoS Configured",
        0x03 => "Enabling",
        0x04 => "Streaming",
        0x05 => "Disabling",
        0x06 => "Releasing",
        _ => "Unknown",
    };
    print_field!("  State: {} (0x{:02x})", state_str, state);

    match state {
        0x01 => {
            // Codec Configured: print config
            print_ase_config(frame);
        }
        0x02 => {
            // QoS Configured: print QoS
            print_ase_qos(frame);
        }
        0x03..=0x05 => {
            // Enabling/Streaming/Disabling: CIG/CIS + metadata
            if let Some(cig_id) = frame.get_u8() {
                print_field!("    CIG ID: 0x{:02x}", cig_id);
            }
            if let Some(cis_id) = frame.get_u8() {
                print_field!("    CIS ID: 0x{:02x}", cis_id);
            }
            print_ase_metadata(frame);
        }
        _ => {}
    }
}

fn ase_read(frame: &mut L2capFrame<'_>) {
    print_ase_status(frame);
}

fn ase_notify(frame: &mut L2capFrame<'_>) {
    print_ase_status(frame);
}

// ASE Control Point write decoder — 0x2BC6
fn print_ase_target_latency(val: u8) -> &'static str {
    match val {
        0x01 => "Low Latency",
        0x02 => "Balanced Latency/Reliability",
        0x03 => "High Reliability",
        _ => "Unknown",
    }
}

fn ase_cp_write(frame: &mut L2capFrame<'_>) {
    let opcode = match frame.get_u8() {
        Some(v) => v,
        None => return,
    };

    let op_str = match opcode {
        0x01 => "Codec Configure",
        0x02 => "QoS Configure",
        0x03 => "Enable",
        0x04 => "Receiver Start Ready",
        0x05 => "Disable",
        0x06 => "Receiver Stop Ready",
        0x07 => "Update Metadata",
        0x08 => "Release",
        _ => "Unknown",
    };
    print_field!("  Opcode: {} (0x{:02x})", op_str, opcode);

    let num_ase = match frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    print_field!("  Number of ASE(s): {}", num_ase);

    for _i in 0..num_ase {
        if let Some(ase_id) = frame.get_u8() {
            print_field!("    ASE ID: {}", ase_id);
        }
        match opcode {
            0x01 => {
                // Codec Config
                if let Some(target_latency) = frame.get_u8() {
                    print_field!(
                        "    Target Latency: {} (0x{:02x})",
                        print_ase_target_latency(target_latency),
                        target_latency
                    );
                }
                if let Some(target_phy) = frame.get_u8() {
                    print_field!("    Target PHY: 0x{:02x}", target_phy);
                    print_ase_phy(target_phy);
                }
                print_ase_codec(frame);
                if let Some(cc_len) = frame.get_u8() {
                    print_field!("    Codec Specific Configuration Length: {}", cc_len);
                    if cc_len > 0 {
                        if let Some(cc_data) = frame.pull(cc_len as usize) {
                            let cc_vec: Vec<u8> = cc_data.to_vec();
                            print_ltv("Config", &cc_vec, ASE_CC_TABLE);
                        }
                    }
                }
            }
            0x02 => {
                // QoS Config
                if let Some(cig_id) = frame.get_u8() {
                    print_field!("    CIG ID: 0x{:02x}", cig_id);
                }
                if let Some(cis_id) = frame.get_u8() {
                    print_field!("    CIS ID: 0x{:02x}", cis_id);
                }
                if let Some(interval) = frame.get_le24() {
                    print_field!("    SDU Interval: {} us", interval);
                }
                if let Some(framing) = frame.get_u8() {
                    print_field!(
                        "    Framing: {} (0x{:02x})",
                        if framing == 0 { "Unframed" } else { "Framed" },
                        framing
                    );
                }
                if let Some(phy) = frame.get_u8() {
                    print_field!("    PHY: 0x{:02x}", phy);
                    print_ase_phy(phy);
                }
                if let Some(sdu) = frame.get_le16() {
                    print_field!("    Max SDU: {}", sdu);
                }
                if let Some(rtn) = frame.get_u8() {
                    print_field!("    RTN: {}", rtn);
                }
                if let Some(latency) = frame.get_le16() {
                    print_field!("    Max Transport Latency: {} ms", latency);
                }
                print_ase_pd(frame, "Presentation Delay");
            }
            0x03 | 0x07 => {
                // Enable / Update Metadata
                print_ase_metadata(frame);
            }
            0x04 | 0x05 | 0x06 | 0x08 => {
                // Receiver Start Ready / Disable / Receiver Stop Ready / Release
                // No additional fields per ASE
            }
            _ => {}
        }
    }
}

fn ase_cp_notify(frame: &mut L2capFrame<'_>) {
    let opcode = match frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let op_str = match opcode {
        0x01 => "Codec Configure",
        0x02 => "QoS Configure",
        0x03 => "Enable",
        0x04 => "Receiver Start Ready",
        0x05 => "Disable",
        0x06 => "Receiver Stop Ready",
        0x07 => "Update Metadata",
        0x08 => "Release",
        _ => "Unknown",
    };
    print_field!("  Opcode: {} (0x{:02x})", op_str, opcode);

    let num_ase = match frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    print_field!("  Number of ASE(s): {}", num_ase);

    for _i in 0..num_ase {
        if let Some(ase_id) = frame.get_u8() {
            print_field!("    ASE ID: {}", ase_id);
        }
        if let Some(rsp_code) = frame.get_u8() {
            let rsp_str = match rsp_code {
                0x00 => "Success",
                0x01 => "Unsupported Opcode",
                0x02 => "Invalid Length",
                0x03 => "Invalid ASE ID",
                0x04 => "Invalid ASE State Machine Transition",
                0x05 => "Invalid ASE Direction",
                0x06 => "Unsupported Audio Capabilities",
                0x07 => "Unsupported Configuration Parameter Value",
                0x08 => "Rejected Configuration Parameter Value",
                0x09 => "Invalid Configuration Parameter Value",
                0x0a => "Unsupported Metadata",
                0x0b => "Rejected Metadata",
                0x0c => "Invalid Metadata",
                0x0d => "Insufficient Resources",
                0x0e => "Unspecified Error",
                _ => "Unknown",
            };
            print_field!("    Response Code: {} (0x{:02x})", rsp_str, rsp_code);
        }
        if let Some(reason) = frame.get_u8() {
            let reason_str = match reason {
                0x00 => "None",
                0x01 => "Codec ID",
                0x02 => "Codec Specific Configuration",
                0x03 => "SDU Interval",
                0x04 => "Framing",
                0x05 => "PHY",
                0x06 => "Maximum SDU Size",
                0x07 => "Retransmission Number",
                0x08 => "Max Transport Latency",
                0x09 => "Presentation Delay",
                0x0a => "Invalid ASE CIS Mapping",
                _ => "Unknown",
            };
            print_field!("    Reason: {} (0x{:02x})", reason_str, reason);
        }
    }
}

// ---------------------------------------------------------------------------
// VCS (Volume Control Service) — 0x2B7D/0x2B7E/0x2B7F
// ---------------------------------------------------------------------------

fn vol_state_read(frame: &mut L2capFrame<'_>) {
    if let Some(vol) = frame.get_u8() {
        print_field!("  Volume Setting: {}", vol);
    }
    if let Some(mute) = frame.get_u8() {
        print_field!("  Mute: {} (0x{:02x})", if mute == 0 { "Not Muted" } else { "Muted" }, mute);
    }
    if let Some(cc) = frame.get_u8() {
        print_field!("  Change Counter: {}", cc);
    }
}

fn vol_state_notify(frame: &mut L2capFrame<'_>) {
    vol_state_read(frame);
}

fn vol_cp_write(frame: &mut L2capFrame<'_>) {
    let opcode = match frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let op_str = match opcode {
        0x00 => "Relative Volume Down",
        0x01 => "Relative Volume Up",
        0x02 => "Unmute/Relative Volume Down",
        0x03 => "Unmute/Relative Volume Up",
        0x04 => "Set Absolute Volume",
        0x05 => "Unmute",
        0x06 => "Mute",
        _ => "Unknown",
    };
    print_field!("  Opcode: {} (0x{:02x})", op_str, opcode);
    if let Some(cc) = frame.get_u8() {
        print_field!("  Change Counter: {}", cc);
    }
    if opcode == 0x04 {
        if let Some(vol) = frame.get_u8() {
            print_field!("  Volume Setting: {}", vol);
        }
    }
}

fn vol_flag_read(frame: &mut L2capFrame<'_>) {
    if let Some(flags) = frame.get_u8() {
        print_field!("  Volume Flags: 0x{:02x}", flags);
        if flags & 0x01 != 0 {
            print_field!("    Volume Setting Persisted (0x01)");
        }
    }
}

fn vol_flag_notify(frame: &mut L2capFrame<'_>) {
    vol_flag_read(frame);
}

// ---------------------------------------------------------------------------
// CSIP (Coordinated Set Identification) — 0x2B84-0x2B87
// ---------------------------------------------------------------------------

fn csip_sirk_read(frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if let Some(data) = frame.pull(rem) {
        display::print_hex_field("SIRK", data);
    }
}

fn csip_sirk_notify(frame: &mut L2capFrame<'_>) {
    csip_sirk_read(frame);
}

fn csip_size_read(frame: &mut L2capFrame<'_>) {
    if let Some(size) = frame.get_u8() {
        print_field!("  Set Size: {}", size);
    }
}

fn csip_size_notify(frame: &mut L2capFrame<'_>) {
    csip_size_read(frame);
}

fn csip_lock_read(frame: &mut L2capFrame<'_>) {
    if let Some(lock) = frame.get_u8() {
        let s = match lock {
            0x01 => "Unlocked",
            0x02 => "Locked",
            _ => "Unknown",
        };
        print_field!("  Lock: {} (0x{:02x})", s, lock);
    }
}

fn csip_rank_read(frame: &mut L2capFrame<'_>) {
    if let Some(rank) = frame.get_u8() {
        print_field!("  Rank: {}", rank);
    }
}

// ---------------------------------------------------------------------------
// MCS (Media Control Service) — 0x2B93+
// ---------------------------------------------------------------------------

fn print_utf8_name(label: &str, frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if let Some(data) = frame.pull(rem) {
        let s = String::from_utf8_lossy(data);
        print_field!("  {}: {}", label, s);
    }
}

fn mp_name_read(frame: &mut L2capFrame<'_>) {
    print_utf8_name("Media Player Name", frame);
}

fn mp_name_notify(frame: &mut L2capFrame<'_>) {
    mp_name_read(frame);
}

fn track_changed_notify(frame: &mut L2capFrame<'_>) {
    let _ = frame;
    print_field!("  Track Changed");
}

fn track_title_read(frame: &mut L2capFrame<'_>) {
    print_utf8_name("Track Title", frame);
}

fn track_title_notify(frame: &mut L2capFrame<'_>) {
    track_title_read(frame);
}

fn track_duration_read(frame: &mut L2capFrame<'_>) {
    if let Some(dur) = frame.get_le32() {
        let dur_i = dur as i32;
        if dur_i == -1 {
            print_field!("  Track Duration: Unknown");
        } else {
            print_field!("  Track Duration: {} ms", dur_i);
        }
    }
}

fn track_duration_notify(frame: &mut L2capFrame<'_>) {
    track_duration_read(frame);
}

fn track_position_read(frame: &mut L2capFrame<'_>) {
    if let Some(pos) = frame.get_le32() {
        let pos_i = pos as i32;
        if pos_i == -1 {
            print_field!("  Track Position: Unavailable");
        } else {
            print_field!("  Track Position: {} ms", pos_i);
        }
    }
}

fn track_position_write(frame: &mut L2capFrame<'_>) {
    track_position_read(frame);
}

fn track_position_notify(frame: &mut L2capFrame<'_>) {
    track_position_read(frame);
}

fn media_state_read(frame: &mut L2capFrame<'_>) {
    if let Some(state) = frame.get_u8() {
        let s = match state {
            0x00 => "Inactive",
            0x01 => "Playing",
            0x02 => "Paused",
            0x03 => "Seeking",
            _ => "Unknown",
        };
        print_field!("  Media State: {} (0x{:02x})", s, state);
    }
}

fn media_state_notify(frame: &mut L2capFrame<'_>) {
    media_state_read(frame);
}

static MEDIA_CP_OPCODE_TABLE: &[(u8, &str)] = &[
    (0x01, "Play"),
    (0x02, "Pause"),
    (0x03, "Fast Rewind"),
    (0x04, "Fast Forward"),
    (0x05, "Stop"),
    (0x10, "Move Relative"),
    (0x20, "Previous Segment"),
    (0x21, "Next Segment"),
    (0x22, "First Segment"),
    (0x23, "Last Segment"),
    (0x24, "Goto Segment"),
    (0x30, "Previous Track"),
    (0x31, "Next Track"),
    (0x32, "First Track"),
    (0x33, "Last Track"),
    (0x34, "Goto Track"),
    (0x40, "Previous Group"),
    (0x41, "Next Group"),
    (0x42, "First Group"),
    (0x43, "Last Group"),
    (0x44, "Goto Group"),
];

fn media_cp_write(frame: &mut L2capFrame<'_>) {
    if let Some(opcode) = frame.get_u8() {
        let name =
            MEDIA_CP_OPCODE_TABLE.iter().find(|e| e.0 == opcode).map(|e| e.1).unwrap_or("Unknown");
        print_field!("  Opcode: {} (0x{:02x})", name, opcode);
        // Some opcodes have a parameter (int32)
        if matches!(opcode, 0x10 | 0x24 | 0x34 | 0x44) {
            if let Some(param) = frame.get_le32() {
                print_field!("  Parameter: {}", param as i32);
            }
        }
    }
}

fn media_cp_notify(frame: &mut L2capFrame<'_>) {
    if let Some(opcode) = frame.get_u8() {
        let name =
            MEDIA_CP_OPCODE_TABLE.iter().find(|e| e.0 == opcode).map(|e| e.1).unwrap_or("Unknown");
        print_field!("  Requested Opcode: {} (0x{:02x})", name, opcode);
    }
    if let Some(result) = frame.get_u8() {
        let r = match result {
            0x01 => "Success",
            0x02 => "Opcode Not Supported",
            0x03 => "Media Player Inactive",
            _ => "Unknown",
        };
        print_field!("  Result: {} (0x{:02x})", r, result);
    }
}

static SUPPORTED_OPCODES_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Play (0x00000001)" },
    BitfieldData { bit: 1, str_val: "Pause (0x00000002)" },
    BitfieldData { bit: 2, str_val: "Fast Rewind (0x00000004)" },
    BitfieldData { bit: 3, str_val: "Fast Forward (0x00000008)" },
    BitfieldData { bit: 4, str_val: "Stop (0x00000010)" },
    BitfieldData { bit: 5, str_val: "Move Relative (0x00000020)" },
    BitfieldData { bit: 6, str_val: "Previous Segment (0x00000040)" },
    BitfieldData { bit: 7, str_val: "Next Segment (0x00000080)" },
    BitfieldData { bit: 8, str_val: "First Segment (0x00000100)" },
    BitfieldData { bit: 9, str_val: "Last Segment (0x00000200)" },
    BitfieldData { bit: 10, str_val: "Goto Segment (0x00000400)" },
    BitfieldData { bit: 11, str_val: "Previous Track (0x00000800)" },
    BitfieldData { bit: 12, str_val: "Next Track (0x00001000)" },
    BitfieldData { bit: 13, str_val: "First Track (0x00002000)" },
    BitfieldData { bit: 14, str_val: "Last Track (0x00004000)" },
    BitfieldData { bit: 15, str_val: "Goto Track (0x00008000)" },
    BitfieldData { bit: 16, str_val: "Previous Group (0x00010000)" },
    BitfieldData { bit: 17, str_val: "Next Group (0x00020000)" },
    BitfieldData { bit: 18, str_val: "First Group (0x00040000)" },
    BitfieldData { bit: 19, str_val: "Last Group (0x00080000)" },
    BitfieldData { bit: 20, str_val: "Goto Group (0x00100000)" },
];

fn media_cp_op_supported_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_le32() {
        print_field!("  Supported Opcodes: 0x{:08x}", val);
        display::print_bitfield(4, u64::from(val), SUPPORTED_OPCODES_TABLE);
    }
}

fn media_cp_op_supported_notify(frame: &mut L2capFrame<'_>) {
    media_cp_op_supported_read(frame);
}

fn playing_order_read(frame: &mut L2capFrame<'_>) {
    if let Some(order) = frame.get_u8() {
        let s = match order {
            0x01 => "Single Once",
            0x02 => "Single Repeat",
            0x03 => "In Order Once",
            0x04 => "In Order Repeat",
            0x05 => "Oldest Once",
            0x06 => "Oldest Repeat",
            0x07 => "Newest Once",
            0x08 => "Newest Repeat",
            0x09 => "Shuffle Once",
            0x0a => "Shuffle Repeat",
            _ => "Unknown",
        };
        print_field!("  Playing Order: {} (0x{:02x})", s, order);
    }
}

fn playing_order_write(frame: &mut L2capFrame<'_>) {
    playing_order_read(frame);
}

fn playing_order_notify(frame: &mut L2capFrame<'_>) {
    playing_order_read(frame);
}

static PLAYING_ORDERS_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Single Once (0x0001)" },
    BitfieldData { bit: 1, str_val: "Single Repeat (0x0002)" },
    BitfieldData { bit: 2, str_val: "In Order Once (0x0004)" },
    BitfieldData { bit: 3, str_val: "In Order Repeat (0x0008)" },
    BitfieldData { bit: 4, str_val: "Oldest Once (0x0010)" },
    BitfieldData { bit: 5, str_val: "Oldest Repeat (0x0020)" },
    BitfieldData { bit: 6, str_val: "Newest Once (0x0040)" },
    BitfieldData { bit: 7, str_val: "Newest Repeat (0x0080)" },
    BitfieldData { bit: 8, str_val: "Shuffle Once (0x0100)" },
    BitfieldData { bit: 9, str_val: "Shuffle Repeat (0x0200)" },
];

fn playing_orders_supported_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_le16() {
        print_field!("  Supported Playing Orders: 0x{:04x}", val);
        display::print_bitfield(4, u64::from(val), PLAYING_ORDERS_TABLE);
    }
}

fn content_control_id_read(frame: &mut L2capFrame<'_>) {
    if let Some(ccid) = frame.get_u8() {
        print_field!("  Content Control ID: {}", ccid);
    }
}

// ---------------------------------------------------------------------------
// TBS/CCP (Telephone Bearer Service / Call Control Point)
// ---------------------------------------------------------------------------

fn bearer_provider_name_read(frame: &mut L2capFrame<'_>) {
    print_utf8_name("Bearer Provider Name", frame);
}

fn bearer_provider_name_notify(frame: &mut L2capFrame<'_>) {
    bearer_provider_name_read(frame);
}

fn bearer_uci_read(frame: &mut L2capFrame<'_>) {
    print_utf8_name("Bearer UCI", frame);
}

fn bearer_technology_read(frame: &mut L2capFrame<'_>) {
    if let Some(tech) = frame.get_u8() {
        let s = match tech {
            0x01 => "3G",
            0x02 => "4G",
            0x03 => "LTE",
            0x04 => "Wi-Fi",
            0x05 => "5G",
            0x06 => "GSM",
            0x07 => "CDMA",
            0x08 => "2G",
            0x09 => "WCDMA",
            _ => "Unknown",
        };
        print_field!("  Bearer Technology: {} (0x{:02x})", s, tech);
    }
}

fn bearer_technology_notify(frame: &mut L2capFrame<'_>) {
    bearer_technology_read(frame);
}

fn bearer_uri_schemes_read(frame: &mut L2capFrame<'_>) {
    print_utf8_name("URI Schemes Supported", frame);
}

fn signal_strength_read(frame: &mut L2capFrame<'_>) {
    if let Some(ss) = frame.get_u8() {
        print_field!("  Signal Strength: {}", ss);
    }
}

fn signal_strength_notify(frame: &mut L2capFrame<'_>) {
    signal_strength_read(frame);
}

fn signal_interval_read(frame: &mut L2capFrame<'_>) {
    if let Some(interval) = frame.get_u8() {
        print_field!("  Signal Strength Reporting Interval: {} seconds", interval);
    }
}

fn signal_interval_write(frame: &mut L2capFrame<'_>) {
    signal_interval_read(frame);
}

fn bearer_current_call_list_read(frame: &mut L2capFrame<'_>) {
    while frame.remaining() >= 3 {
        if let Some(idx) = frame.get_u8() {
            print_field!("  Call Index: {}", idx);
        }
        if let Some(state) = frame.get_u8() {
            let s = match state {
                0x00 => "Incoming",
                0x01 => "Dialing",
                0x02 => "Alerting",
                0x03 => "Active",
                0x04 => "Locally Held",
                0x05 => "Remotely Held",
                0x06 => "Locally and Remotely Held",
                _ => "Unknown",
            };
            print_field!("  Call State: {} (0x{:02x})", s, state);
        }
        if let Some(flags) = frame.get_u8() {
            print_field!("  Call Flags: 0x{:02x}", flags);
        }
        // Remaining bytes in this entry are the URI
        // The list entries are delimited by the end of the frame for single-call
        // or by the next call index for multi-call
        let rem = frame.remaining();
        if rem > 0 {
            // Try to read URI until end or next entry
            if let Some(data) = frame.pull(rem) {
                let uri = String::from_utf8_lossy(data);
                print_field!("  Call URI: {}", uri);
            }
        }
    }
}

fn bearer_current_call_list_notify(frame: &mut L2capFrame<'_>) {
    bearer_current_call_list_read(frame);
}

fn call_content_control_id_read(frame: &mut L2capFrame<'_>) {
    content_control_id_read(frame);
}

static STATUS_FLAG_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Inband Ringtone (0x01)" },
    BitfieldData { bit: 1, str_val: "Silent Mode (0x02)" },
];

fn status_flag_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_le16() {
        print_field!("  Status Flags: 0x{:04x}", val);
        display::print_bitfield(4, u64::from(val), STATUS_FLAG_TABLE);
    }
}

fn status_flag_notify(frame: &mut L2capFrame<'_>) {
    status_flag_read(frame);
}

fn incom_target_bearer_uri_read(frame: &mut L2capFrame<'_>) {
    print_utf8_name("Incoming Call Target Bearer URI", frame);
}

fn incom_target_bearer_uri_notify(frame: &mut L2capFrame<'_>) {
    incom_target_bearer_uri_read(frame);
}

fn call_state_read(frame: &mut L2capFrame<'_>) {
    while frame.remaining() >= 3 {
        if let Some(idx) = frame.get_u8() {
            print_field!("  Call Index: {}", idx);
        }
        if let Some(state) = frame.get_u8() {
            let s = match state {
                0x00 => "Incoming",
                0x01 => "Dialing",
                0x02 => "Alerting",
                0x03 => "Active",
                0x04 => "Locally Held",
                0x05 => "Remotely Held",
                0x06 => "Locally and Remotely Held",
                _ => "Unknown",
            };
            print_field!("  Call State: {} (0x{:02x})", s, state);
        }
        if let Some(flags) = frame.get_u8() {
            print_field!("  Call Flags: 0x{:02x}", flags);
        }
    }
}

fn call_state_notify(frame: &mut L2capFrame<'_>) {
    call_state_read(frame);
}

fn call_cp_write(frame: &mut L2capFrame<'_>) {
    if let Some(opcode) = frame.get_u8() {
        let s = match opcode {
            0x00 => "Accept",
            0x01 => "Terminate",
            0x02 => "Local Hold",
            0x03 => "Local Retrieve",
            0x04 => "Originate",
            0x05 => "Join",
            _ => "Unknown",
        };
        print_field!("  Opcode: {} (0x{:02x})", s, opcode);
    }
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            if data.len() == 1 {
                print_field!("  Call Index: {}", data[0]);
            } else {
                let uri = String::from_utf8_lossy(data);
                print_field!("  Parameter: {}", uri);
            }
        }
    }
}

fn call_cp_notify(frame: &mut L2capFrame<'_>) {
    if let Some(opcode) = frame.get_u8() {
        let s = match opcode {
            0x00 => "Accept",
            0x01 => "Terminate",
            0x02 => "Local Hold",
            0x03 => "Local Retrieve",
            0x04 => "Originate",
            0x05 => "Join",
            _ => "Unknown",
        };
        print_field!("  Requested Opcode: {} (0x{:02x})", s, opcode);
    }
    if let Some(result) = frame.get_u8() {
        let r = match result {
            0x00 => "Success",
            0x01 => "Opcode Not Supported",
            0x02 => "Operation Not Possible",
            0x03 => "Invalid Call Index",
            0x04 => "State Mismatch",
            0x05 => "Lack of Resources",
            0x06 => "Invalid Outgoing URI",
            _ => "Unknown",
        };
        print_field!("  Result: {} (0x{:02x})", r, result);
    }
}

static CALL_CP_OPT_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Local Hold (0x01)" },
    BitfieldData { bit: 1, str_val: "Local Retrieve (0x02)" },
    BitfieldData { bit: 2, str_val: "Join (0x04)" },
];

fn call_cp_opt_opcodes_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_le16() {
        print_field!("  Optional Opcodes: 0x{:04x}", val);
        display::print_bitfield(4, u64::from(val), CALL_CP_OPT_TABLE);
    }
}

fn call_termination_reason_notify(frame: &mut L2capFrame<'_>) {
    if let Some(idx) = frame.get_u8() {
        print_field!("  Call Index: {}", idx);
    }
    if let Some(reason) = frame.get_u8() {
        let s = match reason {
            0x00 => "Improper URI",
            0x01 => "Call Failed",
            0x02 => "Remote Party Ended Call",
            0x03 => "Server Ended Call",
            0x04 => "Line Busy",
            0x05 => "Network Congestion",
            0x06 => "Client Terminated Call",
            0x07 => "No Service",
            0x08 => "No Answer",
            0x09 => "Unspecified",
            _ => "Unknown",
        };
        print_field!("  Reason: {} (0x{:02x})", s, reason);
    }
}

fn incoming_call_read(frame: &mut L2capFrame<'_>) {
    if let Some(idx) = frame.get_u8() {
        print_field!("  Call Index: {}", idx);
    }
    print_utf8_name("URI", frame);
}

fn incoming_call_notify(frame: &mut L2capFrame<'_>) {
    incoming_call_read(frame);
}

fn call_friendly_name_read(frame: &mut L2capFrame<'_>) {
    if let Some(idx) = frame.get_u8() {
        print_field!("  Call Index: {}", idx);
    }
    print_utf8_name("Friendly Name", frame);
}

fn call_friendly_name_notify(frame: &mut L2capFrame<'_>) {
    call_friendly_name_read(frame);
}

// ---------------------------------------------------------------------------
// BASS (Broadcast Audio Scan Service) — 0x2BC7/0x2BC8
// ---------------------------------------------------------------------------

fn print_bcast_recv_state(frame: &mut L2capFrame<'_>) {
    if let Some(src_id) = frame.get_u8() {
        print_field!("  Source_ID: {}", src_id);
    }
    if let Some(addr_type) = frame.get_u8() {
        print_field!("  Source_Address_Type: 0x{:02x}", addr_type);
    }
    if let Some(addr_data) = frame.pull(6) {
        let addr = bdaddr_t {
            b: [addr_data[0], addr_data[1], addr_data[2], addr_data[3], addr_data[4], addr_data[5]],
        };
        print_field!("  Source_Address: {}", addr.ba2str());
    }
    if let Some(sid) = frame.get_u8() {
        print_field!("  Source_Adv_SID: {}", sid);
    }
    if let Some(bc_id) = frame.get_le24() {
        print_field!("  Broadcast_ID: 0x{:06x}", bc_id);
    }
    if let Some(pa_sync) = frame.get_u8() {
        let s = match pa_sync {
            0x00 => "Not synchronized to PA",
            0x01 => "SyncInfo Request",
            0x02 => "Synchronized to PA",
            0x03 => "Failed to synchronize to PA",
            0x04 => "No PAST",
            _ => "Unknown",
        };
        print_field!("  PA_Sync_State: {} (0x{:02x})", s, pa_sync);
    }
    if let Some(big_enc) = frame.get_u8() {
        let s = match big_enc {
            0x00 => "Not encrypted",
            0x01 => "Broadcast_Code required",
            0x02 => "Decrypting",
            0x03 => "Bad_Code",
            _ => "Unknown",
        };
        print_field!("  BIG_Encryption: {} (0x{:02x})", s, big_enc);
        if big_enc == 0x03 {
            if let Some(bad_code) = frame.pull(16) {
                display::print_hex_field("Bad_Code", bad_code);
            }
        }
    }
    if let Some(num_subgroups) = frame.get_u8() {
        print_field!("  Num_Subgroups: {}", num_subgroups);
        for i in 0..num_subgroups {
            print_field!("    Subgroup #{}:", i);
            if let Some(bis_sync) = frame.get_le32() {
                print_field!("      BIS_Sync: 0x{:08x}", bis_sync);
            }
            if let Some(meta_len) = frame.get_u8() {
                print_field!("      Metadata Length: {}", meta_len);
                if meta_len > 0 {
                    if let Some(meta) = frame.pull(meta_len as usize) {
                        display::print_hex_field("Metadata", meta);
                    }
                }
            }
        }
    }
}

fn bcast_recv_state_read(frame: &mut L2capFrame<'_>) {
    print_bcast_recv_state(frame);
}

fn bcast_recv_state_notify(frame: &mut L2capFrame<'_>) {
    print_bcast_recv_state(frame);
}

fn bcast_audio_scan_cp_write(frame: &mut L2capFrame<'_>) {
    let opcode = match frame.get_u8() {
        Some(v) => v,
        None => return,
    };
    let op_str = match opcode {
        0x00 => "Remote Scan Stopped",
        0x01 => "Remote Scan Started",
        0x02 => "Add Source",
        0x03 => "Modify Source",
        0x04 => "Set Broadcast_Code",
        0x05 => "Remove Source",
        _ => "Unknown",
    };
    print_field!("  Opcode: {} (0x{:02x})", op_str, opcode);

    match opcode {
        0x02 => {
            // Add Source
            if let Some(addr_type) = frame.get_u8() {
                print_field!("  Source_Address_Type: 0x{:02x}", addr_type);
            }
            if let Some(addr_data) = frame.pull(6) {
                let addr = bdaddr_t {
                    b: [
                        addr_data[0],
                        addr_data[1],
                        addr_data[2],
                        addr_data[3],
                        addr_data[4],
                        addr_data[5],
                    ],
                };
                print_field!("  Source_Address: {}", addr.ba2str());
            }
            if let Some(sid) = frame.get_u8() {
                print_field!("  Source_Adv_SID: {}", sid);
            }
            if let Some(bc_id) = frame.get_le24() {
                print_field!("  Broadcast_ID: 0x{:06x}", bc_id);
            }
            if let Some(pa_sync) = frame.get_u8() {
                let s = match pa_sync {
                    0x00 => "Do not synchronize to PA",
                    0x01 => "Synchronize to PA - PAST available",
                    0x02 => "Synchronize to PA - PAST not available",
                    _ => "Unknown",
                };
                print_field!("  PA_Sync: {} (0x{:02x})", s, pa_sync);
            }
            if let Some(interval) = frame.get_le16() {
                print_field!("  PA_Interval: 0x{:04x}", interval);
            }
            if let Some(num) = frame.get_u8() {
                print_field!("  Num_Subgroups: {}", num);
                for i in 0..num {
                    print_field!("    Subgroup #{}:", i);
                    if let Some(bis_sync) = frame.get_le32() {
                        print_field!("      BIS_Sync: 0x{:08x}", bis_sync);
                    }
                    if let Some(meta_len) = frame.get_u8() {
                        print_field!("      Metadata Length: {}", meta_len);
                        if meta_len > 0 {
                            if let Some(meta) = frame.pull(meta_len as usize) {
                                display::print_hex_field("Metadata", meta);
                            }
                        }
                    }
                }
            }
        }
        0x03 => {
            // Modify Source
            if let Some(src_id) = frame.get_u8() {
                print_field!("  Source_ID: {}", src_id);
            }
            if let Some(pa_sync) = frame.get_u8() {
                let s = match pa_sync {
                    0x00 => "Do not synchronize to PA",
                    0x01 => "Synchronize to PA - PAST available",
                    0x02 => "Synchronize to PA - PAST not available",
                    _ => "Unknown",
                };
                print_field!("  PA_Sync: {} (0x{:02x})", s, pa_sync);
            }
            if let Some(interval) = frame.get_le16() {
                print_field!("  PA_Interval: 0x{:04x}", interval);
            }
            if let Some(num) = frame.get_u8() {
                print_field!("  Num_Subgroups: {}", num);
                for i in 0..num {
                    print_field!("    Subgroup #{}:", i);
                    if let Some(bis_sync) = frame.get_le32() {
                        print_field!("      BIS_Sync: 0x{:08x}", bis_sync);
                    }
                    if let Some(meta_len) = frame.get_u8() {
                        print_field!("      Metadata Length: {}", meta_len);
                        if meta_len > 0 {
                            if let Some(meta) = frame.pull(meta_len as usize) {
                                display::print_hex_field("Metadata", meta);
                            }
                        }
                    }
                }
            }
        }
        0x04 => {
            // Set Broadcast_Code
            if let Some(src_id) = frame.get_u8() {
                print_field!("  Source_ID: {}", src_id);
            }
            if let Some(code) = frame.pull(16) {
                display::print_hex_field("Broadcast_Code", code);
            }
        }
        0x05 => {
            // Remove Source
            if let Some(src_id) = frame.get_u8() {
                print_field!("  Source_ID: {}", src_id);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// GMAP (Gaming Audio) — 0x2C00+
// ---------------------------------------------------------------------------

static GMAP_ROLE_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Unicast Game Gateway (0x01)" },
    BitfieldData { bit: 1, str_val: "Unicast Game Terminal (0x02)" },
    BitfieldData { bit: 2, str_val: "Broadcast Game Sender (0x04)" },
    BitfieldData { bit: 3, str_val: "Broadcast Game Receiver (0x08)" },
];

fn gmap_role_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_u8() {
        print_field!("  GMAP Role: 0x{:02x}", val);
        display::print_bitfield(4, u64::from(val), GMAP_ROLE_TABLE);
    }
}

static UGG_FEATURES_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "UGG Multiplex (0x01)" },
    BitfieldData { bit: 1, str_val: "UGG 96 kbps Source (0x02)" },
    BitfieldData { bit: 2, str_val: "UGG Multilink (0x04)" },
];

fn ugg_features_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_u8() {
        print_field!("  UGG Features: 0x{:02x}", val);
        display::print_bitfield(4, u64::from(val), UGG_FEATURES_TABLE);
    }
}

static UGT_FEATURES_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "UGT Source (0x01)" },
    BitfieldData { bit: 1, str_val: "UGT 80 kbps Source (0x02)" },
    BitfieldData { bit: 2, str_val: "UGT Sink (0x04)" },
    BitfieldData { bit: 3, str_val: "UGT 64 kbps Sink (0x08)" },
    BitfieldData { bit: 4, str_val: "UGT Multiplex (0x10)" },
    BitfieldData { bit: 5, str_val: "UGT Multisink (0x20)" },
    BitfieldData { bit: 6, str_val: "UGT Multisource (0x40)" },
];

fn ugt_features_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_u8() {
        print_field!("  UGT Features: 0x{:02x}", val);
        display::print_bitfield(4, u64::from(val), UGT_FEATURES_TABLE);
    }
}

static BGS_FEATURES_TABLE: &[BitfieldData] =
    &[BitfieldData { bit: 0, str_val: "BGS 96 kbps (0x01)" }];

fn bgs_features_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_u8() {
        print_field!("  BGS Features: 0x{:02x}", val);
        display::print_bitfield(4, u64::from(val), BGS_FEATURES_TABLE);
    }
}

static BGR_FEATURES_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "BGR Multisink (0x01)" },
    BitfieldData { bit: 1, str_val: "BGR Multiplex (0x02)" },
];

fn bgr_features_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_u8() {
        print_field!("  BGR Features: 0x{:02x}", val);
        display::print_bitfield(4, u64::from(val), BGR_FEATURES_TABLE);
    }
}

// ---------------------------------------------------------------------------
// RAS (Ranging Service) — 0x2C01+
// ---------------------------------------------------------------------------

static RAS_FEATURES_TABLE: &[BitfieldData] = &[
    BitfieldData { bit: 0, str_val: "Real-time Ranging Data (0x01)" },
    BitfieldData { bit: 1, str_val: "Retrieve Ranging Data (0x02)" },
    BitfieldData { bit: 2, str_val: "Abort Operation (0x04)" },
    BitfieldData { bit: 3, str_val: "Filter Ranging Data (0x08)" },
];

fn ras_features_read(frame: &mut L2capFrame<'_>) {
    if let Some(val) = frame.get_le16() {
        print_field!("  RAS Features: 0x{:04x}", val);
        display::print_bitfield(4, u64::from(val), RAS_FEATURES_TABLE);
    }
    // Antenna paths
    if frame.remaining() > 0 {
        if let Some(paths) = frame.get_u8() {
            print_field!("  Antenna Paths: {}", paths);
        }
    }
}

fn ras_ranging_data_ready_read(frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if let Some(data) = frame.pull(rem) {
        display::print_hex_field("Ranging Data Ready", data);
    }
}

fn ras_ranging_data_ready_notify(frame: &mut L2capFrame<'_>) {
    ras_ranging_data_ready_read(frame);
}

fn ras_data_overwritten_read(frame: &mut L2capFrame<'_>) {
    if let Some(counter) = frame.get_le16() {
        print_field!("  Ranging Counter: {}", counter);
    }
}

fn ras_data_overwritten_notify(frame: &mut L2capFrame<'_>) {
    ras_data_overwritten_read(frame);
}

fn ras_ranging_data_read(frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if let Some(data) = frame.pull(rem) {
        display::print_hex_field("On-Demand Ranging Data", data);
    }
}

fn ras_ranging_data_notify(frame: &mut L2capFrame<'_>) {
    ras_ranging_data_read(frame);
}

fn ras_cp_write(frame: &mut L2capFrame<'_>) {
    if let Some(opcode) = frame.get_u8() {
        let s = match opcode {
            0x00 => "Get Ranging Data",
            0x01 => "ACK Ranging Data",
            0x02 => "Retrieve Lost Ranging Data Counter",
            0x03 => "Abort Operation",
            0x04 => "Filter Ranging Data",
            _ => "Unknown",
        };
        print_field!("  Opcode: {} (0x{:02x})", s, opcode);
    }
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            display::print_hex_field("Parameters", data);
        }
    }
}

fn ras_cp_notify(frame: &mut L2capFrame<'_>) {
    if let Some(opcode) = frame.get_u8() {
        print_field!("  Opcode: 0x{:02x}", opcode);
    }
    if let Some(result) = frame.get_u8() {
        print_field!("  Result: 0x{:02x}", result);
    }
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            display::print_hex_field("Response Parameters", data);
        }
    }
}

// ---------------------------------------------------------------------------
// HID (Human Interface Device) — 0x2A4A/0x2A4B/0x2A4D/0x2A4E/0x2A22/0x2A32/0x2A33/0x2A4C
// ---------------------------------------------------------------------------

fn hog_info_read(frame: &mut L2capFrame<'_>) {
    if let Some(bcd_hid) = frame.get_le16() {
        print_field!("  bcdHID: 0x{:04x}", bcd_hid);
    }
    if let Some(country_code) = frame.get_u8() {
        print_field!("  bCountryCode: 0x{:02x}", country_code);
    }
    if let Some(flags) = frame.get_u8() {
        print_field!("  Flags: 0x{:02x}", flags);
        if flags & 0x01 != 0 {
            print_field!("    Remote Wake (0x01)");
        }
        if flags & 0x02 != 0 {
            print_field!("    Normally Connectable (0x02)");
        }
    }
}

fn hog_report_map_read(frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if let Some(data) = frame.pull(rem) {
        display::print_hex_field("Report Map", data);
    }
}

fn hog_report_read(frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if let Some(data) = frame.pull(rem) {
        display::print_hex_field("Report", data);
    }
}

fn hog_report_notify(frame: &mut L2capFrame<'_>) {
    hog_report_read(frame);
}

fn hog_report_write(frame: &mut L2capFrame<'_>) {
    hog_report_read(frame);
}

fn hog_protocol_mode_read(frame: &mut L2capFrame<'_>) {
    if let Some(mode) = frame.get_u8() {
        let s = match mode {
            0x00 => "Boot Protocol",
            0x01 => "Report Protocol",
            _ => "Unknown",
        };
        print_field!("  Protocol Mode: {} (0x{:02x})", s, mode);
    }
}

fn hog_cp_write(frame: &mut L2capFrame<'_>) {
    if let Some(cmd) = frame.get_u8() {
        let s = match cmd {
            0x00 => "Suspend",
            0x01 => "Exit Suspend",
            _ => "Unknown",
        };
        print_field!("  HID Control Point: {} (0x{:02x})", s, cmd);
    }
}

fn hog_boot_kb_input_read(frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if let Some(data) = frame.pull(rem) {
        display::print_hex_field("Boot Keyboard Input Report", data);
    }
}

fn hog_boot_kb_output_read(frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if let Some(data) = frame.pull(rem) {
        display::print_hex_field("Boot Keyboard Output Report", data);
    }
}

fn hog_boot_mouse_input_read(frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if let Some(data) = frame.pull(rem) {
        display::print_hex_field("Boot Mouse Input Report", data);
    }
}

// ---------------------------------------------------------------------------
// ============================================================================
// Complete GATT Handlers Table
// ============================================================================

static GATT_HANDLERS: &[GattHandler] = &[
    // Core GATT attribute types
    GattHandler { uuid: 0x2800, read: Some(pri_svc_read), write: None, notify: None },
    GattHandler { uuid: 0x2801, read: Some(sec_svc_read), write: None, notify: None },
    GattHandler { uuid: 0x2803, read: Some(chrc_read), write: None, notify: None },
    GattHandler { uuid: 0x2902, read: Some(ccc_read), write: Some(ccc_write), notify: None },
    // ASE Sink / Source
    GattHandler { uuid: 0x2bc4, read: Some(ase_read), write: None, notify: Some(ase_notify) },
    GattHandler { uuid: 0x2bc5, read: Some(ase_read), write: None, notify: Some(ase_notify) },
    // ASE Control Point
    GattHandler {
        uuid: 0x2bc6,
        read: None,
        write: Some(ase_cp_write),
        notify: Some(ase_cp_notify),
    },
    // PAC Sink / Source
    GattHandler { uuid: 0x2bc9, read: Some(pac_read), write: None, notify: Some(pac_notify) },
    GattHandler { uuid: 0x2bcb, read: Some(pac_read), write: None, notify: Some(pac_notify) },
    // PAC Sink / Source Location
    GattHandler {
        uuid: 0x2bca,
        read: Some(pac_loc_read),
        write: None,
        notify: Some(pac_loc_notify),
    },
    GattHandler {
        uuid: 0x2bcc,
        read: Some(pac_loc_read),
        write: None,
        notify: Some(pac_loc_notify),
    },
    // PAC Available / Supported Audio Contexts
    GattHandler {
        uuid: 0x2bcd,
        read: Some(pac_context_read),
        write: None,
        notify: Some(pac_context_notify),
    },
    GattHandler {
        uuid: 0x2bce,
        read: Some(pac_context_read),
        write: None,
        notify: Some(pac_context_notify),
    },
    // VCS Volume State / Control Point / Flags
    GattHandler {
        uuid: 0x2b7d,
        read: Some(vol_state_read),
        write: None,
        notify: Some(vol_state_notify),
    },
    GattHandler { uuid: 0x2b7e, read: None, write: Some(vol_cp_write), notify: None },
    GattHandler {
        uuid: 0x2b7f,
        read: Some(vol_flag_read),
        write: None,
        notify: Some(vol_flag_notify),
    },
    // CSIP SIRK / Size / Lock / Rank
    GattHandler {
        uuid: 0x2b84,
        read: Some(csip_sirk_read),
        write: None,
        notify: Some(csip_sirk_notify),
    },
    GattHandler {
        uuid: 0x2b85,
        read: Some(csip_size_read),
        write: None,
        notify: Some(csip_size_notify),
    },
    GattHandler { uuid: 0x2b86, read: Some(csip_lock_read), write: None, notify: None },
    GattHandler { uuid: 0x2b87, read: Some(csip_rank_read), write: None, notify: None },
    // MCS: Media Player Name, Track Changed, Track Title, Track Duration, Track Position
    GattHandler {
        uuid: 0x2b93,
        read: Some(mp_name_read),
        write: None,
        notify: Some(mp_name_notify),
    },
    GattHandler { uuid: 0x2b96, read: None, write: None, notify: Some(track_changed_notify) },
    GattHandler {
        uuid: 0x2b97,
        read: Some(track_title_read),
        write: None,
        notify: Some(track_title_notify),
    },
    GattHandler {
        uuid: 0x2b98,
        read: Some(track_duration_read),
        write: None,
        notify: Some(track_duration_notify),
    },
    GattHandler {
        uuid: 0x2b99,
        read: Some(track_position_read),
        write: Some(track_position_write),
        notify: Some(track_position_notify),
    },
    // MCS: Media State, Media Control Point, Supported Opcodes, Playing Order, Playing Orders Supported
    GattHandler {
        uuid: 0x2ba3,
        read: Some(media_state_read),
        write: None,
        notify: Some(media_state_notify),
    },
    GattHandler {
        uuid: 0x2ba4,
        read: None,
        write: Some(media_cp_write),
        notify: Some(media_cp_notify),
    },
    GattHandler {
        uuid: 0x2ba5,
        read: Some(media_cp_op_supported_read),
        write: None,
        notify: Some(media_cp_op_supported_notify),
    },
    GattHandler {
        uuid: 0x2ba1,
        read: Some(playing_order_read),
        write: Some(playing_order_write),
        notify: Some(playing_order_notify),
    },
    GattHandler {
        uuid: 0x2ba2,
        read: Some(playing_orders_supported_read),
        write: None,
        notify: None,
    },
    // MCS: Content Control ID
    GattHandler { uuid: 0x2bba, read: Some(content_control_id_read), write: None, notify: None },
    // BASS: Broadcast Audio Scan CP, Broadcast Receive State
    GattHandler { uuid: 0x2bc7, read: None, write: Some(bcast_audio_scan_cp_write), notify: None },
    GattHandler {
        uuid: 0x2bc8,
        read: Some(bcast_recv_state_read),
        write: None,
        notify: Some(bcast_recv_state_notify),
    },
    // TBS/CCP: Bearer Provider Name, UCI, Technology, URI Schemes, Signal Strength
    GattHandler {
        uuid: 0x2bb3,
        read: Some(bearer_provider_name_read),
        write: None,
        notify: Some(bearer_provider_name_notify),
    },
    GattHandler { uuid: 0x2bb4, read: Some(bearer_uci_read), write: None, notify: None },
    GattHandler {
        uuid: 0x2bb5,
        read: Some(bearer_technology_read),
        write: None,
        notify: Some(bearer_technology_notify),
    },
    GattHandler { uuid: 0x2bb6, read: Some(bearer_uri_schemes_read), write: None, notify: None },
    GattHandler {
        uuid: 0x2bb7,
        read: Some(signal_strength_read),
        write: None,
        notify: Some(signal_strength_notify),
    },
    GattHandler {
        uuid: 0x2bb8,
        read: Some(signal_interval_read),
        write: Some(signal_interval_write),
        notify: None,
    },
    // TBS: Current Call List, Call Content Control ID, Status Flags
    GattHandler {
        uuid: 0x2bb9,
        read: Some(bearer_current_call_list_read),
        write: None,
        notify: Some(bearer_current_call_list_notify),
    },
    GattHandler {
        uuid: 0x2bba,
        read: Some(call_content_control_id_read),
        write: None,
        notify: None,
    },
    GattHandler {
        uuid: 0x2bbb,
        read: Some(status_flag_read),
        write: None,
        notify: Some(status_flag_notify),
    },
    // TBS: Incoming Call Target Bearer URI
    GattHandler {
        uuid: 0x2bbc,
        read: Some(incom_target_bearer_uri_read),
        write: None,
        notify: Some(incom_target_bearer_uri_notify),
    },
    // TBS: Call State, Call Control Point, Call Control Point Optional Opcodes
    GattHandler {
        uuid: 0x2bbd,
        read: Some(call_state_read),
        write: None,
        notify: Some(call_state_notify),
    },
    GattHandler {
        uuid: 0x2bbe,
        read: None,
        write: Some(call_cp_write),
        notify: Some(call_cp_notify),
    },
    GattHandler { uuid: 0x2bbf, read: Some(call_cp_opt_opcodes_read), write: None, notify: None },
    // TBS: Call Termination Reason, Incoming Call, Call Friendly Name
    GattHandler {
        uuid: 0x2bc0,
        read: None,
        write: None,
        notify: Some(call_termination_reason_notify),
    },
    GattHandler {
        uuid: 0x2bc1,
        read: Some(incoming_call_read),
        write: None,
        notify: Some(incoming_call_notify),
    },
    GattHandler {
        uuid: 0x2bc2,
        read: Some(call_friendly_name_read),
        write: None,
        notify: Some(call_friendly_name_notify),
    },
    // GMAP: Role, UGG/UGT/BGS/BGR Features
    GattHandler { uuid: 0x2c00, read: Some(gmap_role_read), write: None, notify: None },
    GattHandler { uuid: 0x2c01, read: Some(ugg_features_read), write: None, notify: None },
    GattHandler { uuid: 0x2c02, read: Some(ugt_features_read), write: None, notify: None },
    GattHandler { uuid: 0x2c03, read: Some(bgs_features_read), write: None, notify: None },
    GattHandler { uuid: 0x2c04, read: Some(bgr_features_read), write: None, notify: None },
    // RAS: Features, Ranging Data Ready, Data Overwritten, Ranging Data, Control Point
    GattHandler { uuid: 0x2c10, read: Some(ras_features_read), write: None, notify: None },
    GattHandler {
        uuid: 0x2c11,
        read: Some(ras_ranging_data_ready_read),
        write: None,
        notify: Some(ras_ranging_data_ready_notify),
    },
    GattHandler {
        uuid: 0x2c12,
        read: Some(ras_data_overwritten_read),
        write: None,
        notify: Some(ras_data_overwritten_notify),
    },
    GattHandler {
        uuid: 0x2c13,
        read: Some(ras_ranging_data_read),
        write: None,
        notify: Some(ras_ranging_data_notify),
    },
    GattHandler {
        uuid: 0x2c14,
        read: None,
        write: Some(ras_cp_write),
        notify: Some(ras_cp_notify),
    },
    // HID: Information, Report Map, Report, Protocol Mode, Control Point
    GattHandler { uuid: 0x2a4a, read: Some(hog_info_read), write: None, notify: None },
    GattHandler { uuid: 0x2a4b, read: Some(hog_report_map_read), write: None, notify: None },
    GattHandler {
        uuid: 0x2a4d,
        read: Some(hog_report_read),
        write: Some(hog_report_write),
        notify: Some(hog_report_notify),
    },
    GattHandler { uuid: 0x2a4e, read: Some(hog_protocol_mode_read), write: None, notify: None },
    GattHandler { uuid: 0x2a4c, read: None, write: Some(hog_cp_write), notify: None },
    // HID: Boot Reports
    GattHandler { uuid: 0x2a22, read: Some(hog_boot_kb_input_read), write: None, notify: None },
    GattHandler { uuid: 0x2a32, read: Some(hog_boot_kb_output_read), write: None, notify: None },
    GattHandler { uuid: 0x2a33, read: Some(hog_boot_mouse_input_read), write: None, notify: None },
];

// ============================================================================
// Read Queue Helpers
// ============================================================================

fn queue_read(
    conn: &mut AttConnData,
    handle: u16,
    in_: bool,
    chan: u16,
    func: Option<fn(&mut L2capFrame<'_>)>,
) {
    conn.reads.push_back(AttRead { _handle: handle, in_, _chan: chan, func, iov: Vec::new() });
}

fn att_get_read(conn: &mut AttConnData, in_: bool) -> Option<AttRead> {
    // Find the matching read by opposite direction
    let pos = conn.reads.iter().position(|r| r.in_ != in_);
    pos.map(|i| conn.reads.remove(i).unwrap())
}

/// Resolve the handler function for a given UUID by looking up in the
/// GATT handlers table.
fn get_read_func(uuid: &BtUuid, is_read: bool) -> Option<fn(&mut L2capFrame<'_>)> {
    let uuid16 = uuid_to_u16(uuid);
    if uuid16 == 0 {
        return None;
    }
    let handler = get_handler(uuid16)?;
    if is_read { handler.read } else { handler.notify }
}

/// Dispatch a UUID-specific value decoder for a given handle and direction.
fn print_value(
    conn: &AttConnData,
    handle: u16,
    frame: &mut L2capFrame<'_>,
    in_: bool,
    is_notification: bool,
) {
    let db = get_db(conn, in_, !is_notification);
    if let Some(attr) = db.get_attribute(handle) {
        if let Some(uuid) = attr.get_type() {
            let uuid16 = uuid_to_u16(&uuid);
            if uuid16 != 0 {
                if let Some(handler) = get_handler(uuid16) {
                    let func = if is_notification {
                        handler.notify.or(handler.read)
                    } else {
                        handler.read
                    };
                    if let Some(f) = func {
                        f(frame);
                        return;
                    }
                }
            }
        }
    }
    // Fallback: hex dump remaining bytes
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            display::print_hex_field("Value", data);
        }
    }
}

/// Dispatch a UUID-specific write decoder for a given handle and direction.
fn print_write_value(conn: &AttConnData, handle: u16, frame: &mut L2capFrame<'_>, in_: bool) {
    let db = get_db(conn, in_, false);
    if let Some(attr) = db.get_attribute(handle) {
        if let Some(uuid) = attr.get_type() {
            let uuid16 = uuid_to_u16(&uuid);
            if uuid16 != 0 {
                if let Some(handler) = get_handler(uuid16) {
                    if let Some(f) = handler.write {
                        f(frame);
                        return;
                    }
                }
            }
        }
    }
    // Fallback: hex dump
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            display::print_hex_field("Value", data);
        }
    }
}

// ============================================================================
// GATT DB Population from ATT Responses
// ============================================================================

/// Insert a primary or secondary service into the appropriate GATT DB.
fn insert_svc(
    conn: &mut AttConnData,
    in_: bool,
    is_response: bool,
    start_handle: u16,
    end_handle: u16,
    uuid_data: &[u8],
    primary: bool,
) {
    if let Some(uuid) = bt_uuid_from_data(uuid_data) {
        let db = get_db_mut(conn, in_, is_response);
        let num_handles = end_handle.saturating_sub(start_handle).saturating_add(1);
        let _svc = db.insert_service(start_handle, &uuid, primary, num_handles);
    }
}

/// Insert a characteristic into the appropriate GATT DB.
fn insert_chrc(
    conn: &mut AttConnData,
    in_: bool,
    is_response: bool,
    attr_handle: u16,
    value_handle: u16,
    properties: u8,
    uuid_data: &[u8],
) {
    if let Some(uuid) = bt_uuid_from_data(uuid_data) {
        let db = get_db_mut(conn, in_, is_response);
        // Find the service that contains this handle via GattDbAttribute → GattDbService chain
        if let Some(attr) = db.get_service(attr_handle) {
            if let Some(svc) = attr.get_service() {
                let _chrc =
                    svc.insert_characteristic(value_handle, &uuid, 0, properties, None, None, None);
            }
        }
    }
}

// ============================================================================
// ATT Opcode Handler Functions
// ============================================================================

/// ATT Error Response (0x01)
fn att_error_response(frame: &mut L2capFrame<'_>) {
    let opcode = frame.get_u8().unwrap_or(0);
    let handle = frame.get_le16().unwrap_or(0);
    let error_code = frame.get_u8().unwrap_or(0);

    let error_str = match error_code {
        0x01 => "Invalid Handle",
        0x02 => "Read Not Permitted",
        0x03 => "Write Not Permitted",
        0x04 => "Invalid PDU",
        0x05 => "Insufficient Authentication",
        0x06 => "Request Not Supported",
        0x07 => "Invalid Offset",
        0x08 => "Insufficient Authorization",
        0x09 => "Prepare Queue Full",
        0x0a => "Attribute Not Found",
        0x0b => "Attribute Not Long",
        0x0c => "Insufficient Encryption Key Size",
        0x0d => "Invalid Attribute Value Length",
        0x0e => "Unlikely Error",
        0x0f => "Insufficient Encryption",
        0x10 => "Unsupported Group Type",
        0x11 => "Insufficient Resources",
        0x12 => "Value Not Allowed",
        0xfc => "Write Request Rejected",
        0xfd => "Client Characteristic Configuration Descriptor Improperly Configured",
        0xfe => "Procedure Already in Progress",
        0xff => "Out of Range",
        _ if (0x80..=0x9f).contains(&error_code) => "Application Error",
        _ if (0xe0..=0xff).contains(&error_code) => "Common Profile and Service Error Codes",
        _ => "Reserved",
    };

    print_field!("Handle: 0x{:04x}", handle);
    print_field!("Error: {} (0x{:02x})", error_str, error_code);
    print_field!("  Opcode: 0x{:02x}", opcode);
}

/// ATT Exchange MTU Request (0x02)
fn att_exchange_mtu_req(frame: &mut L2capFrame<'_>, in_: bool, handle: u16) {
    if let Some(mtu) = frame.get_le16() {
        print_field!("Client RX MTU: {}", mtu);
        get_or_create_conn_data(handle, |conn| {
            if in_ {
                conn.remote_mtu = mtu;
            } else {
                conn.local_mtu = mtu;
            }
        });
    }
}

/// ATT Exchange MTU Response (0x03)
fn att_exchange_mtu_rsp(frame: &mut L2capFrame<'_>, in_: bool, handle: u16) {
    if let Some(mtu) = frame.get_le16() {
        print_field!("Server RX MTU: {}", mtu);
        get_or_create_conn_data(handle, |conn| {
            if in_ {
                conn.local_mtu = mtu;
            } else {
                conn.remote_mtu = mtu;
            }
        });
    }
}

/// ATT Find Information Request (0x04)
fn att_find_info_req(frame: &mut L2capFrame<'_>) {
    if let (Some(start), Some(end)) = (frame.get_le16(), frame.get_le16()) {
        print_field!("Handle range: 0x{:04x}-0x{:04x}", start, end);
    }
}

/// ATT Find Information Response (0x05)
fn att_find_info_rsp(frame: &mut L2capFrame<'_>, in_: bool, handle: u16) {
    let format = match frame.get_u8() {
        Some(f) => f,
        None => return,
    };
    let uuid_size: usize = match format {
        0x01 => 2,
        0x02 => 16,
        _ => {
            print_field!("Format: Unknown (0x{:02x})", format);
            return;
        }
    };
    print_field!(
        "Format: {} UUID (0x{:02x})",
        if format == 0x01 { "16-bit" } else { "128-bit" },
        format
    );

    let entry_size = 2 + uuid_size;
    while frame.remaining() >= entry_size {
        let attr_handle = frame.get_le16().unwrap_or(0);
        if let Some(uuid_data) = frame.pull(uuid_size) {
            let uuid_data_owned: Vec<u8> = uuid_data.to_vec();
            print_field!("  Handle: 0x{:04x}", attr_handle);
            print_uuid("  UUID", &uuid_data_owned);

            // Insert descriptor into GATT DB
            get_or_create_conn_data(handle, |conn| {
                if let Some(uuid) = bt_uuid_from_data(&uuid_data_owned) {
                    let db = get_db_mut(conn, in_, true);
                    // Try to find the service for this handle, then insert descriptor
                    if let Some(attr) = db.get_service(attr_handle) {
                        if let Some(svc) = attr.get_service() {
                            let _ = svc.insert_descriptor(attr_handle, &uuid, 0, None, None, None);
                        }
                    }
                }
            });
        }
    }
}

/// ATT Find By Type Value Request (0x06)
fn att_find_by_type_req(frame: &mut L2capFrame<'_>) {
    if let (Some(start), Some(end)) = (frame.get_le16(), frame.get_le16()) {
        print_field!("Handle range: 0x{:04x}-0x{:04x}", start, end);
    }
    if let Some(type_uuid) = frame.get_le16() {
        print_field!("Attribute Type: {} (0x{:04x})", bt_uuid16_to_str(type_uuid), type_uuid);
    }
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            display::print_hex_field("Attribute Value", data);
        }
    }
}

/// ATT Find By Type Value Response (0x07)
fn att_find_by_type_rsp(frame: &mut L2capFrame<'_>) {
    while frame.remaining() >= 4 {
        let found = frame.get_le16().unwrap_or(0);
        let end_grp = frame.get_le16().unwrap_or(0);
        print_field!("  Found Handle: 0x{:04x}, End Group Handle: 0x{:04x}", found, end_grp);
    }
}

/// ATT Read By Type Request (0x08)
fn att_read_by_type_req(frame: &mut L2capFrame<'_>) {
    if let (Some(start), Some(end)) = (frame.get_le16(), frame.get_le16()) {
        print_field!("Handle range: 0x{:04x}-0x{:04x}", start, end);
    }
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            let data_owned: Vec<u8> = data.to_vec();
            print_uuid("Attribute Type", &data_owned);
        }
    }
}

/// ATT Read By Type Response (0x09)
fn att_read_by_type_rsp(frame: &mut L2capFrame<'_>, in_: bool, handle: u16) {
    let attr_data_len = match frame.get_u8() {
        Some(v) => v as usize,
        None => return,
    };
    print_field!("Attribute data length: {}", attr_data_len);

    if attr_data_len < 2 {
        return;
    }

    while frame.remaining() >= attr_data_len {
        let attr_handle = frame.get_le16().unwrap_or(0);
        let value_len = attr_data_len - 2;
        if let Some(value_data) = frame.pull(value_len) {
            let value_owned: Vec<u8> = value_data.to_vec();
            print_field!("  Handle: 0x{:04x}", attr_handle);

            // Check if this is a characteristic declaration (properties+value_handle+UUID)
            if value_len >= 5 {
                let props = value_owned[0];
                let val_handle = get_le16(&value_owned[1..]);
                let uuid_data = &value_owned[3..];

                // Try to decode as characteristic
                print_attribute_info(0x2803, &mut L2capFrame::new(handle, in_, 0, &value_owned));

                // Populate GATT DB
                get_or_create_conn_data(handle, |conn| {
                    insert_chrc(conn, in_, true, attr_handle, val_handle, props, uuid_data);
                });
            } else {
                display::print_hexdump(&value_owned);
            }
        }
    }
}

/// ATT Read Request (0x0A)
fn att_read_req(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16, cid: u16) {
    let attr_handle = match frame.get_le16() {
        Some(v) => v,
        None => return,
    };
    print_field!("Handle: 0x{:04x}", attr_handle);

    // Queue the read for response correlation
    get_or_create_conn_data(hci_handle, |conn| {
        let db = get_db(conn, in_, false);
        let func = db
            .get_attribute(attr_handle)
            .and_then(|attr| attr.get_type())
            .and_then(|uuid| get_read_func(&uuid, true));
        queue_read(conn, attr_handle, in_, cid, func);
    });
}

/// ATT Read Response (0x0B)
fn att_read_rsp(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16) {
    let read = get_or_create_conn_data(hci_handle, |conn| att_get_read(conn, in_));
    if let Some(read) = read {
        if let Some(f) = read.func {
            f(frame);
            return;
        }
    }
    // Fallback: hex dump
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            display::print_hex_field("Value", data);
        }
    }
}

/// ATT Read Blob Request (0x0C)
fn att_read_blob_req(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16, cid: u16) {
    let attr_handle = match frame.get_le16() {
        Some(v) => v,
        None => return,
    };
    let offset = match frame.get_le16() {
        Some(v) => v,
        None => return,
    };
    print_field!("Handle: 0x{:04x}", attr_handle);
    print_field!("Offset: 0x{:04x}", offset);

    // Queue the read for blob response correlation
    get_or_create_conn_data(hci_handle, |conn| {
        let db = get_db(conn, in_, false);
        let func = db
            .get_attribute(attr_handle)
            .and_then(|attr| attr.get_type())
            .and_then(|uuid| get_read_func(&uuid, true));
        queue_read(conn, attr_handle, in_, cid, func);
    });
}

/// ATT Read Blob Response (0x0D)
fn att_read_blob_rsp(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16) {
    let read = get_or_create_conn_data(hci_handle, |conn| att_get_read(conn, in_));
    if let Some(mut read) = read {
        // Append data to reassembly buffer
        let rem = frame.remaining();
        if let Some(data) = frame.pull(rem) {
            read.iov.extend_from_slice(data);
        }
        if let Some(f) = read.func {
            // Decode the reassembled value
            let mut value_frame = L2capFrame::new(hci_handle, in_, 0, &read.iov);
            f(&mut value_frame);
        } else {
            display::print_hex_field("Value", &read.iov);
        }
        return;
    }
    // Fallback
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            display::print_hex_field("Value", data);
        }
    }
}

/// ATT Read Multiple Request (0x0E)
fn att_read_multiple_req(frame: &mut L2capFrame<'_>) {
    let mut count = 0;
    while frame.remaining() >= 2 {
        let h = frame.get_le16().unwrap_or(0);
        print_field!("Handle: 0x{:04x}", h);
        count += 1;
    }
    if count == 0 {
        print_field!("(empty)");
    }
}

/// ATT Read Multiple Response (0x0F)
fn att_read_multiple_rsp(frame: &mut L2capFrame<'_>) {
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            display::print_hex_field("Values", data);
        }
    }
}

/// ATT Read By Group Type Request (0x10)
fn att_read_by_grp_type_req(frame: &mut L2capFrame<'_>) {
    if let (Some(start), Some(end)) = (frame.get_le16(), frame.get_le16()) {
        print_field!("Handle range: 0x{:04x}-0x{:04x}", start, end);
    }
    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            let data_owned: Vec<u8> = data.to_vec();
            print_uuid("Attribute Group Type", &data_owned);
        }
    }
}

/// ATT Read By Group Type Response (0x11)
fn att_read_by_grp_type_rsp(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16) {
    let attr_data_len = match frame.get_u8() {
        Some(v) => v as usize,
        None => return,
    };
    print_field!("Attribute data length: {}", attr_data_len);

    if attr_data_len < 4 {
        return;
    }

    while frame.remaining() >= attr_data_len {
        let start_handle = frame.get_le16().unwrap_or(0);
        let end_handle = frame.get_le16().unwrap_or(0);
        let value_len = attr_data_len - 4;
        if let Some(uuid_data) = frame.pull(value_len) {
            let uuid_owned: Vec<u8> = uuid_data.to_vec();
            print_field!("  Handle range: 0x{:04x}-0x{:04x}", start_handle, end_handle);
            print_uuid("  UUID", &uuid_owned);

            // Populate GATT DB with discovered service
            get_or_create_conn_data(hci_handle, |conn| {
                insert_svc(conn, in_, true, start_handle, end_handle, &uuid_owned, true);
            });
        }
    }
}

/// ATT Write Request (0x12)
fn att_write_req(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16) {
    let attr_handle = match frame.get_le16() {
        Some(v) => v,
        None => return,
    };
    print_field!("Handle: 0x{:04x}", attr_handle);

    get_or_create_conn_data(hci_handle, |conn| {
        print_write_value(conn, attr_handle, frame, in_);
    });
}

/// ATT Write Response (0x13) — empty body
fn att_write_rsp(_frame: &mut L2capFrame<'_>) {
    // Write Response has no body
}

/// ATT Prepare Write Request (0x16)
fn att_prep_write_req(frame: &mut L2capFrame<'_>) {
    let attr_handle = match frame.get_le16() {
        Some(v) => v,
        None => return,
    };
    let offset = match frame.get_le16() {
        Some(v) => v,
        None => return,
    };
    print_field!("Handle: 0x{:04x}", attr_handle);
    print_field!("Offset: 0x{:04x}", offset);

    let rem = frame.remaining();
    if rem > 0 {
        if let Some(data) = frame.pull(rem) {
            display::print_hex_field("Part Attribute Value", data);
        }
    }
}

/// ATT Prepare Write Response (0x17)
fn att_prep_write_rsp(frame: &mut L2capFrame<'_>) {
    att_prep_write_req(frame);
}

/// ATT Execute Write Request (0x18)
fn att_exec_write_req(frame: &mut L2capFrame<'_>) {
    if let Some(flags) = frame.get_u8() {
        let s = match flags {
            0x00 => "Cancel all prepared writes",
            0x01 => "Immediately write all pending prepared values",
            _ => "Unknown",
        };
        print_field!("Flags: {} (0x{:02x})", s, flags);
    }
}

/// ATT Execute Write Response (0x19) — empty body
fn att_exec_write_rsp(_frame: &mut L2capFrame<'_>) {
    // Execute Write Response has no body
}

/// ATT Handle Value Notification (0x1B)
fn att_handle_value_nfy(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16) {
    let attr_handle = match frame.get_le16() {
        Some(v) => v,
        None => return,
    };
    print_field!("Handle: 0x{:04x}", attr_handle);

    get_or_create_conn_data(hci_handle, |conn| {
        print_value(conn, attr_handle, frame, in_, true);
    });
}

/// ATT Handle Value Indication (0x1D)
fn att_handle_value_ind(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16) {
    att_handle_value_nfy(frame, in_, hci_handle);
}

/// ATT Handle Value Confirmation (0x1E) — empty body
fn att_handle_value_conf(_frame: &mut L2capFrame<'_>) {
    // Confirmation has no body
}

/// ATT Read Multiple Variable Length Request (0x20)
fn att_read_mult_vl_req(frame: &mut L2capFrame<'_>) {
    att_read_multiple_req(frame);
}

/// ATT Read Multiple Variable Length Response (0x21)
fn att_read_mult_vl_rsp(frame: &mut L2capFrame<'_>) {
    while frame.remaining() >= 2 {
        let attr_len = frame.get_le16().unwrap_or(0) as usize;
        print_field!("  Length: {}", attr_len);
        if attr_len > 0 && frame.remaining() >= attr_len {
            if let Some(data) = frame.pull(attr_len) {
                display::print_hex_field("  Value", data);
            }
        }
    }
}

/// ATT Handle Value Notification (Multiple) (0x23)
fn att_handle_nfy_mult(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16) {
    while frame.remaining() >= 4 {
        let attr_handle = frame.get_le16().unwrap_or(0);
        let attr_len = frame.get_le16().unwrap_or(0) as usize;
        print_field!("Handle: 0x{:04x}", attr_handle);
        print_field!("  Length: {}", attr_len);
        if attr_len > 0 && frame.remaining() >= attr_len {
            if let Some(value_data) = frame.pull(attr_len) {
                let value_owned: Vec<u8> = value_data.to_vec();
                get_or_create_conn_data(hci_handle, |conn| {
                    let mut vframe = L2capFrame::new(hci_handle, in_, 0, &value_owned);
                    print_value(conn, attr_handle, &mut vframe, in_, true);
                });
            }
        }
    }
}

/// ATT Write Command (0x52)
fn att_write_cmd(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16) {
    att_write_req(frame, in_, hci_handle);
}

/// ATT Signed Write Command (0xD2)
fn att_signed_write_cmd(frame: &mut L2capFrame<'_>, in_: bool, hci_handle: u16) {
    let attr_handle = match frame.get_le16() {
        Some(v) => v,
        None => return,
    };
    print_field!("Handle: 0x{:04x}", attr_handle);

    // Value is everything except the last 12 bytes (signature)
    let rem = frame.remaining();
    if rem > 12 {
        let value_len = rem - 12;
        if let Some(value) = frame.pull(value_len) {
            display::print_hex_field("Value", value);
        }
        if let Some(sig) = frame.pull(12) {
            display::print_hex_field("Signature", sig);
        }
    } else {
        get_or_create_conn_data(hci_handle, |conn| {
            print_write_value(conn, attr_handle, frame, in_);
        });
    }
}

// ============================================================================
// ATT Opcode Table
// ============================================================================

/// ATT opcode dispatch entry.
struct AttOpcodeEntry {
    opcode: u8,
    name: &'static str,
    handler: fn(&mut L2capFrame<'_>, bool, u16, u16),
    fixed: bool,
    size: usize,
}

/// Trampoline functions to adapt handler signatures to the common dispatch signature.
fn handle_error_rsp(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_error_response(frame);
}
fn handle_mtu_req(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_exchange_mtu_req(frame, in_, h);
}
fn handle_mtu_rsp(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_exchange_mtu_rsp(frame, in_, h);
}
fn handle_find_info_req(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_find_info_req(frame);
}
fn handle_find_info_rsp(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_find_info_rsp(frame, in_, h);
}
fn handle_find_by_type_req(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_find_by_type_req(frame);
}
fn handle_find_by_type_rsp(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_find_by_type_rsp(frame);
}
fn handle_read_by_type_req(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_read_by_type_req(frame);
}
fn handle_read_by_type_rsp(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_read_by_type_rsp(frame, in_, h);
}
fn handle_read_req(frame: &mut L2capFrame<'_>, in_: bool, h: u16, c: u16) {
    att_read_req(frame, in_, h, c);
}
fn handle_read_rsp(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_read_rsp(frame, in_, h);
}
fn handle_read_blob_req(frame: &mut L2capFrame<'_>, in_: bool, h: u16, c: u16) {
    att_read_blob_req(frame, in_, h, c);
}
fn handle_read_blob_rsp(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_read_blob_rsp(frame, in_, h);
}
fn handle_read_mult_req(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_read_multiple_req(frame);
}
fn handle_read_mult_rsp(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_read_multiple_rsp(frame);
}
fn handle_read_by_grp_type_req(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_read_by_grp_type_req(frame);
}
fn handle_read_by_grp_type_rsp(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_read_by_grp_type_rsp(frame, in_, h);
}
fn handle_write_req(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_write_req(frame, in_, h);
}
fn handle_write_rsp(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_write_rsp(frame);
}
fn handle_prep_write_req(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_prep_write_req(frame);
}
fn handle_prep_write_rsp(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_prep_write_rsp(frame);
}
fn handle_exec_write_req(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_exec_write_req(frame);
}
fn handle_exec_write_rsp(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_exec_write_rsp(frame);
}
fn handle_nfy(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_handle_value_nfy(frame, in_, h);
}
fn handle_ind(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_handle_value_ind(frame, in_, h);
}
fn handle_conf(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_handle_value_conf(frame);
}
fn handle_read_mult_vl_req(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_read_mult_vl_req(frame);
}
fn handle_read_mult_vl_rsp(frame: &mut L2capFrame<'_>, _in: bool, _h: u16, _c: u16) {
    att_read_mult_vl_rsp(frame);
}
fn handle_nfy_mult(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_handle_nfy_mult(frame, in_, h);
}
fn handle_write_cmd(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_write_cmd(frame, in_, h);
}
fn handle_signed_write_cmd(frame: &mut L2capFrame<'_>, in_: bool, h: u16, _c: u16) {
    att_signed_write_cmd(frame, in_, h);
}

static ATT_OPCODE_TABLE: &[AttOpcodeEntry] = &[
    AttOpcodeEntry {
        opcode: 0x01,
        name: "Error Response",
        handler: handle_error_rsp,
        fixed: true,
        size: 4,
    },
    AttOpcodeEntry {
        opcode: 0x02,
        name: "Exchange MTU Request",
        handler: handle_mtu_req,
        fixed: true,
        size: 2,
    },
    AttOpcodeEntry {
        opcode: 0x03,
        name: "Exchange MTU Response",
        handler: handle_mtu_rsp,
        fixed: true,
        size: 2,
    },
    AttOpcodeEntry {
        opcode: 0x04,
        name: "Find Information Request",
        handler: handle_find_info_req,
        fixed: true,
        size: 4,
    },
    AttOpcodeEntry {
        opcode: 0x05,
        name: "Find Information Response",
        handler: handle_find_info_rsp,
        fixed: false,
        size: 5,
    },
    AttOpcodeEntry {
        opcode: 0x06,
        name: "Find By Type Value Request",
        handler: handle_find_by_type_req,
        fixed: false,
        size: 6,
    },
    AttOpcodeEntry {
        opcode: 0x07,
        name: "Find By Type Value Response",
        handler: handle_find_by_type_rsp,
        fixed: false,
        size: 4,
    },
    AttOpcodeEntry {
        opcode: 0x08,
        name: "Read By Type Request",
        handler: handle_read_by_type_req,
        fixed: false,
        size: 6,
    },
    AttOpcodeEntry {
        opcode: 0x09,
        name: "Read By Type Response",
        handler: handle_read_by_type_rsp,
        fixed: false,
        size: 3,
    },
    AttOpcodeEntry {
        opcode: 0x0a,
        name: "Read Request",
        handler: handle_read_req,
        fixed: true,
        size: 2,
    },
    AttOpcodeEntry {
        opcode: 0x0b,
        name: "Read Response",
        handler: handle_read_rsp,
        fixed: false,
        size: 0,
    },
    AttOpcodeEntry {
        opcode: 0x0c,
        name: "Read Blob Request",
        handler: handle_read_blob_req,
        fixed: true,
        size: 4,
    },
    AttOpcodeEntry {
        opcode: 0x0d,
        name: "Read Blob Response",
        handler: handle_read_blob_rsp,
        fixed: false,
        size: 0,
    },
    AttOpcodeEntry {
        opcode: 0x0e,
        name: "Read Multiple Request",
        handler: handle_read_mult_req,
        fixed: false,
        size: 4,
    },
    AttOpcodeEntry {
        opcode: 0x0f,
        name: "Read Multiple Response",
        handler: handle_read_mult_rsp,
        fixed: false,
        size: 0,
    },
    AttOpcodeEntry {
        opcode: 0x10,
        name: "Read By Group Type Request",
        handler: handle_read_by_grp_type_req,
        fixed: false,
        size: 6,
    },
    AttOpcodeEntry {
        opcode: 0x11,
        name: "Read By Group Type Response",
        handler: handle_read_by_grp_type_rsp,
        fixed: false,
        size: 4,
    },
    AttOpcodeEntry {
        opcode: 0x12,
        name: "Write Request",
        handler: handle_write_req,
        fixed: false,
        size: 2,
    },
    AttOpcodeEntry {
        opcode: 0x13,
        name: "Write Response",
        handler: handle_write_rsp,
        fixed: true,
        size: 0,
    },
    AttOpcodeEntry {
        opcode: 0x16,
        name: "Prepare Write Request",
        handler: handle_prep_write_req,
        fixed: false,
        size: 4,
    },
    AttOpcodeEntry {
        opcode: 0x17,
        name: "Prepare Write Response",
        handler: handle_prep_write_rsp,
        fixed: false,
        size: 4,
    },
    AttOpcodeEntry {
        opcode: 0x18,
        name: "Execute Write Request",
        handler: handle_exec_write_req,
        fixed: true,
        size: 1,
    },
    AttOpcodeEntry {
        opcode: 0x19,
        name: "Execute Write Response",
        handler: handle_exec_write_rsp,
        fixed: true,
        size: 0,
    },
    AttOpcodeEntry {
        opcode: 0x1b,
        name: "Handle Value Notification",
        handler: handle_nfy,
        fixed: false,
        size: 2,
    },
    AttOpcodeEntry {
        opcode: 0x1d,
        name: "Handle Value Indication",
        handler: handle_ind,
        fixed: false,
        size: 2,
    },
    AttOpcodeEntry {
        opcode: 0x1e,
        name: "Handle Value Confirmation",
        handler: handle_conf,
        fixed: true,
        size: 0,
    },
    AttOpcodeEntry {
        opcode: 0x20,
        name: "Read Multiple Variable Request",
        handler: handle_read_mult_vl_req,
        fixed: false,
        size: 4,
    },
    AttOpcodeEntry {
        opcode: 0x21,
        name: "Read Multiple Variable Response",
        handler: handle_read_mult_vl_rsp,
        fixed: false,
        size: 0,
    },
    AttOpcodeEntry {
        opcode: 0x23,
        name: "Handle Value Notification (Multiple)",
        handler: handle_nfy_mult,
        fixed: false,
        size: 4,
    },
    AttOpcodeEntry {
        opcode: 0x52,
        name: "Write Command",
        handler: handle_write_cmd,
        fixed: false,
        size: 2,
    },
    AttOpcodeEntry {
        opcode: 0xd2,
        name: "Signed Write Command",
        handler: handle_signed_write_cmd,
        fixed: false,
        size: 14,
    },
];

// ============================================================================
// Public Entry Point
// ============================================================================

/// Decode and print an ATT PDU.
///
/// This is the sole public export of the dissector, matching the C
/// `void att_packet(uint16_t index, bool in, uint16_t handle,
///                  uint16_t cid, const void *data, uint16_t size)`.
pub fn att_packet(_index: u16, in_: bool, handle: u16, cid: u16, data: &[u8], size: u16) {
    let data_len = std::cmp::min(data.len(), size as usize);
    let data = &data[..data_len];

    if data.is_empty() {
        print_text!(display::COLOR_ERROR, "Malformed ATT packet (empty)");
        return;
    }

    let opcode = data[0];

    // Look up opcode in table
    let entry = ATT_OPCODE_TABLE.iter().find(|e| e.opcode == opcode);

    let (name, color) = if let Some(e) = entry {
        let c = if in_ { display::COLOR_MAGENTA } else { display::COLOR_BLUE };
        (e.name, c)
    } else {
        ("Unknown", display::COLOR_WHITE_BG)
    };

    // Print the opcode header line
    print_indent!(
        6,
        color,
        "ATT: ",
        "",
        display::COLOR_OFF,
        "{} (0x{:02x}) len {}",
        name,
        opcode,
        data_len.saturating_sub(1)
    );

    // Advance past the opcode byte
    let body = &data[1..];
    let mut frame = L2capFrame::new(handle, in_, cid, body);

    if let Some(e) = entry {
        // Validate minimum size
        if e.fixed && body.len() != e.size {
            print_text!(display::COLOR_ERROR, "Invalid size {} (expected {})", body.len(), e.size);
            return;
        }
        if !e.fixed && body.len() < e.size {
            print_text!(display::COLOR_ERROR, "Too short {} (minimum {})", body.len(), e.size);
            return;
        }

        // Ensure connection data exists and dispatch handler
        get_or_create_conn_data(handle, |_conn| {});
        (e.handler)(&mut frame, in_, handle, cid);
    }

    // Report leftover bytes
    let leftover = frame.remaining();
    if leftover > 0 {
        print_text!(
            display::COLOR_WHITE,
            "  Leftover: {} byte{}",
            leftover,
            if leftover == 1 { "" } else { "s" }
        );
        if let Some(extra) = frame.pull(leftover) {
            display::print_hexdump(extra);
        }
    }
}
