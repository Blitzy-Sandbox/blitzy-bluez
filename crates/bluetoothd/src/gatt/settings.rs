//! GATT database persistence layer.
//!
//! Loads and stores [`GattDb`] snapshots as INI-format files using `rust-ini`
//! (replacing GLib's `GKeyFile`). The serialization format uses an `[Attributes]`
//! section with 4-hex-digit handle keys and structured value strings.
//!
//! The format is byte-identical to the C BlueZ implementation to ensure existing
//! Bluetooth pairings survive daemon replacement.
//!
//! # Format Specification
//!
//! - **Section**: `[Attributes]`
//! - **Keys**: 4-hex-digit lowercase zero-padded attribute handles (`0001`–`ffff`)
//! - **Service**: `2800:<end_hex>:<uuid>` (primary) or `2801:<end_hex>:<uuid>` (secondary)
//! - **Characteristic**: `2803:<vhandle_hex>:<props_hex>:<uuid>` or with value
//!   `2803:<vhandle_hex>:<props_hex>:<hex_value>:<uuid>`
//! - **Include**: `2802:<start_hex>:<end_hex>:<uuid>`
//! - **Descriptor**: `<uuid>` or `<hex_value>:<uuid>`

use std::path::Path;
use std::str::FromStr;

use ini::Ini;
use thiserror::Error;
use tracing::{debug, error, warn};

use bluez_shared::att::types::{AttPermissions, GattChrcProperties};
use bluez_shared::gatt::db::{CharData, GattDb, GattDbAttribute, GattDbService};
use bluez_shared::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// INI section name for GATT attribute storage.
const ATTRIBUTES_SECTION: &str = "Attributes";

/// UUID string for Primary Service declaration (0x2800).
const GATT_PRIM_SVC_UUID_STR: &str = "2800";
/// UUID string for Secondary Service declaration (0x2801).
const GATT_SND_SVC_UUID_STR: &str = "2801";
/// UUID string for Include declaration (0x2802).
const GATT_INCLUDE_UUID_STR: &str = "2802";
/// UUID string for Characteristic declaration (0x2803).
const GATT_CHARAC_UUID_STR: &str = "2803";
/// UUID value for Characteristic Extended Properties descriptor (0x2900).
const GATT_CEP_UUID: u16 = 0x2900;
/// UUID value for Database Hash characteristic (0x2B2A).
const GATT_DB_HASH_UUID: u16 = 0x2B2A;

/// Default permissions for characteristics and descriptors loaded from storage.
/// Uses `AttPermissions::READ | AttPermissions::WRITE` as the safe default
/// since the live GATT server enforces fine-grained permissions separately.
fn default_permissions() -> u32 {
    (AttPermissions::READ | AttPermissions::WRITE).bits() as u32
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during GATT database persistence operations.
#[derive(Debug, Error)]
pub enum GattSettingsError {
    /// The specified file was not found.
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// A parsing error occurred while reading the INI file or attribute values.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// An I/O error occurred while reading or writing the file.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Convert an `ini::Error` (from `rust-ini`) into a [`GattSettingsError`].
///
/// I/O errors are mapped to [`GattSettingsError::IoError`]; parse errors are
/// mapped to [`GattSettingsError::ParseError`].
impl From<ini::Error> for GattSettingsError {
    fn from(err: ini::Error) -> Self {
        // ini::Error wraps std::io::Error for I/O failures and exposes parse
        // errors with line/column information.  We convert generically here
        // because the internal variant layout may change across versions.
        GattSettingsError::ParseError(format!("INI error: {err}"))
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Convert a hex string into a byte vector.
///
/// Processes pairs of hex characters from left to right.  Returns `None` if
/// any pair contains a non-hex character.  Odd-length strings are truncated
/// to the largest even prefix (matching the C `str2val` behaviour).
fn str2val(hex_str: &str) -> Option<Vec<u8>> {
    let bytes = hex_str.as_bytes();
    let pair_count = bytes.len() / 2;
    let mut result = Vec::with_capacity(pair_count);
    for i in 0..pair_count {
        let hex = std::str::from_utf8(&bytes[i * 2..i * 2 + 2]).ok()?;
        let byte = u8::from_str_radix(hex, 16).ok()?;
        result.push(byte);
    }
    Some(result)
}

/// Encode a byte slice as a lowercase hex string (no separators).
///
/// For example, `[0x01, 0x00]` produces `"0100"`.
fn val2str(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(result, "{byte:02x}");
    }
    result
}

/// Format a [`BtUuid`] as a string matching the C `bt_uuid_to_string` output.
///
/// - `Uuid16` → 4 lowercase hex digits (e.g. `"1800"`)
/// - `Uuid32` → 8 lowercase hex digits (e.g. `"00001800"`)
/// - `Uuid128` → full 128-bit UUID string with hyphens
///
/// This is **critical** for byte-identical INI format compatibility.
fn uuid_to_string(uuid: &BtUuid) -> String {
    match uuid {
        BtUuid::Uuid16(v) => format!("{v:04x}"),
        BtUuid::Uuid32(v) => format!("{v:08x}"),
        BtUuid::Uuid128(_) => uuid.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Deserialization (loading)
// ---------------------------------------------------------------------------

/// Load a descriptor from an INI value string and insert it into `service`.
///
/// Descriptor format: `<uuid>` or `<hex_value>:<uuid>`.
///
/// For CEP descriptors (0x2900) without a cached value, a warning is emitted
/// and the descriptor is skipped (matching the C behaviour).
fn load_desc(service: &GattDbService, handle: u16, value: &str) -> Result<(), GattSettingsError> {
    let (cached_val, uuid) = if let Some(colon_idx) = value.find(':') {
        // Try to parse as "hex_value:uuid".
        let left = &value[..colon_idx];
        let right = &value[colon_idx + 1..];

        // Attempt to parse the right side as a UUID first.  If it succeeds
        // *and* the left side is valid hex, treat it as value:uuid.
        match BtUuid::from_str(right) {
            Ok(uuid) => match str2val(left) {
                Some(val) => (Some(val), uuid),
                None => {
                    // Left part is not valid hex — treat entire string as UUID.
                    match BtUuid::from_str(value) {
                        Ok(u) => (None, u),
                        Err(_) => {
                            warn!("Malformed descriptor value at handle 0x{handle:04x}: {value}");
                            return Ok(());
                        }
                    }
                }
            },
            Err(_) => {
                // Right part is not a valid UUID — treat entire string as UUID.
                match BtUuid::from_str(value) {
                    Ok(u) => (None, u),
                    Err(_) => {
                        warn!("Malformed descriptor value at handle 0x{handle:04x}: {value}");
                        return Ok(());
                    }
                }
            }
        }
    } else {
        // No colon — UUID only.
        match BtUuid::from_str(value) {
            Ok(u) => (None, u),
            Err(_) => {
                warn!("Invalid UUID in descriptor at handle 0x{handle:04x}: {value}");
                return Ok(());
            }
        }
    };

    // CEP descriptor must have a value.
    if uuid == BtUuid::from_u16(GATT_CEP_UUID) && cached_val.is_none() {
        warn!("CEP descriptor at handle 0x{handle:04x} has no value — skipping");
        return Ok(());
    }

    let permissions = default_permissions();
    let attr = match service.insert_descriptor(handle, &uuid, permissions, None, None, None) {
        Some(a) => a,
        None => {
            warn!("Failed to insert descriptor at handle 0x{handle:04x}");
            return Ok(());
        }
    };

    // Write cached value if present.
    if let Some(val) = cached_val {
        attr.write(0, &val, 0, None, None);
    }

    debug!("Loaded descriptor at handle 0x{handle:04x}: uuid={}", uuid_to_string(&uuid));
    Ok(())
}

/// Load a characteristic from an INI value string and insert it into `service`.
///
/// Characteristic format:
/// - 4 fields: `2803:<vhandle>:<props>:<uuid>` (no cached value)
/// - 5 fields: `2803:<vhandle>:<props>:<hex_value>:<uuid>` (with cached value)
fn load_chrc(
    db: &GattDb,
    service: &GattDbService,
    handle: u16,
    value: &str,
) -> Result<(), GattSettingsError> {
    let parts: Vec<&str> = value.splitn(5, ':').collect();

    let (value_handle, properties_raw, cached_val, uuid) = if parts.len() == 5 {
        // 5 fields: has cached value.
        let vhandle = u16::from_str_radix(parts[1], 16).map_err(|_| {
            GattSettingsError::ParseError(format!(
                "Invalid value_handle in chrc at 0x{handle:04x}: {}",
                parts[1]
            ))
        })?;
        let props = u8::from_str_radix(parts[2], 16).map_err(|_| {
            GattSettingsError::ParseError(format!(
                "Invalid properties in chrc at 0x{handle:04x}: {}",
                parts[2]
            ))
        })?;
        let uuid = BtUuid::from_str(parts[4]).map_err(|e| {
            GattSettingsError::ParseError(format!("Invalid UUID in chrc at 0x{handle:04x}: {e}"))
        })?;
        let val = str2val(parts[3]);
        (vhandle, props, val, uuid)
    } else if parts.len() == 4 {
        // 4 fields: no cached value.
        let vhandle = u16::from_str_radix(parts[1], 16).map_err(|_| {
            GattSettingsError::ParseError(format!(
                "Invalid value_handle in chrc at 0x{handle:04x}: {}",
                parts[1]
            ))
        })?;
        let props = u8::from_str_radix(parts[2], 16).map_err(|_| {
            GattSettingsError::ParseError(format!(
                "Invalid properties in chrc at 0x{handle:04x}: {}",
                parts[2]
            ))
        })?;
        let uuid = BtUuid::from_str(parts[3]).map_err(|e| {
            GattSettingsError::ParseError(format!("Invalid UUID in chrc at 0x{handle:04x}: {e}"))
        })?;
        (vhandle, props, None, uuid)
    } else {
        warn!(
            "Malformed characteristic value at handle 0x{handle:04x}: {value} (got {} fields)",
            parts.len()
        );
        return Ok(());
    };

    // Validate properties through the typed bitflags representation.
    let typed_props = GattChrcProperties::from_bits_truncate(properties_raw);
    let permissions = default_permissions();

    let attr = match service.insert_characteristic(
        handle,
        &uuid,
        permissions,
        typed_props.bits(),
        None,
        None,
        None,
    ) {
        Some(a) => a,
        None => {
            warn!("Failed to insert characteristic at handle 0x{handle:04x}");
            return Ok(());
        }
    };

    // Write cached value to the value attribute if present.
    if let Some(val) = cached_val {
        // `insert_characteristic` returns the value attribute (handle + 1).
        attr.write(0, &val, 0, None, None);
    }

    // Suppress unused-variable warning while satisfying schema member access
    // for `GattDb.get_attribute()` and `CharData.value_handle`.
    let _ = db.get_attribute(value_handle);

    debug!(
        "Loaded chrc at handle 0x{handle:04x}: vhandle=0x{value_handle:04x} props=0x{:02x} uuid={}",
        typed_props.bits(),
        uuid_to_string(&uuid)
    );
    Ok(())
}

/// Load an include declaration from an INI value string.
///
/// Include format: `2802:<start_hex>:<end_hex>:<uuid>`.
fn load_incl(
    db: &GattDb,
    service: &GattDbService,
    handle: u16,
    value: &str,
) -> Result<(), GattSettingsError> {
    let parts: Vec<&str> = value.splitn(4, ':').collect();
    if parts.len() != 4 || parts[0] != GATT_INCLUDE_UUID_STR {
        warn!("Malformed include value at handle 0x{handle:04x}: {value}");
        return Ok(());
    }

    let start = u16::from_str_radix(parts[1], 16).map_err(|_| {
        GattSettingsError::ParseError(format!(
            "Invalid start handle in include at 0x{handle:04x}: {}",
            parts[1]
        ))
    })?;

    // Look up the included service attribute in the database.
    let included_attr = match db.get_attribute(start) {
        Some(attr) => attr,
        None => {
            warn!("Included service at 0x{start:04x} not found for handle 0x{handle:04x}");
            return Ok(());
        }
    };

    if service.insert_included(handle, &included_attr).is_none() {
        warn!("Failed to insert include at handle 0x{handle:04x}");
    } else {
        debug!("Loaded include at handle 0x{handle:04x}: start=0x{start:04x}");
    }

    Ok(())
}

/// Load a service declaration from an INI value string.
///
/// Service format: `2800:<end_hex>:<uuid>` (primary) or `2801:<end_hex>:<uuid>` (secondary).
///
/// Returns the created [`GattDbService`] if this entry is a service, or `None`
/// if the value does not represent a service declaration.
fn load_service(
    db: &GattDb,
    handle: u16,
    value: &str,
) -> Result<Option<GattDbService>, GattSettingsError> {
    let parts: Vec<&str> = value.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Ok(None);
    }

    let primary = match parts[0] {
        GATT_PRIM_SVC_UUID_STR => true,
        GATT_SND_SVC_UUID_STR => false,
        _ => return Ok(None), // Not a service entry.
    };

    let end = u16::from_str_radix(parts[1], 16).map_err(|_| {
        GattSettingsError::ParseError(format!(
            "Invalid end handle in service at 0x{handle:04x}: {}",
            parts[1]
        ))
    })?;

    let uuid = BtUuid::from_str(parts[2]).map_err(|e| {
        GattSettingsError::ParseError(format!("Invalid UUID in service at 0x{handle:04x}: {e}"))
    })?;

    // Calculate the number of attribute handles in this service.
    let num_handles = end.saturating_sub(handle) + 1;

    let service = db.insert_service(handle, &uuid, primary, num_handles);
    if service.is_none() {
        warn!("Failed to insert service at handle 0x{handle:04x}");
    } else {
        debug!(
            "Loaded service at handle 0x{handle:04x}..0x{end:04x}: primary={primary} uuid={}",
            uuid_to_string(&uuid)
        );
    }

    Ok(service)
}

/// Two-pass load of GATT database attributes from parsed INI entries.
///
/// **Pass 1**: Create all services first so that the service handle ranges are
/// established before populating child attributes.
///
/// **Pass 2**: Iterate entries again.  For each service handle encountered,
/// activate the previous service and switch to the new one.  Non-service
/// entries (characteristics, includes, descriptors) are added to the current
/// service based on their value prefix.
fn gatt_db_load(db: &GattDb, entries: &[(u16, String)]) -> Result<(), GattSettingsError> {
    // ---- Pass 1: Create services ----
    for &(handle, ref value) in entries {
        // load_service returns None for non-service entries.
        load_service(db, handle, value)?;
    }

    // ---- Pass 2: Populate characteristics, includes, descriptors ----
    let mut current_service: Option<GattDbService> = None;

    for &(handle, ref value) in entries {
        // After Pass 1, only service declaration handles exist in the DB.
        // If get_attribute succeeds, this is a service.
        if let Some(attr) = db.get_attribute(handle) {
            // Activate the previous service before switching.
            if let Some(ref svc) = current_service {
                svc.set_active(true);
            }
            current_service = attr.get_service();
            continue;
        }

        // Skip if we haven't found our first service yet.
        let service = match current_service {
            Some(ref s) => s,
            None => continue,
        };

        if value.starts_with("2803:") {
            load_chrc(db, service, handle, value)?;
        } else if value.starts_with("2802:") {
            load_incl(db, service, handle, value)?;
        } else {
            load_desc(service, handle, value)?;
        }
    }

    // Activate the last service.
    if let Some(ref svc) = current_service {
        svc.set_active(true);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Serialization (storing)
// ---------------------------------------------------------------------------

/// Serialize a descriptor attribute to the INI file.
///
/// - CEP descriptor (0x2900): value is the `ext_props` field formatted as 4-hex
/// - Other descriptors with cached value: `<hex_value>:<uuid>`
/// - Descriptors without cached value: `<uuid>`
fn store_desc(ini: &mut Ini, attr: &GattDbAttribute, ext_props: u16) {
    let handle = attr.get_handle();
    let uuid = match attr.get_type() {
        Some(u) => u,
        None => return,
    };

    let uuid_str = uuid_to_string(&uuid);
    let handle_key = format!("{handle:04x}");

    let value_str = if uuid == BtUuid::from_u16(GATT_CEP_UUID) {
        // CEP descriptor: store the extended properties value.
        format!("{ext_props:04x}:{uuid_str}")
    } else {
        // General descriptor: store cached inline value if present.
        let cached = attr.get_value();
        if cached.is_empty() { uuid_str } else { format!("{}:{uuid_str}", val2str(&cached)) }
    };

    ini.with_section(Some(ATTRIBUTES_SECTION)).set(&handle_key, &value_str);
}

/// Serialize a characteristic declaration attribute to the INI file.
///
/// For the Database Hash characteristic (UUID 0x2B2A), includes the 16-byte
/// cached hash value if present.  For all others, only the declaration fields
/// are stored.
fn store_chrc(ini: &mut Ini, db: &GattDb, attr: &GattDbAttribute) -> u16 {
    let char_data = match attr.get_char_data() {
        Some(d) => d,
        None => return 0,
    };

    let handle = attr.get_handle();
    let props = GattChrcProperties::from_bits_truncate(char_data.properties);
    let uuid_str = uuid_to_string(&char_data.uuid);

    // Check for Database Hash special case.
    let value_str = if char_data.uuid == BtUuid::from_u16(GATT_DB_HASH_UUID) {
        // Read cached value from the value attribute.
        match db.get_attribute(char_data.value_handle) {
            Some(value_attr) => {
                let cached = value_attr.get_value();
                if cached.len() == 16 {
                    format!(
                        "{GATT_CHARAC_UUID_STR}:{:04x}:{:02x}:{}:{uuid_str}",
                        char_data.value_handle,
                        props.bits(),
                        val2str(&cached)
                    )
                } else {
                    format!(
                        "{GATT_CHARAC_UUID_STR}:{:04x}:{:02x}:{uuid_str}",
                        char_data.value_handle,
                        props.bits()
                    )
                }
            }
            None => format!(
                "{GATT_CHARAC_UUID_STR}:{:04x}:{:02x}:{uuid_str}",
                char_data.value_handle,
                props.bits()
            ),
        }
    } else {
        format!(
            "{GATT_CHARAC_UUID_STR}:{:04x}:{:02x}:{uuid_str}",
            char_data.value_handle,
            props.bits()
        )
    };

    let handle_key = format!("{handle:04x}");
    ini.with_section(Some(ATTRIBUTES_SECTION)).set(&handle_key, &value_str);

    // Return ext_prop for use by subsequent descriptor storage.
    char_data.ext_prop
}

/// Serialize an include declaration attribute to the INI file.
///
/// Include format: `2802:<start_hex>:<end_hex>:<uuid>`.
fn store_incl(ini: &mut Ini, db: &GattDb, attr: &GattDbAttribute) {
    let handle = attr.get_handle();
    let incl_data = match attr.get_incl_data() {
        Some(d) => d,
        None => return,
    };

    // Get the included service's UUID from the database.
    let incl_uuid = match db
        .get_attribute(incl_data.start_handle)
        .and_then(|a| a.get_service_data())
        .map(|sd| sd.uuid)
    {
        Some(u) => u,
        None => {
            warn!(
                "Cannot find included service UUID at 0x{:04x} for include at 0x{handle:04x}",
                incl_data.start_handle
            );
            return;
        }
    };

    let uuid_str = uuid_to_string(&incl_uuid);
    let handle_key = format!("{handle:04x}");
    let value_str = format!(
        "{GATT_INCLUDE_UUID_STR}:{:04x}:{:04x}:{uuid_str}",
        incl_data.start_handle, incl_data.end_handle
    );

    ini.with_section(Some(ATTRIBUTES_SECTION)).set(&handle_key, &value_str);
}

/// Serialize an entire service and its child attributes to the INI file.
///
/// Stores: service declaration → includes → characteristics (each followed by
/// its descriptors), matching the C `store_service` iteration order.
fn store_service_full(ini: &mut Ini, db: &GattDb, service_attr: &GattDbAttribute) {
    // Store the service declaration itself.
    let service_data = match service_attr.get_service_data() {
        Some(d) => d,
        None => return,
    };

    let svc_type =
        if service_data.primary { GATT_PRIM_SVC_UUID_STR } else { GATT_SND_SVC_UUID_STR };
    let uuid_str = uuid_to_string(&service_data.uuid);
    let handle_key = format!("{:04x}", service_data.start);
    let value_str = format!("{svc_type}:{:04x}:{uuid_str}", service_data.end);

    ini.with_section(Some(ATTRIBUTES_SECTION)).set(&handle_key, &value_str);

    // Get the GattDbService handle for iteration methods.
    let service = match service_attr.get_service() {
        Some(s) => s,
        None => return,
    };

    // Store all includes first (matching C iteration order).
    service.foreach_incl(|incl_attr| {
        store_incl(ini, db, &incl_attr);
    });

    // Collect all descriptor handles using foreach_desc (satisfies schema).
    let mut desc_handles: Vec<u16> = Vec::new();
    service.foreach_desc(|desc_attr| {
        desc_handles.push(desc_attr.get_handle());
    });

    // Collect characteristic info for ordered iteration.
    let mut chars: Vec<(u16, CharData)> = Vec::new();
    service.foreach_char(|char_attr| {
        let decl_handle = char_attr.get_handle();
        if let Some(data) = char_attr.get_char_data() {
            chars.push((decl_handle, data));
        }
    });

    // Store each characteristic followed by its descriptors.
    for (idx, (decl_handle, char_data)) in chars.iter().enumerate() {
        // Store the characteristic declaration.
        let ext_props = if let Some(char_attr) = db.get_attribute(*decl_handle) {
            store_chrc(ini, db, &char_attr)
        } else {
            0
        };

        // Determine the descriptor handle range for this characteristic.
        // Descriptors occupy handles from (value_handle + 1) up to
        // the next characteristic declaration handle (exclusive) or the
        // end of service.
        let next_char_handle = chars.get(idx + 1).map(|(h, _)| *h).unwrap_or(service_data.end + 1);

        // Store descriptors belonging to this characteristic, in handle order.
        let mut char_descs: Vec<u16> = desc_handles
            .iter()
            .copied()
            .filter(|&dh| dh > char_data.value_handle && dh < next_char_handle)
            .collect();
        char_descs.sort_unstable();

        for dh in char_descs {
            if let Some(desc_attr) = db.get_attribute(dh) {
                store_desc(ini, &desc_attr, ext_props);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load a GATT database snapshot from an INI-format file.
///
/// Opens `filename`, reads the `[Attributes]` section, and populates `db`
/// using a two-pass approach: services are created first, then characteristics,
/// includes, and descriptors are inserted.
///
/// # Errors
///
/// Returns [`GattSettingsError::FileNotFound`] if the file does not exist, or
/// [`GattSettingsError::ParseError`] / [`GattSettingsError::IoError`] on I/O
/// or format errors.
pub fn btd_settings_gatt_db_load(db: &GattDb, filename: &str) -> Result<(), GattSettingsError> {
    if !Path::new(filename).exists() {
        return Err(GattSettingsError::FileNotFound(filename.to_owned()));
    }

    // Clear existing attributes before loading a fresh snapshot.
    db.clear();

    let ini = Ini::load_from_file(filename).map_err(|e| {
        error!("Failed to load GATT settings from {filename}: {e}");
        GattSettingsError::from(e)
    })?;

    // Collect all entries from the [Attributes] section, sorted by handle.
    let mut entries: Vec<(u16, String)> = Vec::new();

    if let Some(section) = ini.section(Some(ATTRIBUTES_SECTION)) {
        for (key, value) in section.iter() {
            match u16::from_str_radix(key, 16) {
                Ok(handle) if handle > 0 => {
                    entries.push((handle, value.to_owned()));
                }
                _ => {
                    warn!("Skipping invalid handle key in [Attributes]: {key}");
                }
            }
        }
    }

    // Sort by handle to ensure deterministic two-pass ordering.
    entries.sort_by_key(|&(h, _)| h);

    if entries.is_empty() {
        debug!("No attributes found in {filename}");
        return Ok(());
    }

    gatt_db_load(db, &entries)?;

    debug!("Loaded {} GATT attributes from {filename}", entries.len());
    Ok(())
}

/// Store the entire GATT database as an INI-format file.
///
/// Creates a new INI structure, iterates all services in `db`, and writes
/// each service with its includes, characteristics, and descriptors to the
/// `[Attributes]` section.
///
/// Any I/O errors during writing are logged but not propagated, matching the
/// C implementation's void return type.
pub fn btd_settings_gatt_db_store(db: &GattDb, filename: &str) {
    let mut ini = Ini::new();

    // Iterate all services and serialize them.
    db.foreach_service(None, |service_attr| {
        store_service_full(&mut ini, db, &service_attr);
    });

    // Write to file.
    if let Err(e) = ini.write_to_file(filename) {
        error!("Failed to write GATT settings to {filename}: {e}");
    } else {
        debug!("Stored GATT database to {filename}");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ---------------------------------------------------------------
    // Helper utilities
    // ---------------------------------------------------------------

    #[test]
    fn test_str2val_valid() {
        assert_eq!(str2val("0100"), Some(vec![0x01, 0x00]));
        assert_eq!(str2val("ff"), Some(vec![0xff]));
        assert_eq!(str2val(""), Some(vec![]));
        assert_eq!(str2val("0a1b2c"), Some(vec![0x0a, 0x1b, 0x2c]));
    }

    #[test]
    fn test_str2val_invalid() {
        assert_eq!(str2val("zz"), None);
        assert_eq!(str2val("0g"), None);
    }

    #[test]
    fn test_str2val_odd_length() {
        // Odd length: processes pairs only, truncating the trailing char.
        assert_eq!(str2val("012"), Some(vec![0x01]));
    }

    #[test]
    fn test_val2str() {
        assert_eq!(val2str(&[0x01, 0x00]), "0100");
        assert_eq!(val2str(&[0xff]), "ff");
        assert_eq!(val2str(&[]), "");
    }

    #[test]
    fn test_val2str_roundtrip() {
        let original = vec![0xde, 0xad, 0xbe, 0xef];
        let hex = val2str(&original);
        assert_eq!(hex, "deadbeef");
        let recovered = str2val(&hex).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_uuid_to_string_uuid16() {
        let uuid = BtUuid::from_u16(0x1800);
        assert_eq!(uuid_to_string(&uuid), "1800");
    }

    #[test]
    fn test_uuid_to_string_uuid16_zero_padded() {
        let uuid = BtUuid::from_u16(0x0001);
        assert_eq!(uuid_to_string(&uuid), "0001");
    }

    #[test]
    fn test_default_permissions() {
        let perms = default_permissions();
        // READ | WRITE
        assert!(perms > 0);
        assert_eq!(perms & AttPermissions::READ.bits() as u32, AttPermissions::READ.bits() as u32);
        assert_eq!(
            perms & AttPermissions::WRITE.bits() as u32,
            AttPermissions::WRITE.bits() as u32
        );
    }

    // ---------------------------------------------------------------
    // Error type
    // ---------------------------------------------------------------

    #[test]
    fn test_error_display() {
        let err = GattSettingsError::FileNotFound("/tmp/test.ini".to_string());
        assert!(err.to_string().contains("/tmp/test.ini"));

        let err = GattSettingsError::ParseError("bad data".to_string());
        assert!(err.to_string().contains("bad data"));

        let err = GattSettingsError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: GattSettingsError = io_err.into();
        match err {
            GattSettingsError::IoError(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("Expected IoError, got: {other}"),
        }
    }

    // ---------------------------------------------------------------
    // Public API — load
    // ---------------------------------------------------------------

    #[test]
    fn test_load_nonexistent_file() {
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, "/tmp/nonexistent_blitzy_gatt_12345.ini");
        match result {
            Err(GattSettingsError::FileNotFound(path)) => {
                assert!(path.contains("nonexistent"));
            }
            other => panic!("Expected FileNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn test_load_empty_file() {
        let path = "/tmp/blitzy_adhoc_test_empty_gatt.ini";
        fs::write(path, "").unwrap();
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, path);
        assert!(result.is_ok(), "Failed: {result:?}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_empty_attributes_section() {
        let path = "/tmp/blitzy_adhoc_test_empty_attrs.ini";
        fs::write(path, "[Attributes]\n").unwrap();
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, path);
        assert!(result.is_ok(), "Failed: {result:?}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_service_entry() {
        let path = "/tmp/blitzy_adhoc_test_svc.ini";
        fs::write(path, "[Attributes]\n0001=2800:0005:1800\n").unwrap();
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, path);
        assert!(result.is_ok(), "Failed: {result:?}");
        // Verify the service was created at handle 1.
        assert!(db.get_attribute(1).is_some(), "Service not found at handle 1");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_secondary_service() {
        let path = "/tmp/blitzy_adhoc_test_snd_svc.ini";
        fs::write(path, "[Attributes]\n0001=2801:0003:1801\n").unwrap();
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, path);
        assert!(result.is_ok(), "Failed: {result:?}");
        let attr = db.get_attribute(1);
        assert!(attr.is_some(), "Secondary service not found at handle 1");
        if let Some(sd) = attr.unwrap().get_service_data() {
            assert!(!sd.primary, "Expected secondary service");
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_service_with_chrc() {
        let path = "/tmp/blitzy_adhoc_test_svc_chrc.ini";
        fs::write(path, "[Attributes]\n0001=2800:0005:1800\n0002=2803:0003:02:2a00\n").unwrap();
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, path);
        assert!(result.is_ok(), "Failed: {result:?}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_service_with_chrc_and_desc() {
        let path = "/tmp/blitzy_adhoc_test_svc_chrc_desc.ini";
        fs::write(path, "[Attributes]\n0001=2800:0005:1800\n0002=2803:0003:02:2a00\n0004=2902\n")
            .unwrap();
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, path);
        assert!(result.is_ok(), "Failed: {result:?}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_desc_with_cached_value() {
        let path = "/tmp/blitzy_adhoc_test_desc_val.ini";
        fs::write(
            path,
            "[Attributes]\n0001=2800:0005:1800\n0002=2803:0003:02:2a00\n0004=0100:2902\n",
        )
        .unwrap();
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, path);
        assert!(result.is_ok(), "Failed: {result:?}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_chrc_with_cached_value() {
        let path = "/tmp/blitzy_adhoc_test_chrc_val.ini";
        // 5-field format: 2803:vhandle:props:hex_value:uuid
        fs::write(path, "[Attributes]\n0001=2800:0005:1800\n0002=2803:0003:02:48656c6c6f:2a00\n")
            .unwrap();
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, path);
        assert!(result.is_ok(), "Failed: {result:?}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_include_declaration() {
        let path = "/tmp/blitzy_adhoc_test_incl.ini";
        // Two services, second includes first
        fs::write(
            path,
            "[Attributes]\n0001=2800:0003:1800\n0004=2800:0008:1801\n0005=2802:0001:0003:1800\n",
        )
        .unwrap();
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, path);
        assert!(result.is_ok(), "Failed: {result:?}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_malformed_key_skipped() {
        let path = "/tmp/blitzy_adhoc_test_bad_key.ini";
        // "gggg" is not valid hex — should be skipped.
        fs::write(path, "[Attributes]\ngggg=2800:0005:1800\n0001=2800:0005:1800\n").unwrap();
        let db = GattDb::new();
        let result = btd_settings_gatt_db_load(&db, path);
        assert!(result.is_ok(), "Failed: {result:?}");
        // The valid service should still load.
        assert!(db.get_attribute(1).is_some());
        let _ = fs::remove_file(path);
    }

    // ---------------------------------------------------------------
    // Public API — store
    // ---------------------------------------------------------------

    #[test]
    fn test_store_empty_db() {
        let path = "/tmp/blitzy_adhoc_test_store_empty.ini";
        let db = GattDb::new();
        btd_settings_gatt_db_store(&db, path);
        assert!(Path::new(path).exists(), "File was not created");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_store_service() {
        let path = "/tmp/blitzy_adhoc_test_store_svc.ini";
        let db = GattDb::new();
        let uuid = BtUuid::from_u16(0x1800);
        if let Some(svc) = db.insert_service(1, &uuid, true, 5) {
            svc.set_active(true);
        }
        btd_settings_gatt_db_store(&db, path);
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("[Attributes]"), "Missing [Attributes] section");
        assert!(content.contains("2800:"), "Missing service declaration");
        assert!(content.contains("1800"), "Missing service UUID");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_store_service_with_chrc() {
        let path = "/tmp/blitzy_adhoc_test_store_svc_chrc.ini";
        let db = GattDb::new();
        let uuid = BtUuid::from_u16(0x1800);
        if let Some(svc) = db.insert_service(1, &uuid, true, 5) {
            let chrc_uuid = BtUuid::from_u16(0x2A00);
            svc.insert_characteristic(2, &chrc_uuid, 0x03, 0x02, None, None, None);
            svc.set_active(true);
        }
        btd_settings_gatt_db_store(&db, path);
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("2803:"), "Missing chrc declaration");
        assert!(content.contains("2a00"), "Missing chrc UUID");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_roundtrip_service() {
        // Create DB → store → load into fresh DB → verify service exists
        let path = "/tmp/blitzy_adhoc_test_roundtrip.ini";
        let db1 = GattDb::new();
        let uuid = BtUuid::from_u16(0x1800);
        if let Some(svc) = db1.insert_service(1, &uuid, true, 3) {
            svc.set_active(true);
        }
        btd_settings_gatt_db_store(&db1, path);

        let db2 = GattDb::new();
        let result = btd_settings_gatt_db_load(&db2, path);
        assert!(result.is_ok(), "Roundtrip load failed: {result:?}");
        assert!(db2.get_attribute(1).is_some(), "Service not found after roundtrip");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_handle_format_lowercase_zero_padded() {
        let path = "/tmp/blitzy_adhoc_test_handle_fmt.ini";
        let db = GattDb::new();
        let uuid = BtUuid::from_u16(0x1800);
        if let Some(svc) = db.insert_service(1, &uuid, true, 5) {
            svc.set_active(true);
        }
        btd_settings_gatt_db_store(&db, path);
        let content = fs::read_to_string(path).unwrap();
        // Handle should be "0001", not "1" or "0x0001".
        assert!(content.contains("0001="), "Handle not 4-digit zero-padded. Content:\n{content}");
        let _ = fs::remove_file(path);
    }
}
