//! SDP record ↔ XML conversion module.
//!
//! Provides bidirectional conversion between SDP (Service Discovery Protocol)
//! records and their XML representation. This is used for persisting SDP service
//! records and for external profile registration via D-Bus.
//!
//! This module is a Rust rewrite of the C implementation in `src/sdp-xml.c`
//! preserving byte-identical XML output formatting for behavioral compatibility.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as FmtWrite;

use quick_xml::Reader;
use quick_xml::events::Event;
use tracing::{debug, error};

// ---------------------------------------------------------------------------
// Constants matching the C implementation
// ---------------------------------------------------------------------------

/// Maximum indentation level (in tab characters). Mirrors MAXINDENT in C.
const MAXINDENT: usize = 64;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during SDP XML parsing or conversion.
#[derive(Debug)]
pub enum XmlError {
    /// General XML parsing error.
    Parse(String),
    /// An attribute value could not be interpreted.
    InvalidValue(String),
    /// An unrecognised SDP data-type element was encountered.
    InvalidType(String),
    /// The parser stack was popped when empty.
    StackUnderflow,
    /// Underlying quick-xml error.
    QuickXml(quick_xml::Error),
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XmlError::Parse(msg) => write!(f, "XML parse error: {msg}"),
            XmlError::InvalidValue(msg) => write!(f, "invalid attribute value: {msg}"),
            XmlError::InvalidType(msg) => write!(f, "invalid SDP type: {msg}"),
            XmlError::StackUnderflow => write!(f, "parser stack underflow"),
            XmlError::QuickXml(e) => write!(f, "quick-xml error: {e}"),
        }
    }
}

impl std::error::Error for XmlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            XmlError::QuickXml(e) => Some(e),
            _ => None,
        }
    }
}

impl From<quick_xml::Error> for XmlError {
    fn from(e: quick_xml::Error) -> Self {
        XmlError::QuickXml(e)
    }
}

// ---------------------------------------------------------------------------
// SDP data model
// ---------------------------------------------------------------------------

/// Recursive SDP data value, replacing the C `sdp_data_t` linked-list tree.
///
/// Each variant directly contains its payload; sequences and alternates hold
/// their children in a `Vec` (replacing C's `dataseq` linked list via `next`).
#[derive(Debug, Clone, PartialEq)]
pub enum SdpData {
    /// Data element nil (`SDP_DATA_NIL`).
    Nil,
    /// Boolean (`SDP_BOOL`).
    Bool(bool),
    /// Unsigned 8-bit integer (`SDP_UINT8`).
    UInt8(u8),
    /// Unsigned 16-bit integer (`SDP_UINT16`).
    UInt16(u16),
    /// Unsigned 32-bit integer (`SDP_UINT32`).
    UInt32(u32),
    /// Unsigned 64-bit integer (`SDP_UINT64`).
    UInt64(u64),
    /// Unsigned 128-bit integer (`SDP_UINT128`) stored big-endian.
    UInt128([u8; 16]),
    /// Signed 8-bit integer (`SDP_INT8`).
    Int8(i8),
    /// Signed 16-bit integer (`SDP_INT16`).
    Int16(i16),
    /// Signed 32-bit integer (`SDP_INT32`).
    Int32(i32),
    /// Signed 64-bit integer (`SDP_INT64`).
    Int64(i64),
    /// Signed 128-bit integer (`SDP_INT128`) stored big-endian.
    Int128([u8; 16]),
    /// UUID-16 (`SDP_UUID16`).
    Uuid16(u16),
    /// UUID-32 (`SDP_UUID32`).
    Uuid32(u32),
    /// UUID-128 (`SDP_UUID128`) stored big-endian.
    Uuid128([u8; 16]),
    /// Text string (`SDP_TEXT_STR8/16/32`). Raw bytes — may not be valid UTF-8.
    Text(Vec<u8>),
    /// URL string (`SDP_URL_STR8/16/32`).
    Url(String),
    /// Data element sequence (`SDP_SEQ8/16/32`).
    Sequence(Vec<SdpData>),
    /// Data element alternate (`SDP_ALT8/16/32`).
    Alternate(Vec<SdpData>),
}

/// An SDP service record consisting of a handle and a set of attributes keyed
/// by 16-bit attribute IDs.  Attribute ordering is preserved via `BTreeMap`.
#[derive(Debug, Clone, PartialEq)]
pub struct SdpRecord {
    /// SDP service record handle.
    pub handle: u32,
    /// Attribute map (attribute-ID → value).
    pub attrs: BTreeMap<u16, SdpData>,
}

impl SdpRecord {
    /// Create a new empty record with the given handle.
    pub fn new(handle: u32) -> Self {
        Self { handle, attrs: BTreeMap::new() }
    }
}

// ---------------------------------------------------------------------------
// Internal encoding discriminant (mirrors SDP_XML_ENCODING_* in C)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XmlEncoding {
    Normal,
    Hex,
}

// ---------------------------------------------------------------------------
// Low-level helper functions
// ---------------------------------------------------------------------------

/// Returns `true` when `b` is a printable ASCII character, matching the
/// behaviour of C `isprint()` — values in the range 0x20 ..= 0x7E.
fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

/// Build an indentation string of tab characters for a given nesting level,
/// capped at `MAXINDENT - 2` (62) tabs to match the C implementation.
fn make_indent(level: usize) -> String {
    let capped = level.min(MAXINDENT - 2);
    "\t".repeat(capped)
}

/// Manually unescape the five standard XML character entity references.
/// This mirrors the automatic unescaping that GMarkup performs on attribute
/// values when the C code receives them.
fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// Parse an integer string with automatic base detection (matching C
/// `strtoul` / `strtoull` with base 0).
///
/// * `0x` or `0X` prefix → hexadecimal
/// * `0` prefix (without `x`) → octal
/// * Otherwise → decimal
fn parse_auto_base_u64(s: &str) -> Result<u64, XmlError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(XmlError::InvalidValue("empty integer string".into()));
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.is_empty() {
            return Ok(0);
        }
        u64::from_str_radix(hex, 16)
            .map_err(|e| XmlError::InvalidValue(format!("bad hex u64 '{s}': {e}")))
    } else if s.starts_with('0') && s.len() > 1 && s.as_bytes()[1].is_ascii_digit() {
        u64::from_str_radix(&s[1..], 8)
            .map_err(|e| XmlError::InvalidValue(format!("bad octal u64 '{s}': {e}")))
    } else {
        s.parse::<u64>().map_err(|e| XmlError::InvalidValue(format!("bad decimal u64 '{s}': {e}")))
    }
}

/// Signed variant of [`parse_auto_base_u64`].
fn parse_auto_base_i64(s: &str) -> Result<i64, XmlError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(XmlError::InvalidValue("empty integer string".into()));
    }
    let (neg, abs) = if let Some(rest) = s.strip_prefix('-') { (true, rest) } else { (false, s) };
    let magnitude = parse_auto_base_u64(abs)? as i64;
    Ok(if neg { -magnitude } else { magnitude })
}

/// Decode a string of hexadecimal character-pairs into bytes.
/// E.g. `"48656c6c6f"` → `[0x48, 0x65, 0x6c, 0x6c, 0x6f]`.
fn hex_decode_pairs(s: &str) -> Result<Vec<u8>, XmlError> {
    if s.len() % 2 != 0 {
        return Err(XmlError::InvalidValue(format!("odd-length hex string ({})", s.len())));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// Convert a single ASCII hex character to its 4-bit value.
fn hex_nibble(b: u8) -> Result<u8, XmlError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(XmlError::InvalidValue(format!("invalid hex character: 0x{b:02x}"))),
    }
}

/// Parse a 128-bit UUID from a hex string that may or may not contain dashes.
/// Accepts 32 pure hex chars or 36 chars with dashes (standard UUID format).
fn parse_uuid128(s: &str) -> Result<[u8; 16], XmlError> {
    let mut val = [0u8; 16];
    let mut j = 0usize;
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && j < 16 {
        if bytes[i] == b'-' {
            i += 1;
            continue;
        }
        if i + 1 >= bytes.len() {
            return Err(XmlError::InvalidValue("truncated UUID128 hex string".into()));
        }
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        val[j] = (hi << 4) | lo;
        j += 1;
        i += 2;
    }
    if j != 16 {
        return Err(XmlError::InvalidValue(format!("UUID128 needs 16 bytes, got {j}")));
    }
    Ok(val)
}

// ---------------------------------------------------------------------------
// Type-specific XML → SDP parsers (mirror C `sdp_xml_parse_*` functions)
// ---------------------------------------------------------------------------

/// Parse a UUID value string.  Behaviour mirrors `sdp_xml_parse_uuid` in C:
///
/// * 36-character string (with dashes) → UUID-128
/// * 32-character pure hex → UUID-128
/// * Otherwise strip `0x` prefix, parse hex; if > 0xFFFF → UUID-32, else UUID-16.
fn parse_uuid(text: &str) -> Result<SdpData, XmlError> {
    let len = text.len();

    // 36-char dashed form → UUID-128
    if len == 36 {
        let val = parse_uuid128(text)?;
        return Ok(SdpData::Uuid128(val));
    }

    // 32-char pure hex form → UUID-128
    if len == 32 {
        let val = parse_uuid128(text)?;
        return Ok(SdpData::Uuid128(val));
    }

    // Strip "0x" / "0X" and parse as a number
    let hex_str = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);

    let val = u64::from_str_radix(hex_str, 16)
        .map_err(|e| XmlError::InvalidValue(format!("bad UUID hex '{text}': {e}")))?;

    if val > u64::from(u16::MAX) {
        Ok(SdpData::Uuid32(val as u32))
    } else {
        Ok(SdpData::Uuid16(val as u16))
    }
}

/// Parse an integer/boolean value.  `type_name` is the XML element name
/// (`"boolean"`, `"uint8"`, `"int32"`, etc.).  Mirrors `sdp_xml_parse_int`.
fn parse_int_value(text: &str, type_name: &str) -> Result<SdpData, XmlError> {
    match type_name {
        "boolean" => {
            let val = text.starts_with('t') || text.starts_with('T') || text.starts_with('1');
            Ok(SdpData::Bool(val))
        }
        "uint8" => {
            let v = parse_auto_base_u64(text)? as u8;
            Ok(SdpData::UInt8(v))
        }
        "uint16" => {
            let v = parse_auto_base_u64(text)? as u16;
            Ok(SdpData::UInt16(v))
        }
        "uint32" => {
            let v = parse_auto_base_u64(text)? as u32;
            Ok(SdpData::UInt32(v))
        }
        "uint64" => {
            let v = parse_auto_base_u64(text)?;
            Ok(SdpData::UInt64(v))
        }
        "uint128" => {
            // Strip optional "0x" / "0X" prefix, then decode 32 hex characters
            let hex = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
            let bytes = hex_decode_32_chars(hex)?;
            Ok(SdpData::UInt128(bytes))
        }
        "int8" => {
            let v = parse_auto_base_i64(text)? as i8;
            Ok(SdpData::Int8(v))
        }
        "int16" => {
            let v = parse_auto_base_i64(text)? as i16;
            Ok(SdpData::Int16(v))
        }
        "int32" => {
            let v = parse_auto_base_i64(text)? as i32;
            Ok(SdpData::Int32(v))
        }
        "int64" => {
            let v = parse_auto_base_i64(text)?;
            Ok(SdpData::Int64(v))
        }
        "int128" => {
            let hex = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
            let bytes = hex_decode_32_chars(hex)?;
            Ok(SdpData::Int128(bytes))
        }
        other => Err(XmlError::InvalidType(format!("unknown integer type '{other}'"))),
    }
}

/// Decode exactly 32 hex characters into 16 bytes.
fn hex_decode_32_chars(hex: &str) -> Result<[u8; 16], XmlError> {
    let decoded = hex_decode_pairs(hex)?;
    if decoded.len() != 16 {
        return Err(XmlError::InvalidValue(format!(
            "expected 16 bytes for 128-bit value, got {}",
            decoded.len()
        )));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

/// Parse a text value with the given encoding.
/// Normal encoding: raw string copy.
/// Hex encoding: hex-pair decode to bytes.
fn parse_text_value(text: &str, encoding: XmlEncoding) -> Result<SdpData, XmlError> {
    match encoding {
        XmlEncoding::Normal => Ok(SdpData::Text(text.as_bytes().to_vec())),
        XmlEncoding::Hex => {
            let bytes = hex_decode_pairs(text)?;
            Ok(SdpData::Text(bytes))
        }
    }
}

/// Parse a URL value (always normal encoding).
fn parse_url_value(text: &str) -> Result<SdpData, XmlError> {
    Ok(SdpData::Url(text.to_owned()))
}

/// Dispatch an element name to the appropriate type-specific parser.
/// Mirrors `sdp_xml_parse_datatype` in C.
fn parse_datatype(
    type_name: &str,
    value: &str,
    encoding: XmlEncoding,
) -> Result<SdpData, XmlError> {
    match type_name {
        "nil" => Ok(SdpData::Nil),
        "boolean" | "uint8" | "uint16" | "uint32" | "uint64" | "uint128" | "int8" | "int16"
        | "int32" | "int64" | "int128" => parse_int_value(value, type_name),
        "uuid" => parse_uuid(value),
        "text" => parse_text_value(value, encoding),
        "url" => parse_url_value(value),
        other => {
            error!("unknown SDP element type: {other}");
            Err(XmlError::InvalidType(other.to_owned()))
        }
    }
}

// ---------------------------------------------------------------------------
// XML attribute extraction helpers for quick-xml BytesStart
// ---------------------------------------------------------------------------

/// Extract the tag name from a `BytesStart` event as a UTF-8 string.
fn tag_name_start(e: &quick_xml::events::BytesStart<'_>) -> Result<String, XmlError> {
    std::str::from_utf8(e.name().as_ref())
        .map(|s| s.to_owned())
        .map_err(|err| XmlError::Parse(format!("non-UTF-8 tag name: {err}")))
}

/// Extract the tag name from a `BytesEnd` event as a UTF-8 string.
fn tag_name_end(e: &quick_xml::events::BytesEnd<'_>) -> Result<String, XmlError> {
    std::str::from_utf8(e.name().as_ref())
        .map(|s| s.to_owned())
        .map_err(|err| XmlError::Parse(format!("non-UTF-8 end-tag name: {err}")))
}

/// Collect all XML attributes of an element into a `Vec<(String, String)>`,
/// performing XML entity unescaping on values (matching GMarkup behaviour).
fn collect_attrs(e: &quick_xml::events::BytesStart<'_>) -> Result<Vec<(String, String)>, XmlError> {
    let mut out = Vec::new();
    for attr_result in e.attributes() {
        let attr =
            attr_result.map_err(|err| XmlError::Parse(format!("attribute read error: {err}")))?;
        let key = std::str::from_utf8(attr.key.as_ref())
            .map_err(|err| XmlError::Parse(format!("non-UTF-8 attr key: {err}")))?
            .to_owned();
        let raw_val = std::str::from_utf8(attr.value.as_ref())
            .map_err(|err| XmlError::Parse(format!("non-UTF-8 attr value: {err}")))?;
        // Unescape XML entities to match GMarkup automatic unescaping
        let val = xml_unescape(raw_val);
        out.push((key, val));
    }
    Ok(out)
}

/// Look up a single attribute value by name from a collected attribute list.
fn find_attr<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------------------
// XML → SDP:  parse_record
// ---------------------------------------------------------------------------

/// Parse an XML string into an [`SdpRecord`].
///
/// This replaces the C function `sdp_xml_parse_record` which used
/// `GMarkupParseContext`.  A SAX-style event loop over `quick_xml::Reader`
/// drives a stack-based state machine identical to the original.
///
/// # Errors
///
/// Returns [`XmlError`] if the XML is malformed, contains unrecognised element
/// names, or has invalid attribute values.
pub fn parse_record(xml: &str) -> Result<SdpRecord, XmlError> {
    debug!("parsing SDP record from XML ({} bytes)", xml.len());

    let mut reader = Reader::from_str(xml);

    let mut record = SdpRecord::new(0);
    // Stack of containers (Sequence / Alternate) currently being built.
    let mut stack: Vec<SdpData> = Vec::new();
    // The attribute ID of the `<attribute>` element we are currently inside.
    let mut current_attr_id: Option<u16> = None;
    // Whether we are between `<attribute ...>` and `</attribute>`.
    let mut in_attribute = false;

    loop {
        match reader.read_event() {
            // --- Opening tags: <record>, <attribute>, <sequence>, <alternate> ---
            Ok(Event::Start(ref e)) => {
                let tag = tag_name_start(e)?;
                let attrs = collect_attrs(e)?;
                match tag.as_str() {
                    "record" => { /* Root element — nothing to do. */ }
                    "attribute" => {
                        if let Some(id_str) = find_attr(&attrs, "id") {
                            current_attr_id = Some(parse_auto_base_u64(id_str)? as u16);
                        } else {
                            error!("attribute element missing 'id'");
                            return Err(XmlError::Parse("attribute element missing 'id'".into()));
                        }
                        in_attribute = true;
                    }
                    "sequence" => {
                        stack.push(SdpData::Sequence(Vec::new()));
                    }
                    "alternate" => {
                        stack.push(SdpData::Alternate(Vec::new()));
                    }
                    _ => {
                        // Non-self-closing data element (unusual but legal).
                        let value = find_attr(&attrs, "value").unwrap_or("");
                        let encoding = if find_attr(&attrs, "encoding") == Some("hex") {
                            XmlEncoding::Hex
                        } else {
                            XmlEncoding::Normal
                        };
                        let data = parse_datatype(&tag, value, encoding)?;
                        stack.push(data);
                    }
                }
            }

            // --- Self-closing elements: <uint8 .../>, <nil/>, etc. ---
            Ok(Event::Empty(ref e)) => {
                let tag = tag_name_start(e)?;
                let attrs = collect_attrs(e)?;
                let value = find_attr(&attrs, "value").unwrap_or("");
                let encoding = if find_attr(&attrs, "encoding") == Some("hex") {
                    XmlEncoding::Hex
                } else {
                    XmlEncoding::Normal
                };
                let data = parse_datatype(&tag, value, encoding)?;
                push_data(&mut stack, &mut record, current_attr_id, in_attribute, data)?;
            }

            // --- Closing tags ---
            Ok(Event::End(ref e)) => {
                let tag = tag_name_end(e)?;
                match tag.as_str() {
                    "record" => { /* End of root element. */ }
                    "attribute" => {
                        in_attribute = false;
                        current_attr_id = None;
                    }
                    "sequence" | "alternate" => {
                        let completed = stack.pop().ok_or(XmlError::StackUnderflow)?;
                        push_data(
                            &mut stack,
                            &mut record,
                            current_attr_id,
                            in_attribute,
                            completed,
                        )?;
                    }
                    _ => {
                        // End of a non-self-closing data element.
                        let completed = stack.pop().ok_or(XmlError::StackUnderflow)?;
                        push_data(
                            &mut stack,
                            &mut record,
                            current_attr_id,
                            in_attribute,
                            completed,
                        )?;
                    }
                }
            }

            Ok(Event::Eof) => break,
            // Ignore XML declaration, comments, processing instructions, text.
            Ok(_) => {}
            Err(e) => {
                error!("XML parsing error: {e}");
                return Err(XmlError::QuickXml(e));
            }
        }
    }

    debug!("parsed SDP record with {} attributes", record.attrs.len());
    Ok(record)
}

/// Push a completed [`SdpData`] value into the correct destination.
///
/// If the stack contains a parent container (Sequence / Alternate), the value
/// is appended to that container.  Otherwise, if we are inside an `<attribute>`
/// element, the value is inserted directly into the record.
fn push_data(
    stack: &mut [SdpData],
    record: &mut SdpRecord,
    current_attr_id: Option<u16>,
    in_attribute: bool,
    data: SdpData,
) -> Result<(), XmlError> {
    if let Some(parent) = stack.last_mut() {
        match parent {
            SdpData::Sequence(items) => items.push(data),
            SdpData::Alternate(items) => items.push(data),
            _ => {
                error!("unexpected non-container parent on stack");
                return Err(XmlError::Parse("unexpected non-container parent on stack".into()));
            }
        }
    } else if in_attribute {
        if let Some(attr_id) = current_attr_id {
            record.attrs.insert(attr_id, data);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SDP → XML:  record_to_xml
// ---------------------------------------------------------------------------

/// Convert an [`SdpRecord`] to its XML string representation.
///
/// The output format is byte-identical to the C function
/// `convert_sdp_record_to_xml`.  The XML header, record wrapper, and
/// per-attribute indentation exactly replicate the original.
pub fn record_to_xml(record: &SdpRecord) -> String {
    let mut buf = String::with_capacity(4096);

    // XML declaration + blank line (matches C output exactly)
    buf.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\n");
    buf.push_str("<record>\n");

    for (&attr_id, data) in &record.attrs {
        // Attribute opening tag with one-tab indentation
        let _ = writeln!(buf, "\t<attribute id=\"0x{attr_id:04x}\">");
        // Data at indent level 2
        data_to_xml(data, 2, &mut buf);
        buf.push_str("\t</attribute>\n");
    }

    buf.push_str("</record>\n");
    buf
}

/// Recursively convert a single [`SdpData`] value to XML, appending to `buf`.
///
/// This mirrors the C function `convert_raw_data_to_xml` with identical
/// indentation and format strings.
fn data_to_xml(data: &SdpData, indent_level: usize, buf: &mut String) {
    let indent = make_indent(indent_level);

    match data {
        SdpData::Nil => {
            let _ = writeln!(buf, "{indent}<nil/>");
        }
        SdpData::Bool(v) => {
            let s = if *v { "true" } else { "false" };
            let _ = writeln!(buf, "{indent}<boolean value=\"{s}\" />");
        }
        SdpData::UInt8(v) => {
            let _ = writeln!(buf, "{indent}<uint8 value=\"0x{v:02x}\" />");
        }
        SdpData::UInt16(v) => {
            let _ = writeln!(buf, "{indent}<uint16 value=\"0x{v:04x}\" />");
        }
        SdpData::UInt32(v) => {
            let _ = writeln!(buf, "{indent}<uint32 value=\"0x{v:08x}\" />");
        }
        SdpData::UInt64(v) => {
            let _ = writeln!(buf, "{indent}<uint64 value=\"0x{v:016x}\" />");
        }
        SdpData::UInt128(v) => {
            let hex = bytes_to_hex(v);
            let _ = writeln!(buf, "{indent}<uint128 value=\"0x{hex}\" />");
        }
        SdpData::Int8(v) => {
            let _ = writeln!(buf, "{indent}<int8 value=\"{v}\" />");
        }
        SdpData::Int16(v) => {
            let _ = writeln!(buf, "{indent}<int16 value=\"{v}\" />");
        }
        SdpData::Int32(v) => {
            let _ = writeln!(buf, "{indent}<int32 value=\"{v}\" />");
        }
        SdpData::Int64(v) => {
            let _ = writeln!(buf, "{indent}<int64 value=\"{v}\" />");
        }
        SdpData::Int128(v) => {
            let hex = bytes_to_hex(v);
            let _ = writeln!(buf, "{indent}<int128 value=\"0x{hex}\" />");
        }
        SdpData::Uuid16(v) => {
            let _ = writeln!(buf, "{indent}<uuid value=\"0x{v:04x}\" />");
        }
        SdpData::Uuid32(v) => {
            let _ = writeln!(buf, "{indent}<uuid value=\"0x{v:08x}\" />");
        }
        SdpData::Uuid128(v) => {
            let formatted = format_uuid128(v);
            let _ = writeln!(buf, "{indent}<uuid value=\"{formatted}\" />");
        }
        SdpData::Text(bytes) => {
            emit_text_xml(bytes, &indent, buf);
        }
        SdpData::Url(s) => {
            let _ = writeln!(buf, "{indent}<url value=\"{s}\" />");
        }
        SdpData::Sequence(items) => {
            let _ = writeln!(buf, "{indent}<sequence>");
            for child in items {
                data_to_xml(child, indent_level + 1, buf);
            }
            let _ = writeln!(buf, "{indent}</sequence>");
        }
        SdpData::Alternate(items) => {
            let _ = writeln!(buf, "{indent}<alternate>");
            for child in items {
                data_to_xml(child, indent_level + 1, buf);
            }
            let _ = writeln!(buf, "{indent}</alternate>");
        }
    }
}

// ---------------------------------------------------------------------------
// XML output helpers
// ---------------------------------------------------------------------------

/// Format a UUID-128 byte array as a dashed hex string, matching the C format:
/// `%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x`
fn format_uuid128(v: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        v[0],
        v[1],
        v[2],
        v[3],
        v[4],
        v[5],
        v[6],
        v[7],
        v[8],
        v[9],
        v[10],
        v[11],
        v[12],
        v[13],
        v[14],
        v[15],
    )
}

/// Convert a byte slice to a lowercase hex string (two chars per byte).
fn bytes_to_hex(v: &[u8]) -> String {
    let mut s = String::with_capacity(v.len() * 2);
    for b in v {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Emit a `<text …/>` element for the given byte slice.
///
/// If all bytes (up to the first NUL) are printable ASCII, the value is
/// XML-escaped and written as `<text value="…" />`.  Otherwise the entire
/// byte payload is hex-encoded: `<text encoding="hex" value="…" />`.
///
/// This exactly mirrors the C logic in `convert_raw_data_to_xml` for
/// `SDP_TEXT_STR*` types.
fn emit_text_xml(bytes: &[u8], indent: &str, buf: &mut String) {
    // Determine whether to use hex encoding.
    // C checks bytes until a NUL or non-printable is found.
    let use_hex = bytes.iter().take_while(|&&b| b != 0).any(|&b| !is_printable(b));

    if use_hex {
        let _ = write!(buf, "{indent}<text encoding=\"hex\" value=\"");
        for b in bytes {
            let _ = write!(buf, "{b:02x}");
        }
        buf.push_str("\" />\n");
    } else {
        let _ = write!(buf, "{indent}<text value=\"");
        xml_escape_text(bytes, buf);
        buf.push_str("\" />\n");
    }
}

/// Append XML-escaped text bytes to `buf`, matching the C escaping rules:
///
/// * `&` → `&amp;`
/// * `<` → `&lt;`
/// * `>` → `&gt;`
/// * `"` → `&quot;`
/// * NUL byte → space
/// * All other bytes are appended verbatim.
fn xml_escape_text(bytes: &[u8], buf: &mut String) {
    for &b in bytes {
        match b {
            b'&' => buf.push_str("&amp;"),
            b'<' => buf.push_str("&lt;"),
            b'>' => buf.push_str("&gt;"),
            b'"' => buf.push_str("&quot;"),
            0 => buf.push(' '),
            _ => buf.push(b as char),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: build a record, convert to XML, parse back, compare.
    #[test]
    fn round_trip_simple() {
        let mut rec = SdpRecord::new(0);
        rec.attrs.insert(0x0001, SdpData::UInt16(0x1101));
        rec.attrs.insert(0x0002, SdpData::Bool(true));

        let xml = record_to_xml(&rec);
        let parsed = parse_record(&xml).expect("parse failed");

        assert_eq!(parsed.attrs.len(), 2);
        assert_eq!(parsed.attrs[&0x0001], SdpData::UInt16(0x1101));
        assert_eq!(parsed.attrs[&0x0002], SdpData::Bool(true));
    }

    /// Verify the XML output format exactly matches the C implementation.
    #[test]
    fn xml_output_format() {
        let mut rec = SdpRecord::new(0);
        rec.attrs.insert(0x0001, SdpData::UInt16(0x1101));

        let xml = record_to_xml(&rec);
        let expected = "\
<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\
\n\
<record>\n\
\t<attribute id=\"0x0001\">\n\
\t\t<uint16 value=\"0x1101\" />\n\
\t</attribute>\n\
</record>\n";
        assert_eq!(xml, expected);
    }

    /// Verify UUID formatting.
    #[test]
    fn uuid_formatting() {
        let mut rec = SdpRecord::new(0);
        rec.attrs.insert(
            0x0001,
            SdpData::Uuid128([
                0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b,
                0x34, 0xfb,
            ]),
        );
        let xml = record_to_xml(&rec);
        assert!(xml.contains("00001101-0000-1000-8000-00805f9b34fb"));
    }

    /// Parse a sequence with nested elements.
    #[test]
    fn parse_sequence() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8" ?>

<record>
	<attribute id="0x0001">
		<sequence>
			<uuid value="0x1101" />
			<uuid value="0x1102" />
		</sequence>
	</attribute>
</record>
"#;
        let rec = parse_record(xml).expect("parse failed");
        assert_eq!(rec.attrs.len(), 1);
        match &rec.attrs[&0x0001] {
            SdpData::Sequence(items) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], SdpData::Uuid16(0x1101));
                assert_eq!(items[1], SdpData::Uuid16(0x1102));
            }
            other => panic!("expected Sequence, got {other:?}"),
        }
    }

    /// Test text encoding — printable ASCII.
    #[test]
    fn text_printable() {
        let mut rec = SdpRecord::new(0);
        rec.attrs.insert(0x0100, SdpData::Text(b"Hello World".to_vec()));
        let xml = record_to_xml(&rec);
        assert!(xml.contains("<text value=\"Hello World\" />"));
        let parsed = parse_record(&xml).expect("parse");
        assert_eq!(parsed.attrs[&0x0100], SdpData::Text(b"Hello World".to_vec()));
    }

    /// Test text encoding — binary (non-printable) triggers hex.
    #[test]
    fn text_binary_hex() {
        let mut rec = SdpRecord::new(0);
        rec.attrs.insert(0x0100, SdpData::Text(vec![0x01, 0x02, 0xff]));
        let xml = record_to_xml(&rec);
        assert!(xml.contains("encoding=\"hex\""));
        assert!(xml.contains("value=\"0102ff\""));
        let parsed = parse_record(&xml).expect("parse");
        assert_eq!(parsed.attrs[&0x0100], SdpData::Text(vec![0x01, 0x02, 0xff]));
    }

    /// Test XML entity escaping in text values.
    #[test]
    fn text_xml_escaping() {
        let mut rec = SdpRecord::new(0);
        rec.attrs.insert(0x0100, SdpData::Text(b"a&b<c>d\"e".to_vec()));
        let xml = record_to_xml(&rec);
        assert!(xml.contains("a&amp;b&lt;c&gt;d&quot;e"));
        let parsed = parse_record(&xml).expect("parse");
        assert_eq!(parsed.attrs[&0x0100], SdpData::Text(b"a&b<c>d\"e".to_vec()));
    }

    /// All integer types round-trip correctly.
    #[test]
    fn round_trip_integers() {
        let mut rec = SdpRecord::new(0);
        rec.attrs.insert(0x0001, SdpData::UInt8(0xff));
        rec.attrs.insert(0x0002, SdpData::UInt16(0xabcd));
        rec.attrs.insert(0x0003, SdpData::UInt32(0xdeadbeef));
        rec.attrs.insert(0x0004, SdpData::UInt64(0x0123456789abcdef));
        rec.attrs.insert(0x0005, SdpData::Int8(-42));
        rec.attrs.insert(0x0006, SdpData::Int16(-1000));
        rec.attrs.insert(0x0007, SdpData::Int32(-100_000));
        rec.attrs.insert(0x0008, SdpData::Int64(-999_999_999_999));
        rec.attrs.insert(0x0009, SdpData::Nil);
        rec.attrs.insert(0x000a, SdpData::Url("http://example.com".into()));

        let xml = record_to_xml(&rec);
        let parsed = parse_record(&xml).expect("parse");
        assert_eq!(rec.attrs, parsed.attrs);
    }

    /// 128-bit integer round-trip.
    #[test]
    fn round_trip_128bit() {
        let bytes: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut rec = SdpRecord::new(0);
        rec.attrs.insert(0x0001, SdpData::UInt128(bytes));
        rec.attrs.insert(0x0002, SdpData::Int128(bytes));

        let xml = record_to_xml(&rec);
        let parsed = parse_record(&xml).expect("parse");
        assert_eq!(parsed.attrs[&0x0001], SdpData::UInt128(bytes));
        assert_eq!(parsed.attrs[&0x0002], SdpData::Int128(bytes));
    }

    /// Nested sequences and alternates.
    #[test]
    fn nested_containers() {
        let inner_seq = SdpData::Sequence(vec![SdpData::UInt8(1), SdpData::UInt8(2)]);
        let alt = SdpData::Alternate(vec![SdpData::UInt16(0x0001), inner_seq]);
        let mut rec = SdpRecord::new(0);
        rec.attrs.insert(0x0001, alt);

        let xml = record_to_xml(&rec);
        let parsed = parse_record(&xml).expect("parse");
        assert_eq!(rec.attrs, parsed.attrs);
    }

    /// Empty record.
    #[test]
    fn empty_record() {
        let rec = SdpRecord::new(0);
        let xml = record_to_xml(&rec);
        let parsed = parse_record(&xml).expect("parse");
        assert!(parsed.attrs.is_empty());
    }

    /// Boolean parsing edge cases.
    #[test]
    fn boolean_parsing() {
        let xml_true =
            r#"<record><attribute id="0x0001"><boolean value="true" /></attribute></record>"#;
        let xml_one =
            r#"<record><attribute id="0x0001"><boolean value="1" /></attribute></record>"#;
        let xml_false =
            r#"<record><attribute id="0x0001"><boolean value="false" /></attribute></record>"#;

        let r1 = parse_record(xml_true).unwrap();
        let r2 = parse_record(xml_one).unwrap();
        let r3 = parse_record(xml_false).unwrap();

        assert_eq!(r1.attrs[&0x0001], SdpData::Bool(true));
        assert_eq!(r2.attrs[&0x0001], SdpData::Bool(true));
        assert_eq!(r3.attrs[&0x0001], SdpData::Bool(false));
    }

    /// UUID-32 parsing.
    #[test]
    fn uuid32_parsing() {
        let xml =
            r#"<record><attribute id="0x0001"><uuid value="0x00010001" /></attribute></record>"#;
        let rec = parse_record(xml).unwrap();
        assert_eq!(rec.attrs[&0x0001], SdpData::Uuid32(0x00010001));
    }
}
