// SPDX-License-Identifier: GPL-2.0-or-later
//
//! PBAP (Phone Book Access Profile) service plugin, phonebook backends, and
//! vCard serialization.
//!
//! Consolidates the following C source files into a single Rust module:
//! - `obexd/plugins/pbap.c` — PBAP service driver + MIME drivers
//! - `obexd/plugins/phonebook.h` — Phonebook backend API contract
//! - `obexd/plugins/phonebook-dummy.c` — Dummy filesystem-based backend
//! - `obexd/plugins/phonebook-ebook.c` — Evolution Data Server backend (stubbed)
//! - `obexd/plugins/phonebook-tracker.c` — Tracker SPARQL backend (stubbed)
//! - `obexd/plugins/vcard.c` — vCard 2.1/3.0 serializer
//! - `obexd/plugins/vcard.h` — vCard types and exports

// ---------------------------------------------------------------------------
// External imports
// ---------------------------------------------------------------------------

use std::any::Any;
use std::fmt::Write as FmtWrite;
use std::sync::{Arc, Mutex, OnceLock};

use nix::errno::Errno;

// ---------------------------------------------------------------------------
// Internal imports
// ---------------------------------------------------------------------------

use super::filesystem::{StringReadState, string_read};
use super::{
    OBEX_PBAP, ObexMimeTypeDriver, ObexPluginDesc, ObexServiceDriver,
    obex_mime_type_driver_register, obex_mime_type_driver_unregister, obex_service_driver_register,
    obex_service_driver_unregister,
};
use crate::obex::apparam::ObexApparam;
use crate::obex::header::HDR_APPARAM;
use crate::obex::session::ObexSession;

// ===========================================================================
// PBAP Target UUID — 16-byte UUID identifying the PBAP service
// ===========================================================================

/// PBAP target UUID bytes — byte-identical to the C `PBAP_TARGET` array.
pub const PBAP_TARGET: [u8; 16] = [
    0x79, 0x61, 0x35, 0xF0, 0xF0, 0xC5, 0x11, 0xD8, 0x09, 0x66, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66,
];

/// Size of the PBAP target UUID in bytes.
const TARGET_SIZE: usize = 16;

// ===========================================================================
// Phonebook path constants (from phonebook.h)
// ===========================================================================

pub const PB_TELECOM_FOLDER: &str = "/telecom";
pub const PB_CONTACTS_FOLDER: &str = "/telecom/pb";
pub const PB_CALENDAR_FOLDER: &str = "/telecom/cal";
pub const PB_NOTES_FOLDER: &str = "/telecom/nt";
pub const PB_CALLS_COMBINED_FOLDER: &str = "/telecom/cch";
pub const PB_CALLS_INCOMING_FOLDER: &str = "/telecom/ich";
pub const PB_CALLS_MISSED_FOLDER: &str = "/telecom/mch";
pub const PB_CALLS_OUTGOING_FOLDER: &str = "/telecom/och";
pub const PB_CALLS_SPEEDDIAL_FOLDER: &str = "/telecom/spd";
pub const PB_CALLS_FAVORITE_FOLDER: &str = "/telecom/fav";
pub const PB_LUID_FOLDER: &str = "/telecom/pb/luid";

pub const PB_CONTACTS: &str = "/telecom/pb.vcf";
pub const PB_CALLS_COMBINED: &str = "/telecom/cch.vcf";
pub const PB_CALLS_INCOMING: &str = "/telecom/ich.vcf";
pub const PB_CALLS_MISSED: &str = "/telecom/mch.vcf";
pub const PB_CALLS_OUTGOING: &str = "/telecom/och.vcf";
pub const PB_CALLS_SPEEDDIAL: &str = "/telecom/spd.vcf";
pub const PB_CALLS_FAVORITE: &str = "/telecom/fav.vcf";
pub const PB_DEVINFO: &str = "/telecom/devinfo.txt";
pub const PB_INFO_LOG: &str = "/telecom/pb/info.log";
pub const PB_CC_LOG: &str = "/telecom/pb/luid/cc.log";

/// Invalid phonebook handle sentinel value.
pub const PHONEBOOK_INVALID_HANDLE: u32 = 0xFFFF_FFFF;

// ===========================================================================
// MIME type strings
// ===========================================================================

const PHONEBOOK_TYPE: &str = "x-bt/phonebook";
const VCARDLISTING_TYPE: &str = "x-bt/vcard-listing";
const VCARDENTRY_TYPE: &str = "x-bt/vcard";

// ===========================================================================
// Application parameter tag IDs (PBAP-specific)
// ===========================================================================

/// PBAP Application Parameter tag: Order (u8).
pub const ORDER_TAG: u8 = 0x01;
/// PBAP Application Parameter tag: SearchValue (string).
pub const SEARCHVALUE_TAG: u8 = 0x02;
/// PBAP Application Parameter tag: SearchAttribute (u8).
pub const SEARCHATTRIB_TAG: u8 = 0x03;
/// PBAP Application Parameter tag: MaxListCount (u16).
pub const MAXLISTCOUNT_TAG: u8 = 0x04;
/// PBAP Application Parameter tag: ListStartOffset (u16).
pub const LISTSTARTOFFSET_TAG: u8 = 0x05;
/// PBAP Application Parameter tag: Filter (u64).
pub const FILTER_TAG: u8 = 0x06;
/// PBAP Application Parameter tag: Format (u8).
pub const FORMAT_TAG: u8 = 0x07;
/// PBAP Application Parameter tag: PhonebookSize (u16) — response only.
pub const PHONEBOOKSIZE_TAG: u8 = 0x08;
/// PBAP Application Parameter tag: NewMissedCalls (u8) — response only.
pub const NEWMISSEDCALLS_TAG: u8 = 0x09;

// ===========================================================================
// vCard filter bitmask constants (from vcard.c)
// ===========================================================================

const FILTER_VERSION: u64 = 1 << 0;
const FILTER_FN: u64 = 1 << 1;
const FILTER_N: u64 = 1 << 2;
const FILTER_PHOTO: u64 = 1 << 3;
const FILTER_BDAY: u64 = 1 << 4;
const FILTER_ADR: u64 = 1 << 5;
const FILTER_TEL: u64 = 1 << 7;
const FILTER_EMAIL: u64 = 1 << 8;
const FILTER_ORG: u64 = 1 << 16;
const FILTER_ROLE: u64 = 1 << 13;
const FILTER_TITLE: u64 = 1 << 12;
const FILTER_URL: u64 = 1 << 20;
const FILTER_UID: u64 = 1 << 21;
const FILTER_NICKNAME: u64 = 1 << 23;
const FILTER_X_IRMC_CALL_DATETIME: u64 = 1 << 28;

// ===========================================================================
// vCard format constants
// ===========================================================================

const FORMAT_VCARD21: u8 = 0x00;
const FORMAT_VCARD30: u8 = 0x01;

// ===========================================================================
// vCard encoding constants
// ===========================================================================

const LEN_MAX: usize = 128;
const TYPE_INTERNATIONAL: i32 = 145;
const QP_LINE_LEN: usize = 75;
const QP_CHAR_LEN: usize = 3;
const QP_CR: u8 = 0x0D;
const QP_LF: u8 = 0x0A;
const QP_SOFT_LINE_BREAK: &str = "=";
const QP_SELECT: &str = "\n!\"#$=@[\\]^`{|}~";
const ASCII_LIMIT: u8 = 0x7F;
const ADDR_FIELD_AMOUNT: usize = 7;

// ===========================================================================
// XML listing templates
// ===========================================================================

const VCARD_LISTING_BEGIN: &str = "<?xml version=\"1.0\"?>\r\n\
    <!DOCTYPE vcard-listing SYSTEM \"vcard-listing.dtd\">\r\n\
    <vCard-listing version=\"1.0\">\r\n";
const VCARD_LISTING_END: &str = "</vCard-listing>";

// ===========================================================================
// vCard types (from vcard.h)
// ===========================================================================

/// Type of telephone number in a phonebook entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhonebookNumberType {
    /// Home number.
    Home,
    /// Mobile number.
    Mobile,
    /// Fax number.
    Fax,
    /// Work number.
    Work,
    /// Other / unclassified number.
    Other,
}

/// Type classification for phonebook fields (email, URL, address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhonebookFieldType {
    /// Home-type field.
    Home,
    /// Work-type field.
    Work,
    /// Other / unclassified field.
    Other,
}

/// Call history classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PhonebookCallType {
    /// Not a call record (regular contact).
    #[default]
    NotACall,
    /// Missed call.
    Missed,
    /// Incoming (received) call.
    Incoming,
    /// Outgoing (dialed) call.
    Outgoing,
}

/// Phonebook field with text and type classification.
#[derive(Debug, Clone)]
pub struct PhonebookField {
    /// Text content of the field.
    pub text: String,
    /// Field type discriminator (maps to enum variant ordinal).
    pub field_type: i32,
}

/// Phonebook address composed of up to 7 structured sub-fields.
#[derive(Debug, Clone)]
pub struct PhonebookAddr {
    /// Address sub-fields (PO Box; Extended; Street; City; Region; Postal; Country).
    pub fields: Vec<PhonebookField>,
    /// Address type discriminator.
    pub addr_type: i32,
}

/// Complete phonebook contact record.
#[derive(Debug, Clone, Default)]
pub struct PhonebookContact {
    /// Unique identifier.
    pub uid: Option<String>,
    /// Formatted full name (FN property).
    pub fullname: Option<String>,
    /// Given (first) name.
    pub given: Option<String>,
    /// Family (last) name.
    pub family: Option<String>,
    /// Additional / middle name.
    pub additional: Option<String>,
    /// Telephone numbers with type classification.
    pub numbers: Vec<PhonebookField>,
    /// Email addresses with type classification.
    pub emails: Vec<PhonebookField>,
    /// Name prefix (e.g. "Mr.", "Dr.").
    pub prefix: Option<String>,
    /// Name suffix (e.g. "Jr.", "III").
    pub suffix: Option<String>,
    /// Structured addresses.
    pub addresses: Vec<PhonebookAddr>,
    /// Birthday (ISO 8601 date string).
    pub birthday: Option<String>,
    /// Nickname.
    pub nickname: Option<String>,
    /// URLs with type classification.
    pub urls: Vec<PhonebookField>,
    /// Photo (base64 encoded or URL).
    pub photo: Option<String>,
    /// Company / organization name.
    pub company: Option<String>,
    /// Department within the organization.
    pub department: Option<String>,
    /// Organizational role.
    pub role: Option<String>,
    /// Job title.
    pub title: Option<String>,
    /// Call datetime (X-IRMC-CALL-DATETIME value).
    pub datetime: Option<String>,
    /// Call type classification (missed / incoming / outgoing).
    pub calltype: PhonebookCallType,
}

// ===========================================================================
// Application Parameters structure (from phonebook.h)
// ===========================================================================

/// PBAP application parameters parsed from OBEX APPARAM header.
#[derive(Debug, Clone)]
pub struct ApparamField {
    /// Maximum number of entries to return in a listing response.
    pub maxlistcount: u16,
    /// Starting offset for listing pagination.
    pub liststartoffset: u16,
    /// 64-bit bitmask selecting which vCard properties to include.
    pub filter: u64,
    /// vCard format: 0 = vCard 2.1, 1 = vCard 3.0.
    pub format: u8,
    /// Sort order: 0 = indexed, 1 = alphabetical, 2 = phonetical.
    pub order: u8,
    /// Search attribute: 0 = name, 1 = number, 2 = sound.
    pub searchattrib: u8,
    /// Search value string (case-insensitive substring match).
    pub searchval: Option<String>,
}

impl Default for ApparamField {
    fn default() -> Self {
        Self {
            maxlistcount: u16::MAX,
            liststartoffset: 0,
            filter: 0,
            format: FORMAT_VCARD21,
            order: 0,
            searchattrib: 0,
            searchval: None,
        }
    }
}

// ===========================================================================
// vCard serialization helpers (from vcard.c)
// ===========================================================================

/// Apply RFC 2425 line folding: lines > 75 characters are folded with
/// CRLF + space continuation.
fn vcard_printf(vcards: &mut String, line: &str) {
    let mut pos = 0;
    let bytes = line.as_bytes();
    let len = bytes.len();

    while pos < len {
        let remaining = len - pos;
        if pos == 0 {
            let chunk = remaining.min(QP_LINE_LEN);
            vcards.push_str(&line[pos..pos + chunk]);
            pos += chunk;
        } else {
            vcards.push_str("\r\n ");
            let chunk = remaining.min(QP_LINE_LEN - 1);
            vcards.push_str(&line[pos..pos + chunk]);
            pos += chunk;
        }
    }
    vcards.push_str("\r\n");
}

/// vCard 3.0 escape function: backslash-escape `\n`, `\r`, `\\`, `;`, `,`.
fn add_slash(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            _ => out.push(ch),
        }
    }
    out
}

/// vCard 2.1 escape function: backslash-escape only semicolons.
fn escape_semicolon(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        if ch == ';' {
            out.push_str("\\;");
        } else {
            out.push(ch);
        }
    }
    out
}

/// Select the appropriate escape function for the given vCard format.
fn escape_value(input: &str, format: u8) -> String {
    if format == FORMAT_VCARD30 { add_slash(input) } else { escape_semicolon(input) }
}

/// Join sub-fields with `;` separator after applying the format-specific
/// escape function.
fn get_escaped_fields(fields: &[&str], format: u8) -> String {
    fields.iter().map(|f| escape_value(f, format)).collect::<Vec<_>>().join(";")
}

/// Detect if a character requires Quoted-Printable encoding.
fn set_qp_encoding(ch: u8) -> bool {
    if ch > ASCII_LIMIT {
        return true;
    }
    QP_SELECT.as_bytes().contains(&ch)
}

/// Detect if any character in the string requires Quoted-Printable encoding
/// (vCard 2.1 only).
fn select_qp_encoding(format: u8, value: &str) -> bool {
    if format != FORMAT_VCARD21 {
        return false;
    }
    value.bytes().any(set_qp_encoding)
}

/// Emit a Quoted-Printable encoded property line for vCard 2.1.
fn vcard_qp_print_encoded(vcards: &mut String, property: &str, value: &str) {
    let header = format!("{};ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:", property);
    vcards.push_str(&header);

    let bytes = value.as_bytes();
    let header_len = header.len();
    let mut limit: usize = QP_LINE_LEN.saturating_sub(header_len);

    for &b in bytes {
        if b == QP_CR {
            continue;
        }
        if b == QP_LF {
            if limit < QP_CHAR_LEN + 1 {
                vcards.push_str(QP_SOFT_LINE_BREAK);
                vcards.push_str("\r\n ");
                limit = QP_LINE_LEN - 1;
            }
            let _ = write!(vcards, "={:02X}", b);
            limit = limit.saturating_sub(QP_CHAR_LEN);
            continue;
        }

        let needs_encoding = set_qp_encoding(b);
        if needs_encoding {
            if limit < QP_CHAR_LEN {
                vcards.push_str(QP_SOFT_LINE_BREAK);
                vcards.push_str("\r\n ");
                limit = QP_LINE_LEN - 1;
            }
            let _ = write!(vcards, "={:02X}", b);
            limit = limit.saturating_sub(QP_CHAR_LEN);
        } else {
            if limit < 1 {
                vcards.push_str(QP_SOFT_LINE_BREAK);
                vcards.push_str("\r\n ");
                limit = QP_LINE_LEN - 1;
            }
            vcards.push(b as char);
            limit = limit.saturating_sub(1);
        }
    }

    vcards.push_str("\r\n");
}

/// Emit BEGIN:VCARD and VERSION line.
fn vcard_printf_begin(vcards: &mut String, format: u8) {
    vcard_printf(vcards, "BEGIN:VCARD");
    if format == FORMAT_VCARD30 {
        vcard_printf(vcards, "VERSION:3.0");
    } else {
        vcard_printf(vcards, "VERSION:2.1");
    }
}

/// Check if any personal data fields are present in the contact.
fn contact_fields_present(contact: &PhonebookContact) -> bool {
    let has = |o: &Option<String>| o.as_ref().is_some_and(|s| !s.is_empty());
    has(&contact.family)
        || has(&contact.given)
        || has(&contact.additional)
        || has(&contact.prefix)
        || has(&contact.suffix)
}

/// Emit the N (structured name) property.
fn vcard_printf_name(vcards: &mut String, contact: &PhonebookContact, filter: u64, format: u8) {
    if filter & FILTER_N == 0 {
        return;
    }

    // Nokia BH-903 compatibility: emit bare "N:" when no personal data fields
    if !contact_fields_present(contact) {
        vcard_printf(vcards, "N:");
        return;
    }

    let family = contact.family.as_deref().unwrap_or("");
    let given = contact.given.as_deref().unwrap_or("");
    let additional = contact.additional.as_deref().unwrap_or("");
    let prefix = contact.prefix.as_deref().unwrap_or("");
    let suffix = contact.suffix.as_deref().unwrap_or("");

    let fields = [family, given, additional, prefix, suffix];
    let escaped = get_escaped_fields(&fields, format);

    if select_qp_encoding(format, &escaped) {
        vcard_qp_print_encoded(vcards, "N", &escaped);
    } else {
        let line = format!("N:{}", escaped);
        vcard_printf(vcards, &line);
    }
}

/// Emit the FN (formatted name) property.
fn vcard_printf_fullname(vcards: &mut String, contact: &PhonebookContact, filter: u64, format: u8) {
    if filter & FILTER_FN == 0 {
        return;
    }

    match contact.fullname.as_deref() {
        Some(name) if !name.is_empty() => {
            let escaped = escape_value(name, format);
            if select_qp_encoding(format, &escaped) {
                vcard_qp_print_encoded(vcards, "FN", &escaped);
            } else {
                let line = format!("FN:{}", escaped);
                vcard_printf(vcards, &line);
            }
        }
        _ => {
            vcard_printf(vcards, "FN:");
        }
    }
}

/// Map number type to version-specific TEL;TYPE= string component.
fn tel_type_str(field_type: i32, format: u8) -> &'static str {
    let ntype = match field_type {
        0 => PhonebookNumberType::Home,
        1 => PhonebookNumberType::Mobile,
        2 => PhonebookNumberType::Fax,
        3 => PhonebookNumberType::Work,
        _ => PhonebookNumberType::Other,
    };

    match (ntype, format == FORMAT_VCARD30) {
        (PhonebookNumberType::Home, false) => "HOME;VOICE",
        (PhonebookNumberType::Home, true) => "TYPE=HOME;TYPE=VOICE",
        (PhonebookNumberType::Mobile, false) => "CELL",
        (PhonebookNumberType::Mobile, true) => "TYPE=CELL",
        (PhonebookNumberType::Fax, false) => "FAX",
        (PhonebookNumberType::Fax, true) => "TYPE=FAX",
        (PhonebookNumberType::Work, false) => "WORK;VOICE",
        (PhonebookNumberType::Work, true) => "TYPE=WORK;TYPE=VOICE",
        (PhonebookNumberType::Other, false) => "VOICE",
        (PhonebookNumberType::Other, true) => "TYPE=VOICE",
    }
}

/// Emit TEL property lines for all numbers.
fn vcard_printf_number(vcards: &mut String, contact: &PhonebookContact, filter: u64, format: u8) {
    if filter & FILTER_TEL == 0 {
        return;
    }

    if contact.numbers.is_empty() {
        vcard_printf(vcards, "TEL:");
        return;
    }

    for number in &contact.numbers {
        let type_str = tel_type_str(number.field_type, format);
        let text = if number.field_type == TYPE_INTERNATIONAL && !number.text.starts_with('+') {
            format!("+{}", number.text)
        } else {
            number.text.clone()
        };
        let line = format!("TEL;{}:{}", type_str, text);
        vcard_printf(vcards, &line);
    }
}

/// Map field type to version-specific tag category for EMAIL.
fn email_category(field_type: i32, format: u8) -> &'static str {
    let ftype = match field_type {
        0 => PhonebookFieldType::Home,
        1 => PhonebookFieldType::Work,
        _ => PhonebookFieldType::Other,
    };
    match (ftype, format == FORMAT_VCARD30) {
        (PhonebookFieldType::Home, false) => "INTERNET;HOME",
        (PhonebookFieldType::Home, true) => "TYPE=INTERNET;TYPE=HOME",
        (PhonebookFieldType::Work, false) => "INTERNET;WORK",
        (PhonebookFieldType::Work, true) => "TYPE=INTERNET;TYPE=WORK",
        (PhonebookFieldType::Other, false) => "INTERNET",
        (PhonebookFieldType::Other, true) => "TYPE=INTERNET",
    }
}

/// Emit EMAIL property lines.
fn vcard_printf_email(vcards: &mut String, contact: &PhonebookContact, filter: u64, format: u8) {
    if filter & FILTER_EMAIL == 0 {
        return;
    }
    for email in &contact.emails {
        let cat = email_category(email.field_type, format);
        let escaped = escape_value(&email.text, format);
        if select_qp_encoding(format, &escaped) {
            let prop = format!("EMAIL;{}", cat);
            vcard_qp_print_encoded(vcards, &prop, &escaped);
        } else {
            let line = format!("EMAIL;{}:{}", cat, escaped);
            vcard_printf(vcards, &line);
        }
    }
}

/// Map field type to version-specific tag category for URL.
fn url_category(field_type: i32, format: u8) -> &'static str {
    let ftype = match field_type {
        0 => PhonebookFieldType::Home,
        1 => PhonebookFieldType::Work,
        _ => PhonebookFieldType::Other,
    };
    match (ftype, format == FORMAT_VCARD30) {
        (PhonebookFieldType::Home, false) => "INTERNET;HOME",
        (PhonebookFieldType::Home, true) => "TYPE=INTERNET;TYPE=HOME",
        (PhonebookFieldType::Work, false) => "INTERNET;WORK",
        (PhonebookFieldType::Work, true) => "TYPE=INTERNET;TYPE=WORK",
        (PhonebookFieldType::Other, false) => "INTERNET",
        (PhonebookFieldType::Other, true) => "TYPE=INTERNET",
    }
}

/// Emit URL property lines.
fn vcard_printf_url(vcards: &mut String, contact: &PhonebookContact, filter: u64, format: u8) {
    if filter & FILTER_URL == 0 {
        return;
    }
    for url in &contact.urls {
        let cat = url_category(url.field_type, format);
        let line = format!("URL;{}:{}", cat, url.text);
        vcard_printf(vcards, &line);
    }
}

/// Map address type to version-specific ADR qualifier.
fn adr_category(addr_type: i32, format: u8) -> &'static str {
    let ftype = match addr_type {
        0 => PhonebookFieldType::Home,
        1 => PhonebookFieldType::Work,
        _ => PhonebookFieldType::Other,
    };
    match (ftype, format == FORMAT_VCARD30) {
        (PhonebookFieldType::Home, false) => "HOME",
        (PhonebookFieldType::Home, true) => "TYPE=HOME",
        (PhonebookFieldType::Work, false) => "WORK",
        (PhonebookFieldType::Work, true) => "TYPE=WORK",
        (PhonebookFieldType::Other, false) => "",
        (PhonebookFieldType::Other, true) => "",
    }
}

/// Emit ADR property lines with up to 7 structured sub-fields.
fn vcard_printf_address(vcards: &mut String, contact: &PhonebookContact, filter: u64, format: u8) {
    if filter & FILTER_ADR == 0 {
        return;
    }
    for addr in &contact.addresses {
        let cat = adr_category(addr.addr_type, format);
        let mut parts: Vec<String> = Vec::with_capacity(ADDR_FIELD_AMOUNT);
        for i in 0..ADDR_FIELD_AMOUNT {
            let val = addr.fields.get(i).map(|f| escape_value(&f.text, format)).unwrap_or_default();
            parts.push(val);
        }
        let joined = parts.join(";");

        if cat.is_empty() {
            let line = format!("ADR:{}", joined);
            vcard_printf(vcards, &line);
        } else {
            let line = format!("ADR;{}:{}", cat, joined);
            vcard_printf(vcards, &line);
        }
    }
}

/// Emit ORG property: `ORG:company;department`.
fn vcard_printf_org(vcards: &mut String, contact: &PhonebookContact, filter: u64, format: u8) {
    if filter & FILTER_ORG == 0 {
        return;
    }
    let company = contact.company.as_deref().unwrap_or("");
    let department = contact.department.as_deref().unwrap_or("");

    if company.is_empty() && department.is_empty() {
        return;
    }

    let c_esc = escape_value(company, format);
    let d_esc = escape_value(department, format);
    let combined = format!("{};{}", c_esc, d_esc);

    if select_qp_encoding(format, &combined) {
        vcard_qp_print_encoded(vcards, "ORG", &combined);
    } else {
        let line = format!("ORG:{}", combined);
        vcard_printf(vcards, &line);
    }
}

/// Emit a generic tag with optional category and QP support.
fn vcard_printf_tag(vcards: &mut String, tag: &str, category: &str, value: &str, format: u8) {
    if value.is_empty() {
        return;
    }
    let escaped = escape_value(value, format);
    let prop = if category.is_empty() { tag.to_string() } else { format!("{};{}", tag, category) };

    if select_qp_encoding(format, &escaped) {
        vcard_qp_print_encoded(vcards, &prop, &escaped);
    } else {
        let line = format!("{}:{}", prop, escaped);
        vcard_printf(vcards, &line);
    }
}

/// Emit X-IRMC-CALL-DATETIME property with the appropriate call type.
fn vcard_printf_datetime(vcards: &mut String, contact: &PhonebookContact) {
    let datetime = match contact.datetime.as_deref() {
        Some(dt) if !dt.is_empty() => dt,
        _ => return,
    };

    let call_type_str = match contact.calltype {
        PhonebookCallType::Missed => "MISSED",
        PhonebookCallType::Incoming => "RECEIVED",
        PhonebookCallType::Outgoing => "DIALED",
        PhonebookCallType::NotACall => return,
    };

    let line = format!("X-IRMC-CALL-DATETIME;{}:{}", call_type_str, datetime);
    vcard_printf(vcards, &line);
}

// ===========================================================================
// Main vCard serialization entry point
// ===========================================================================

/// Append a vCard representation of the given contact to the `vcards` buffer.
///
/// `filter` selects which properties to include (0 = all defaults).
/// `format` selects vCard 2.1 (`0x00`) or vCard 3.0 (`0x01`).
pub fn phonebook_add_contact(
    vcards: &mut String,
    contact: &PhonebookContact,
    filter: u64,
    format: u8,
) {
    // Normalize filter: force mandatory properties when any bits are set
    let filter = if filter != 0 {
        let mandatory = if format == FORMAT_VCARD30 {
            FILTER_VERSION | FILTER_FN | FILTER_N | FILTER_TEL
        } else {
            FILTER_VERSION | FILTER_N | FILTER_TEL
        };
        filter | mandatory
    } else {
        FILTER_VERSION
            | FILTER_FN
            | FILTER_N
            | FILTER_TEL
            | FILTER_EMAIL
            | FILTER_ADR
            | FILTER_BDAY
            | FILTER_NICKNAME
            | FILTER_URL
            | FILTER_PHOTO
            | FILTER_ORG
            | FILTER_ROLE
            | FILTER_TITLE
            | FILTER_UID
            | FILTER_X_IRMC_CALL_DATETIME
    };

    vcard_printf_begin(vcards, format);

    // UID
    if filter & FILTER_UID != 0 {
        if let Some(uid) = contact.uid.as_deref() {
            if !uid.is_empty() {
                vcard_printf_tag(vcards, "UID", "", uid, format);
            }
        }
    }

    vcard_printf_name(vcards, contact, filter, format);
    vcard_printf_fullname(vcards, contact, filter, format);
    vcard_printf_number(vcards, contact, filter, format);
    vcard_printf_email(vcards, contact, filter, format);
    vcard_printf_address(vcards, contact, filter, format);

    if filter & FILTER_BDAY != 0 {
        if let Some(bday) = contact.birthday.as_deref() {
            if !bday.is_empty() {
                vcard_printf_tag(vcards, "BDAY", "", bday, format);
            }
        }
    }

    if filter & FILTER_NICKNAME != 0 {
        if let Some(nick) = contact.nickname.as_deref() {
            if !nick.is_empty() {
                vcard_printf_tag(vcards, "NICKNAME", "", nick, format);
            }
        }
    }

    vcard_printf_url(vcards, contact, filter, format);

    if filter & FILTER_PHOTO != 0 {
        if let Some(photo) = contact.photo.as_deref() {
            if !photo.is_empty() {
                vcard_printf_tag(vcards, "PHOTO", "", photo, format);
            }
        }
    }

    vcard_printf_org(vcards, contact, filter, format);

    if filter & FILTER_ROLE != 0 {
        if let Some(role) = contact.role.as_deref() {
            if !role.is_empty() {
                vcard_printf_tag(vcards, "ROLE", "", role, format);
            }
        }
    }

    if filter & FILTER_TITLE != 0 {
        if let Some(title) = contact.title.as_deref() {
            if !title.is_empty() {
                vcard_printf_tag(vcards, "TITLE", "", title, format);
            }
        }
    }

    if filter & FILTER_X_IRMC_CALL_DATETIME != 0 {
        vcard_printf_datetime(vcards, contact);
    }

    vcard_printf(vcards, "END:VCARD");
}

// ===========================================================================
// Phonebook backend callback types (from phonebook.h)
// ===========================================================================

/// Callback invoked when phonebook data is available from pull or get_entry.
///
/// Parameters: (buffer, bufsize, vcards_count, missed_count, is_last_part)
pub type PhonebookCb = Box<dyn Fn(&str, usize, i32, i32, bool) + Send + 'static>;

/// Callback invoked for each cache entry during create_cache.
///
/// Parameters: (id, handle, name, sound, tel)
pub type PhonebookEntryCb = Box<dyn Fn(&str, u32, &str, &str, &str) + Send + 'static>;

/// Callback invoked when cache creation is complete.
pub type PhonebookCacheReadyCb = Box<dyn Fn() + Send + 'static>;

// ===========================================================================
// Phonebook backend trait (from phonebook.h)
// ===========================================================================

/// Abstraction over phonebook data sources (dummy filesystem, EDS, Tracker).
pub trait PhonebookBackend: Send + Sync {
    /// Initialize the backend.
    fn init(&self) -> Result<(), i32>;

    /// Clean up the backend.
    fn exit(&self);

    /// Navigate the phonebook folder hierarchy.
    fn set_folder(&self, current_folder: &str, new_folder: &str, flags: u8) -> Result<String, i32>;

    /// Pull phonebook data (full .vcf download).
    fn pull(
        &self,
        name: &str,
        params: &ApparamField,
        cb: PhonebookCb,
    ) -> Result<Box<dyn Any + Send>, i32>;

    /// Trigger reading of a previously initiated pull request.
    fn pull_read(&self, request: &mut dyn Any) -> Result<(), i32>;

    /// Retrieve a single vCard entry by ID.
    fn get_entry(
        &self,
        folder: &str,
        id: &str,
        params: &ApparamField,
        cb: PhonebookCb,
    ) -> Result<Box<dyn Any + Send>, i32>;

    /// Build the contact cache for listing operations.
    fn create_cache(
        &self,
        name: &str,
        entry_cb: PhonebookEntryCb,
        ready_cb: PhonebookCacheReadyCb,
    ) -> Result<Box<dyn Any + Send>, i32>;

    /// Finalize and clean up a backend request.
    fn req_finalize(&self, request: Box<dyn Any>);
}

// ===========================================================================
// Dummy phonebook backend (from phonebook-dummy.c)
// ===========================================================================

/// Filesystem-based phonebook backend that reads vCard files from
/// `$HOME/phonebook/`.
struct DummyPhonebookBackend {
    root_folder: Mutex<String>,
}

/// Request state for the dummy backend.
struct DummyRequest {
    folder: String,
    params: ApparamField,
    callback: Option<PhonebookCb>,
    completed: bool,
}

impl DummyPhonebookBackend {
    fn new() -> Self {
        Self { root_folder: Mutex::new(String::new()) }
    }

    /// Build the full filesystem path from the phonebook virtual path.
    fn build_path(&self, virtual_path: &str) -> std::path::PathBuf {
        let root = self.root_folder.lock().unwrap_or_else(|e| e.into_inner());
        let mut path = std::path::PathBuf::from(root.as_str());
        let trimmed = virtual_path.trim_start_matches('/');
        let trimmed = trimmed.strip_suffix(".vcf").unwrap_or(trimmed);
        if !trimmed.is_empty() {
            path.push(trimmed);
        }
        path
    }

    /// Read all vCard files from a directory and concatenate them.
    fn read_vcards_from_dir(
        &self,
        dir_path: &std::path::Path,
        params: &ApparamField,
    ) -> (String, i32) {
        let entries = match std::fs::read_dir(dir_path) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::error!("Failed to read directory {:?}: {}", dir_path, e);
                return (String::new(), 0);
            }
        };

        let mut files: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext == "vcf"))
            .collect();

        files.sort();

        let mut vcards = String::new();
        let mut count: i32 = 0;

        for file_path in &files {
            match std::fs::read_to_string(file_path) {
                Ok(content) => {
                    if (count as u16) < params.liststartoffset {
                        count += 1;
                        continue;
                    }
                    if params.maxlistcount != 0
                        && (count as u16).saturating_sub(params.liststartoffset)
                            >= params.maxlistcount
                    {
                        break;
                    }
                    vcards.push_str(&content);
                    count += 1;
                }
                Err(e) => {
                    tracing::warn!("Failed to read vCard file {:?}: {}", file_path, e);
                }
            }
        }

        (vcards, count)
    }

    /// Parse a vCard file to extract the N: and TEL: fields for cache entries.
    fn parse_vcard_for_cache(content: &str) -> (String, String) {
        let mut name = String::new();
        let mut tel = String::new();

        for line in content.lines() {
            let line = line.trim();
            if let Some(n_val) = line.strip_prefix("N:") {
                name = n_val.split(';').next().unwrap_or("").to_string();
            } else if let Some(t_val) = line.strip_prefix("TEL") {
                if let Some(colon_pos) = t_val.find(':') {
                    tel = t_val[colon_pos + 1..].to_string();
                }
            }
        }

        (name, tel)
    }
}

impl PhonebookBackend for DummyPhonebookBackend {
    fn init(&self) -> Result<(), i32> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let root = format!("{}/phonebook/", home);
        let mut lock = self.root_folder.lock().unwrap_or_else(|e| e.into_inner());
        *lock = root;
        tracing::debug!("Dummy phonebook backend initialized");
        Ok(())
    }

    fn exit(&self) {
        tracing::debug!("Dummy phonebook backend exited");
    }

    fn set_folder(&self, current_folder: &str, new_folder: &str, flags: u8) -> Result<String, i32> {
        match flags {
            0x02 => {
                if new_folder.is_empty() {
                    Ok("/".to_string())
                } else {
                    let new_path = if current_folder == "/" {
                        format!("/{}", new_folder)
                    } else {
                        format!("{}/{}", current_folder, new_folder)
                    };

                    let known_folders = [
                        PB_TELECOM_FOLDER,
                        PB_CONTACTS_FOLDER,
                        PB_CALENDAR_FOLDER,
                        PB_NOTES_FOLDER,
                        PB_CALLS_COMBINED_FOLDER,
                        PB_CALLS_INCOMING_FOLDER,
                        PB_CALLS_MISSED_FOLDER,
                        PB_CALLS_OUTGOING_FOLDER,
                        PB_CALLS_SPEEDDIAL_FOLDER,
                        PB_CALLS_FAVORITE_FOLDER,
                        PB_LUID_FOLDER,
                    ];

                    if known_folders.contains(&new_path.as_str()) {
                        Ok(new_path)
                    } else {
                        tracing::warn!("Invalid phonebook folder: {}", new_path);
                        Err(-(Errno::ENOENT as i32))
                    }
                }
            }
            0x03 => {
                if current_folder == "/" {
                    return Err(-(Errno::ENOENT as i32));
                }
                match current_folder.rfind('/') {
                    Some(0) => Ok("/".to_string()),
                    Some(pos) => Ok(current_folder[..pos].to_string()),
                    None => Ok("/".to_string()),
                }
            }
            _ => {
                tracing::error!("Invalid set_folder flags: {:#x}", flags);
                Err(-(Errno::EBADR as i32))
            }
        }
    }

    fn pull(
        &self,
        name: &str,
        params: &ApparamField,
        cb: PhonebookCb,
    ) -> Result<Box<dyn Any + Send>, i32> {
        let request = DummyRequest {
            folder: name.to_string(),
            params: params.clone(),
            callback: Some(cb),
            completed: false,
        };
        Ok(Box::new(request))
    }

    fn pull_read(&self, request: &mut dyn Any) -> Result<(), i32> {
        let req = match request.downcast_mut::<DummyRequest>() {
            Some(r) => r,
            None => return Err(-(Errno::EBADR as i32)),
        };

        if req.completed {
            return Ok(());
        }

        let dir_path = self.build_path(&req.folder);
        let (vcards, count) = self.read_vcards_from_dir(&dir_path, &req.params);

        if let Some(cb) = req.callback.take() {
            cb(&vcards, vcards.len(), count, 0, true);
        }
        req.completed = true;
        Ok(())
    }

    fn get_entry(
        &self,
        folder: &str,
        id: &str,
        params: &ApparamField,
        cb: PhonebookCb,
    ) -> Result<Box<dyn Any + Send>, i32> {
        let mut path = self.build_path(folder);
        path.push(format!("{}.vcf", id));

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => {
                tracing::warn!("vCard entry not found: {:?}", path);
                cb("", 0, 0, 0, true);
                return Ok(Box::new(DummyRequest {
                    folder: folder.to_string(),
                    params: params.clone(),
                    callback: None,
                    completed: true,
                }));
            }
        };

        cb(&content, content.len(), 1, 0, true);
        Ok(Box::new(DummyRequest {
            folder: folder.to_string(),
            params: params.clone(),
            callback: None,
            completed: true,
        }))
    }

    fn create_cache(
        &self,
        name: &str,
        entry_cb: PhonebookEntryCb,
        ready_cb: PhonebookCacheReadyCb,
    ) -> Result<Box<dyn Any + Send>, i32> {
        let dir_path = self.build_path(name);
        let entries = match std::fs::read_dir(&dir_path) {
            Ok(e) => e,
            Err(_) => {
                tracing::debug!("No phonebook directory at {:?}", dir_path);
                ready_cb();
                return Ok(Box::new(()));
            }
        };

        let mut files: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext == "vcf"))
            .collect();

        files.sort();

        for (idx, file_path) in files.iter().enumerate() {
            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let id = file_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let (fname, tel) = Self::parse_vcard_for_cache(&content);

            entry_cb(id, idx as u32, &fname, "", &tel);
        }

        ready_cb();
        Ok(Box::new(()))
    }

    fn req_finalize(&self, _request: Box<dyn Any>) {
        // DummyRequest dropped automatically
    }
}

// ===========================================================================
// Global phonebook backend instance
// ===========================================================================

static PHONEBOOK_BACKEND: OnceLock<Box<dyn PhonebookBackend>> = OnceLock::new();

fn get_backend() -> &'static dyn PhonebookBackend {
    PHONEBOOK_BACKEND.get().expect("phonebook backend not initialized").as_ref()
}

fn phonebook_init() -> Result<(), i32> {
    let backend = Box::new(DummyPhonebookBackend::new());
    backend.init()?;
    let _ = PHONEBOOK_BACKEND.set(backend);
    Ok(())
}

fn phonebook_exit() {
    if let Some(backend) = PHONEBOOK_BACKEND.get() {
        backend.exit();
    }
}

// ===========================================================================
// PBAP session and object state
// ===========================================================================

/// Single entry in the contact listing cache.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Unique identifier string from the backend.
    id: String,
    /// Numeric handle (auto-assigned if backend returns PHONEBOOK_INVALID_HANDLE).
    handle: u32,
    /// Display name (from vCard N: field).
    name: String,
    /// Phonetic representation (from vCard SOUND: field).
    sound: String,
    /// Primary telephone number.
    tel: String,
}

/// Contact listing cache with validity flag.
#[derive(Debug, Clone, Default)]
struct ContactCache {
    /// Whether the cache contents are current.
    valid: bool,
    /// Cached entries for listing.
    entries: Vec<CacheEntry>,
}

/// Per-session PBAP state, stored as `Box<dyn Any + Send>` in the OBEX core.
struct PbapSession {
    /// Current navigated folder path (default "/").
    folder: Mutex<String>,
    /// Parsed application parameters from the last GET request.
    params: Mutex<Option<ApparamField>>,
    /// Contact listing cache (shared between service driver and MIME drivers).
    cache: Mutex<ContactCache>,
    /// Handle counter for locating entries.
    find_handle: Mutex<u32>,
}

impl PbapSession {
    fn new() -> Self {
        Self {
            folder: Mutex::new("/".to_string()),
            params: Mutex::new(None),
            cache: Mutex::new(ContactCache::default()),
            find_handle: Mutex::new(PHONEBOOK_INVALID_HANDLE),
        }
    }
}

/// Per-object state for MIME type driver operations.
struct PbapObject {
    /// String buffer containing vCard/XML data to serve.
    buffer: StringReadState,
    /// Outgoing APPARAM response data.
    apparam: Option<ObexApparam>,
    /// Whether this is the first packet (emit APPARAM header).
    firstpacket: bool,
    /// Whether the last chunk of data has been received from the backend.
    lastpart: bool,
    /// Backend request handle for cleanup.
    request: Option<Box<dyn Any + Send>>,
    /// The max list count from the request (for size-only queries).
    maxlistcount: u16,
    /// Snapshot of the cache for generating listing response.
    cache_snapshot: Option<Vec<CacheEntry>>,
    /// Cached params snapshot for listing generation.
    params_snapshot: Option<ApparamField>,
}

impl PbapObject {
    fn new() -> Self {
        Self {
            buffer: StringReadState::new(String::new()),
            apparam: None,
            firstpacket: true,
            lastpart: false,
            request: None,
            maxlistcount: u16::MAX,
            cache_snapshot: None,
            params_snapshot: None,
        }
    }
}

// ===========================================================================
// APPARAM parsing
// ===========================================================================

/// Parse OBEX application parameters into an `ApparamField`.
///
/// Decodes a raw APPARAM byte buffer (from OBEX header 0x4C) into typed fields
/// using the PBAP-specific tag IDs defined in this module. Called from the OBEX
/// service layer when processing PBAP GET requests.
pub fn parse_apparam(data: &[u8]) -> ApparamField {
    let mut params = ApparamField::default();

    let apparam = match ObexApparam::decode(data) {
        Ok(a) => a,
        Err(_) => {
            tracing::warn!("Failed to decode APPARAM data");
            return params;
        }
    };

    if let Some(v) = apparam.get_u8(ORDER_TAG) {
        params.order = v;
    }
    if let Some(v) = apparam.get_u8(SEARCHATTRIB_TAG) {
        params.searchattrib = v;
    }
    if let Some(v) = apparam.get_u8(FORMAT_TAG) {
        params.format = v;
    }
    if let Some(v) = apparam.get_u16(MAXLISTCOUNT_TAG) {
        params.maxlistcount = v;
    }
    if let Some(v) = apparam.get_u16(LISTSTARTOFFSET_TAG) {
        params.liststartoffset = v;
    }
    if let Some(v) = apparam.get_u64(FILTER_TAG) {
        params.filter = v;
    }
    if let Some(v) = apparam.get_string(SEARCHVALUE_TAG) {
        params.searchval = Some(v);
    }

    params
}

// ===========================================================================
// XML escape for listing elements
// ===========================================================================

/// Escape XML special characters for vCard listing element values.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

// ===========================================================================
// Listing generation (generate_response from pbap.c)
// ===========================================================================

/// Generate the XML vCard listing response from the cache, applying
/// ORDER sorting, SEARCHATTRIB/SEARCHVALUE filtering, and pagination.
fn generate_response(entries: &[CacheEntry], params: &ApparamField) -> (String, u16) {
    let mut filtered: Vec<&CacheEntry> = entries.iter().collect();

    // Apply SEARCHATTRIB/SEARCHVALUE filtering
    if let Some(ref search_val) = params.searchval {
        if !search_val.is_empty() {
            let sv_lower = search_val.to_lowercase();
            filtered.retain(|e| {
                match params.searchattrib {
                    0 => e.name.to_lowercase().contains(&sv_lower), // name
                    1 => e.tel.to_lowercase().contains(&sv_lower),  // number
                    2 => e.sound.to_lowercase().contains(&sv_lower), // sound
                    _ => true,
                }
            });
        }
    }

    // Apply ORDER sorting
    match params.order {
        0 => filtered.sort_by_key(|e| e.handle), // indexed
        1 => filtered.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())), // alpha
        2 => {
            // phonetical: sort by sound, fallback to handle
            filtered.sort_by(|a, b| {
                if a.sound.is_empty() && b.sound.is_empty() {
                    a.handle.cmp(&b.handle)
                } else if a.sound.is_empty() {
                    std::cmp::Ordering::Greater
                } else if b.sound.is_empty() {
                    std::cmp::Ordering::Less
                } else {
                    a.sound.to_lowercase().cmp(&b.sound.to_lowercase())
                }
            });
        }
        _ => {} // unknown order, keep original
    }

    let total_count = filtered.len() as u16;

    // Apply LISTSTARTOFFSET paging
    let offset = params.liststartoffset as usize;
    if offset >= filtered.len() {
        return (format!("{}{}", VCARD_LISTING_BEGIN, VCARD_LISTING_END), total_count);
    }
    let filtered = &filtered[offset..];

    // Apply MAXLISTCOUNT limit
    let limit = if params.maxlistcount == 0 { 0usize } else { params.maxlistcount as usize };

    let filtered = if limit > 0 && limit < filtered.len() { &filtered[..limit] } else { filtered };

    // Build XML listing
    let mut xml = String::with_capacity(256 + filtered.len() * LEN_MAX);
    xml.push_str(VCARD_LISTING_BEGIN);

    for entry in filtered {
        let escaped_name = xml_escape(&entry.name);
        let _ = write!(
            xml,
            "<card handle = \"{}.vcf\" name = \"{}\"/>\r\n",
            entry.handle, escaped_name
        );
    }

    xml.push_str(VCARD_LISTING_END);

    (xml, total_count)
}

// ===========================================================================
// PBAP Service Driver
// ===========================================================================

/// PBAP service driver implementing the `ObexServiceDriver` trait.
struct PbapServiceDriver;

impl ObexServiceDriver for PbapServiceDriver {
    fn name(&self) -> &str {
        "Phonebook Access server"
    }

    fn service(&self) -> u16 {
        OBEX_PBAP
    }

    fn channel(&self) -> u8 {
        19
    }

    fn secure(&self) -> bool {
        true
    }

    fn record(&self) -> Option<&str> {
        None
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&PBAP_TARGET)
    }

    fn target_size(&self) -> usize {
        TARGET_SIZE
    }

    fn who(&self) -> Option<&[u8]> {
        None
    }

    fn who_size(&self) -> usize {
        0
    }

    fn connect(&self, _os: &ObexSession) -> Result<Box<dyn Any + Send>, i32> {
        tracing::debug!("PBAP service connected");
        let session = PbapSession::new();
        Ok(Box::new(session))
    }

    fn disconnect(&self, _os: &ObexSession, user_data: &mut dyn Any) {
        tracing::debug!("PBAP service disconnected");
        if let Some(session) = user_data.downcast_ref::<PbapSession>() {
            let mut params = session.params.lock().unwrap_or_else(|e| e.into_inner());
            *params = None;
            let mut cache = session.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.valid = false;
            cache.entries.clear();
        }
    }

    fn get(&self, _os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        // The actual GET logic is handled by the MIME type drivers.
        // The service driver's get() is called to validate the request.
        let _session = user_data.downcast_ref::<PbapSession>().ok_or(-(Errno::EBADR as i32))?;
        tracing::debug!("PBAP GET request");
        Ok(())
    }

    fn put(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        // PBAP is read-only
        Err(-(Errno::EBADR as i32))
    }

    fn chkput(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        // PBAP is read-only — always reject PUT
        Err(-(Errno::EBADR as i32))
    }

    fn setpath(&self, _os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        let session = user_data.downcast_ref::<PbapSession>().ok_or(-(Errno::EBADR as i32))?;

        // Default flags for setpath: navigate into child (0x02)
        // The actual nonhdr data parsing would come from the OBEX layer
        let folder = session.folder.lock().unwrap_or_else(|e| e.into_inner());
        let current = folder.clone();
        drop(folder);

        tracing::debug!("PBAP setpath from '{}'", current);

        // Clear cache on folder navigation
        let mut cache = session.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.valid = false;
        cache.entries.clear();

        Ok(())
    }

    fn action(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn progress(&self, _os: &ObexSession, _user_data: &mut dyn Any) {}

    fn reset(&self, _os: &ObexSession, _user_data: &mut dyn Any) {}
}

// ===========================================================================
// PBAP Pull MIME Type Driver ("x-bt/phonebook")
// ===========================================================================

/// MIME driver for `x-bt/phonebook` — serves full phonebook downloads.
struct PbapPullMimeDriver;

impl ObexMimeTypeDriver for PbapPullMimeDriver {
    fn mimetype(&self) -> Option<&str> {
        Some(PHONEBOOK_TYPE)
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&PBAP_TARGET)
    }

    fn target_size(&self) -> usize {
        TARGET_SIZE
    }

    fn who(&self) -> Option<&[u8]> {
        None
    }

    fn who_size(&self) -> usize {
        0
    }

    fn open(
        &self,
        name: &str,
        _flags: i32,
        _mode: u32,
        context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32> {
        let session = context.downcast_ref::<PbapSession>().ok_or(-(Errno::EBADR as i32))?;

        let params = session.params.lock().unwrap_or_else(|e| e.into_inner());
        let ap = params.clone().unwrap_or_default();
        drop(params);

        let folder = session.folder.lock().unwrap_or_else(|e| e.into_inner());
        let current_folder = folder.clone();
        drop(folder);

        // Normalize path: if name starts with "/", use as-is; else prepend folder
        let pull_name = if name.starts_with('/') {
            name.to_string()
        } else if current_folder == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", current_folder, name)
        };

        let mut obj = PbapObject::new();
        obj.maxlistcount = ap.maxlistcount;

        // Determine callback based on MaxListCount
        let buffer = Arc::new(Mutex::new(String::new()));
        let phonebook_size = Arc::new(Mutex::new(0u16));
        let missed_calls = Arc::new(Mutex::new(0u8));

        let buf_clone = Arc::clone(&buffer);
        let size_clone = Arc::clone(&phonebook_size);
        let missed_clone = Arc::clone(&missed_calls);

        let cb: PhonebookCb = if ap.maxlistcount == 0 {
            // Size-only query: just record the count
            Box::new(
                move |_buf: &str, _bufsize: usize, vcards: i32, missed: i32, _lastpart: bool| {
                    let mut s = size_clone.lock().unwrap_or_else(|e| e.into_inner());
                    *s = vcards as u16;
                    let mut m = missed_clone.lock().unwrap_or_else(|e| e.into_inner());
                    *m = missed as u8;
                },
            )
        } else {
            // Normal query: accumulate vCard data
            Box::new(move |buf: &str, bufsize: usize, vcards: i32, missed: i32, _lastpart: bool| {
                let mut b = buf_clone.lock().unwrap_or_else(|e| e.into_inner());
                if bufsize > 0 {
                    b.push_str(&buf[..bufsize.min(buf.len())]);
                }
                let mut s = size_clone.lock().unwrap_or_else(|e| e.into_inner());
                *s = vcards as u16;
                let mut m = missed_clone.lock().unwrap_or_else(|e| e.into_inner());
                *m = missed as u8;
            })
        };

        let backend = get_backend();
        let mut request = backend.pull(&pull_name, &ap, cb)?;

        // Trigger the read immediately (dummy backend completes synchronously)
        backend.pull_read(request.as_mut())?;

        // Collect results
        let buf_data = buffer.lock().unwrap_or_else(|e| e.into_inner());
        obj.buffer = StringReadState { data: buf_data.clone(), offset: 0 };
        obj.lastpart = true;

        // Build APPARAM response
        let size_val = *phonebook_size.lock().unwrap_or_else(|e| e.into_inner());
        let missed_val = *missed_calls.lock().unwrap_or_else(|e| e.into_inner());

        let mut response_apparam = ObexApparam::new();
        response_apparam.set_u16(PHONEBOOKSIZE_TAG, size_val);
        response_apparam.set_u8(NEWMISSEDCALLS_TAG, missed_val);
        obj.apparam = Some(response_apparam);

        obj.request = Some(request);
        Ok(Box::new(obj))
    }

    fn close(&self, object: &mut dyn Any) -> Result<(), i32> {
        if let Some(obj) = object.downcast_mut::<PbapObject>() {
            if let Some(request) = obj.request.take() {
                get_backend().req_finalize(request);
            }
        }
        Ok(())
    }

    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<PbapObject>().ok_or(-(Errno::EBADR as i32))?;

        if obj.maxlistcount == 0 {
            // Size-only query: no body data
            return Ok(0);
        }

        if obj.buffer.data.is_empty() && !obj.lastpart {
            return Err(-(Errno::EAGAIN as i32));
        }

        string_read(&mut obj.buffer, buf)
    }

    fn write(&self, _object: &mut dyn Any, _buf: &[u8]) -> Result<usize, i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn flush(&self, _object: &mut dyn Any) -> Result<(), i32> {
        Ok(())
    }

    fn remove(&self, _name: &str) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn copy(&self, _name: &str, _dest: &str) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn rename(&self, _name: &str, _dest: &str) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn get_next_header(&self, object: &mut dyn Any) -> Option<(u8, Vec<u8>)> {
        let obj = object.downcast_mut::<PbapObject>()?;

        if !obj.firstpacket {
            return None;
        }
        obj.firstpacket = false;

        let apparam = obj.apparam.as_ref()?;
        let encoded = apparam.encode_to_vec().ok()?;
        if encoded.is_empty() {
            return None;
        }
        Some((HDR_APPARAM, encoded))
    }
}

// ===========================================================================
// PBAP vCard Listing MIME Type Driver ("x-bt/vcard-listing")
// ===========================================================================

/// MIME driver for `x-bt/vcard-listing` — serves contact listing responses.
struct PbapListMimeDriver;

impl ObexMimeTypeDriver for PbapListMimeDriver {
    fn mimetype(&self) -> Option<&str> {
        Some(VCARDLISTING_TYPE)
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&PBAP_TARGET)
    }

    fn target_size(&self) -> usize {
        TARGET_SIZE
    }

    fn who(&self) -> Option<&[u8]> {
        None
    }

    fn who_size(&self) -> usize {
        0
    }

    fn open(
        &self,
        name: &str,
        _flags: i32,
        _mode: u32,
        context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32> {
        let session = context.downcast_ref::<PbapSession>().ok_or(-(Errno::EBADR as i32))?;

        let params = session.params.lock().unwrap_or_else(|e| e.into_inner());
        let ap = params.clone().unwrap_or_default();
        drop(params);

        let folder = session.folder.lock().unwrap_or_else(|e| e.into_inner());
        let current_folder = folder.clone();
        drop(folder);

        // Build the listing target path relative to current folder
        let list_name = if name.is_empty() {
            current_folder.clone()
        } else if name.starts_with('/') {
            name.to_string()
        } else if current_folder == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", current_folder, name)
        };

        let mut obj = PbapObject::new();
        obj.maxlistcount = ap.maxlistcount;
        obj.params_snapshot = Some(ap);

        // Check if cache is already valid
        let cache = session.cache.lock().unwrap_or_else(|e| e.into_inner());
        let cache_valid = cache.valid;
        let cache_entries = cache.entries.clone();
        drop(cache);

        if cache_valid {
            // Use existing cache
            obj.cache_snapshot = Some(cache_entries);
            obj.lastpart = true;

            // Generate response immediately
            if let (Some(entries), Some(params)) = (&obj.cache_snapshot, &obj.params_snapshot) {
                if params.maxlistcount == 0 {
                    // Size-only: build apparam with total count
                    let mut response_apparam = ObexApparam::new();
                    response_apparam.set_u16(PHONEBOOKSIZE_TAG, entries.len() as u16);
                    response_apparam.set_u8(NEWMISSEDCALLS_TAG, 0);
                    obj.apparam = Some(response_apparam);
                } else {
                    let (xml, total) = generate_response(entries, params);
                    obj.buffer = StringReadState { data: xml, offset: 0 };
                    let mut response_apparam = ObexApparam::new();
                    response_apparam.set_u16(PHONEBOOKSIZE_TAG, total);
                    response_apparam.set_u8(NEWMISSEDCALLS_TAG, 0);
                    obj.apparam = Some(response_apparam);
                }
            }
        } else {
            // Build cache via backend
            let cache_ref = Arc::new(Mutex::new(Vec::<CacheEntry>::new()));
            let cache_for_entry = Arc::clone(&cache_ref);
            let cache_for_ready = Arc::clone(&cache_ref);

            let entry_cb: PhonebookEntryCb =
                Box::new(move |id: &str, handle: u32, name: &str, sound: &str, tel: &str| {
                    let mut entries = cache_for_entry.lock().unwrap_or_else(|e| e.into_inner());
                    let actual_handle = if handle == PHONEBOOK_INVALID_HANDLE {
                        entries.len() as u32
                    } else {
                        handle
                    };
                    entries.push(CacheEntry {
                        id: id.to_string(),
                        handle: actual_handle,
                        name: name.to_string(),
                        sound: sound.to_string(),
                        tel: tel.to_string(),
                    });
                });

            let ready_cb: PhonebookCacheReadyCb = Box::new(move || {
                // Signal that the cache is complete (no-op for sync backend)
                let _ = &cache_for_ready;
            });

            let backend = get_backend();
            let request = backend.create_cache(&list_name, entry_cb, ready_cb)?;
            obj.request = Some(request);

            // For the sync dummy backend, entries are already populated
            let built_entries = cache_ref.lock().unwrap_or_else(|e| e.into_inner());
            let built_vec = built_entries.clone();

            // Update the session cache
            let mut session_cache = session.cache.lock().unwrap_or_else(|e| e.into_inner());
            session_cache.valid = true;
            session_cache.entries = built_vec.clone();
            drop(session_cache);

            obj.cache_snapshot = Some(built_vec);
            obj.lastpart = true;

            // Generate response
            if let (Some(entries), Some(params)) = (&obj.cache_snapshot, &obj.params_snapshot) {
                if params.maxlistcount == 0 {
                    let mut response_apparam = ObexApparam::new();
                    response_apparam.set_u16(PHONEBOOKSIZE_TAG, entries.len() as u16);
                    response_apparam.set_u8(NEWMISSEDCALLS_TAG, 0);
                    obj.apparam = Some(response_apparam);
                } else {
                    let (xml, total) = generate_response(entries, params);
                    obj.buffer = StringReadState { data: xml, offset: 0 };
                    let mut response_apparam = ObexApparam::new();
                    response_apparam.set_u16(PHONEBOOKSIZE_TAG, total);
                    response_apparam.set_u8(NEWMISSEDCALLS_TAG, 0);
                    obj.apparam = Some(response_apparam);
                }
            }
        }

        Ok(Box::new(obj))
    }

    fn close(&self, object: &mut dyn Any) -> Result<(), i32> {
        if let Some(obj) = object.downcast_mut::<PbapObject>() {
            if let Some(request) = obj.request.take() {
                get_backend().req_finalize(request);
            }
        }
        Ok(())
    }

    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<PbapObject>().ok_or(-(Errno::EBADR as i32))?;

        if obj.maxlistcount == 0 {
            // Size-only query: no body data to return
            return Ok(0);
        }

        if obj.buffer.data.is_empty() && !obj.lastpart {
            return Err(-(Errno::EAGAIN as i32));
        }

        string_read(&mut obj.buffer, buf)
    }

    fn write(&self, _object: &mut dyn Any, _buf: &[u8]) -> Result<usize, i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn flush(&self, _object: &mut dyn Any) -> Result<(), i32> {
        Ok(())
    }

    fn remove(&self, _name: &str) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn copy(&self, _name: &str, _dest: &str) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn rename(&self, _name: &str, _dest: &str) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn get_next_header(&self, object: &mut dyn Any) -> Option<(u8, Vec<u8>)> {
        let obj = object.downcast_mut::<PbapObject>()?;

        if !obj.firstpacket {
            return None;
        }
        obj.firstpacket = false;

        // Wait for cache to be valid before emitting header
        if !obj.lastpart {
            return None;
        }

        let apparam = obj.apparam.as_ref()?;
        let encoded = apparam.encode_to_vec().ok()?;
        if encoded.is_empty() {
            return None;
        }
        Some((HDR_APPARAM, encoded))
    }
}

// ===========================================================================
// PBAP vCard Entry MIME Type Driver ("x-bt/vcard")
// ===========================================================================

/// MIME driver for `x-bt/vcard` — serves individual vCard entries.
struct PbapVcardMimeDriver;

impl ObexMimeTypeDriver for PbapVcardMimeDriver {
    fn mimetype(&self) -> Option<&str> {
        Some(VCARDENTRY_TYPE)
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&PBAP_TARGET)
    }

    fn target_size(&self) -> usize {
        TARGET_SIZE
    }

    fn who(&self) -> Option<&[u8]> {
        None
    }

    fn who_size(&self) -> usize {
        0
    }

    fn open(
        &self,
        name: &str,
        _flags: i32,
        _mode: u32,
        context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32> {
        let session = context.downcast_ref::<PbapSession>().ok_or(-(Errno::EBADR as i32))?;

        let params = session.params.lock().unwrap_or_else(|e| e.into_inner());
        let ap = params.clone().unwrap_or_default();
        drop(params);

        let folder = session.folder.lock().unwrap_or_else(|e| e.into_inner());
        let current_folder = folder.clone();
        drop(folder);

        // Parse handle from "N.vcf" format
        let handle_str = name.strip_suffix(".vcf").unwrap_or(name);

        let mut obj = PbapObject::new();
        obj.maxlistcount = ap.maxlistcount;

        // Check cache for the entry and update find_handle
        let cache = session.cache.lock().unwrap_or_else(|e| e.into_inner());
        let cache_valid = cache.valid;
        let entry_id = if cache_valid {
            if let Ok(handle) = handle_str.parse::<u32>() {
                let mut fh = session.find_handle.lock().unwrap_or_else(|e| e.into_inner());
                *fh = handle;
                cache.entries.iter().find(|e| e.handle == handle).map(|e| e.id.clone())
            } else {
                // Try finding by ID directly
                cache.entries.iter().find(|e| e.id == handle_str).map(|e| e.id.clone())
            }
        } else {
            Some(handle_str.to_string())
        };
        drop(cache);

        let id = entry_id.unwrap_or_else(|| handle_str.to_string());

        // Retrieve the entry from the backend
        let buffer = Arc::new(Mutex::new(String::new()));
        let buf_clone = Arc::clone(&buffer);

        let cb: PhonebookCb = Box::new(
            move |buf: &str, bufsize: usize, _vcards: i32, _missed: i32, _lastpart: bool| {
                let mut b = buf_clone.lock().unwrap_or_else(|e| e.into_inner());
                if bufsize > 0 {
                    b.push_str(&buf[..bufsize.min(buf.len())]);
                }
            },
        );

        let backend = get_backend();
        let request = backend.get_entry(&current_folder, &id, &ap, cb)?;

        let buf_data = buffer.lock().unwrap_or_else(|e| e.into_inner());
        obj.buffer = StringReadState { data: buf_data.clone(), offset: 0 };
        obj.lastpart = true;
        obj.request = Some(request);

        Ok(Box::new(obj))
    }

    fn close(&self, object: &mut dyn Any) -> Result<(), i32> {
        if let Some(obj) = object.downcast_mut::<PbapObject>() {
            if let Some(request) = obj.request.take() {
                get_backend().req_finalize(request);
            }
        }
        Ok(())
    }

    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<PbapObject>().ok_or(-(Errno::EBADR as i32))?;

        if obj.buffer.data.is_empty() && !obj.lastpart {
            return Err(-(Errno::EAGAIN as i32));
        }

        string_read(&mut obj.buffer, buf)
    }

    fn write(&self, _object: &mut dyn Any, _buf: &[u8]) -> Result<usize, i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn flush(&self, _object: &mut dyn Any) -> Result<(), i32> {
        Ok(())
    }

    fn remove(&self, _name: &str) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn copy(&self, _name: &str, _dest: &str) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn rename(&self, _name: &str, _dest: &str) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }

    fn get_next_header(&self, _object: &mut dyn Any) -> Option<(u8, Vec<u8>)> {
        // vCard entries do not emit APPARAM headers
        None
    }
}

// ===========================================================================
// Plugin registration
// ===========================================================================

/// Initialize the PBAP plugin: register service driver and MIME type drivers.
fn pbap_init() -> Result<(), i32> {
    phonebook_init()?;

    obex_mime_type_driver_register(Arc::new(PbapPullMimeDriver))?;
    obex_mime_type_driver_register(Arc::new(PbapListMimeDriver))?;
    obex_mime_type_driver_register(Arc::new(PbapVcardMimeDriver))?;

    obex_service_driver_register(Arc::new(PbapServiceDriver))?;

    tracing::info!("PBAP plugin initialized");
    Ok(())
}

/// Shut down the PBAP plugin: unregister all drivers.
fn pbap_exit() {
    obex_service_driver_unregister(&PbapServiceDriver);

    obex_mime_type_driver_unregister(&PbapVcardMimeDriver);
    obex_mime_type_driver_unregister(&PbapListMimeDriver);
    obex_mime_type_driver_unregister(&PbapPullMimeDriver);

    phonebook_exit();

    tracing::info!("PBAP plugin exited");
}

// Register the PBAP plugin via inventory for runtime discovery.
inventory::submit! {
    ObexPluginDesc {
        name: "pbap",
        init: pbap_init,
        exit: pbap_exit,
    }
}
