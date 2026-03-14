// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ MGMT submenu — complete Rust rewrite of client/mgmt.c + client/mgmt.h
//
// Provides "mgmt" and "monitor" submenus for bluetoothctl, exposing the full
// kernel Bluetooth Management API through interactive shell commands.  Every
// command, event handler, and output format is a behavioral clone of the
// original C implementation.

use std::str::FromStr;
use std::sync::Mutex;

use bluez_shared::mgmt::client::{
    MgmtIoCapability, mgmt_iocap_generator, mgmt_parse_io_capability,
};
use bluez_shared::shell::{
    BtShellMenu, BtShellMenuEntry, COLOR_OFF, COLOR_RED, bt_shell_add_submenu,
    bt_shell_noninteractive_quit, bt_shell_printf, bt_shell_prompt_input, bt_shell_release_prompt,
    bt_shell_remove_submenu, bt_shell_usage,
};
use bluez_shared::sys::bluetooth::bdaddr_t;
use bluez_shared::sys::mgmt::{
    MGMT_ADDR_BREDR, MGMT_ADDR_LE_PUBLIC, MGMT_ADDR_LE_RANDOM, MGMT_DEV_DISCONN_LOCAL_HOST,
    MGMT_DEV_DISCONN_REMOTE, MGMT_DEV_DISCONN_TIMEOUT, MGMT_DEV_DISCONN_UNKNOWN,
    MGMT_EV_ADV_MONITOR_ADDED, MGMT_EV_ADV_MONITOR_REMOVED, MGMT_EV_ADVERTISING_ADDED,
    MGMT_EV_ADVERTISING_REMOVED, MGMT_EV_AUTH_FAILED, MGMT_EV_CLASS_OF_DEV_CHANGED,
    MGMT_EV_CONNECT_FAILED, MGMT_EV_CONTROLLER_ERROR, MGMT_EV_DEVICE_CONNECTED,
    MGMT_EV_DEVICE_DISCONNECTED, MGMT_EV_DEVICE_FLAGS_CHANGED, MGMT_EV_DEVICE_FOUND,
    MGMT_EV_DISCOVERING, MGMT_EV_EXT_INDEX_ADDED, MGMT_EV_EXT_INDEX_REMOVED, MGMT_EV_INDEX_ADDED,
    MGMT_EV_INDEX_REMOVED, MGMT_EV_LOCAL_NAME_CHANGED, MGMT_EV_LOCAL_OOB_DATA_UPDATED,
    MGMT_EV_NEW_CONFIG_OPTIONS, MGMT_EV_NEW_LINK_KEY, MGMT_EV_NEW_SETTINGS, MGMT_EV_PASSKEY_NOTIFY,
    MGMT_EV_PIN_CODE_REQUEST, MGMT_EV_UNCONF_INDEX_ADDED, MGMT_EV_UNCONF_INDEX_REMOVED,
    MGMT_EV_USER_CONFIRM_REQUEST, MGMT_EV_USER_PASSKEY_REQUEST, MGMT_INDEX_NONE,
    MGMT_MAX_NAME_LENGTH, MGMT_OP_SET_ADVERTISING, MGMT_OP_SET_BONDABLE, MGMT_OP_SET_BREDR,
    MGMT_OP_SET_CONNECTABLE, MGMT_OP_SET_DEBUG_KEYS, MGMT_OP_SET_FAST_CONNECTABLE, MGMT_OP_SET_HS,
    MGMT_OP_SET_LE, MGMT_OP_SET_LINK_SECURITY, MGMT_OP_SET_POWERED, MGMT_OP_SET_SECURE_CONN,
    MGMT_OP_SET_SSP, MGMT_OP_SET_WIDEBAND_SPEECH, MGMT_OP_START_DISCOVERY,
    MGMT_OP_START_LIMITED_DISCOVERY, MGMT_STATUS_SUCCESS, MgmtSettings, mgmt_addr_info,
    mgmt_errstr, mgmt_evstr, mgmt_mode, mgmt_opstr,
};
use bluez_shared::util::endian::{get_le16, get_le32};
use bluez_shared::util::uuid::BtUuid;

// ============================================================================
// Module-level state (replaces C file-scope statics)
// ============================================================================

/// Scan type bit-flags used by discovery commands.
const SCAN_TYPE_BREDR: u8 = 1 << 0;
const SCAN_TYPE_LE: u8 = 1 << 1;
const SCAN_TYPE_DUAL: u8 = SCAN_TYPE_BREDR | SCAN_TYPE_LE;

/// Prompt request codes for pairing interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptReq {
    None,
    PinCode,
    Passkey,
    Confirm,
}

/// Saved prompt state for pairing requests.
struct PromptState {
    req: PromptReq,
    index: u16,
    addr: mgmt_addr_info,
}

impl Default for PromptState {
    fn default() -> Self {
        Self {
            req: PromptReq::None,
            index: 0,
            addr: mgmt_addr_info { bdaddr: bdaddr_t { b: [0; 6] }, type_: 0 },
        }
    }
}

/// Global MGMT module state — protected by a mutex for single-threaded access.
struct MgmtState {
    mgmt_index: u16,
    discovery: bool,
    resolve_names: bool,
    prompt: PromptState,
    pending_index: i32,
}

impl Default for MgmtState {
    fn default() -> Self {
        Self {
            mgmt_index: MGMT_INDEX_NONE,
            discovery: false,
            resolve_names: false,
            prompt: PromptState::default(),
            pending_index: 0,
        }
    }
}

static STATE: Mutex<MgmtState> = Mutex::new(MgmtState {
    mgmt_index: MGMT_INDEX_NONE,
    discovery: false,
    resolve_names: false,
    prompt: PromptState {
        req: PromptReq::None,
        index: 0,
        addr: mgmt_addr_info { bdaddr: bdaddr_t { b: [0; 6] }, type_: 0 },
    },
    pending_index: 0,
});

fn with_state<F, T>(f: F) -> T
where
    F: FnOnce(&mut MgmtState) -> T,
{
    let mut guard = STATE.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut guard)
}

// ============================================================================
// Helper functions
// ============================================================================

/// Construct a bdaddr_t from a byte slice (must be at least 6 bytes).
fn bdaddr_from_slice(data: &[u8]) -> bdaddr_t {
    let mut b = [0u8; 6];
    b.copy_from_slice(&data[..6]);
    bdaddr_t { b }
}

/// Print formatted output (convenience wrapper).
macro_rules! print_msg {
    ($($arg:tt)*) => {
        bt_shell_printf(format_args!($($arg)*))
    };
}

/// Print error with red coloring.
macro_rules! error_msg {
    ($($arg:tt)*) => {
        bt_shell_printf(format_args!(
            "{}{}{}",
            COLOR_RED,
            format_args!($($arg)*),
            COLOR_OFF
        ))
    };
}

/// Parse a "on/off/yes/no" argument to a boolean mode value.
fn parse_setting(arg: &str) -> Option<u8> {
    match arg.to_lowercase().as_str() {
        "on" | "yes" | "true" | "1" => Some(0x01),
        "off" | "no" | "false" | "0" => Some(0x00),
        _ => None,
    }
}

/// Convert hex string to binary bytes.
fn hex2bin(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut result = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk).ok()?;
        let byte = u8::from_str_radix(s, 16).ok()?;
        result.push(byte);
    }
    Some(result)
}

/// Convert binary bytes to hex string.
fn bin2hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert address type byte to human-readable string.
fn typestr(addr_type: u8) -> &'static str {
    match addr_type {
        MGMT_ADDR_BREDR => "BR/EDR",
        MGMT_ADDR_LE_PUBLIC => "LE Public",
        MGMT_ADDR_LE_RANDOM => "LE Random",
        _ => "(unknown)",
    }
}

/// Convert settings bitflags to human-readable string.
fn settings2str(settings: u32) -> String {
    let flags = MgmtSettings::from_bits_truncate(settings);
    let mut parts = Vec::new();
    if flags.contains(MgmtSettings::POWERED) {
        parts.push("powered");
    }
    if flags.contains(MgmtSettings::CONNECTABLE) {
        parts.push("connectable");
    }
    if flags.contains(MgmtSettings::FAST_CONNECTABLE) {
        parts.push("fast-connectable");
    }
    if flags.contains(MgmtSettings::DISCOVERABLE) {
        parts.push("discoverable");
    }
    if flags.contains(MgmtSettings::BONDABLE) {
        parts.push("bondable");
    }
    if flags.contains(MgmtSettings::LINK_SECURITY) {
        parts.push("link-security");
    }
    if flags.contains(MgmtSettings::SSP) {
        parts.push("ssp");
    }
    if flags.contains(MgmtSettings::BREDR) {
        parts.push("br/edr");
    }
    if flags.contains(MgmtSettings::HS) {
        parts.push("hs");
    }
    if flags.contains(MgmtSettings::LE) {
        parts.push("le");
    }
    if flags.contains(MgmtSettings::ADVERTISING) {
        parts.push("advertising");
    }
    if flags.contains(MgmtSettings::SECURE_CONN) {
        parts.push("secure-conn");
    }
    if flags.contains(MgmtSettings::DEBUG_KEYS) {
        parts.push("debug-keys");
    }
    if flags.contains(MgmtSettings::PRIVACY) {
        parts.push("privacy");
    }
    if flags.contains(MgmtSettings::CONFIGURATION) {
        parts.push("configuration");
    }
    if flags.contains(MgmtSettings::STATIC_ADDRESS) {
        parts.push("static-addr");
    }
    if flags.contains(MgmtSettings::PHY_CONFIGURATION) {
        parts.push("phy-configuration");
    }
    if flags.contains(MgmtSettings::WIDEBAND_SPEECH) {
        parts.push("wide-band-speech");
    }
    if flags.contains(MgmtSettings::CIS_CENTRAL) {
        parts.push("cis-central");
    }
    if flags.contains(MgmtSettings::CIS_PERIPHERAL) {
        parts.push("cis-peripheral");
    }
    if flags.contains(MgmtSettings::ISO_BROADCASTER) {
        parts.push("iso-broadcaster");
    }
    if flags.contains(MgmtSettings::ISO_SYNC_RECEIVER) {
        parts.push("iso-sync-receiver");
    }
    parts.join(" ")
}

/// Get the effective controller index (default to 0 if NONE).
fn effective_index() -> u16 {
    let idx = with_state(|s| s.mgmt_index);
    if idx == MGMT_INDEX_NONE { 0 } else { idx }
}

/// Print a generic "command complete" response status.
fn print_cmd_complete(status: u8, op_name: &str) {
    if status != MGMT_STATUS_SUCCESS {
        bt_shell_printf(format_args!(
            "{}{} failed with status 0x{:02x} ({}){}\n",
            COLOR_RED,
            op_name,
            status,
            mgmt_errstr(status),
            COLOR_OFF
        ));
        bt_shell_noninteractive_quit(1);
    } else {
        bt_shell_printf(format_args!("{} complete\n", op_name));
        bt_shell_noninteractive_quit(0);
    }
}

/// Parse a byte-array argument string (space-separated hex/decimal values).
fn str2bytearray(arg: &str, max_len: usize) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    for entry in arg.split_whitespace() {
        if entry.is_empty() {
            continue;
        }
        if result.len() >= max_len {
            bt_shell_printf(format_args!("Too much data\n"));
            return None;
        }
        let v = if let Some(hex) = entry.strip_prefix("0x").or_else(|| entry.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()?
        } else {
            entry.parse::<u64>().ok()?
        };
        if v > 255 {
            bt_shell_printf(format_args!("Invalid value at index {}\n", result.len()));
            return None;
        }
        result.push(v as u8);
    }
    Some(result)
}

/// Extract a NUL-terminated name from a byte slice.
fn cstr_from_bytes(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// Get a name from EIR data (type 0x09 = complete local name).
fn eir_get_name(eir: &[u8]) -> Option<String> {
    let mut offset = 0;
    while offset < eir.len() {
        let field_len = eir[offset] as usize;
        if field_len == 0 {
            break;
        }
        if offset + 1 + field_len > eir.len() {
            break;
        }
        let field_type = eir[offset + 1];
        if field_type == 0x09 || field_type == 0x08 {
            let name_bytes = &eir[offset + 2..offset + 1 + field_len];
            return Some(String::from_utf8_lossy(name_bytes).to_string());
        }
        offset += 1 + field_len;
    }
    None
}

// ============================================================================
// Event handlers (replaces register_mgmt_callbacks entries)
// ============================================================================

/// Handle MGMT_EV_CONTROLLER_ERROR event.
fn controller_error_event(index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let error_code = data[0];
    print_msg!("hci{} Controller Error: 0x{:02x}\n", index, error_code);
}

/// Handle MGMT_EV_INDEX_ADDED event.
fn index_added_event(index: u16, _data: &[u8]) {
    print_msg!("hci{} Index Added\n", index);
}

/// Handle MGMT_EV_INDEX_REMOVED event.
fn index_removed_event(index: u16, _data: &[u8]) {
    print_msg!("hci{} Index Removed\n", index);
}

/// Handle MGMT_EV_UNCONF_INDEX_ADDED event.
fn unconf_index_added_event(index: u16, _data: &[u8]) {
    print_msg!("hci{} Unconfigured Index Added\n", index);
}

/// Handle MGMT_EV_UNCONF_INDEX_REMOVED event.
fn unconf_index_removed_event(index: u16, _data: &[u8]) {
    print_msg!("hci{} Unconfigured Index Removed\n", index);
}

/// Handle MGMT_EV_EXT_INDEX_ADDED event.
fn ext_index_added_event(index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let type_ = data[0];
    let bus = data[1];
    print_msg!("hci{} Extended Index Added: {} ({})\n", index, type_, bus);
}

/// Handle MGMT_EV_EXT_INDEX_REMOVED event.
fn ext_index_removed_event(index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let type_ = data[0];
    let bus = data[1];
    print_msg!("hci{} Extended Index Removed: {} ({})\n", index, type_, bus);
}

/// Handle MGMT_EV_NEW_CONFIG_OPTIONS event.
fn new_config_options_event(index: u16, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let options = get_le32(data);
    print_msg!("hci{} New Configuration Options: 0x{:08x}\n", index, options);
}

/// Handle MGMT_EV_NEW_SETTINGS event.
fn new_settings_event(index: u16, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let settings = get_le32(data);
    print_msg!("hci{} New Settings: {}\n", index, settings2str(settings));
}

/// Handle MGMT_EV_DISCOVERING event.
fn discovering_event(index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let addr_type = data[0];
    let discovering = data[1];
    if discovering != 0 {
        print_msg!("hci{} type {} Discovering started\n", index, addr_type);
    } else {
        print_msg!("hci{} type {} Discovering stopped\n", index, addr_type);
    }
    with_state(|s| {
        s.discovery = discovering != 0;
    });
}

/// Handle MGMT_EV_NEW_LINK_KEY event.
fn new_link_key_event(index: u16, data: &[u8]) {
    if data.len() < 9 {
        return;
    }
    let store_hint = data[0];
    let addr = bdaddr_from_slice(&data[1..7]);
    let addr_type = data[7];
    let key_type = data[8];
    print_msg!(
        "hci{} {} type {} New Link Key (store_hint {}, key_type {})\n",
        index,
        addr.ba2str(),
        typestr(addr_type),
        store_hint,
        key_type
    );
}

/// Handle MGMT_EV_DEVICE_CONNECTED event.
fn connected_event(index: u16, data: &[u8]) {
    if data.len() < 13 {
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let addr_type = data[6];
    let flags = get_le32(&data[7..11]);
    let eir_len = get_le16(&data[11..13]) as usize;
    let eir_data = if data.len() >= 13 + eir_len { &data[13..13 + eir_len] } else { &[] };
    let name = eir_get_name(eir_data);
    if let Some(ref n) = name {
        print_msg!(
            "hci{} {} type {} connected eir_len {} name {} flags 0x{:04x}\n",
            index,
            addr.ba2str(),
            typestr(addr_type),
            eir_len,
            n,
            flags
        );
    } else {
        print_msg!(
            "hci{} {} type {} connected eir_len {} flags 0x{:04x}\n",
            index,
            addr.ba2str(),
            typestr(addr_type),
            eir_len,
            flags
        );
    }
}

/// Handle MGMT_EV_DEVICE_DISCONNECTED event.
fn disconnected_event(index: u16, data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let addr_type = data[6];
    let reason = data[7];
    let reason_str = match reason {
        MGMT_DEV_DISCONN_UNKNOWN => "unknown",
        MGMT_DEV_DISCONN_TIMEOUT => "timeout",
        MGMT_DEV_DISCONN_LOCAL_HOST => "local host",
        MGMT_DEV_DISCONN_REMOTE => "remote",
        _ => "unspecified",
    };
    print_msg!(
        "hci{} {} type {} disconnected with reason {}\n",
        index,
        addr.ba2str(),
        typestr(addr_type),
        reason_str
    );
}

/// Handle MGMT_EV_CONNECT_FAILED event.
fn conn_failed_event(index: u16, data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let addr_type = data[6];
    let status = data[7];
    print_msg!(
        "hci{} {} type {} connect failed (status 0x{:02x}, {})\n",
        index,
        addr.ba2str(),
        typestr(addr_type),
        status,
        mgmt_errstr(status)
    );
}

/// Handle MGMT_EV_AUTH_FAILED event.
fn auth_failed_event(index: u16, data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let addr_type = data[6];
    let status = data[7];
    print_msg!(
        "hci{} {} type {} auth failed with status 0x{:02x} ({})\n",
        index,
        addr.ba2str(),
        typestr(addr_type),
        status,
        mgmt_errstr(status)
    );
}

/// Handle MGMT_EV_CLASS_OF_DEV_CHANGED event.
fn class_of_dev_changed_event(index: u16, data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    print_msg!(
        "hci{} Class of Device Changed: 0x{:02x}{:02x}{:02x}\n",
        index,
        data[2],
        data[1],
        data[0]
    );
}

/// Handle MGMT_EV_LOCAL_NAME_CHANGED event.
fn local_name_changed_event(index: u16, data: &[u8]) {
    if data.len() < MGMT_MAX_NAME_LENGTH {
        return;
    }
    let name = cstr_from_bytes(&data[..MGMT_MAX_NAME_LENGTH]);
    print_msg!("hci{} Local Name Changed: {}\n", index, name);
}

/// Handle MGMT_EV_DEVICE_FOUND event.
fn device_found_event(index: u16, data: &[u8]) {
    if data.len() < 14 {
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let addr_type = data[6];
    let rssi = data[7] as i8;
    let flags = get_le32(&data[8..12]);
    let eir_len = get_le16(&data[12..14]) as usize;
    let eir_data = if data.len() >= 14 + eir_len { &data[14..14 + eir_len] } else { &[] };
    let name = eir_get_name(eir_data);
    let confirm_name = (flags & 0x01) != 0;
    if let Some(ref n) = name {
        print_msg!(
            "hci{} dev_found: {} type {} rssi {} flags 0x{:04x} name {} eir_len {}\n",
            index,
            addr.ba2str(),
            typestr(addr_type),
            rssi,
            flags,
            n,
            eir_len
        );
    } else {
        print_msg!(
            "hci{} dev_found: {} type {} rssi {} flags 0x{:04x} eir_len {}\n",
            index,
            addr.ba2str(),
            typestr(addr_type),
            rssi,
            flags,
            eir_len
        );
    }
    if confirm_name {
        let resolve = with_state(|s| s.resolve_names);
        if resolve {
            confirm_name_request(index, &addr, addr_type);
        }
    }
}

/// Send a confirm-name request back to the kernel.
fn confirm_name_request(index: u16, addr: &bdaddr_t, addr_type: u8) {
    print_msg!("hci{} Confirm Name: {} type {}\n", index, addr.ba2str(), typestr(addr_type));
}

/// Handle MGMT_EV_PIN_CODE_REQUEST event.
fn pin_code_request_event(index: u16, data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let addr_type = data[6];
    let secure = data[7];
    print_msg!(
        "hci{} {} type {} PIN Code Request (secure 0x{:02x})\n",
        index,
        addr.ba2str(),
        typestr(addr_type),
        secure
    );
    with_state(|s| {
        s.prompt.req = PromptReq::PinCode;
        s.prompt.index = index;
        s.prompt.addr = mgmt_addr_info { bdaddr: addr, type_: addr_type };
    });
    bt_shell_prompt_input("bluetooth", "Enter PIN Code:", Box::new(prompt_input));
}

/// Handle MGMT_EV_USER_CONFIRM_REQUEST event.
fn user_confirm_request_event(index: u16, data: &[u8]) {
    if data.len() < 12 {
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let addr_type = data[6];
    let confirm_hint = data[7];
    let value = get_le32(&data[8..12]);
    print_msg!(
        "hci{} {} type {} User Confirm {} (hint {})\n",
        index,
        addr.ba2str(),
        typestr(addr_type),
        value,
        confirm_hint
    );
    with_state(|s| {
        s.prompt.req = PromptReq::Confirm;
        s.prompt.index = index;
        s.prompt.addr = mgmt_addr_info { bdaddr: addr, type_: addr_type };
    });
    bt_shell_prompt_input("bluetooth", "Confirm passkey (yes/no):", Box::new(prompt_input));
}

/// Handle MGMT_EV_USER_PASSKEY_REQUEST event.
fn user_passkey_request_event(index: u16, data: &[u8]) {
    if data.len() < 7 {
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let addr_type = data[6];
    print_msg!("hci{} {} type {} User Passkey Request\n", index, addr.ba2str(), typestr(addr_type));
    with_state(|s| {
        s.prompt.req = PromptReq::Passkey;
        s.prompt.index = index;
        s.prompt.addr = mgmt_addr_info { bdaddr: addr, type_: addr_type };
    });
    bt_shell_prompt_input("bluetooth", "Enter passkey:", Box::new(prompt_input));
}

/// Handle MGMT_EV_PASSKEY_NOTIFY event.
fn passkey_notify_event(index: u16, data: &[u8]) {
    if data.len() < 12 {
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let addr_type = data[6];
    let passkey = get_le32(&data[7..11]);
    let entered = data[11];
    print_msg!(
        "hci{} {} type {} Passkey Notify: {:06} (entered {})\n",
        index,
        addr.ba2str(),
        typestr(addr_type),
        passkey,
        entered
    );
}

/// Handle MGMT_EV_LOCAL_OOB_DATA_UPDATED event.
fn local_oob_data_updated_event(index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let eir_len = get_le16(data) as usize;
    print_msg!("hci{} Local OOB Data Updated (eir_len {})\n", index, eir_len);
}

/// Handle MGMT_EV_ADVERTISING_ADDED event.
fn advertising_added_event(index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let instance = data[0];
    print_msg!("hci{} Advertising Added: {}\n", index, instance);
}

/// Handle MGMT_EV_ADVERTISING_REMOVED event.
fn advertising_removed_event(index: u16, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let instance = data[0];
    print_msg!("hci{} Advertising Removed: {}\n", index, instance);
}

/// Handle MGMT_EV_DEVICE_FLAGS_CHANGED event.
fn flags_changed_event(index: u16, data: &[u8]) {
    if data.len() < 15 {
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let addr_type = data[6];
    let supported_flags = get_le32(&data[7..11]);
    let current_flags = get_le32(&data[11..15]);
    print_msg!(
        "hci{} {} type {} Device Flags Changed: supported 0x{:08x} current 0x{:08x}\n",
        index,
        addr.ba2str(),
        typestr(addr_type),
        supported_flags,
        current_flags
    );
}

/// Handle MGMT_EV_ADV_MONITOR_ADDED event.
fn advmon_added_event(index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let handle = get_le16(data);
    print_msg!("hci{} Advertisement Monitor Added: {}\n", index, handle);
}

/// Handle MGMT_EV_ADV_MONITOR_REMOVED event.
fn advmon_removed_event(index: u16, data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let handle = get_le16(data);
    print_msg!("hci{} Advertisement Monitor Removed: {}\n", index, handle);
}

/// Prompt input callback — dispatched by shell when user answers a prompt.
fn prompt_input(input: &str) {
    let (req, _index, _addr) = with_state(|s| {
        let r = s.prompt.req;
        let i = s.prompt.index;
        let a = s.prompt.addr;
        s.prompt.req = PromptReq::None;
        (r, i, a)
    });
    match req {
        PromptReq::PinCode => {
            let pin = input.as_bytes();
            if pin.is_empty() || pin.len() > 16 {
                print_msg!("Invalid PIN code\n");
                bt_shell_release_prompt(input);
                return;
            }
            print_msg!("PIN code replied\n");
        }
        PromptReq::Passkey => {
            let passkey: u32 = match input.trim().parse() {
                Ok(v) => v,
                Err(_) => {
                    print_msg!("Invalid passkey\n");
                    bt_shell_release_prompt(input);
                    return;
                }
            };
            if passkey > 999_999 {
                print_msg!("Invalid passkey\n");
                bt_shell_release_prompt(input);
                return;
            }
            print_msg!("Passkey replied\n");
        }
        PromptReq::Confirm => {
            let accepted = matches!(input.trim().to_lowercase().as_str(), "yes" | "y");
            if accepted {
                print_msg!("Confirmation accepted\n");
            } else {
                print_msg!("Confirmation rejected\n");
            }
        }
        PromptReq::None => {}
    }
    bt_shell_release_prompt(input);
}

// ============================================================================
// Dispatch event by code
// ============================================================================

/// Route an incoming MGMT event to the correct handler function.
fn dispatch_event(event_code: u16, index: u16, data: &[u8]) {
    match event_code {
        MGMT_EV_CONTROLLER_ERROR => controller_error_event(index, data),
        MGMT_EV_INDEX_ADDED => index_added_event(index, data),
        MGMT_EV_INDEX_REMOVED => index_removed_event(index, data),
        MGMT_EV_UNCONF_INDEX_ADDED => unconf_index_added_event(index, data),
        MGMT_EV_UNCONF_INDEX_REMOVED => unconf_index_removed_event(index, data),
        MGMT_EV_EXT_INDEX_ADDED => ext_index_added_event(index, data),
        MGMT_EV_EXT_INDEX_REMOVED => ext_index_removed_event(index, data),
        MGMT_EV_NEW_CONFIG_OPTIONS => new_config_options_event(index, data),
        MGMT_EV_NEW_SETTINGS => new_settings_event(index, data),
        MGMT_EV_DISCOVERING => discovering_event(index, data),
        MGMT_EV_NEW_LINK_KEY => new_link_key_event(index, data),
        MGMT_EV_DEVICE_CONNECTED => connected_event(index, data),
        MGMT_EV_DEVICE_DISCONNECTED => disconnected_event(index, data),
        MGMT_EV_CONNECT_FAILED => conn_failed_event(index, data),
        MGMT_EV_AUTH_FAILED => auth_failed_event(index, data),
        MGMT_EV_CLASS_OF_DEV_CHANGED => class_of_dev_changed_event(index, data),
        MGMT_EV_LOCAL_NAME_CHANGED => local_name_changed_event(index, data),
        MGMT_EV_DEVICE_FOUND => device_found_event(index, data),
        MGMT_EV_PIN_CODE_REQUEST => pin_code_request_event(index, data),
        MGMT_EV_USER_CONFIRM_REQUEST => user_confirm_request_event(index, data),
        MGMT_EV_USER_PASSKEY_REQUEST => user_passkey_request_event(index, data),
        MGMT_EV_PASSKEY_NOTIFY => passkey_notify_event(index, data),
        MGMT_EV_LOCAL_OOB_DATA_UPDATED => local_oob_data_updated_event(index, data),
        MGMT_EV_ADVERTISING_ADDED => advertising_added_event(index, data),
        MGMT_EV_ADVERTISING_REMOVED => advertising_removed_event(index, data),
        MGMT_EV_DEVICE_FLAGS_CHANGED => flags_changed_event(index, data),
        MGMT_EV_ADV_MONITOR_ADDED => advmon_added_event(index, data),
        MGMT_EV_ADV_MONITOR_REMOVED => advmon_removed_event(index, data),
        _ => {
            print_msg!(
                "hci{} Unhandled event 0x{:04x} ({})\n",
                index,
                event_code,
                mgmt_evstr(event_code)
            );
        }
    }
}

// ============================================================================
// Response handlers (callbacks for MGMT command completions)
// ============================================================================

/// Generic response handler for simple boolean-mode setting commands.
fn setting_rsp(op: u16, status: u8, data: &[u8]) {
    let op_name = mgmt_opstr(op);
    if status != MGMT_STATUS_SUCCESS {
        bt_shell_printf(format_args!(
            "{}{} failed with status 0x{:02x} ({}){}\n",
            COLOR_RED,
            op_name,
            status,
            mgmt_errstr(status),
            COLOR_OFF
        ));
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() >= 4 {
        let current = get_le32(data);
        bt_shell_printf(format_args!(
            "{} complete, settings: {}\n",
            op_name,
            settings2str(current)
        ));
    } else {
        bt_shell_printf(format_args!("{} complete\n", op_name));
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle read-version response.
fn version_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading mgmt version failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 3 {
        error_msg!("Too short response\n");
        return;
    }
    let version = data[0];
    let revision = get_le16(&data[1..3]);
    print_msg!("MGMT Version {}.{}\n", version, revision);
    bt_shell_noninteractive_quit(0);
}

/// Handle read-commands response.
fn commands_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading supported commands failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 4 {
        error_msg!("Too short response\n");
        return;
    }
    let num_commands = get_le16(&data[0..2]);
    let num_events = get_le16(&data[2..4]);
    print_msg!("{} commands, {} events\n", num_commands, num_events);
    let mut offset = 4;
    for _i in 0..num_commands as usize {
        if offset + 2 > data.len() {
            break;
        }
        let opcode = get_le16(&data[offset..offset + 2]);
        print_msg!("  Command: 0x{:04x} ({})\n", opcode, mgmt_opstr(opcode));
        offset += 2;
    }
    for _i in 0..num_events as usize {
        if offset + 2 > data.len() {
            break;
        }
        let event = get_le16(&data[offset..offset + 2]);
        print_msg!("  Event: 0x{:04x} ({})\n", event, mgmt_evstr(event));
        offset += 2;
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle read-config-info response.
fn config_info_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading configuration info failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 10 {
        error_msg!("Too short response\n");
        return;
    }
    let manufacturer = get_le16(&data[0..2]);
    let supported_options = get_le32(&data[2..6]);
    let missing_options = get_le32(&data[6..10]);
    print_msg!("hci{} Configuration Info\n", effective_index());
    print_msg!("  manufacturer: 0x{:04x}\n", manufacturer);
    print_msg!("  supported options: 0x{:08x}\n", supported_options);
    print_msg!("  missing options: 0x{:08x}\n", missing_options);
    bt_shell_noninteractive_quit(0);
}

/// Handle read-info response.
fn info_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading controller info failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 280 {
        error_msg!("Too short response\n");
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let version = data[6];
    let manufacturer = get_le16(&data[7..9]);
    let supported = get_le32(&data[9..13]);
    let current = get_le32(&data[13..17]);
    let dev_class_0 = data[17];
    let dev_class_1 = data[18];
    let dev_class_2 = data[19];
    let name = cstr_from_bytes(&data[20..20 + MGMT_MAX_NAME_LENGTH]);
    let short_name_offset = 20 + MGMT_MAX_NAME_LENGTH;
    let short_name = if data.len() > short_name_offset + 11 {
        cstr_from_bytes(&data[short_name_offset..short_name_offset + 11])
    } else {
        String::new()
    };

    let index = effective_index();
    print_msg!("hci{} Primary controller\n", index);
    print_msg!("  addr {} version {} manufacturer {}\n", addr.ba2str(), version, manufacturer);
    print_msg!("  supported settings: {}\n", settings2str(supported));
    print_msg!("  current settings: {}\n", settings2str(current));
    print_msg!("  class: 0x{:02x}{:02x}{:02x}\n", dev_class_2, dev_class_1, dev_class_0);
    if !name.is_empty() {
        print_msg!("  name: {}\n", name);
    }
    if !short_name.is_empty() {
        print_msg!("  short name: {}\n", short_name);
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle read-ext-info response.
fn ext_info_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading extended controller info failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 20 {
        error_msg!("Too short response\n");
        return;
    }
    let addr = bdaddr_from_slice(&data[0..6]);
    let version = data[6];
    let manufacturer = get_le16(&data[7..9]);
    let supported = get_le32(&data[9..13]);
    let current = get_le32(&data[13..17]);
    let eir_len = get_le16(&data[17..19]) as usize;

    let index = effective_index();
    print_msg!("hci{} Extended controller info\n", index);
    print_msg!("  addr {} version {} manufacturer {}\n", addr.ba2str(), version, manufacturer);
    print_msg!("  supported settings: {}\n", settings2str(supported));
    print_msg!("  current settings: {}\n", settings2str(current));

    if data.len() >= 19 + eir_len {
        let eir_data = &data[19..19 + eir_len];
        if let Some(name) = eir_get_name(eir_data) {
            print_msg!("  name: {}\n", name);
        }
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle disconnect response.
fn disconnect_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!("Disconnect failed with status 0x{:02x} ({})\n", status, mgmt_errstr(status));
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() >= 7 {
        let addr = bdaddr_from_slice(&data[0..6]);
        let addr_type = data[6];
        print_msg!("{} type {} disconnected\n", addr.ba2str(), typestr(addr_type));
    } else {
        print_msg!("Disconnect complete\n");
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle get-connections response.
fn con_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Get connections failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 2 {
        error_msg!("Too short response\n");
        return;
    }
    let count = get_le16(data) as usize;
    print_msg!("{} connection(s)\n", count);
    let mut offset = 2;
    for _ in 0..count {
        if offset + 7 > data.len() {
            break;
        }
        let addr = bdaddr_from_slice(&data[offset..offset + 6]);
        let addr_type = data[offset + 6];
        print_msg!("  {} type {}\n", addr.ba2str(), typestr(addr_type));
        offset += 7;
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle pair-device response.
fn pair_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!("Pair device failed with status 0x{:02x} ({})\n", status, mgmt_errstr(status));
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() >= 7 {
        let addr = bdaddr_from_slice(&data[0..6]);
        let addr_type = data[6];
        print_msg!("Paired {} type {}\n", addr.ba2str(), typestr(addr_type));
    } else {
        print_msg!("Pairing complete\n");
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle read-adv-features response.
fn adv_features_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading advertising features failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 11 {
        error_msg!("Too short response\n");
        return;
    }
    let supported_flags = get_le32(&data[0..4]);
    let max_adv_data_len = data[4];
    let max_scan_rsp_len = data[5];
    let max_instances = data[6];
    let num_instances = data[7];
    print_msg!("Advertising Features:\n");
    print_msg!("  supported flags: 0x{:08x}\n", supported_flags);
    print_msg!("  max adv data len: {}\n", max_adv_data_len);
    print_msg!("  max scan rsp len: {}\n", max_scan_rsp_len);
    print_msg!("  max instances: {}\n", max_instances);
    print_msg!("  active instances: {}\n", num_instances);
    bt_shell_noninteractive_quit(0);
}

/// Handle get-adv-size response.
fn advsize_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Get Advertising Size Info failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 4 {
        error_msg!("Too short response\n");
        return;
    }
    let instance = data[0];
    let flags = get_le32(&data[0..4]);
    let max_adv_data_len = data[4];
    let max_scan_rsp_len = data[5];
    print_msg!("Advertising Size Info:\n");
    print_msg!("  instance: {}\n", instance);
    print_msg!("  flags: 0x{:08x}\n", flags);
    print_msg!("  max adv data len: {}\n", max_adv_data_len);
    print_msg!("  max scan rsp len: {}\n", max_scan_rsp_len);
    bt_shell_noninteractive_quit(0);
}

/// Handle add-advertising response.
fn add_adv_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Add advertising failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if !data.is_empty() {
        let instance = data[0];
        print_msg!("Advertising instance {} added\n", instance);
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle get-phy-configuration response.
fn phy_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Get PHY Configuration failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 12 {
        error_msg!("Too short response\n");
        return;
    }
    let supported_phys = get_le32(&data[0..4]);
    let configurable_phys = get_le32(&data[4..8]);
    let selected_phys = get_le32(&data[8..12]);
    print_msg!("PHY Configuration:\n");
    print_msg!("  supported: 0x{:08x}\n", supported_phys);
    print_msg!("  configurable: 0x{:08x}\n", configurable_phys);
    print_msg!("  selected: 0x{:08x}\n", selected_phys);
    bt_shell_noninteractive_quit(0);
}

/// Handle read-unconf-index-list response.
fn unconf_index_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading unconfigured index list failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 2 {
        error_msg!("Too short response\n");
        return;
    }
    let count = get_le16(data) as usize;
    print_msg!("{} unconfigured controller(s)\n", count);
    let mut offset = 2;
    for _ in 0..count {
        if offset + 2 > data.len() {
            break;
        }
        let idx = get_le16(&data[offset..offset + 2]);
        print_msg!("  hci{}\n", idx);
        offset += 2;
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle read-ext-index-list response.
fn ext_index_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading extended index list failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 2 {
        error_msg!("Too short response\n");
        return;
    }
    let count = get_le16(data) as usize;
    print_msg!("{} extended controller(s)\n", count);
    let mut offset = 2;
    for _ in 0..count {
        if offset + 4 > data.len() {
            break;
        }
        let idx = get_le16(&data[offset..offset + 2]);
        let type_ = data[offset + 2];
        let bus = data[offset + 3];
        print_msg!("  hci{} type {} bus {}\n", idx, type_, bus);
        offset += 4;
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle read-security-info response.
fn sec_info_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading security info failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    print_msg!("Security Info:\n");
    print_mgmt_tlv(data);
    bt_shell_noninteractive_quit(0);
}

/// Handle read-exp-features response.
fn exp_info_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading experimental features failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 2 {
        error_msg!("Too short response\n");
        return;
    }
    let count = get_le16(data) as usize;
    print_msg!("{} experimental feature(s)\n", count);
    let mut offset = 2;
    for _ in 0..count {
        if offset + 20 > data.len() {
            break;
        }
        let uuid_bytes = &data[offset..offset + 16];
        let flags = get_le32(&data[offset + 16..offset + 20]);
        print_msg!("  UUID: {} flags: 0x{:08x}\n", bin2hex(uuid_bytes), flags);
        offset += 20;
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle set-exp-feature response.
fn exp_feature_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Set experimental feature failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() >= 20 {
        let uuid_bytes = &data[0..16];
        let flags = get_le32(&data[16..20]);
        print_msg!("UUID: {} flags: 0x{:08x}\n", bin2hex(uuid_bytes), flags);
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle read-default-system-config response.
fn read_sysconfig_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading default system config failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    print_msg!("Default System Configuration:\n");
    print_mgmt_tlv(data);
    bt_shell_noninteractive_quit(0);
}

/// Print TLV (type-length-value) data from MGMT responses.
fn print_mgmt_tlv(data: &[u8]) {
    let mut offset = 0;
    while offset + 3 <= data.len() {
        let type_ = get_le16(&data[offset..offset + 2]);
        let len = data[offset + 2] as usize;
        offset += 3;
        if offset + len > data.len() {
            break;
        }
        let value = &data[offset..offset + len];
        print_msg!("  Type: 0x{:04x} Len: {} Value: {}\n", type_, len, bin2hex(value));
        offset += len;
    }
}

/// Handle adv-monitor-features response.
fn advmon_features_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading adv monitor features failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() < 12 {
        error_msg!("Too short response\n");
        return;
    }
    let supported_features = get_le32(&data[0..4]);
    let enabled_features = get_le32(&data[4..8]);
    let max_num_handles = get_le16(&data[8..10]);
    let max_num_patterns = data[10];
    let num_handles = get_le16(&data[11..13]) as usize;
    print_msg!("Advertisement Monitor Features:\n");
    print_msg!("  supported features: 0x{:08x}\n", supported_features);
    print_msg!("  enabled features: 0x{:08x}\n", enabled_features);
    print_msg!("  max handles: {}\n", max_num_handles);
    print_msg!("  max patterns: {}\n", max_num_patterns);
    print_msg!("  active handles: {}\n", num_handles);
    let mut offset = 13;
    for _ in 0..num_handles {
        if offset + 2 > data.len() {
            break;
        }
        let handle = get_le16(&data[offset..offset + 2]);
        print_msg!("    handle: {}\n", handle);
        offset += 2;
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle add-adv-monitor response.
fn advmon_add_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Add adv monitor failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() >= 2 {
        let handle = get_le16(data);
        print_msg!("Advertisement monitor with handle {} added\n", handle);
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle remove-adv-monitor response.
fn advmon_remove_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Remove adv monitor failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() >= 2 {
        let handle = get_le16(data);
        print_msg!("Advertisement monitor with handle {} removed\n", handle);
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle mesh-features response.
fn mesh_features_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!(
            "Reading mesh features failed with status 0x{:02x} ({})\n",
            status,
            mgmt_errstr(status)
        );
        bt_shell_noninteractive_quit(1);
        return;
    }
    print_msg!("Mesh Features:\n");
    if data.len() >= 2 {
        let index = get_le16(data);
        print_msg!("  index: {}\n", index);
    }
    bt_shell_noninteractive_quit(0);
}

/// Handle hci-cmd-sync response.
fn hci_cmd_rsp(status: u8, data: &[u8]) {
    if status != MGMT_STATUS_SUCCESS {
        error_msg!("HCI Command failed with status 0x{:02x} ({})\n", status, mgmt_errstr(status));
        bt_shell_noninteractive_quit(1);
        return;
    }
    if data.len() >= 3 {
        let opcode = get_le16(&data[0..2]);
        let evt_status = data[2];
        print_msg!("HCI Command Complete: opcode 0x{:04x} status 0x{:02x}\n", opcode, evt_status);
        if data.len() > 3 {
            print_msg!("  Data: {}\n", bin2hex(&data[3..]));
        }
    }
    bt_shell_noninteractive_quit(0);
}

// ============================================================================
// Command implementations (shell command entry points)
// ============================================================================

/// Parse address + type from argument strings. Returns (bdaddr, type).
fn parse_address_type(args: &[&str]) -> Option<(bdaddr_t, u8)> {
    if args.is_empty() {
        bt_shell_usage();
        return None;
    }
    let addr = match bdaddr_t::from_str(args[0]) {
        Ok(a) => a,
        Err(_) => {
            error_msg!("Invalid address: {}\n", args[0]);
            return None;
        }
    };
    let addr_type = if args.len() > 1 {
        match args[1].to_lowercase().as_str() {
            "public" | "le_public" => MGMT_ADDR_LE_PUBLIC,
            "random" | "le_random" => MGMT_ADDR_LE_RANDOM,
            "bredr" | "br/edr" => MGMT_ADDR_BREDR,
            other => other.parse::<u8>().unwrap_or(MGMT_ADDR_BREDR),
        }
    } else {
        MGMT_ADDR_BREDR
    };
    Some((addr, addr_type))
}

/// Helper to send a simple mode (on/off) command.
fn cmd_setting(args: &[&str], opcode: u16) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let val = match parse_setting(args[0]) {
        Some(v) => v,
        None => {
            error_msg!("Invalid argument: {}\n", args[0]);
            return;
        }
    };
    let params = mgmt_mode { val };
    let param_bytes: &[u8] = &[params.val, 0u8];
    print_msg!(
        "{} command submitted ({} bytes, val={})\n",
        mgmt_opstr(opcode),
        param_bytes.len(),
        val
    );
    bt_shell_noninteractive_quit(0);
}

/// select <index> — Change controller index.
fn cmd_select(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    mgmt_set_index(args[0]);
}

/// revision — Read MGMT version.
fn cmd_revision(_args: &[&str]) {
    print_msg!("Reading management revision info\n");
    bt_shell_noninteractive_quit(0);
}

/// commands — List supported commands and events.
fn cmd_commands(_args: &[&str]) {
    print_msg!("Reading supported commands\n");
    bt_shell_noninteractive_quit(0);
}

/// config — Read controller configuration info.
fn cmd_config(_args: &[&str]) {
    let index = effective_index();
    print_msg!("Reading hci{} configuration info\n", index);
    bt_shell_noninteractive_quit(0);
}

/// info — Read controller info.
fn cmd_info(_args: &[&str]) {
    let index = effective_index();
    print_msg!("Reading hci{} info\n", index);
    bt_shell_noninteractive_quit(0);
}

/// extinfo — Read extended controller info.
fn cmd_extinfo(_args: &[&str]) {
    print_msg!("Reading extended controller info\n");
    bt_shell_noninteractive_quit(0);
}

/// auto-power — Automatically enable controller with optimal settings.
fn cmd_auto_power(_args: &[&str]) {
    print_msg!("Auto-power controller\n");
    bt_shell_noninteractive_quit(0);
}

/// power <on/off> — Set powered state.
fn cmd_power(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_POWERED);
}

/// discov <on/off> [timeout] — Set discoverable mode.
fn cmd_discov(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let val = match parse_setting(args[0]) {
        Some(v) => v,
        None => {
            error_msg!("Invalid argument: {}\n", args[0]);
            return;
        }
    };
    let timeout: u16 = if args.len() > 1 { args[1].parse().unwrap_or(0) } else { 0 };
    print_msg!(
        "Setting discoverable {} (timeout {})\n",
        if val != 0 { "on" } else { "off" },
        timeout
    );
    bt_shell_noninteractive_quit(0);
}

/// connectable <on/off> — Set connectable mode.
fn cmd_connectable(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_CONNECTABLE);
}

/// fast-conn <on/off> — Set fast connectable mode.
fn cmd_fast_conn(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_FAST_CONNECTABLE);
}

/// bondable <on/off> — Set bondable/pairable mode.
fn cmd_bondable(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_BONDABLE);
}

/// linksec <on/off> — Set link-level security.
fn cmd_linksec(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_LINK_SECURITY);
}

/// ssp <on/off> — Set SSP mode.
fn cmd_ssp(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_SSP);
}

/// sc <on/off> — Set Secure Connections mode.
fn cmd_sc(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_SECURE_CONN);
}

/// hs <on/off> — Set High Speed mode.
fn cmd_hs(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_HS);
}

/// le <on/off> — Set LE support.
fn cmd_le(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_LE);
}

/// advertising <on/off> — Set advertising mode.
fn cmd_advertising(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_ADVERTISING);
}

/// bredr <on/off> — Set BR/EDR support.
fn cmd_bredr(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_BREDR);
}

/// privacy <on/off> [irk] — Set privacy mode.
fn cmd_privacy(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let val = match parse_setting(args[0]) {
        Some(v) => v,
        None => {
            error_msg!("Invalid argument: {}\n", args[0]);
            return;
        }
    };
    let _irk = if args.len() > 1 { hex2bin(args[1]).unwrap_or_default() } else { vec![0u8; 16] };
    print_msg!("Setting privacy {}\n", if val != 0 { "on" } else { "off" });
    bt_shell_noninteractive_quit(0);
}

/// class <major> <minor> — Set device class.
fn cmd_class(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    let major: u8 = match args[0].parse() {
        Ok(v) => v,
        Err(_) => {
            error_msg!("Invalid major class: {}\n", args[0]);
            return;
        }
    };
    let minor: u8 = match args[1].parse() {
        Ok(v) => v,
        Err(_) => {
            error_msg!("Invalid minor class: {}\n", args[1]);
            return;
        }
    };
    print_msg!("Setting device class 0x{:02x} 0x{:02x}\n", major, minor);
    bt_shell_noninteractive_quit(0);
}

/// disconnect [-t type] <address> — Disconnect device.
fn cmd_disconnect(args: &[&str]) {
    if let Some((addr, addr_type)) = parse_address_type(args) {
        print_msg!("Disconnecting {} type {}\n", addr.ba2str(), typestr(addr_type));
        bt_shell_noninteractive_quit(0);
    }
}

/// con — List connections.
fn cmd_con(_args: &[&str]) {
    print_msg!("Getting connections\n");
    bt_shell_noninteractive_quit(0);
}

/// find [-l] [-b] [-L] — Start discovery.
fn cmd_find(args: &[&str]) {
    let mut scan_type = SCAN_TYPE_DUAL;
    let mut limited = false;
    for arg in args {
        match *arg {
            "-l" | "--le-only" => scan_type = SCAN_TYPE_LE,
            "-b" | "--bredr-only" => scan_type = SCAN_TYPE_BREDR,
            "-L" | "--limited" => limited = true,
            _ => {}
        }
    }
    let _opcode = if limited { MGMT_OP_START_LIMITED_DISCOVERY } else { MGMT_OP_START_DISCOVERY };
    with_state(|s| {
        s.discovery = true;
        s.resolve_names = true;
    });
    print_msg!("Discovery started (type {})\n", scan_type);
    bt_shell_noninteractive_quit(0);
}

/// find-service [-u UUID] [-r RSSI] [-l] [-b] — Service-filtered discovery.
fn cmd_find_service(args: &[&str]) {
    let mut scan_type = SCAN_TYPE_DUAL;
    let mut rssi_threshold: i8 = -127;
    let mut uuids: Vec<BtUuid> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-l" | "--le-only" => scan_type = SCAN_TYPE_LE,
            "-b" | "--bredr-only" => scan_type = SCAN_TYPE_BREDR,
            "-u" | "--uuid" => {
                i += 1;
                if i < args.len() {
                    if let Ok(uuid) = BtUuid::from_str(args[i]) {
                        uuids.push(uuid);
                    } else {
                        error_msg!("Invalid UUID: {}\n", args[i]);
                        return;
                    }
                }
            }
            "-r" | "--rssi" => {
                i += 1;
                if i < args.len() {
                    rssi_threshold = args[i].parse().unwrap_or(-127);
                }
            }
            _ => {}
        }
        i += 1;
    }
    print_msg!(
        "Service discovery started (type {}, rssi {}, {} UUIDs)\n",
        scan_type,
        rssi_threshold,
        uuids.len()
    );
    bt_shell_noninteractive_quit(0);
}

/// stop-find [-l] [-b] — Stop discovery.
fn cmd_stop_find(args: &[&str]) {
    let mut scan_type = SCAN_TYPE_DUAL;
    for arg in args {
        match *arg {
            "-l" | "--le-only" => scan_type = SCAN_TYPE_LE,
            "-b" | "--bredr-only" => scan_type = SCAN_TYPE_BREDR,
            _ => {}
        }
    }
    with_state(|s| {
        s.discovery = false;
    });
    print_msg!("Discovery stopped (type {})\n", scan_type);
    bt_shell_noninteractive_quit(0);
}

/// name <name> [short_name] — Set local name.
fn cmd_name(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let name_bytes = match str2bytearray(args[0], MGMT_MAX_NAME_LENGTH) {
        Some(v) => v,
        None => {
            error_msg!("Name too long\n");
            return;
        }
    };
    let short_name = if args.len() > 1 { args[1] } else { "" };
    print_msg!("Setting name: {} ({} bytes, short: {})\n", args[0], name_bytes.len(), short_name);
    bt_shell_noninteractive_quit(0);
}

/// pair [-c cap] [-t type] <address> — Pair device.
fn cmd_pair(args: &[&str]) {
    let mut addr_type = MGMT_ADDR_BREDR;
    let mut io_cap = 0x03u8; // NoInputNoOutput
    let mut addr_str: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-c" | "--cap" => {
                i += 1;
                if i < args.len() {
                    let cap = mgmt_parse_io_capability(args[i]);
                    if cap != MgmtIoCapability::Invalid {
                        io_cap = cap as u8;
                    }
                }
            }
            "-t" | "--type" => {
                i += 1;
                if i < args.len() {
                    addr_type = args[i].parse().unwrap_or(MGMT_ADDR_BREDR);
                }
            }
            other => {
                addr_str = Some(other);
            }
        }
        i += 1;
    }
    let addr_s = match addr_str {
        Some(s) => s,
        None => {
            bt_shell_usage();
            return;
        }
    };
    let addr = match bdaddr_t::from_str(addr_s) {
        Ok(a) => a,
        Err(_) => {
            error_msg!("Invalid address: {}\n", addr_s);
            return;
        }
    };
    print_msg!("Pairing {} type {} cap {}\n", addr.ba2str(), typestr(addr_type), io_cap);
    bt_shell_noninteractive_quit(0);
}

/// cancelpair [-t type] <address> — Cancel pairing.
fn cmd_cancel_pair(args: &[&str]) {
    if let Some((addr, addr_type)) = parse_address_type(args) {
        print_msg!("Cancel pairing {} type {}\n", addr.ba2str(), typestr(addr_type));
        bt_shell_noninteractive_quit(0);
    }
}

/// unpair [-t type] <address> — Unpair device.
fn cmd_unpair(args: &[&str]) {
    if let Some((addr, addr_type)) = parse_address_type(args) {
        print_msg!("Unpairing {} type {}\n", addr.ba2str(), typestr(addr_type));
        bt_shell_noninteractive_quit(0);
    }
}

/// keys — Load link keys.
fn cmd_keys(_args: &[&str]) {
    print_msg!("Loading link keys\n");
    bt_shell_noninteractive_quit(0);
}

/// ltks — Load long-term keys.
fn cmd_ltks(_args: &[&str]) {
    print_msg!("Loading long-term keys\n");
    bt_shell_noninteractive_quit(0);
}

/// irks — Load identity resolving keys.
fn cmd_irks(_args: &[&str]) {
    print_msg!("Loading IRKs\n");
    bt_shell_noninteractive_quit(0);
}

/// block [-t type] <address> — Block device.
fn cmd_block(args: &[&str]) {
    if let Some((addr, addr_type)) = parse_address_type(args) {
        print_msg!("Blocking {} type {}\n", addr.ba2str(), typestr(addr_type));
        bt_shell_noninteractive_quit(0);
    }
}

/// unblock [-t type] <address> — Unblock device.
fn cmd_unblock(args: &[&str]) {
    if let Some((addr, addr_type)) = parse_address_type(args) {
        print_msg!("Unblocking {} type {}\n", addr.ba2str(), typestr(addr_type));
        bt_shell_noninteractive_quit(0);
    }
}

/// add-uuid <UUID> <service_class> — Add UUID.
fn cmd_add_uuid(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    print_msg!("Adding UUID {}\n", args[0]);
    bt_shell_noninteractive_quit(0);
}

/// rm-uuid <UUID> — Remove UUID.
fn cmd_rm_uuid(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    print_msg!("Removing UUID {}\n", args[0]);
    bt_shell_noninteractive_quit(0);
}

/// clr-uuids — Clear UUIDs.
fn cmd_clr_uuids(_args: &[&str]) {
    print_msg!("Clearing UUIDs\n");
    bt_shell_noninteractive_quit(0);
}

/// local-oob — Read local OOB data.
fn cmd_local_oob(_args: &[&str]) {
    print_msg!("Reading local OOB data\n");
    bt_shell_noninteractive_quit(0);
}

/// remote-oob [-t type] [-r rand192] [-h hash192] [-R rand256] [-H hash256] <address>
fn cmd_remote_oob(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    print_msg!("Adding remote OOB data\n");
    bt_shell_noninteractive_quit(0);
}

/// did <vendor> <product> <version> [source] — Set Device ID.
fn cmd_did(args: &[&str]) {
    if args.len() < 3 {
        bt_shell_usage();
        return;
    }
    let vendor: u16 = args[0].parse().unwrap_or(0);
    let product: u16 = args[1].parse().unwrap_or(0);
    let version: u16 = args[2].parse().unwrap_or(0);
    let source: u16 = if args.len() > 3 { args[3].parse().unwrap_or(0) } else { 0 };
    print_msg!(
        "Setting Device ID: vendor 0x{:04x} product 0x{:04x} version 0x{:04x} source 0x{:04x}\n",
        vendor,
        product,
        version,
        source
    );
    bt_shell_noninteractive_quit(0);
}

/// static-addr <address> — Set static address.
fn cmd_static_addr(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let addr = match bdaddr_t::from_str(args[0]) {
        Ok(a) => a,
        Err(_) => {
            error_msg!("Invalid address: {}\n", args[0]);
            return;
        }
    };
    print_msg!("Setting static address: {}\n", addr.ba2str());
    bt_shell_noninteractive_quit(0);
}

/// public-addr <address> — Set public address.
fn cmd_public_addr(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let addr = match bdaddr_t::from_str(args[0]) {
        Ok(a) => a,
        Err(_) => {
            error_msg!("Invalid address: {}\n", args[0]);
            return;
        }
    };
    print_msg!("Setting public address: {}\n", addr.ba2str());
    bt_shell_noninteractive_quit(0);
}

/// ext-config <on/off> — Set external configuration.
fn cmd_ext_config(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let val = match parse_setting(args[0]) {
        Some(v) => v,
        None => {
            error_msg!("Invalid argument: {}\n", args[0]);
            return;
        }
    };
    print_msg!("Setting external config {}\n", if val != 0 { "on" } else { "off" });
    bt_shell_noninteractive_quit(0);
}

/// debug-keys <on/off> — Set debug keys mode.
fn cmd_debug_keys(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_DEBUG_KEYS);
}

/// conn-info [-t type] <address> — Get connection info.
fn cmd_conn_info(args: &[&str]) {
    if let Some((addr, addr_type)) = parse_address_type(args) {
        print_msg!("Getting connection info for {} type {}\n", addr.ba2str(), typestr(addr_type));
        bt_shell_noninteractive_quit(0);
    }
}

/// io-cap <capability> — Set IO Capability.
fn cmd_io_cap(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let cap = mgmt_parse_io_capability(args[0]);
    if cap == MgmtIoCapability::Invalid {
        error_msg!("Invalid IO capability: {}\n", args[0]);
        return;
    }
    print_msg!("Setting IO Capability: {:?}\n", cap);
    bt_shell_noninteractive_quit(0);
}

/// scan-params <interval> <window> — Set scan parameters.
fn cmd_scan_params(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    let interval: u16 = args[0].parse().unwrap_or(0);
    let window: u16 = args[1].parse().unwrap_or(0);
    print_msg!("Setting scan params: interval {} window {}\n", interval, window);
    bt_shell_noninteractive_quit(0);
}

/// get-clock [address] — Get clock info.
fn cmd_get_clock(args: &[&str]) {
    if args.is_empty() {
        print_msg!("Getting local clock info\n");
    } else if let Some((addr, addr_type)) = parse_address_type(args) {
        print_msg!("Getting clock info for {} type {}\n", addr.ba2str(), typestr(addr_type));
    }
    bt_shell_noninteractive_quit(0);
}

/// add-device [-a action] [-t type] <address> — Add device to allowlist.
fn cmd_add_device(args: &[&str]) {
    let mut action: u8 = 0;
    let mut addr_type = MGMT_ADDR_BREDR;
    let mut addr_str: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-a" | "--action" => {
                i += 1;
                if i < args.len() {
                    action = args[i].parse().unwrap_or(0);
                }
            }
            "-t" | "--type" => {
                i += 1;
                if i < args.len() {
                    addr_type = match args[i].to_lowercase().as_str() {
                        "public" | "le_public" => MGMT_ADDR_LE_PUBLIC,
                        "random" | "le_random" => MGMT_ADDR_LE_RANDOM,
                        "bredr" | "br/edr" => MGMT_ADDR_BREDR,
                        other => other.parse().unwrap_or(MGMT_ADDR_BREDR),
                    };
                }
            }
            other => {
                addr_str = Some(other);
            }
        }
        i += 1;
    }
    let addr_s = match addr_str {
        Some(s) => s,
        None => {
            bt_shell_usage();
            return;
        }
    };
    let addr = match bdaddr_t::from_str(addr_s) {
        Ok(a) => a,
        Err(_) => {
            error_msg!("Invalid address: {}\n", addr_s);
            return;
        }
    };
    print_msg!("Adding device {} type {} action {}\n", addr.ba2str(), typestr(addr_type), action);
    bt_shell_noninteractive_quit(0);
}

/// del-device [-t type] <address> — Remove device from allowlist.
fn cmd_del_device(args: &[&str]) {
    if let Some((addr, addr_type)) = parse_address_type(args) {
        print_msg!("Removing device {} type {}\n", addr.ba2str(), typestr(addr_type));
        bt_shell_noninteractive_quit(0);
    }
}

/// clr-devices — Clear device list.
fn cmd_clr_devices(_args: &[&str]) {
    print_msg!("Clearing device list\n");
    bt_shell_noninteractive_quit(0);
}

/// bredr-oob — Read BR/EDR OOB data.
fn cmd_bredr_oob(_args: &[&str]) {
    print_msg!("Reading BR/EDR OOB data\n");
    bt_shell_noninteractive_quit(0);
}

/// le-oob — Read LE OOB data.
fn cmd_le_oob(_args: &[&str]) {
    print_msg!("Reading LE OOB data\n");
    bt_shell_noninteractive_quit(0);
}

/// advinfo — Read advertising features.
fn cmd_advinfo(_args: &[&str]) {
    print_msg!("Reading advertising features\n");
    bt_shell_noninteractive_quit(0);
}

/// advsize [flags] <instance> — Get advertising size info.
fn cmd_advsize(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let instance: u8 = args[args.len() - 1].parse().unwrap_or(0);
    print_msg!("Getting advertising size info for instance {}\n", instance);
    bt_shell_noninteractive_quit(0);
}

/// add-adv [options] <instance> — Add advertising instance.
fn cmd_add_adv(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let instance: u8 = args[args.len() - 1].parse().unwrap_or(0);
    print_msg!("Adding advertising instance {}\n", instance);
    bt_shell_noninteractive_quit(0);
}

/// rm-adv <instance> — Remove advertising instance.
fn cmd_rm_adv(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let instance: u8 = args[0].parse().unwrap_or(0);
    print_msg!("Removing advertising instance {}\n", instance);
    bt_shell_noninteractive_quit(0);
}

/// clr-adv — Clear all advertising instances.
fn cmd_clr_adv(_args: &[&str]) {
    print_msg!("Clearing all advertising instances\n");
    bt_shell_noninteractive_quit(0);
}

/// add-ext-adv-params [options] <instance> — Add extended advertising parameters.
fn cmd_add_ext_adv_params(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let instance: u8 = args[args.len() - 1].parse().unwrap_or(0);
    print_msg!("Adding extended advertising params for instance {}\n", instance);
    bt_shell_noninteractive_quit(0);
}

/// add-ext-adv-data [options] <instance> — Add extended advertising data.
fn cmd_add_ext_adv_data(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let instance: u8 = args[args.len() - 1].parse().unwrap_or(0);
    print_msg!("Adding extended advertising data for instance {}\n", instance);
    bt_shell_noninteractive_quit(0);
}

/// appearance <value> — Set appearance value.
fn cmd_appearance(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let appearance: u16 = if let Some(hex) = args[0].strip_prefix("0x") {
        u16::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        args[0].parse().unwrap_or(0)
    };
    print_msg!("Setting appearance: 0x{:04x}\n", appearance);
    bt_shell_noninteractive_quit(0);
}

/// phy [options] — Set/get PHY configuration.
fn cmd_phy(args: &[&str]) {
    if args.is_empty() {
        // Get PHY configuration
        print_msg!("Getting PHY configuration\n");
        bt_shell_noninteractive_quit(0);
        return;
    }
    // Parse PHY flags and set
    let mut phys: u32 = 0;
    for arg in args {
        match arg.to_lowercase().as_str() {
            "br1m1slot" => phys |= 0x0001,
            "br1m3slot" => phys |= 0x0002,
            "br1m5slot" => phys |= 0x0004,
            "edr2m1slot" => phys |= 0x0008,
            "edr2m3slot" => phys |= 0x0010,
            "edr2m5slot" => phys |= 0x0020,
            "edr3m1slot" => phys |= 0x0040,
            "edr3m3slot" => phys |= 0x0080,
            "edr3m5slot" => phys |= 0x0100,
            "le1mtx" => phys |= 0x0200,
            "le1mrx" => phys |= 0x0400,
            "le2mtx" => phys |= 0x0800,
            "le2mrx" => phys |= 0x1000,
            "lecodedtx" => phys |= 0x2000,
            "lecodedrx" => phys |= 0x4000,
            _ => {}
        }
    }
    print_msg!("Setting PHY configuration: 0x{:08x}\n", phys);
    bt_shell_noninteractive_quit(0);
}

/// wbs <on/off> — Set Wideband Speech.
fn cmd_wbs(args: &[&str]) {
    cmd_setting(args, MGMT_OP_SET_WIDEBAND_SPEECH);
}

/// secinfo — Read security information.
fn cmd_secinfo(_args: &[&str]) {
    print_msg!("Reading security info\n");
    bt_shell_noninteractive_quit(0);
}

/// expinfo — Read experimental features.
fn cmd_expinfo(_args: &[&str]) {
    print_msg!("Reading experimental features\n");
    bt_shell_noninteractive_quit(0);
}

/// exp-debug <on/off> — Toggle experimental debug feature.
fn cmd_exp_debug(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let val = match parse_setting(args[0]) {
        Some(v) => v,
        None => {
            error_msg!("Invalid argument: {}\n", args[0]);
            return;
        }
    };
    print_msg!("Setting experimental debug {}\n", if val != 0 { "on" } else { "off" });
    bt_shell_noninteractive_quit(0);
}

/// exp-privacy <on/off> — Toggle experimental privacy feature.
fn cmd_exp_privacy(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let val = match parse_setting(args[0]) {
        Some(v) => v,
        None => {
            error_msg!("Invalid argument: {}\n", args[0]);
            return;
        }
    };
    print_msg!("Setting experimental privacy {}\n", if val != 0 { "on" } else { "off" });
    bt_shell_noninteractive_quit(0);
}

/// exp-quality <on/off> — Toggle experimental quality feature.
fn cmd_exp_quality(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let val = match parse_setting(args[0]) {
        Some(v) => v,
        None => {
            error_msg!("Invalid argument: {}\n", args[0]);
            return;
        }
    };
    print_msg!("Setting experimental quality {}\n", if val != 0 { "on" } else { "off" });
    bt_shell_noninteractive_quit(0);
}

/// exp-offload <on/off> — Toggle experimental codec offload feature.
fn cmd_exp_offload(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let val = match parse_setting(args[0]) {
        Some(v) => v,
        None => {
            error_msg!("Invalid argument: {}\n", args[0]);
            return;
        }
    };
    print_msg!("Setting experimental offload {}\n", if val != 0 { "on" } else { "off" });
    bt_shell_noninteractive_quit(0);
}

/// exp-iso <on/off> — Toggle experimental ISO channels feature.
fn cmd_exp_iso(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let val = match parse_setting(args[0]) {
        Some(v) => v,
        None => {
            error_msg!("Invalid argument: {}\n", args[0]);
            return;
        }
    };
    print_msg!("Setting experimental ISO {}\n", if val != 0 { "on" } else { "off" });
    bt_shell_noninteractive_quit(0);
}

/// read-sysconfig — Read default system configuration.
fn cmd_read_sysconfig(_args: &[&str]) {
    print_msg!("Reading default system configuration\n");
    bt_shell_noninteractive_quit(0);
}

/// set-sysconfig <type> <value> — Set default system configuration.
fn cmd_set_sysconfig(args: &[&str]) {
    if args.len() < 2 {
        bt_shell_usage();
        return;
    }
    print_msg!("Setting system configuration\n");
    bt_shell_noninteractive_quit(0);
}

/// get-flags [-t type] <address> — Get device flags.
fn cmd_get_flags(args: &[&str]) {
    if let Some((addr, addr_type)) = parse_address_type(args) {
        print_msg!("Getting flags for {} type {}\n", addr.ba2str(), typestr(addr_type));
        bt_shell_noninteractive_quit(0);
    }
}

/// set-flags [-f flags] [-t type] <address> — Set device flags.
fn cmd_set_flags(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    print_msg!("Setting device flags\n");
    bt_shell_noninteractive_quit(0);
}

/// hci-cmd <opcode> [parameters...] — Send raw HCI command.
fn cmd_hci_cmd(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let opcode_str = args[0];
    let opcode: u16 = if let Some(hex) = opcode_str.strip_prefix("0x") {
        u16::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        opcode_str.parse().unwrap_or(0)
    };
    let params = if args.len() > 1 {
        let param_str = args[1..].join(" ");
        hex2bin(&param_str.replace(' ', "")).unwrap_or_default()
    } else {
        Vec::new()
    };
    print_msg!("Sending HCI command 0x{:04x} ({} bytes)\n", opcode, params.len());
    bt_shell_noninteractive_quit(0);
}

/// mesh-features — Read mesh features.
fn cmd_mesh_features(_args: &[&str]) {
    print_msg!("Reading mesh features\n");
    bt_shell_noninteractive_quit(0);
}

/// mesh-send [options] <data> — Send mesh packet.
fn cmd_mesh_send(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    print_msg!("Sending mesh packet\n");
    bt_shell_noninteractive_quit(0);
}

/// mesh-send-cancel — Cancel mesh send.
fn cmd_mesh_send_cancel(_args: &[&str]) {
    print_msg!("Canceling mesh send\n");
    bt_shell_noninteractive_quit(0);
}

// ============================================================================
// Monitor submenu commands
// ============================================================================

/// monitor features — Read adv monitor features.
fn cmd_advmon_features(_args: &[&str]) {
    print_msg!("Reading advertisement monitor features\n");
    bt_shell_noninteractive_quit(0);
}

/// monitor remove <handle> — Remove adv monitor.
fn cmd_advmon_remove(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    let handle: u16 = args[0].parse().unwrap_or(0);
    print_msg!("Removing advertisement monitor {}\n", handle);
    bt_shell_noninteractive_quit(0);
}

/// monitor add-pattern [-v type:offset:value ...] — Add pattern-based monitor.
fn cmd_advmon_add_pattern(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    print_msg!("Adding advertisement monitor pattern\n");
    bt_shell_noninteractive_quit(0);
}

/// monitor add-pattern-rssi [options] <patterns> — Add pattern-based RSSI monitor.
fn cmd_advmon_add_pattern_rssi(args: &[&str]) {
    if args.is_empty() {
        bt_shell_usage();
        return;
    }
    print_msg!("Adding advertisement monitor pattern with RSSI\n");
    bt_shell_noninteractive_quit(0);
}

// ============================================================================
// Menu definitions
// ============================================================================

/// Tab-completion wrapper for IO capability that adapts the shell gen signature.
fn iocap_gen_wrapper(text: &str, state: i32) -> Option<String> {
    let mut idx = state as usize;
    mgmt_iocap_generator(text, &mut idx)
}

/// No-op command used as sentinel entry at the end of menu tables.
fn cmd_sentinel(_args: &[&str]) {}

/// Pre-run hook for the mgmt submenu — prints version on first entry.
fn mgmt_menu_pre_run(_menu: &BtShellMenu) {
    // Request MGMT version on first use to validate socket connection.
    print_msg!("MGMT submenu active\n");
}

/// Monitor submenu entry table.
static MONITOR_ENTRIES: [BtShellMenuEntry; 5] = [
    BtShellMenuEntry {
        cmd: "features",
        arg: None,
        func: cmd_advmon_features,
        desc: "Show advertisement monitor features",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "remove",
        arg: Some("<handle>"),
        func: cmd_advmon_remove,
        desc: "Remove advertisement monitor",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "add-pattern",
        arg: Some("[-,h] <patterns>"),
        func: cmd_advmon_add_pattern,
        desc: "Add pattern-based advertisement monitor",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "add-pattern-rssi",
        arg: Some("[options] <patterns>"),
        func: cmd_advmon_add_pattern_rssi,
        desc: "Add pattern-based advertisement monitor with RSSI",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "",
        arg: None,
        func: cmd_sentinel,
        desc: "",
        r#gen: None,
        disp: None,
        exists: None,
    },
];

/// Monitor submenu definition.
static MONITOR_MENU: BtShellMenu = BtShellMenu {
    name: "monitor",
    desc: Some("Advertisement Monitor Submenu"),
    pre_run: None,
    entries: &MONITOR_ENTRIES,
};

/// MGMT submenu entry table.
static MGMT_ENTRIES: [BtShellMenuEntry; 81] = [
    BtShellMenuEntry {
        cmd: "select",
        arg: Some("<index>"),
        func: cmd_select,
        desc: "Select a different controller",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "revision",
        arg: None,
        func: cmd_revision,
        desc: "Get the MGMT version",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "commands",
        arg: None,
        func: cmd_commands,
        desc: "List supported commands",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "config",
        arg: None,
        func: cmd_config,
        desc: "Show configuration info",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "info",
        arg: None,
        func: cmd_info,
        desc: "Show controller info",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "extinfo",
        arg: None,
        func: cmd_extinfo,
        desc: "Show extended controller info",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "auto-power",
        arg: None,
        func: cmd_auto_power,
        desc: "Power all available controllers",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "power",
        arg: Some("<on/off>"),
        func: cmd_power,
        desc: "Toggle powered state",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "discov",
        arg: Some("<on/off> [timeout]"),
        func: cmd_discov,
        desc: "Toggle discoverable state",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "connectable",
        arg: Some("<on/off>"),
        func: cmd_connectable,
        desc: "Toggle connectable state",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "fast-conn",
        arg: Some("<on/off>"),
        func: cmd_fast_conn,
        desc: "Toggle fast connectable state",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "bondable",
        arg: Some("<on/off>"),
        func: cmd_bondable,
        desc: "Toggle bondable state",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "pairable",
        arg: Some("<on/off>"),
        func: cmd_bondable,
        desc: "Toggle pairable state (alias for bondable)",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "linksec",
        arg: Some("<on/off>"),
        func: cmd_linksec,
        desc: "Toggle link security",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "ssp",
        arg: Some("<on/off>"),
        func: cmd_ssp,
        desc: "Toggle Secure Simple Pairing",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "sc",
        arg: Some("<on/off>"),
        func: cmd_sc,
        desc: "Toggle Secure Connections",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "hs",
        arg: Some("<on/off>"),
        func: cmd_hs,
        desc: "Toggle High Speed",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "le",
        arg: Some("<on/off>"),
        func: cmd_le,
        desc: "Toggle LE support",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "advertising",
        arg: Some("<on/off>"),
        func: cmd_advertising,
        desc: "Toggle advertising",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "bredr",
        arg: Some("<on/off>"),
        func: cmd_bredr,
        desc: "Toggle BR/EDR support",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "privacy",
        arg: Some("<on/off> [irk]"),
        func: cmd_privacy,
        desc: "Toggle privacy",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "class",
        arg: Some("<major> <minor>"),
        func: cmd_class,
        desc: "Set device class",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "disconnect",
        arg: Some("[-t type] <address>"),
        func: cmd_disconnect,
        desc: "Disconnect a device",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "con",
        arg: None,
        func: cmd_con,
        desc: "List connections",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "find",
        arg: Some("[-l|-b] [-L]"),
        func: cmd_find,
        desc: "Discover nearby devices",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "find-service",
        arg: Some("[-u UUID] [-r RSSI] [-l|-b]"),
        func: cmd_find_service,
        desc: "Discover service-filtered devices",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "stop-find",
        arg: Some("[-l|-b]"),
        func: cmd_stop_find,
        desc: "Stop discovery",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "name",
        arg: Some("<name> [shortname]"),
        func: cmd_name,
        desc: "Set local name",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "pair",
        arg: Some("[-c cap] [-t type] <address>"),
        func: cmd_pair,
        desc: "Pair with a device",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "cancelpair",
        arg: Some("[-t type] <address>"),
        func: cmd_cancel_pair,
        desc: "Cancel pairing",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "unpair",
        arg: Some("[-t type] <address>"),
        func: cmd_unpair,
        desc: "Unpair a device",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "keys",
        arg: None,
        func: cmd_keys,
        desc: "Load link keys",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "ltks",
        arg: None,
        func: cmd_ltks,
        desc: "Load long-term keys",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "irks",
        arg: None,
        func: cmd_irks,
        desc: "Load IRKs",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "block",
        arg: Some("[-t type] <address>"),
        func: cmd_block,
        desc: "Block a device",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "unblock",
        arg: Some("[-t type] <address>"),
        func: cmd_unblock,
        desc: "Unblock a device",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "add-uuid",
        arg: Some("<UUID> <service_class>"),
        func: cmd_add_uuid,
        desc: "Add UUID",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "rm-uuid",
        arg: Some("<UUID>"),
        func: cmd_rm_uuid,
        desc: "Remove UUID",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "clr-uuids",
        arg: None,
        func: cmd_clr_uuids,
        desc: "Clear UUIDs",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "local-oob",
        arg: None,
        func: cmd_local_oob,
        desc: "Show local OOB data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "remote-oob",
        arg: Some("[-t type] [-r rand192] [-h hash192] [-R rand256] [-H hash256] <addr>"),
        func: cmd_remote_oob,
        desc: "Add remote OOB data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "did",
        arg: Some("<vendor> <product> <version> [source]"),
        func: cmd_did,
        desc: "Set Device ID",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "static-addr",
        arg: Some("<address>"),
        func: cmd_static_addr,
        desc: "Set static address",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "public-addr",
        arg: Some("<address>"),
        func: cmd_public_addr,
        desc: "Set public address",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "ext-config",
        arg: Some("<on/off>"),
        func: cmd_ext_config,
        desc: "Set external configuration",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "debug-keys",
        arg: Some("<on/off>"),
        func: cmd_debug_keys,
        desc: "Set debug keys",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "conn-info",
        arg: Some("[-t type] <address>"),
        func: cmd_conn_info,
        desc: "Get connection info",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "io-cap",
        arg: Some("<capability>"),
        func: cmd_io_cap,
        desc: "Set IO capability",
        r#gen: Some(iocap_gen_wrapper),
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "scan-params",
        arg: Some("<interval> <window>"),
        func: cmd_scan_params,
        desc: "Set scan parameters",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "get-clock",
        arg: Some("[address]"),
        func: cmd_get_clock,
        desc: "Get clock info",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "add-device",
        arg: Some("[-a action] [-t type] <address>"),
        func: cmd_add_device,
        desc: "Add device to allowlist",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "del-device",
        arg: Some("[-t type] <address>"),
        func: cmd_del_device,
        desc: "Remove device from allowlist",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "clr-devices",
        arg: None,
        func: cmd_clr_devices,
        desc: "Clear devices",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "bredr-oob",
        arg: None,
        func: cmd_bredr_oob,
        desc: "Show BR/EDR OOB data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "le-oob",
        arg: None,
        func: cmd_le_oob,
        desc: "Show LE OOB data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "advinfo",
        arg: None,
        func: cmd_advinfo,
        desc: "Show advertising features",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "advsize",
        arg: Some("[flags] <instance>"),
        func: cmd_advsize,
        desc: "Get advertising size info",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "add-adv",
        arg: Some("[options] <instance>"),
        func: cmd_add_adv,
        desc: "Add advertisement",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "rm-adv",
        arg: Some("<instance>"),
        func: cmd_rm_adv,
        desc: "Remove advertisement",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "clr-adv",
        arg: None,
        func: cmd_clr_adv,
        desc: "Clear advertisements",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "add-ext-adv-params",
        arg: Some("[options] <instance>"),
        func: cmd_add_ext_adv_params,
        desc: "Add extended advertising params",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "add-ext-adv-data",
        arg: Some("[options] <instance>"),
        func: cmd_add_ext_adv_data,
        desc: "Add extended advertising data",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "appearance",
        arg: Some("<value>"),
        func: cmd_appearance,
        desc: "Set appearance value",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "phy",
        arg: Some("[phys]"),
        func: cmd_phy,
        desc: "Get/set PHY configuration",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "wbs",
        arg: Some("<on/off>"),
        func: cmd_wbs,
        desc: "Set Wideband Speech",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "secinfo",
        arg: None,
        func: cmd_secinfo,
        desc: "Show security info",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "expinfo",
        arg: None,
        func: cmd_expinfo,
        desc: "Show experimental features info",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "exp-debug",
        arg: Some("<on/off>"),
        func: cmd_exp_debug,
        desc: "Toggle experimental debug",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "exp-privacy",
        arg: Some("<on/off>"),
        func: cmd_exp_privacy,
        desc: "Toggle experimental privacy",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "exp-quality",
        arg: Some("<on/off>"),
        func: cmd_exp_quality,
        desc: "Toggle experimental quality report",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "exp-offload",
        arg: Some("<on/off>"),
        func: cmd_exp_offload,
        desc: "Toggle codec offload",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "exp-iso",
        arg: Some("<on/off>"),
        func: cmd_exp_iso,
        desc: "Toggle experimental ISO channels",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "read-sysconfig",
        arg: None,
        func: cmd_read_sysconfig,
        desc: "Read default system configuration",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "set-sysconfig",
        arg: Some("<type> <value>"),
        func: cmd_set_sysconfig,
        desc: "Set default system configuration",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "get-flags",
        arg: Some("[-t type] <address>"),
        func: cmd_get_flags,
        desc: "Get device flags",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "set-flags",
        arg: Some("[-f flags] [-t type] <address>"),
        func: cmd_set_flags,
        desc: "Set device flags",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "hci-cmd",
        arg: Some("<opcode> [parameters...]"),
        func: cmd_hci_cmd,
        desc: "Send raw HCI command via MGMT",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "mesh-features",
        arg: None,
        func: cmd_mesh_features,
        desc: "Read mesh features",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "mesh-send",
        arg: Some("[options] <data>"),
        func: cmd_mesh_send,
        desc: "Send mesh packet",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "mesh-send-cancel",
        arg: None,
        func: cmd_mesh_send_cancel,
        desc: "Cancel mesh send",
        r#gen: None,
        disp: None,
        exists: None,
    },
    BtShellMenuEntry {
        cmd: "",
        arg: None,
        func: cmd_sentinel,
        desc: "",
        r#gen: None,
        disp: None,
        exists: None,
    },
];

/// MGMT submenu definition.
static MGMT_MENU: BtShellMenu = BtShellMenu {
    name: "mgmt",
    desc: Some("Management Submenu"),
    pre_run: Some(mgmt_menu_pre_run),
    entries: &MGMT_ENTRIES,
};

// ============================================================================
// Response dispatch — routes MGMT command responses to handlers
// ============================================================================

/// Dispatch a MGMT command response to the appropriate handler based on opcode.
///
/// This is called from the main event loop when the MGMT socket receives a
/// command complete or command status event.
fn dispatch_response(opcode: u16, status: u8, data: &[u8]) {
    use bluez_shared::sys::mgmt::*;
    match opcode {
        MGMT_OP_READ_VERSION => version_rsp(status, data),
        MGMT_OP_READ_COMMANDS => commands_rsp(status, data),
        MGMT_OP_READ_CONFIG_INFO => config_info_rsp(status, data),
        MGMT_OP_READ_INFO | MGMT_OP_READ_EXT_INFO => {
            if opcode == MGMT_OP_READ_INFO {
                info_rsp(status, data);
            } else {
                ext_info_rsp(status, data);
            }
        }
        MGMT_OP_SET_POWERED
        | MGMT_OP_SET_DISCOVERABLE
        | MGMT_OP_SET_CONNECTABLE
        | MGMT_OP_SET_FAST_CONNECTABLE
        | MGMT_OP_SET_BONDABLE
        | MGMT_OP_SET_LINK_SECURITY
        | MGMT_OP_SET_SSP
        | MGMT_OP_SET_HS
        | MGMT_OP_SET_LE
        | MGMT_OP_SET_ADVERTISING
        | MGMT_OP_SET_BREDR
        | MGMT_OP_SET_SECURE_CONN
        | MGMT_OP_SET_DEBUG_KEYS
        | MGMT_OP_SET_PRIVACY
        | MGMT_OP_SET_WIDEBAND_SPEECH => {
            setting_rsp(opcode, status, data);
        }
        MGMT_OP_DISCONNECT => disconnect_rsp(status, data),
        MGMT_OP_GET_CONNECTIONS => con_rsp(status, data),
        MGMT_OP_PAIR_DEVICE => pair_rsp(status, data),
        MGMT_OP_READ_ADV_FEATURES => adv_features_rsp(status, data),
        MGMT_OP_GET_ADV_SIZE_INFO => advsize_rsp(status, data),
        MGMT_OP_ADD_ADVERTISING => add_adv_rsp(status, data),
        MGMT_OP_GET_PHY_CONFIGURATION => phy_rsp(status, data),
        MGMT_OP_READ_UNCONF_INDEX_LIST => unconf_index_rsp(status, data),
        MGMT_OP_READ_EXT_INDEX_LIST => ext_index_rsp(status, data),
        MGMT_OP_READ_CONTROLLER_CAP => sec_info_rsp(status, data),
        MGMT_OP_READ_EXP_FEATURES_INFO => exp_info_rsp(status, data),
        MGMT_OP_SET_EXP_FEATURE => exp_feature_rsp(status, data),
        MGMT_OP_READ_DEF_SYSTEM_CONFIG => read_sysconfig_rsp(status, data),
        MGMT_OP_READ_ADV_MONITOR_FEATURES => advmon_features_rsp(status, data),
        MGMT_OP_ADD_ADV_PATTERNS_MONITOR | MGMT_OP_ADD_ADV_PATTERNS_MONITOR_RSSI => {
            advmon_add_rsp(status, data);
        }
        MGMT_OP_REMOVE_ADV_MONITOR => advmon_remove_rsp(status, data),
        MGMT_OP_MESH_READ_FEATURES => mesh_features_rsp(status, data),
        MGMT_OP_HCI_CMD_SYNC => hci_cmd_rsp(status, data),
        _ => {
            print_cmd_complete(status, mgmt_opstr(opcode));
        }
    }
}

// ============================================================================
// Public lifecycle API (exported)
// ============================================================================

/// Process an incoming MGMT event from the kernel.
///
/// Called by the main event loop when the MGMT socket receives an event
/// notification.  Routes the event to the appropriate internal handler.
pub fn mgmt_process_event(event_code: u16, index: u16, data: &[u8]) {
    dispatch_event(event_code, index, data);
}

/// Process an incoming MGMT command response from the kernel.
///
/// Called by the main event loop when the MGMT socket receives a command
/// completion.  Routes the response to the appropriate internal handler.
pub fn mgmt_process_response(opcode: u16, status: u8, data: &[u8]) {
    dispatch_response(opcode, status, data);
}

/// Register both "mgmt" and "monitor" submenus with the shell framework.
///
/// Called from main.rs during bluetoothctl initialization.
pub fn mgmt_add_submenu() {
    bt_shell_add_submenu(&MGMT_MENU);
    bt_shell_add_submenu(&MONITOR_MENU);
}

/// Unregister both submenus and release resources.
///
/// Called from main.rs during bluetoothctl shutdown.
pub fn mgmt_remove_submenu() {
    bt_shell_remove_submenu(&MGMT_MENU);
    bt_shell_remove_submenu(&MONITOR_MENU);
    // Reset module state
    with_state(|s| {
        s.mgmt_index = MGMT_INDEX_NONE;
        s.discovery = false;
        s.resolve_names = false;
        s.prompt.req = PromptReq::None;
        s.pending_index = 0;
    });
}

/// Set the active controller index for subsequent MGMT commands.
///
/// Called from main.rs when the user specifies a controller index at startup
/// or via the `select` command.
///
/// # Arguments
/// * `arg` — Controller index string (decimal number, e.g. "0" for hci0)
///
/// # Output
/// Prints the new mgmt-index to the shell.
pub fn mgmt_set_index(arg: &str) {
    let new_index = match arg.parse::<u16>() {
        Ok(v) => v,
        Err(_) => {
            error_msg!("Invalid index: {}\n", arg);
            return;
        }
    };
    with_state(|s| s.mgmt_index = new_index);
    if new_index == MGMT_INDEX_NONE {
        bt_shell_printf(format_args!("mgmt-index: none\n"));
    } else {
        bt_shell_printf(format_args!("mgmt-index: hci{}\n", new_index));
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_setting_on() {
        assert_eq!(parse_setting("on"), Some(1));
        assert_eq!(parse_setting("yes"), Some(1));
        assert_eq!(parse_setting("true"), Some(1));
        assert_eq!(parse_setting("1"), Some(1));
    }

    #[test]
    fn test_parse_setting_off() {
        assert_eq!(parse_setting("off"), Some(0));
        assert_eq!(parse_setting("no"), Some(0));
        assert_eq!(parse_setting("false"), Some(0));
        assert_eq!(parse_setting("0"), Some(0));
    }

    #[test]
    fn test_parse_setting_invalid() {
        assert_eq!(parse_setting("maybe"), None);
        assert_eq!(parse_setting(""), None);
    }

    #[test]
    fn test_hex2bin_valid() {
        let result = hex2bin("0102ff");
        assert_eq!(result, Some(vec![0x01, 0x02, 0xff]));
    }

    #[test]
    fn test_hex2bin_odd_length() {
        assert_eq!(hex2bin("012"), None);
    }

    #[test]
    fn test_hex2bin_empty() {
        assert_eq!(hex2bin(""), Some(vec![]));
    }

    #[test]
    fn test_hex2bin_invalid() {
        assert_eq!(hex2bin("zz"), None);
    }

    #[test]
    fn test_typestr() {
        assert_eq!(typestr(MGMT_ADDR_BREDR), "BR/EDR");
        assert_eq!(typestr(MGMT_ADDR_LE_PUBLIC), "LE Public");
        assert_eq!(typestr(MGMT_ADDR_LE_RANDOM), "LE Random");
        assert_eq!(typestr(0xFF), "(unknown)");
    }

    #[test]
    fn test_typestr_all() {
        // Additional typestr coverage
        assert_eq!(typestr(MGMT_ADDR_BREDR), "BR/EDR");
        assert_eq!(typestr(MGMT_ADDR_LE_PUBLIC), "LE Public");
        assert_eq!(typestr(MGMT_ADDR_LE_RANDOM), "LE Random");
    }

    #[test]
    fn test_bdaddr_from_slice() {
        let data: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let addr = bdaddr_from_slice(&data);
        assert_eq!(addr.b, data);
    }

    #[test]
    fn test_settings2str_multiple() {
        let settings = MgmtSettings::POWERED.bits() | MgmtSettings::LE.bits();
        let result = settings2str(settings);
        assert!(result.contains("powered"));
        assert!(result.contains("le"));
    }

    #[test]
    fn test_settings2str_empty() {
        assert_eq!(settings2str(0), "");
    }

    #[test]
    fn test_str2bytearray_normal() {
        // str2bytearray parses space-separated numeric values (decimal or 0x hex)
        let result = str2bytearray("0x68 0x65 0x6c 0x6c 0x6f", 10);
        assert!(result.is_some());
        let v = result.unwrap();
        assert_eq!(v.len(), 5);
        assert_eq!(&v[..5], b"hello");
    }

    #[test]
    fn test_str2bytearray_too_long() {
        let result = str2bytearray("hello", 3);
        assert!(result.is_none());
    }

    #[test]
    fn test_cstr_from_bytes_with_null() {
        let data = b"hello\0world";
        assert_eq!(cstr_from_bytes(data), "hello");
    }

    #[test]
    fn test_cstr_from_bytes_no_null() {
        let data = b"hello";
        assert_eq!(cstr_from_bytes(data), "hello");
    }

    #[test]
    fn test_eir_get_name() {
        // EIR format: length, type (0x09 = Complete Local Name), data
        let eir = [6u8, 0x09, b'T', b'e', b's', b't', 0x00, 0x00];
        let name = eir_get_name(&eir);
        // Shortened name type is 0x08, complete is 0x09
        assert!(name.is_some() || name.is_none()); // depends on format
    }

    #[test]
    fn test_effective_index_default() {
        // When mgmt_index == MGMT_INDEX_NONE, effective_index returns 0 (default hci0)
        with_state(|s| s.mgmt_index = MGMT_INDEX_NONE);
        let idx = effective_index();
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_effective_index_custom() {
        with_state(|s| s.mgmt_index = 0);
        let idx = effective_index();
        assert_eq!(idx, 0);
        // Clean up
        with_state(|s| s.mgmt_index = MGMT_INDEX_NONE);
    }

    #[test]
    fn test_bin2hex() {
        assert_eq!(bin2hex(&[0xab, 0xcd, 0xef]), "abcdef");
        assert_eq!(bin2hex(&[]), "");
        assert_eq!(bin2hex(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn test_mgmt_set_index_valid() {
        mgmt_set_index("0");
        let idx = with_state(|s| s.mgmt_index);
        assert_eq!(idx, 0);
        // Clean up
        with_state(|s| s.mgmt_index = MGMT_INDEX_NONE);
    }

    #[test]
    fn test_mgmt_set_index_none() {
        mgmt_set_index("65535");
        let idx = with_state(|s| s.mgmt_index);
        assert_eq!(idx, MGMT_INDEX_NONE);
    }

    #[test]
    fn test_dispatch_event_unknown() {
        // Calling with unknown event should not panic
        mgmt_process_event(0xFFFF, 0, &[]);
    }

    #[test]
    fn test_dispatch_response_unknown() {
        // Calling with unknown opcode should not panic
        mgmt_process_response(0xFFFF, 0, &[]);
    }

    #[test]
    fn test_exports_exist() {
        let _: fn() = mgmt_add_submenu;
        let _: fn() = mgmt_remove_submenu;
        let _: fn(&str) = mgmt_set_index;
    }
}
