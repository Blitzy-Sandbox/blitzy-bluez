// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2000-2001  Qualcomm Incorporated
// Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
// Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>

//! Configuration model and INI parser for the `bluetoothd` daemon.
//!
//! This module is a complete Rust rewrite of the configuration parsing
//! portions of `src/main.c` and the configuration structures defined in
//! `src/btd.h` from the BlueZ C codebase.
//!
//! The configuration file `main.conf` (typically found at
//! `/etc/bluetooth/main.conf`) is parsed using the `rust-ini` crate with
//! identical section/key semantics and default values as the original
//! GLib `GKeyFile`-based C implementation.
//!
//! # Configuration Sections
//!
//! - `[General]` — Name, Class, DiscoverableTimeout, AlwaysPairable, etc.
//! - `[BR]` — BR/EDR scanning and page parameters.
//! - `[LE]` — LE advertisement, scan, and connection parameters.
//! - `[Policy]` — Reconnection UUIDs, attempts, intervals, AutoEnable.
//! - `[GATT]` — GATT cache, MTU, channels, export settings.
//! - `[CSIS]` — CSIS SIRK, encryption, set size and rank.
//! - `[AVDTP]` — AVDTP session and stream transport modes.
//! - `[AVRCP]` — AVRCP volume handling options.
//! - `[AdvMon]` — Advertisement monitor RSSI sampling period.
//!
//! # Key Rules
//!
//! - Configuration key names, section names, and default values are
//!   **never changed** from the C original (per AAP §0.7.9, §0.8.2).
//! - Unknown keys and groups produce warnings matching C behaviour.
//! - Absent keys use identical default values as the C code.

use crate::log::{btd_debug, btd_error, btd_warn};
use bluez_shared::att::types::{BT_ATT_DEFAULT_LE_MTU, BT_ATT_MAX_LE_MTU};
use bluez_shared::crypto::aes_cmac::bt_crypto_sirk;
use bluez_shared::socket::L2capMode;

use ini::Ini;
use tracing::{debug, error, info, warn};

use std::env;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Constants — matching C #define values from src/main.c
// ---------------------------------------------------------------------------

/// Default pairable timeout in seconds (disabled).
const DEFAULT_PAIRABLE_TIMEOUT: u32 = 0;

/// Default discoverable timeout in seconds (3 minutes).
const DEFAULT_DISCOVERABLE_TIMEOUT: u32 = 180;

/// Default temporary device timeout in seconds.
const DEFAULT_TEMPORARY_TIMEOUT: u32 = 30;

/// Default remote name request retry delay in seconds (5 minutes).
const DEFAULT_NAME_REQUEST_RETRY_DELAY: u32 = 300;

/// BlueZ version string.  In the C code this is the autotools VERSION
/// macro; here we derive it from the crate version at compile time.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration directory when CONFIGURATION_DIRECTORY is not set.
/// In the C code this comes from the autotools CONFIGDIR define.
const CONFIGDIR: &str = "/etc/bluetooth";

// ---------------------------------------------------------------------------
// Valid KernelExperimental UUIDs
// ---------------------------------------------------------------------------

/// UUIDs accepted by the `KernelExperimental` configuration key.
/// Matches the C `valid_uuids[]` array in src/main.c.
const VALID_KERNEL_UUIDS: &[&str] = &[
    "d4992530-b9ec-469f-ab01-6c481c47da1c",
    "671b10b5-42c0-4696-9227-eb28d1b049d6",
    "15c0a148-c273-11ea-b3de-0242ac130004",
    "330859bc-7506-492d-9370-9a6f0614037f",
    "a6695ace-ee7f-4fb9-881a-5fac66c629af",
    "6fbaf188-05e0-496a-9885-d6ddfdb4e03e",
    "*",
];

// ---------------------------------------------------------------------------
// Supported options tables — matching C supported_options[], br_options[],
// le_options[], policy_options[], gatt_options[], csip_options[],
// avdtp_options[], avrcp_options[], advmon_options[]
// ---------------------------------------------------------------------------

const SUPPORTED_OPTIONS: &[&str] = &[
    "Name",
    "Class",
    "DiscoverableTimeout",
    "AlwaysPairable",
    "PairableTimeout",
    "DeviceID",
    "ReverseServiceDiscovery",
    "NameResolving",
    "DebugKeys",
    "ControllerMode",
    "MaxControllers",
    "MultiProfile",
    "FastConnectable",
    "SecureConnections",
    "Privacy",
    "JustWorksRepairing",
    "TemporaryTimeout",
    "RefreshDiscovery",
    "Experimental",
    "Testing",
    "KernelExperimental",
    "RemoteNameRequestRetryDelay",
    "FilterDiscoverable",
];

const BR_OPTIONS: &[&str] = &[
    "PageScanType",
    "PageScanInterval",
    "PageScanWindow",
    "InquiryScanType",
    "InquiryScanInterval",
    "InquiryScanWindow",
    "LinkSupervisionTimeout",
    "PageTimeout",
    "IdleTimeout",
    "MinSniffInterval",
    "MaxSniffInterval",
];

const LE_OPTIONS: &[&str] = &[
    "CentralAddressResolution",
    "MinAdvertisementInterval",
    "MaxAdvertisementInterval",
    "MultiAdvertisementRotationInterval",
    "ScanIntervalAutoConnect",
    "ScanWindowAutoConnect",
    "ScanIntervalSuspend",
    "ScanWindowSuspend",
    "ScanIntervalDiscovery",
    "ScanWindowDiscovery",
    "ScanIntervalAdvMonitor",
    "ScanWindowAdvMonitor",
    "ScanIntervalConnect",
    "ScanWindowConnect",
    "MinConnectionInterval",
    "MaxConnectionInterval",
    "ConnectionLatency",
    "ConnectionSupervisionTimeout",
    "Autoconnecttimeout",
    "AdvMonAllowlistScanDuration",
    "AdvMonNoFilterScanDuration",
    "EnableAdvMonInterleaveScan",
];

const POLICY_OPTIONS: &[&str] =
    &["ReconnectUUIDs", "ReconnectAttempts", "ReconnectIntervals", "AutoEnable", "ResumeDelay"];

const GATT_OPTIONS: &[&str] =
    &["Cache", "KeySize", "ExchangeMTU", "Channels", "Client", "ExportClaimedServices"];

const CSIP_OPTIONS: &[&str] = &["SIRK", "Encryption", "Size", "Rank"];

const AVDTP_OPTIONS: &[&str] = &["SessionMode", "StreamMode"];

const AVRCP_OPTIONS: &[&str] = &["VolumeWithoutTarget", "VolumeCategory"];

const ADVMON_OPTIONS: &[&str] = &["RSSISamplingPeriod"];

/// Mapping of section names to their supported options.
const VALID_GROUPS: &[(&str, &[&str])] = &[
    ("General", SUPPORTED_OPTIONS),
    ("BR", BR_OPTIONS),
    ("LE", LE_OPTIONS),
    ("Policy", POLICY_OPTIONS),
    ("GATT", GATT_OPTIONS),
    ("CSIS", CSIP_OPTIONS),
    ("AVDTP", AVDTP_OPTIONS),
    ("AVRCP", AVRCP_OPTIONS),
    ("AdvMon", ADVMON_OPTIONS),
];

// ---------------------------------------------------------------------------
// Configuration Enums — from btd.h
// ---------------------------------------------------------------------------

/// Bluetooth controller mode selection.
///
/// Corresponds to C `bt_mode_t` in `btd.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BtMode {
    /// Dual-mode (BR/EDR + LE).
    #[default]
    Dual,
    /// BR/EDR only.
    Bredr,
    /// LE only.
    Le,
}

/// GATT cache mode.
///
/// Corresponds to C `bt_gatt_cache_t` in `btd.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BtGattCache {
    /// Always cache GATT database.
    #[default]
    Always,
    /// Cache GATT database (weaker than Always).
    Yes,
    /// Never cache GATT database.
    No,
}

/// Just Works repairing policy.
///
/// Corresponds to C `enum jw_repairing_t` in `btd.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JwRepairing {
    /// Never allow Just Works repairing.
    #[default]
    Never,
    /// Allow Just Works repairing with user confirmation.
    Confirm,
    /// Always allow Just Works repairing.
    Always,
}

/// Multi-profile mode selection.
///
/// Corresponds to C `enum mps_mode_t` in `btd.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MpsMode {
    /// Multi-profile disabled.
    #[default]
    Off,
    /// Single multi-profile connection.
    Single,
    /// Multiple multi-profile connections.
    Multiple,
}

/// Secure Connections mode selection.
///
/// Corresponds to C `enum sc_mode_t` in `btd.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScMode {
    /// Secure Connections disabled.
    Off,
    /// Secure Connections enabled.
    #[default]
    On,
    /// Secure Connections only.
    Only,
}

/// GATT service export policy.
///
/// Corresponds to C `enum bt_gatt_export_t` in `btd.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BtGattExport {
    /// Do not export claimed GATT services.
    Off,
    /// Export claimed GATT services as read-only.
    #[default]
    ReadOnly,
    /// Export claimed GATT services as read-write.
    ReadWrite,
}

// ---------------------------------------------------------------------------
// Configuration Structs — from btd.h
// ---------------------------------------------------------------------------

/// BR/EDR default parameter configuration.
///
/// Corresponds to C `struct btd_br_defaults` in `btd.h`.
#[derive(Debug, Clone)]
pub struct BtdBrDefaults {
    /// Page scan type (0 = standard, 1 = interlaced). Default: 0xFFFF (unset).
    pub page_scan_type: u16,
    /// Page scan interval (range: 0x0012-0x1000). Default: 0.
    pub page_scan_interval: u16,
    /// Page scan window (range: 0x0011-0x1000). Default: 0.
    pub page_scan_win: u16,
    /// Inquiry scan type (0 = standard, 1 = interlaced). Default: 0xFFFF (unset).
    pub scan_type: u16,
    /// Inquiry scan interval (range: 0x0012-0x1000). Default: 0.
    pub scan_interval: u16,
    /// Inquiry scan window (range: 0x0011-0x1000). Default: 0.
    pub scan_win: u16,
    /// Link supervision timeout (range: 0x0001-0xFFFF). Default: 0.
    pub link_supervision_timeout: u16,
    /// Page timeout (range: 0x0001-0xFFFF). Default: 0.
    pub page_timeout: u16,
    /// Minimum sniff interval (range: 0x0001-0xFFFE). Default: 0.
    pub min_sniff_interval: u16,
    /// Maximum sniff interval (range: 0x0001-0xFFFE). Default: 0.
    pub max_sniff_interval: u16,
    /// Idle timeout in milliseconds (range: 500-3600000). Default: 0.
    pub idle_timeout: u32,
}

impl Default for BtdBrDefaults {
    fn default() -> Self {
        Self {
            page_scan_type: 0xFFFF,
            page_scan_interval: 0,
            page_scan_win: 0,
            scan_type: 0xFFFF,
            scan_interval: 0,
            scan_win: 0,
            link_supervision_timeout: 0,
            page_timeout: 0,
            min_sniff_interval: 0,
            max_sniff_interval: 0,
            idle_timeout: 0,
        }
    }
}

/// LE default parameter configuration.
///
/// Corresponds to C `struct btd_le_defaults` in `btd.h`.
#[derive(Debug, Clone)]
pub struct BtdLeDefaults {
    /// Central address resolution support (0 or 1). Default: 1.
    pub addr_resolution: u8,
    /// Minimum advertisement interval (range: 0x0020-0x4000). Default: 0.
    pub min_adv_interval: u16,
    /// Maximum advertisement interval (range: 0x0020-0x4000). Default: 0.
    pub max_adv_interval: u16,
    /// Multi-advertisement rotation interval (range: 0x0001-0xFFFF). Default: 0.
    pub adv_rotation_interval: u16,
    /// Auto-connect scan interval (range: 0x0004-0x4000). Default: 0.
    pub scan_interval_autoconnect: u16,
    /// Auto-connect scan window (range: 0x0004-0x4000). Default: 0.
    pub scan_win_autoconnect: u16,
    /// Suspend scan interval (range: 0x0004-0x4000). Default: 0.
    pub scan_interval_suspend: u16,
    /// Suspend scan window (range: 0x0004-0x4000). Default: 0.
    pub scan_win_suspend: u16,
    /// Discovery scan interval (range: 0x0004-0x4000). Default: 0.
    pub scan_interval_discovery: u16,
    /// Discovery scan window (range: 0x0004-0x4000). Default: 0.
    pub scan_win_discovery: u16,
    /// Advertisement monitor scan interval (range: 0x0004-0x4000). Default: 0.
    pub scan_interval_adv_monitor: u16,
    /// Advertisement monitor scan window (range: 0x0004-0x4000). Default: 0.
    pub scan_win_adv_monitor: u16,
    /// Connect scan interval (range: 0x0004-0x4000). Default: 0.
    pub scan_interval_connect: u16,
    /// Connect scan window (range: 0x0004-0x4000). Default: 0.
    pub scan_win_connect: u16,
    /// Minimum connection interval (range: 0x0006-0x0C80). Default: 0.
    pub min_conn_interval: u16,
    /// Maximum connection interval (range: 0x0006-0x0C80). Default: 0.
    pub max_conn_interval: u16,
    /// Connection latency (range: 0x0000-0x01F3). Default: 0.
    pub conn_latency: u16,
    /// Connection link supervision timeout (range: 0x000A-0x0C80). Default: 0.
    pub conn_lsto: u16,
    /// Auto-connect timeout (range: 0x0001-0x4000). Default: 0.
    pub autoconnect_timeout: u16,
    /// Advertisement monitor allowlist scan duration (range: 1-10000). Default: 0.
    pub advmon_allowlist_scan_duration: u16,
    /// Advertisement monitor no-filter scan duration (range: 1-10000). Default: 0.
    pub advmon_no_filter_scan_duration: u16,
    /// Enable advertisement monitor interleave scan (0 or 1). Default: 0xFF (unset).
    pub enable_advmon_interleave_scan: bool,
}

impl Default for BtdLeDefaults {
    fn default() -> Self {
        Self {
            addr_resolution: 0x01,
            min_adv_interval: 0,
            max_adv_interval: 0,
            adv_rotation_interval: 0,
            scan_interval_autoconnect: 0,
            scan_win_autoconnect: 0,
            scan_interval_suspend: 0,
            scan_win_suspend: 0,
            scan_interval_discovery: 0,
            scan_win_discovery: 0,
            scan_interval_adv_monitor: 0,
            scan_win_adv_monitor: 0,
            scan_interval_connect: 0,
            scan_win_connect: 0,
            min_conn_interval: 0,
            max_conn_interval: 0,
            conn_latency: 0,
            conn_lsto: 0,
            autoconnect_timeout: 0,
            advmon_allowlist_scan_duration: 0,
            advmon_no_filter_scan_duration: 0,
            enable_advmon_interleave_scan: false,
        }
    }
}

/// Combined BR/EDR and LE default parameter configuration.
///
/// Corresponds to C `struct btd_defaults` in `btd.h`.
#[derive(Debug, Clone, Default)]
pub struct BtdDefaults {
    /// BR/EDR defaults.
    pub br: BtdBrDefaults,
    /// LE defaults.
    pub le: BtdLeDefaults,
}

/// CSIS (Coordinated Set Identification Service) configuration.
///
/// Corresponds to C `struct btd_csis` in `btd.h`.
#[derive(Debug, Clone)]
pub struct BtdCsis {
    /// 128-bit Set Identity Resolving Key.
    pub sirk: [u8; 16],
    /// Whether SIRK encryption is enabled.
    pub encrypt: bool,
    /// Coordinated set size.
    pub size: u8,
    /// Coordinated set rank.
    pub rank: u8,
}

impl Default for BtdCsis {
    fn default() -> Self {
        Self { sirk: [0u8; 16], encrypt: true, size: 0, rank: 0 }
    }
}

/// AVDTP transport mode options.
///
/// Corresponds to C `struct btd_avdtp_opts` in `btd.h`.
#[derive(Debug, Clone)]
pub struct BtdAvdtpOpts {
    /// Session transport mode (L2capMode value as u8).
    pub session_mode: u8,
    /// Stream transport mode (L2capMode value as u8).
    pub stream_mode: u8,
}

impl Default for BtdAvdtpOpts {
    fn default() -> Self {
        Self { session_mode: L2capMode::Basic as u8, stream_mode: L2capMode::Basic as u8 }
    }
}

/// AVRCP options.
///
/// Corresponds to C `struct btd_avrcp_opts` in `btd.h`.
#[derive(Debug, Clone)]
pub struct BtdAvrcpOpts {
    /// Allow volume control without an explicit target.
    pub volume_without_target: bool,
    /// Volume category enabled.
    pub volume_category: bool,
}

impl Default for BtdAvrcpOpts {
    fn default() -> Self {
        Self { volume_without_target: false, volume_category: true }
    }
}

/// Advertisement monitor options.
///
/// Corresponds to C `struct btd_advmon_opts` in `btd.h`.
#[derive(Debug, Clone)]
pub struct BtdAdvmonOpts {
    /// RSSI sampling period (0x00-0xFF). Default: 0xFF.
    pub rssi_sampling_period: u8,
}

impl Default for BtdAdvmonOpts {
    fn default() -> Self {
        Self { rssi_sampling_period: 0xFF }
    }
}

/// Master configuration structure for the bluetoothd daemon.
///
/// Corresponds to C `struct btd_opts` in `btd.h`. Contains all parsed
/// configuration values from `main.conf` plus computed defaults.
#[derive(Debug, Clone)]
pub struct BtdOpts {
    /// Adapter name. Default: "BlueZ <version>".
    pub name: Option<String>,
    /// Device class (24-bit, parsed from hex). Default: 0x000000.
    pub class: u32,
    /// Whether the adapter is always pairable.
    pub pairable: bool,
    /// Pairable timeout in seconds. Default: 0 (disabled).
    pub pairto: u32,
    /// Discoverable timeout in seconds. Default: 180.
    pub discovto: u32,
    /// Temporary device timeout in seconds. Default: 30.
    pub tmpto: u32,
    /// Privacy mode (0x00=off, 0x01=network/device, 0x02=limited-device).
    pub privacy: u8,
    /// Device privacy enabled.
    pub device_privacy: bool,
    /// Remote name request retry delay in seconds. Default: 300.
    pub name_request_retry_delay: u32,
    /// Reverse service discovery enabled. Default: true.
    pub reverse_sdp: bool,
    /// Name resolving enabled. Default: true.
    pub name_resolv: bool,
    /// Debug keys enabled.
    pub debug_keys: bool,
    /// Fast connectable mode enabled.
    pub fast_conn: bool,
    /// Refresh discovery enabled. Default: true.
    pub refresh_discovery: bool,
    /// Experimental interfaces enabled.  `-E, --experimental` flag.
    pub experimental: bool,
    /// Testing interfaces enabled.  `-T, --testing` flag.
    pub testing: bool,
    /// Filter discoverable devices. Default: true.
    pub filter_discoverable: bool,
    /// Kernel experimental feature UUIDs.
    pub kernel: Vec<String>,
    /// Device ID source (0x0000=none, 0x0001=bluetooth, 0x0002=usb).
    pub did_source: u16,
    /// Device ID vendor.
    pub did_vendor: u16,
    /// Device ID product.
    pub did_product: u16,
    /// Device ID version.
    pub did_version: u16,
    /// Controller mode.
    pub mode: BtMode,
    /// Multi-profile mode.
    pub mps: MpsMode,
    /// Just Works repairing policy.
    pub jw_repairing: JwRepairing,
    /// Secure connections mode.
    pub secure_conn: ScMode,
    /// BR/EDR and LE default parameters.
    pub defaults: BtdDefaults,
    /// GATT cache mode.
    pub gatt_cache: BtGattCache,
    /// GATT maximum MTU. Default: BT_ATT_MAX_LE_MTU (517).
    pub gatt_mtu: u16,
    /// GATT L2CAP channels (range: 1-6). Default: 1.
    pub gatt_channels: u8,
    /// GATT client enabled. Default: true.
    pub gatt_client: bool,
    /// GATT minimum encryption key size (range: 7-16).
    pub key_size: u8,
    /// GATT service export policy.
    pub gatt_export: BtGattExport,
    /// CSIS configuration.
    pub csis: BtdCsis,
    /// AVDTP transport options.
    pub avdtp: BtdAvdtpOpts,
    /// AVRCP options.
    pub avrcp: BtdAvrcpOpts,
    /// Advertisement monitor options.
    pub advmon: BtdAdvmonOpts,
    /// Maximum number of adapters. Default: 0 (unlimited).
    pub max_adapters: u16,
    /// UUIDs for automatic reconnection.
    pub reconnect_uuids: Vec<String>,
    /// Maximum reconnection attempts.
    pub reconnect_attempts: u8,
    /// Reconnection interval schedule in seconds.
    pub reconnect_intervals: Vec<u32>,
    /// Auto-enable adapter on startup.
    pub auto_enable: bool,
    /// Resume delay in seconds after suspend.
    pub resume_delay: u32,
}

impl Default for BtdOpts {
    fn default() -> Self {
        Self {
            name: None,
            class: 0x000000,
            pairable: false,
            pairto: DEFAULT_PAIRABLE_TIMEOUT,
            discovto: DEFAULT_DISCOVERABLE_TIMEOUT,
            tmpto: DEFAULT_TEMPORARY_TIMEOUT,
            privacy: 0x00,
            device_privacy: false,
            name_request_retry_delay: DEFAULT_NAME_REQUEST_RETRY_DELAY,
            reverse_sdp: true,
            name_resolv: true,
            debug_keys: false,
            fast_conn: false,
            refresh_discovery: true,
            experimental: false,
            testing: false,
            filter_discoverable: true,
            kernel: Vec::new(),
            did_source: 0x0000,
            did_vendor: 0x0000,
            did_product: 0x0000,
            did_version: 0x0000,
            mode: BtMode::default(),
            mps: MpsMode::default(),
            jw_repairing: JwRepairing::default(),
            secure_conn: ScMode::default(),
            defaults: BtdDefaults::default(),
            gatt_cache: BtGattCache::default(),
            gatt_mtu: BT_ATT_MAX_LE_MTU,
            gatt_channels: 1,
            gatt_client: true,
            key_size: 0,
            gatt_export: BtGattExport::default(),
            csis: BtdCsis::default(),
            avdtp: BtdAvdtpOpts::default(),
            avrcp: BtdAvrcpOpts::default(),
            advmon: BtdAdvmonOpts::default(),
            max_adapters: 0,
            reconnect_uuids: Vec::new(),
            reconnect_attempts: 0,
            reconnect_intervals: Vec::new(),
            auto_enable: false,
            resume_delay: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Initialization — init_defaults()
// ---------------------------------------------------------------------------

/// Initialize a `BtdOpts` with all C-default values.
///
/// This replicates the C `init_defaults()` function from `src/main.c` lines
/// 1234-1281, setting all configuration values to their defaults before any
/// INI parsing occurs.
///
/// The `name` field defaults to `"BlueZ <major>.<minor>"` derived from the
/// crate version.  The Device ID fields are set to USB (source=0x0002),
/// Linux Foundation (vendor=0x1d6b), BlueZ (product=0x0246) with the
/// version encoded as (major << 8 | minor).
pub fn init_defaults() -> BtdOpts {
    // Parse major.minor from the version string for DID encoding.
    let (major, minor) = parse_version(VERSION);
    let did_version = (u16::from(major) << 8) | u16::from(minor);

    BtdOpts {
        // Default name: "BlueZ <version>"
        name: Some(format!("BlueZ {VERSION}")),
        // Default Device ID fields — matches C init_defaults() exactly
        did_source: 0x0002,  // USB
        did_vendor: 0x1d6b,  // Linux Foundation
        did_product: 0x0246, // BlueZ
        did_version,
        // BR/LE defaults are already set by the struct Default impls
        // which match the C init_defaults() values.
        ..BtdOpts::default()
    }
}

/// Parse major and minor version numbers from a version string.
///
/// Returns (0, 0) if parsing fails.
fn parse_version(version: &str) -> (u8, u8) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);
    (major, minor)
}

// ---------------------------------------------------------------------------
// INI Loading — load_config()
// ---------------------------------------------------------------------------

/// Determine the configuration file path and load the INI file.
///
/// If `name` is `Some`, uses that path directly.  Otherwise checks the
/// `CONFIGURATION_DIRECTORY` environment variable (used when running as a
/// systemd service) and falls back to [`CONFIGDIR`] (`/etc/bluetooth`).
///
/// Returns `None` if the file does not exist or cannot be parsed.
///
/// Equivalent to the C `load_config()` function in `src/main.c`.
pub fn load_config(name: Option<&str>) -> Option<Ini> {
    let path = resolve_config_path(name);

    match Ini::load_from_file(&path) {
        Ok(ini) => {
            info!("Loaded configuration from {}", path.display());
            Some(ini)
        }
        Err(e) => {
            // Only log an error if the file exists but cannot be parsed;
            // a missing file is not an error (matching C behaviour where
            // G_FILE_ERROR_NOENT is silently ignored).
            let err_str = format!("{e}");
            if !err_str.contains("No such file") && !err_str.contains("not found") {
                error!("Parsing {} failed: {}", path.display(), e);
                btd_error(0xFFFF, &format!("Parsing {} failed: {e}", path.display()));
            }
            None
        }
    }
}

/// Resolve the path to the main.conf configuration file.
///
/// Replicates the C logic:
/// 1. If an explicit path is given, use it.
/// 2. Check `CONFIGURATION_DIRECTORY` env var (systemd).
///    If it contains `:` separators, use only the first path.
/// 3. Fall back to `CONFIGDIR/main.conf`.
fn resolve_config_path(name: Option<&str>) -> PathBuf {
    if let Some(explicit) = name {
        return PathBuf::from(explicit);
    }

    let config_dir = if let Ok(dir) = env::var("CONFIGURATION_DIRECTORY") {
        // If multiple paths separated by ':', use only the first one
        if let Some(pos) = dir.find(':') { dir[..pos].to_owned() } else { dir }
    } else {
        CONFIGDIR.to_owned()
    };

    Path::new(&config_dir).join("main.conf")
}

// ---------------------------------------------------------------------------
// Config Validation — check_config()
// ---------------------------------------------------------------------------

/// Validate all groups and keys in the configuration file against the
/// supported options tables.
///
/// Unknown groups and unknown keys within known groups produce warnings
/// via `btd_warn`, matching the C `check_config()` behaviour exactly.
fn check_config(config: &Ini, config_path: &str) {
    // Check for unknown groups
    for (section, _props) in config.iter() {
        if let Some(group) = section {
            let known = VALID_GROUPS.iter().any(|(name, _)| *name == group);
            if !known {
                let msg = format!("Unknown group {group} in {config_path}");
                warn!("{}", msg);
                btd_warn(0xFFFF, &msg);
            }
        }
    }

    // Check for unknown keys within known groups
    for &(group, options) in VALID_GROUPS {
        if let Some(props) = config.section(Some(group)) {
            for (key, _value) in props {
                if !options.contains(&key) {
                    let msg = format!("Unknown key {key} for group {group} in {config_path}");
                    warn!("{}", msg);
                    btd_warn(0xFFFF, &msg);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Typed config accessors — matching C parse_config_* helpers
// ---------------------------------------------------------------------------

/// Read a string value from a specific section and key.
///
/// Returns `None` if the section or key does not exist.
fn get_config_string(config: &Ini, group: &str, key: &str) -> Option<String> {
    let props = config.section(Some(group))?;
    let val = props.get(key)?;
    debug!("{}.{} = {}", group, key, val);
    btd_debug(0xFFFF, &format!("{group}.{key} = {val}"));
    Some(val.to_owned())
}

/// Read a boolean value from a specific section and key.
///
/// Accepts `true`/`false` (case-insensitive). Returns `None` if the key
/// does not exist or cannot be parsed.
fn get_config_bool(config: &Ini, group: &str, key: &str) -> Option<bool> {
    let val = get_config_string(config, group, key)?;
    match val.to_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => {
            let msg = format!("{group}.{key} = {val} is not boolean");
            btd_debug(0xFFFF, &msg);
            None
        }
    }
}

/// Read an integer value from a specific section and key, with range
/// validation.
///
/// Returns `None` if the key does not exist, the value is not a valid
/// integer, or the value is outside the [min, max] range.  Range
/// violations produce warnings matching C behaviour.
fn get_config_int(config: &Ini, group: &str, key: &str, min: i64, max: i64) -> Option<i64> {
    let val_str = get_config_string(config, group, key)?;

    // Support hex (0x...), octal (0o...), and decimal — matching C strtol
    // base 0 behavior
    let parsed = parse_int_str(&val_str);
    let tmp = match parsed {
        Some(v) => v,
        None => {
            let msg = format!("{group}.{key} = {val_str} is not integer");
            error!("{}", msg);
            btd_error(0xFFFF, &msg);
            return None;
        }
    };

    if tmp < min {
        let msg = format!("{group}.{key} = {tmp} is out of range (< {min})");
        warn!("{}", msg);
        btd_warn(0xFFFF, &msg);
        return None;
    }

    if tmp > max {
        let msg = format!("{group}.{key} = {tmp} is out of range (> {max})");
        warn!("{}", msg);
        btd_warn(0xFFFF, &msg);
        return None;
    }

    Some(tmp)
}

/// Parse a string as an integer, supporting C-style prefixes:
/// - `0x` or `0X` for hexadecimal
/// - `0` prefix for octal
/// - decimal otherwise
///
/// This matches C `strtol(str, NULL, 0)` behaviour.
fn parse_int_str(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else if s.starts_with('0')
        && s.len() > 1
        && s.chars().nth(1).is_some_and(|c| c.is_ascii_digit())
    {
        i64::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse::<i64>().ok()
    }
}

/// Read a u32 value with range validation.
fn get_config_u32(config: &Ini, group: &str, key: &str, min: u32, max: u32) -> Option<u32> {
    get_config_int(config, group, key, i64::from(min), i64::from(max)).map(|v| v as u32)
}

/// Read a u16 value with range validation.
fn get_config_u16(config: &Ini, group: &str, key: &str, min: u16, max: u16) -> Option<u16> {
    get_config_int(config, group, key, i64::from(min), i64::from(max)).map(|v| v as u16)
}

/// Read a u8 value with range validation.
fn get_config_u8(config: &Ini, group: &str, key: &str, min: u8, max: u8) -> Option<u8> {
    get_config_int(config, group, key, i64::from(min), i64::from(max)).map(|v| v as u8)
}

/// Read a hex-encoded u32 value from a string key.
fn get_config_hex(config: &Ini, group: &str, key: &str) -> Option<u32> {
    let val_str = get_config_string(config, group, key)?;
    u32::from_str_radix(val_str.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}

// ---------------------------------------------------------------------------
// Section-specific parsers
// ---------------------------------------------------------------------------

/// Parse the `[General]` section.
///
/// Replicates C `parse_general()` from `src/main.c` lines 1030-1074.
fn parse_general(config: &Ini, opts: &mut BtdOpts) {
    if let Some(name) = get_config_string(config, "General", "Name") {
        opts.name = Some(name);
    }

    if let Some(class) = get_config_hex(config, "General", "Class") {
        opts.class = class;
    }

    if let Some(v) = get_config_u32(config, "General", "DiscoverableTimeout", 0, u32::MAX) {
        opts.discovto = v;
    }

    if let Some(v) = get_config_bool(config, "General", "AlwaysPairable") {
        opts.pairable = v;
    }

    if let Some(v) = get_config_u32(config, "General", "PairableTimeout", 0, u32::MAX) {
        opts.pairto = v;
    }

    // DeviceID
    parse_device_id(config, opts);

    if let Some(v) = get_config_bool(config, "General", "ReverseServiceDiscovery") {
        opts.reverse_sdp = v;
    }

    if let Some(v) = get_config_bool(config, "General", "NameResolving") {
        opts.name_resolv = v;
    }

    if let Some(v) = get_config_bool(config, "General", "DebugKeys") {
        opts.debug_keys = v;
    }

    // ControllerMode
    parse_ctrl_mode(config, opts);

    if let Some(v) = get_config_u16(config, "General", "MaxControllers", 0, u16::MAX) {
        opts.max_adapters = v;
    }

    // MultiProfile
    parse_multi_profile(config, opts);

    if let Some(v) = get_config_bool(config, "General", "FastConnectable") {
        opts.fast_conn = v;
    }

    // Privacy
    parse_privacy(config, opts);

    // JustWorksRepairing
    parse_repairing(config, opts);

    if let Some(v) = get_config_u32(config, "General", "TemporaryTimeout", 0, u32::MAX) {
        opts.tmpto = v;
    }

    if let Some(v) = get_config_bool(config, "General", "RefreshDiscovery") {
        opts.refresh_discovery = v;
    }

    // SecureConnections
    parse_secure_conns(config, opts);

    if let Some(v) = get_config_bool(config, "General", "Experimental") {
        opts.experimental = v;
    }

    if let Some(v) = get_config_bool(config, "General", "Testing") {
        opts.testing = v;
    }

    // KernelExperimental
    parse_kernel_exp(config, opts);

    if let Some(v) = get_config_u32(config, "General", "RemoteNameRequestRetryDelay", 0, u32::MAX) {
        opts.name_request_retry_delay = v;
    }

    if let Some(v) = get_config_bool(config, "General", "FilterDiscoverable") {
        opts.filter_discoverable = v;
    }
}

/// Parse the DeviceID key from `[General]`.
///
/// Replicates C `parse_did()` from `src/main.c` lines 291-327.
fn parse_device_id(config: &Ini, opts: &mut BtdOpts) {
    let did = match get_config_string(config, "General", "DeviceID") {
        Some(s) => s,
        None => return,
    };

    parse_did(&did, opts);
}

/// Parse a DeviceID string in one of the supported formats.
///
/// Formats:
/// - `"false"` — disable Device ID
/// - `"bluetooth:VVVV:PPPP:RRRR"` — Bluetooth DID (source=0x0001)
/// - `"usb:VVVV:PPPP:RRRR"` — USB DID (source=0x0002)
/// - `"VVVV:PPPP:RRRR"` — USB DID (source=0x0002)
fn parse_did(did: &str, opts: &mut BtdOpts) {
    if did.eq_ignore_ascii_case("false") {
        opts.did_source = 0x0000;
        opts.did_vendor = 0x0000;
        opts.did_product = 0x0000;
        opts.did_version = 0x0000;
        return;
    }

    // Try "bluetooth:VVVV:PPPP:RRRR" format
    if let Some(rest) = did.strip_prefix("bluetooth:") {
        if let Some((vendor, product, version)) = parse_did_fields(rest) {
            opts.did_source = 0x0001;
            opts.did_vendor = vendor;
            opts.did_product = product;
            opts.did_version = version;
            return;
        }
    }

    // Try "usb:VVVV:PPPP:RRRR" format
    if let Some(rest) = did.strip_prefix("usb:") {
        if let Some((vendor, product, version)) = parse_did_fields(rest) {
            opts.did_source = 0x0002;
            opts.did_vendor = vendor;
            opts.did_product = product;
            opts.did_version = version;
            return;
        }
    }

    // Try "VVVV:PPPP:RRRR" format (source=0x0002/USB)
    if let Some((vendor, product, version)) = parse_did_fields(did) {
        opts.did_source = 0x0002;
        opts.did_vendor = vendor;
        opts.did_product = product;
        opts.did_version = version;
    }
}

/// Parse colon-separated hex fields "VVVV:PPPP[:RRRR]".
///
/// Returns (vendor, product, version) where version defaults to 0 if
/// omitted.  Returns `None` if fewer than 2 fields are present.
fn parse_did_fields(s: &str) -> Option<(u16, u16, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() < 2 {
        return None;
    }

    let vendor = u16::from_str_radix(parts[0], 16).ok()?;
    let product = u16::from_str_radix(parts[1], 16).ok()?;
    let version = if parts.len() >= 3 { u16::from_str_radix(parts[2], 16).unwrap_or(0) } else { 0 };

    Some((vendor, product, version))
}

/// Parse the ControllerMode key.
///
/// Replicates C `get_mode()` and `parse_ctrl_mode()`.
fn parse_ctrl_mode(config: &Ini, opts: &mut BtdOpts) {
    let mode_str = match get_config_string(config, "General", "ControllerMode") {
        Some(s) => s,
        None => return,
    };

    opts.mode = match mode_str.as_str() {
        "dual" => BtMode::Dual,
        "bredr" => BtMode::Bredr,
        "le" => BtMode::Le,
        _ => {
            let msg = format!("Unknown controller mode \"{mode_str}\"");
            error!("{}", msg);
            btd_error(0xFFFF, &msg);
            BtMode::Dual
        }
    };
}

/// Parse the MultiProfile key.
///
/// Replicates C `parse_multi_profile()`.
fn parse_multi_profile(config: &Ini, opts: &mut BtdOpts) {
    let str_val = match get_config_string(config, "General", "MultiProfile") {
        Some(s) => s,
        None => return,
    };

    opts.mps = match str_val.as_str() {
        "single" => MpsMode::Single,
        "multiple" => MpsMode::Multiple,
        _ => MpsMode::Off,
    };
}

/// Parse the Privacy key with its complex string-value semantics.
///
/// Replicates C `parse_privacy()` from `src/main.c` lines 871-908.
fn parse_privacy(config: &Ini, opts: &mut BtdOpts) {
    let str_val = match get_config_string(config, "General", "Privacy") {
        Some(s) => s,
        None => {
            opts.privacy = 0x00;
            opts.device_privacy = true;
            return;
        }
    };

    match str_val.as_str() {
        "network" | "on" => {
            opts.privacy = 0x01;
        }
        "device" => {
            opts.privacy = 0x01;
            opts.device_privacy = true;
        }
        "limited-network" => {
            if opts.mode != BtMode::Dual {
                btd_debug(0xFFFF, &format!("Invalid privacy option: {str_val}"));
                opts.privacy = 0x00;
            }
            opts.privacy = 0x01;
        }
        "limited-device" => {
            if opts.mode != BtMode::Dual {
                btd_debug(0xFFFF, &format!("Invalid privacy option: {str_val}"));
                opts.privacy = 0x00;
            }
            opts.privacy = 0x02;
            opts.device_privacy = true;
        }
        "off" => {
            opts.privacy = 0x00;
            opts.device_privacy = true;
        }
        _ => {
            btd_debug(0xFFFF, &format!("Invalid privacy option: {str_val}"));
            opts.privacy = 0x00;
        }
    }
}

/// Parse the JustWorksRepairing key.
///
/// Replicates C `parse_repairing()`.
fn parse_repairing(config: &Ini, opts: &mut BtdOpts) {
    let str_val = match get_config_string(config, "General", "JustWorksRepairing") {
        Some(s) => s,
        None => {
            opts.jw_repairing = JwRepairing::Never;
            return;
        }
    };

    opts.jw_repairing = match str_val.as_str() {
        "never" => JwRepairing::Never,
        "confirm" => JwRepairing::Confirm,
        "always" => JwRepairing::Always,
        _ => JwRepairing::Never,
    };
}

/// Parse the SecureConnections key.
///
/// Replicates C `parse_secure_conns()`.
fn parse_secure_conns(config: &Ini, opts: &mut BtdOpts) {
    let str_val = match get_config_string(config, "General", "SecureConnections") {
        Some(s) => s,
        None => return,
    };

    match str_val.as_str() {
        "off" => opts.secure_conn = ScMode::Off,
        "on" => opts.secure_conn = ScMode::On,
        "only" => opts.secure_conn = ScMode::Only,
        _ => {}
    }
}

/// Parse the KernelExperimental key.
///
/// Replicates C `parse_kernel_exp()` and `btd_parse_kernel_experimental()`.
fn parse_kernel_exp(config: &Ini, opts: &mut BtdOpts) {
    let str_val = match get_config_string(config, "General", "KernelExperimental") {
        Some(s) => s,
        None => return,
    };

    if !opts.kernel.is_empty() {
        let msg = "Unable to parse KernelExperimental: list already set";
        warn!("{}", msg);
        btd_warn(0xFFFF, msg);
        return;
    }

    // Handle wildcard or empty value
    if str_val.is_empty() || str_val.starts_with('*') {
        opts.kernel.push("*".to_owned());
        return;
    }

    // Split on comma
    for item in str_val.split(',') {
        let uuid = item.trim();
        if uuid.is_empty() {
            continue;
        }

        // Handle boolean-style values
        if uuid.eq_ignore_ascii_case("false") || uuid.eq_ignore_ascii_case("off") {
            opts.kernel.clear();
            return;
        }

        let effective_uuid = if uuid.eq_ignore_ascii_case("true") || uuid.eq_ignore_ascii_case("on")
        {
            "*"
        } else {
            uuid
        };

        // Validate against known UUIDs
        let valid = VALID_KERNEL_UUIDS.iter().any(|v| v.eq_ignore_ascii_case(effective_uuid));

        if !valid {
            let msg = format!("Invalid KernelExperimental UUID: {uuid}");
            warn!("{}", msg);
            btd_warn(0xFFFF, &msg);
            continue;
        }

        btd_debug(0xFFFF, effective_uuid);
        opts.kernel.push(effective_uuid.to_owned());
    }
}

/// Parse the `[BR]` section.
///
/// Replicates C `parse_br_config()` from `src/main.c` lines 524-588.
/// Skipped entirely if mode is LE-only.
fn parse_br_config(config: &Ini, opts: &mut BtdOpts) {
    if opts.mode == BtMode::Le {
        return;
    }

    if let Some(v) = get_config_u16(config, "BR", "PageScanType", 0, 1) {
        opts.defaults.br.page_scan_type = v;
    }

    if let Some(v) = get_config_u16(config, "BR", "PageScanInterval", 0x0012, 0x1000) {
        opts.defaults.br.page_scan_interval = v;
    }

    if let Some(v) = get_config_u16(config, "BR", "PageScanWindow", 0x0011, 0x1000) {
        opts.defaults.br.page_scan_win = v;
    }

    if let Some(v) = get_config_u16(config, "BR", "InquiryScanType", 0, 1) {
        opts.defaults.br.scan_type = v;
    }

    if let Some(v) = get_config_u16(config, "BR", "InquiryScanInterval", 0x0012, 0x1000) {
        opts.defaults.br.scan_interval = v;
    }

    if let Some(v) = get_config_u16(config, "BR", "InquiryScanWindow", 0x0011, 0x1000) {
        opts.defaults.br.scan_win = v;
    }

    if let Some(v) = get_config_u16(config, "BR", "LinkSupervisionTimeout", 0x0001, 0xFFFF) {
        opts.defaults.br.link_supervision_timeout = v;
    }

    if let Some(v) = get_config_u16(config, "BR", "PageTimeout", 0x0001, 0xFFFF) {
        opts.defaults.br.page_timeout = v;
    }

    if let Some(v) = get_config_u16(config, "BR", "MinSniffInterval", 0x0001, 0xFFFE) {
        opts.defaults.br.min_sniff_interval = v;
    }

    if let Some(v) = get_config_u16(config, "BR", "MaxSniffInterval", 0x0001, 0xFFFE) {
        opts.defaults.br.max_sniff_interval = v;
    }

    if let Some(v) = get_config_u32(config, "BR", "IdleTimeout", 500, 3_600_000) {
        opts.defaults.br.idle_timeout = v;
    }
}

/// Parse the `[LE]` section.
///
/// Replicates C `parse_le_config()` from `src/main.c` lines 590-709.
/// Skipped entirely if mode is BR/EDR-only.
fn parse_le_config(config: &Ini, opts: &mut BtdOpts) {
    if opts.mode == BtMode::Bredr {
        return;
    }

    if let Some(v) = get_config_u8(config, "LE", "CentralAddressResolution", 0, 1) {
        opts.defaults.le.addr_resolution = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "MinAdvertisementInterval", 0x0020, 0x4000) {
        opts.defaults.le.min_adv_interval = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "MaxAdvertisementInterval", 0x0020, 0x4000) {
        opts.defaults.le.max_adv_interval = v;
    }

    if let Some(v) =
        get_config_u16(config, "LE", "MultiAdvertisementRotationInterval", 0x0001, 0xFFFF)
    {
        opts.defaults.le.adv_rotation_interval = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ScanIntervalAutoConnect", 0x0004, 0x4000) {
        opts.defaults.le.scan_interval_autoconnect = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ScanWindowAutoConnect", 0x0004, 0x4000) {
        opts.defaults.le.scan_win_autoconnect = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ScanIntervalSuspend", 0x0004, 0x4000) {
        opts.defaults.le.scan_interval_suspend = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ScanWindowSuspend", 0x0004, 0x4000) {
        opts.defaults.le.scan_win_suspend = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ScanIntervalDiscovery", 0x0004, 0x4000) {
        opts.defaults.le.scan_interval_discovery = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ScanWindowDiscovery", 0x0004, 0x4000) {
        opts.defaults.le.scan_win_discovery = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ScanIntervalAdvMonitor", 0x0004, 0x4000) {
        opts.defaults.le.scan_interval_adv_monitor = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ScanWindowAdvMonitor", 0x0004, 0x4000) {
        opts.defaults.le.scan_win_adv_monitor = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ScanIntervalConnect", 0x0004, 0x4000) {
        opts.defaults.le.scan_interval_connect = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ScanWindowConnect", 0x0004, 0x4000) {
        opts.defaults.le.scan_win_connect = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "MinConnectionInterval", 0x0006, 0x0C80) {
        opts.defaults.le.min_conn_interval = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "MaxConnectionInterval", 0x0006, 0x0C80) {
        opts.defaults.le.max_conn_interval = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ConnectionLatency", 0x0000, 0x01F3) {
        opts.defaults.le.conn_latency = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "ConnectionSupervisionTimeout", 0x000A, 0x0C80) {
        opts.defaults.le.conn_lsto = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "Autoconnecttimeout", 0x0001, 0x4000) {
        opts.defaults.le.autoconnect_timeout = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "AdvMonAllowlistScanDuration", 1, 10000) {
        opts.defaults.le.advmon_allowlist_scan_duration = v;
    }

    if let Some(v) = get_config_u16(config, "LE", "AdvMonNoFilterScanDuration", 1, 10000) {
        opts.defaults.le.advmon_no_filter_scan_duration = v;
    }

    if let Some(v) = get_config_u8(config, "LE", "EnableAdvMonInterleaveScan", 0, 1) {
        opts.defaults.le.enable_advmon_interleave_scan = v != 0;
    }
}

/// Parse the `[Policy]` section.
///
/// In the C code, these options are consumed by `plugins/policy.c`.
/// However, our `BtdOpts` schema consolidates all configuration into a
/// single struct.
fn parse_policy(config: &Ini, opts: &mut BtdOpts) {
    // ReconnectUUIDs — comma-separated list of UUIDs
    if let Some(val) = get_config_string(config, "Policy", "ReconnectUUIDs") {
        opts.reconnect_uuids =
            val.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect();
    }

    // ReconnectAttempts
    if let Some(v) = get_config_u8(config, "Policy", "ReconnectAttempts", 0, u8::MAX) {
        opts.reconnect_attempts = v;
    }

    // ReconnectIntervals — comma-separated list of seconds
    if let Some(val) = get_config_string(config, "Policy", "ReconnectIntervals") {
        opts.reconnect_intervals =
            val.split(',').filter_map(|s| s.trim().parse::<u32>().ok()).collect();
    }

    // AutoEnable
    if let Some(v) = get_config_bool(config, "Policy", "AutoEnable") {
        opts.auto_enable = v;
    }

    // ResumeDelay
    if let Some(v) = get_config_u32(config, "Policy", "ResumeDelay", 0, u32::MAX) {
        opts.resume_delay = v;
    }
}

/// Parse the `[GATT]` section.
///
/// Replicates C `parse_gatt()` from `src/main.c` lines 1115-1125.
fn parse_gatt(config: &Ini, opts: &mut BtdOpts) {
    // Cache
    parse_gatt_cache(config, opts);

    // KeySize
    if let Some(v) = get_config_u8(config, "GATT", "KeySize", 7, 16) {
        opts.key_size = v;
    }

    // ExchangeMTU — range [BT_ATT_DEFAULT_LE_MTU, BT_ATT_MAX_LE_MTU]
    if let Some(v) =
        get_config_u16(config, "GATT", "ExchangeMTU", BT_ATT_DEFAULT_LE_MTU, BT_ATT_MAX_LE_MTU)
    {
        opts.gatt_mtu = v;
    }

    // Channels
    if let Some(v) = get_config_u8(config, "GATT", "Channels", 1, 6) {
        opts.gatt_channels = v;
    }

    // Client
    if let Some(v) = get_config_bool(config, "GATT", "Client") {
        opts.gatt_client = v;
    }

    // ExportClaimedServices
    parse_gatt_export(config, opts);
}

/// Parse the GATT Cache key.
///
/// Replicates C `parse_gatt_cache()` and `parse_gatt_cache_str()`.
fn parse_gatt_cache(config: &Ini, opts: &mut BtdOpts) {
    let str_val = match get_config_string(config, "GATT", "Cache") {
        Some(s) => s,
        None => return,
    };

    opts.gatt_cache = match str_val.as_str() {
        "always" => BtGattCache::Always,
        "yes" => BtGattCache::Yes,
        "no" => BtGattCache::No,
        _ => {
            btd_debug(0xFFFF, &format!("Invalid value for KeepCache={str_val}"));
            BtGattCache::Always
        }
    };
}

/// Parse the ExportClaimedServices key.
///
/// Replicates C `parse_gatt_export()` and `parse_gatt_export_str()`.
fn parse_gatt_export(config: &Ini, opts: &mut BtdOpts) {
    let str_val = match get_config_string(config, "GATT", "ExportClaimedServices") {
        Some(s) => s,
        None => return,
    };

    opts.gatt_export = match str_val.as_str() {
        "no" | "false" | "off" => BtGattExport::Off,
        "read-only" => BtGattExport::ReadOnly,
        "read-write" => BtGattExport::ReadWrite,
        _ => {
            btd_debug(0xFFFF, &format!("Invalid value for ExportClaimedServices={str_val}"));
            BtGattExport::ReadOnly
        }
    };
}

/// Parse the `[CSIS]` section.
///
/// Replicates C `parse_csis()` from `src/main.c` lines 1142-1151.
fn parse_csis(config: &Ini, opts: &mut BtdOpts) {
    parse_csis_sirk(config, opts);

    if let Some(v) = get_config_bool(config, "CSIS", "Encryption") {
        opts.csis.encrypt = v;
    }

    if let Some(v) = get_config_u8(config, "CSIS", "Size", 0, u8::MAX) {
        opts.csis.size = v;
    }

    if let Some(v) = get_config_u8(config, "CSIS", "Rank", 0, u8::MAX) {
        opts.csis.rank = v;
    }
}

/// Parse the CSIS SIRK value.
///
/// Replicates C `parse_csis_sirk()` from `src/main.c` lines 1127-1140.
///
/// If the SIRK value is a 32-character hex string, it is decoded directly.
/// Otherwise, it is treated as an alphanumeric string and used to generate
/// a SIRK using `bt_crypto_sirk()`.
fn parse_csis_sirk(config: &Ini, opts: &mut BtdOpts) {
    let str_val = match get_config_string(config, "CSIS", "SIRK") {
        Some(s) => s,
        None => return,
    };

    if str_val.len() == 32 && check_sirk_alpha_numeric(&str_val) {
        // Direct hex decode
        if let Some(bytes) = hex2bin(&str_val, 16) {
            opts.csis.sirk[..bytes.len()].copy_from_slice(&bytes);
        }
    } else {
        // Generate SIRK using crypto function
        match bt_crypto_sirk(
            &str_val,
            opts.did_vendor,
            opts.did_product,
            opts.did_version,
            opts.did_source,
        ) {
            Ok(sirk) => {
                opts.csis.sirk = sirk;
            }
            Err(_) => {
                btd_debug(0xFFFF, "Unable to generate SIRK from string");
            }
        }
    }
}

/// Check if a string is exactly 32 characters of hex alphanumeric (0-9, a-z, A-Z).
///
/// Replicates C `check_sirk_alpha_numeric()` from `src/main.c` lines 203-223.
fn check_sirk_alpha_numeric(s: &str) -> bool {
    if s.len() != 32 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() || c.is_ascii_uppercase())
}

/// Decode a hexadecimal string into a byte buffer.
///
/// Replicates C `hex2bin()` from `src/main.c` lines 225-241.
fn hex2bin(hexstr: &str, buflen: usize) -> Option<Vec<u8>> {
    let hex_len = hexstr.len();
    let out_len = std::cmp::min(hex_len / 2, buflen);
    let mut buf = Vec::with_capacity(out_len);

    for i in 0..out_len {
        let byte_str = &hexstr[i * 2..i * 2 + 2];
        match u8::from_str_radix(byte_str, 16) {
            Ok(b) => buf.push(b),
            Err(_) => buf.push(0),
        }
    }

    Some(buf)
}

/// Parse the `[AVDTP]` section.
///
/// Replicates C `parse_avdtp()` from `src/main.c` lines 1191-1195.
fn parse_avdtp(config: &Ini, opts: &mut BtdOpts) {
    parse_avdtp_session_mode(config, opts);
    parse_avdtp_stream_mode(config, opts);
}

/// Parse the AVDTP SessionMode key.
///
/// Replicates C `parse_avdtp_session_mode()` from `src/main.c` lines 1153-1170.
fn parse_avdtp_session_mode(config: &Ini, opts: &mut BtdOpts) {
    let str_val = match get_config_string(config, "AVDTP", "SessionMode") {
        Some(s) => s,
        None => return,
    };

    opts.avdtp.session_mode = match str_val.as_str() {
        "basic" => L2capMode::Basic as u8,
        "ertm" => L2capMode::Ertm as u8,
        _ => {
            btd_debug(0xFFFF, &format!("Invalid mode option: {str_val}"));
            L2capMode::Basic as u8
        }
    };
}

/// Parse the AVDTP StreamMode key.
///
/// Replicates C `parse_avdtp_stream_mode()` from `src/main.c` lines 1172-1189.
fn parse_avdtp_stream_mode(config: &Ini, opts: &mut BtdOpts) {
    let str_val = match get_config_string(config, "AVDTP", "StreamMode") {
        Some(s) => s,
        None => return,
    };

    opts.avdtp.stream_mode = match str_val.as_str() {
        "basic" => L2capMode::Basic as u8,
        "streaming" => L2capMode::Streaming as u8,
        _ => {
            btd_debug(0xFFFF, &format!("Invalid mode option: {str_val}"));
            L2capMode::Basic as u8
        }
    };
}

/// Parse the `[AVRCP]` section.
///
/// Replicates C `parse_avrcp()` from `src/main.c` lines 1197-1205.
fn parse_avrcp(config: &Ini, opts: &mut BtdOpts) {
    if let Some(v) = get_config_bool(config, "AVRCP", "VolumeWithoutTarget") {
        opts.avrcp.volume_without_target = v;
    }

    if let Some(v) = get_config_bool(config, "AVRCP", "VolumeCategory") {
        opts.avrcp.volume_category = v;
    }
}

/// Parse the `[AdvMon]` section.
///
/// Replicates C `parse_advmon()` from `src/main.c` lines 1207-1212.
fn parse_advmon(config: &Ini, opts: &mut BtdOpts) {
    if let Some(v) = get_config_u8(config, "AdvMon", "RSSISamplingPeriod", 0, u8::MAX) {
        opts.advmon.rssi_sampling_period = v;
    }
}

// ---------------------------------------------------------------------------
// Main parse_config() entry point
// ---------------------------------------------------------------------------

/// Parse all sections of the loaded INI configuration.
///
/// Replicates C `parse_config()` from `src/main.c` lines 1214-1232.
///
/// This function first validates the configuration against the supported
/// options tables (producing warnings for unknown groups/keys), then parses
/// each section in order.
pub fn parse_config(config: &Ini, opts: &mut BtdOpts) {
    // Determine config path for diagnostic messages
    let config_path = resolve_config_path(None);
    let path_str = config_path.to_string_lossy().to_string();

    check_config(config, &path_str);

    debug!("parsing {}", path_str);
    btd_debug(0xFFFF, &format!("parsing {path_str}"));

    // Parse all sections in the same order as the C code
    parse_general(config, opts);
    parse_br_config(config, opts);
    parse_le_config(config, opts);
    parse_policy(config, opts);
    parse_gatt(config, opts);
    parse_csis(config, opts);
    parse_avdtp(config, opts);
    parse_avrcp(config, opts);
    parse_advmon(config, opts);
}

// ---------------------------------------------------------------------------
// KernelExperimental query
// ---------------------------------------------------------------------------

/// Check if a specific kernel experimental UUID is enabled.
///
/// Returns `true` if the UUID matches any entry in the kernel experimental
/// list, or if the wildcard `"*"` is present.
///
/// Replicates C `btd_kernel_experimental_enabled()` from `src/main.c`
/// lines 722-731.
pub fn btd_kernel_experimental_enabled(opts: &BtdOpts, uuid: &str) -> bool {
    if opts.kernel.is_empty() {
        return false;
    }

    opts.kernel.iter().any(|entry| {
        if entry == "*" {
            return true;
        }
        entry.eq_ignore_ascii_case(uuid)
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_defaults_name() {
        let opts = init_defaults();
        assert!(opts.name.as_ref().unwrap().starts_with("BlueZ "));
    }

    #[test]
    fn test_init_defaults_discoverable_timeout() {
        let opts = init_defaults();
        assert_eq!(opts.discovto, 180);
    }

    #[test]
    fn test_init_defaults_pairable_timeout() {
        let opts = init_defaults();
        assert_eq!(opts.pairto, 0);
    }

    #[test]
    fn test_init_defaults_temporary_timeout() {
        let opts = init_defaults();
        assert_eq!(opts.tmpto, 30);
    }

    #[test]
    fn test_init_defaults_secure_conn() {
        let opts = init_defaults();
        assert_eq!(opts.secure_conn, ScMode::On);
    }

    #[test]
    fn test_init_defaults_reverse_sdp() {
        let opts = init_defaults();
        assert!(opts.reverse_sdp);
    }

    #[test]
    fn test_init_defaults_name_resolv() {
        let opts = init_defaults();
        assert!(opts.name_resolv);
    }

    #[test]
    fn test_init_defaults_filter_discoverable() {
        let opts = init_defaults();
        assert!(opts.filter_discoverable);
    }

    #[test]
    fn test_init_defaults_gatt_mtu() {
        let opts = init_defaults();
        assert_eq!(opts.gatt_mtu, BT_ATT_MAX_LE_MTU);
    }

    #[test]
    fn test_init_defaults_gatt_channels() {
        let opts = init_defaults();
        assert_eq!(opts.gatt_channels, 1);
    }

    #[test]
    fn test_init_defaults_gatt_client() {
        let opts = init_defaults();
        assert!(opts.gatt_client);
    }

    #[test]
    fn test_init_defaults_gatt_export() {
        let opts = init_defaults();
        assert_eq!(opts.gatt_export, BtGattExport::ReadOnly);
    }

    #[test]
    fn test_init_defaults_avdtp() {
        let opts = init_defaults();
        assert_eq!(opts.avdtp.session_mode, L2capMode::Basic as u8);
        assert_eq!(opts.avdtp.stream_mode, L2capMode::Basic as u8);
    }

    #[test]
    fn test_init_defaults_avrcp() {
        let opts = init_defaults();
        assert!(!opts.avrcp.volume_without_target);
        assert!(opts.avrcp.volume_category);
    }

    #[test]
    fn test_init_defaults_advmon() {
        let opts = init_defaults();
        assert_eq!(opts.advmon.rssi_sampling_period, 0xFF);
    }

    #[test]
    fn test_init_defaults_csis() {
        let opts = init_defaults();
        assert!(opts.csis.encrypt);
    }

    #[test]
    fn test_init_defaults_did() {
        let opts = init_defaults();
        assert_eq!(opts.did_source, 0x0002);
        assert_eq!(opts.did_vendor, 0x1d6b);
        assert_eq!(opts.did_product, 0x0246);
    }

    #[test]
    fn test_init_defaults_br_scan_types() {
        let opts = init_defaults();
        assert_eq!(opts.defaults.br.page_scan_type, 0xFFFF);
        assert_eq!(opts.defaults.br.scan_type, 0xFFFF);
    }

    #[test]
    fn test_init_defaults_le_addr_resolution() {
        let opts = init_defaults();
        assert_eq!(opts.defaults.le.addr_resolution, 0x01);
    }

    #[test]
    fn test_parse_config_empty() {
        let ini = Ini::load_from_str("").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        // All defaults should be preserved
        assert_eq!(opts.discovto, 180);
        assert!(opts.reverse_sdp);
    }

    #[test]
    fn test_parse_general_name() {
        let ini = Ini::load_from_str("[General]\nName = TestDevice\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.name.as_deref(), Some("TestDevice"));
    }

    #[test]
    fn test_parse_general_class() {
        let ini = Ini::load_from_str("[General]\nClass = 0x040424\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.class, 0x040424);
    }

    #[test]
    fn test_parse_general_discoverable_timeout() {
        let ini = Ini::load_from_str("[General]\nDiscoverableTimeout = 0\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.discovto, 0);
    }

    #[test]
    fn test_parse_general_always_pairable() {
        let ini = Ini::load_from_str("[General]\nAlwaysPairable = true\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert!(opts.pairable);
    }

    #[test]
    fn test_parse_controller_mode_bredr() {
        let ini = Ini::load_from_str("[General]\nControllerMode = bredr\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.mode, BtMode::Bredr);
    }

    #[test]
    fn test_parse_controller_mode_le() {
        let ini = Ini::load_from_str("[General]\nControllerMode = le\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.mode, BtMode::Le);
    }

    #[test]
    fn test_parse_controller_mode_dual() {
        let ini = Ini::load_from_str("[General]\nControllerMode = dual\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.mode, BtMode::Dual);
    }

    #[test]
    fn test_parse_controller_mode_invalid() {
        let ini = Ini::load_from_str("[General]\nControllerMode = bogus\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.mode, BtMode::Dual);
    }

    #[test]
    fn test_parse_multi_profile_single() {
        let ini = Ini::load_from_str("[General]\nMultiProfile = single\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.mps, MpsMode::Single);
    }

    #[test]
    fn test_parse_multi_profile_multiple() {
        let ini = Ini::load_from_str("[General]\nMultiProfile = multiple\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.mps, MpsMode::Multiple);
    }

    #[test]
    fn test_parse_secure_conn_off() {
        let ini = Ini::load_from_str("[General]\nSecureConnections = off\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.secure_conn, ScMode::Off);
    }

    #[test]
    fn test_parse_secure_conn_only() {
        let ini = Ini::load_from_str("[General]\nSecureConnections = only\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.secure_conn, ScMode::Only);
    }

    #[test]
    fn test_parse_jw_repairing_always() {
        let ini = Ini::load_from_str("[General]\nJustWorksRepairing = always\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.jw_repairing, JwRepairing::Always);
    }

    #[test]
    fn test_parse_jw_repairing_confirm() {
        let ini = Ini::load_from_str("[General]\nJustWorksRepairing = confirm\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.jw_repairing, JwRepairing::Confirm);
    }

    #[test]
    fn test_parse_privacy_network() {
        let ini = Ini::load_from_str("[General]\nPrivacy = network\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.privacy, 0x01);
    }

    #[test]
    fn test_parse_privacy_device() {
        let ini = Ini::load_from_str("[General]\nPrivacy = device\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.privacy, 0x01);
        assert!(opts.device_privacy);
    }

    #[test]
    fn test_parse_privacy_off() {
        let ini = Ini::load_from_str("[General]\nPrivacy = off\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.privacy, 0x00);
        assert!(opts.device_privacy);
    }

    #[test]
    fn test_parse_gatt_cache_no() {
        let ini = Ini::load_from_str("[GATT]\nCache = no\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.gatt_cache, BtGattCache::No);
    }

    #[test]
    fn test_parse_gatt_mtu() {
        let ini = Ini::load_from_str("[GATT]\nExchangeMTU = 256\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.gatt_mtu, 256);
    }

    #[test]
    fn test_parse_gatt_mtu_too_low() {
        let ini = Ini::load_from_str("[GATT]\nExchangeMTU = 10\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        // Should keep default since 10 < BT_ATT_DEFAULT_LE_MTU (23)
        assert_eq!(opts.gatt_mtu, BT_ATT_MAX_LE_MTU);
    }

    #[test]
    fn test_parse_gatt_channels() {
        let ini = Ini::load_from_str("[GATT]\nChannels = 3\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.gatt_channels, 3);
    }

    #[test]
    fn test_parse_gatt_key_size() {
        let ini = Ini::load_from_str("[GATT]\nKeySize = 12\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.key_size, 12);
    }

    #[test]
    fn test_parse_gatt_export_off() {
        let ini = Ini::load_from_str("[GATT]\nExportClaimedServices = off\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.gatt_export, BtGattExport::Off);
    }

    #[test]
    fn test_parse_gatt_export_read_write() {
        let ini = Ini::load_from_str("[GATT]\nExportClaimedServices = read-write\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.gatt_export, BtGattExport::ReadWrite);
    }

    #[test]
    fn test_parse_avdtp_session_mode_ertm() {
        let ini = Ini::load_from_str("[AVDTP]\nSessionMode = ertm\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.avdtp.session_mode, L2capMode::Ertm as u8);
    }

    #[test]
    fn test_parse_avdtp_stream_mode_streaming() {
        let ini = Ini::load_from_str("[AVDTP]\nStreamMode = streaming\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.avdtp.stream_mode, L2capMode::Streaming as u8);
    }

    #[test]
    fn test_parse_avrcp_options() {
        let ini =
            Ini::load_from_str("[AVRCP]\nVolumeWithoutTarget = true\nVolumeCategory = false\n")
                .unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert!(opts.avrcp.volume_without_target);
        assert!(!opts.avrcp.volume_category);
    }

    #[test]
    fn test_parse_advmon_rssi() {
        let ini = Ini::load_from_str("[AdvMon]\nRSSISamplingPeriod = 10\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.advmon.rssi_sampling_period, 10);
    }

    #[test]
    fn test_parse_csis_encryption() {
        let ini = Ini::load_from_str("[CSIS]\nEncryption = false\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert!(!opts.csis.encrypt);
    }

    #[test]
    fn test_parse_csis_size_rank() {
        let ini = Ini::load_from_str("[CSIS]\nSize = 5\nRank = 2\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.csis.size, 5);
        assert_eq!(opts.csis.rank, 2);
    }

    #[test]
    fn test_parse_policy_auto_enable() {
        let ini = Ini::load_from_str("[Policy]\nAutoEnable = true\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert!(opts.auto_enable);
    }

    #[test]
    fn test_parse_policy_resume_delay() {
        let ini = Ini::load_from_str("[Policy]\nResumeDelay = 5\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.resume_delay, 5);
    }

    #[test]
    fn test_parse_policy_reconnect_uuids() {
        let ini = Ini::load_from_str(
            "[Policy]\nReconnectUUIDs = 00001108-0000-1000-8000-00805f9b34fb,0000110b-0000-1000-8000-00805f9b34fb\n",
        )
        .unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.reconnect_uuids.len(), 2);
    }

    #[test]
    fn test_parse_br_page_scan() {
        let ini = Ini::load_from_str(
            "[BR]\nPageScanType = 1\nPageScanInterval = 0x0100\nPageScanWindow = 0x0050\n",
        )
        .unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.defaults.br.page_scan_type, 1);
        assert_eq!(opts.defaults.br.page_scan_interval, 0x0100);
        assert_eq!(opts.defaults.br.page_scan_win, 0x0050);
    }

    #[test]
    fn test_parse_le_scan_intervals() {
        let ini = Ini::load_from_str(
            "[LE]\nScanIntervalAutoConnect = 0x0100\nScanWindowAutoConnect = 0x0020\n",
        )
        .unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.defaults.le.scan_interval_autoconnect, 0x0100);
        assert_eq!(opts.defaults.le.scan_win_autoconnect, 0x0020);
    }

    #[test]
    fn test_parse_le_conn_params() {
        let ini = Ini::load_from_str(
            "[LE]\nMinConnectionInterval = 6\nMaxConnectionInterval = 50\nConnectionLatency = 10\n",
        )
        .unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        assert_eq!(opts.defaults.le.min_conn_interval, 6);
        assert_eq!(opts.defaults.le.max_conn_interval, 50);
        assert_eq!(opts.defaults.le.conn_latency, 10);
    }

    #[test]
    fn test_parse_did_bluetooth() {
        let mut opts = init_defaults();
        parse_did("bluetooth:1234:5678:0001", &mut opts);
        assert_eq!(opts.did_source, 0x0001);
        assert_eq!(opts.did_vendor, 0x1234);
        assert_eq!(opts.did_product, 0x5678);
        assert_eq!(opts.did_version, 0x0001);
    }

    #[test]
    fn test_parse_did_usb() {
        let mut opts = init_defaults();
        parse_did("usb:ABCD:1234:0005", &mut opts);
        assert_eq!(opts.did_source, 0x0002);
        assert_eq!(opts.did_vendor, 0xABCD);
        assert_eq!(opts.did_product, 0x1234);
        assert_eq!(opts.did_version, 0x0005);
    }

    #[test]
    fn test_parse_did_plain() {
        let mut opts = init_defaults();
        parse_did("1234:5678", &mut opts);
        assert_eq!(opts.did_source, 0x0002);
        assert_eq!(opts.did_vendor, 0x1234);
        assert_eq!(opts.did_product, 0x5678);
        assert_eq!(opts.did_version, 0x0000);
    }

    #[test]
    fn test_parse_did_false() {
        let mut opts = init_defaults();
        parse_did("false", &mut opts);
        assert_eq!(opts.did_source, 0x0000);
    }

    #[test]
    fn test_kernel_experimental_enabled_empty() {
        let opts = init_defaults();
        assert!(!btd_kernel_experimental_enabled(&opts, "some-uuid"));
    }

    #[test]
    fn test_kernel_experimental_enabled_wildcard() {
        let mut opts = init_defaults();
        opts.kernel.push("*".to_owned());
        assert!(btd_kernel_experimental_enabled(&opts, "any-uuid"));
    }

    #[test]
    fn test_kernel_experimental_enabled_specific() {
        let mut opts = init_defaults();
        opts.kernel.push("d4992530-b9ec-469f-ab01-6c481c47da1c".to_owned());
        assert!(btd_kernel_experimental_enabled(&opts, "d4992530-b9ec-469f-ab01-6c481c47da1c"));
        assert!(!btd_kernel_experimental_enabled(&opts, "other-uuid"));
    }

    #[test]
    fn test_check_sirk_alpha_numeric_valid() {
        assert!(check_sirk_alpha_numeric("0123456789abcdefABCDEF0123456789"));
    }

    #[test]
    fn test_check_sirk_alpha_numeric_invalid_length() {
        assert!(!check_sirk_alpha_numeric("0123"));
    }

    #[test]
    fn test_check_sirk_alpha_numeric_invalid_char() {
        assert!(!check_sirk_alpha_numeric("0123456789abcdef!BCDEF0123456789"));
    }

    #[test]
    fn test_hex2bin() {
        let result = hex2bin("DEADBEEF", 4).unwrap();
        assert_eq!(result, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_hex2bin_truncate() {
        let result = hex2bin("DEADBEEFCAFE", 4).unwrap();
        assert_eq!(result, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_int_str_decimal() {
        assert_eq!(parse_int_str("42"), Some(42));
    }

    #[test]
    fn test_parse_int_str_hex() {
        assert_eq!(parse_int_str("0xFF"), Some(255));
    }

    #[test]
    fn test_parse_int_str_octal() {
        assert_eq!(parse_int_str("010"), Some(8));
    }

    #[test]
    fn test_parse_int_str_zero() {
        assert_eq!(parse_int_str("0"), Some(0));
    }

    #[test]
    fn test_parse_int_str_empty() {
        assert_eq!(parse_int_str(""), None);
    }

    #[test]
    fn test_parse_int_str_invalid() {
        assert_eq!(parse_int_str("hello"), None);
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("5.86.0"), (5, 86));
        assert_eq!(parse_version("1.2"), (1, 2));
        assert_eq!(parse_version(""), (0, 0));
    }

    #[test]
    fn test_le_section_skipped_in_bredr_mode() {
        let ini = Ini::load_from_str(
            "[General]\nControllerMode = bredr\n[LE]\nMinAdvertisementInterval = 0x0030\n",
        )
        .unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        // LE section should be skipped; default should remain
        assert_eq!(opts.defaults.le.min_adv_interval, 0);
    }

    #[test]
    fn test_br_section_skipped_in_le_mode() {
        let ini =
            Ini::load_from_str("[General]\nControllerMode = le\n[BR]\nPageScanType = 1\n").unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);
        // BR section should be skipped; default should remain
        assert_eq!(opts.defaults.br.page_scan_type, 0xFFFF);
    }

    #[test]
    fn test_parse_full_config() {
        let config_str = r#"
[General]
Name = TestBluez
Class = 0x040424
DiscoverableTimeout = 120
AlwaysPairable = true
PairableTimeout = 60
ControllerMode = dual
MultiProfile = single
FastConnectable = true
SecureConnections = only
JustWorksRepairing = confirm
TemporaryTimeout = 15
NameResolving = false
DebugKeys = true
RefreshDiscovery = false
Experimental = true
Testing = true
FilterDiscoverable = false
RemoteNameRequestRetryDelay = 600

[BR]
PageScanType = 1
PageScanInterval = 0x0100
IdleTimeout = 1000

[LE]
MinAdvertisementInterval = 0x0030
MaxAdvertisementInterval = 0x0060
ScanIntervalAutoConnect = 0x0100
ScanWindowAutoConnect = 0x0020

[GATT]
Cache = no
KeySize = 16
ExchangeMTU = 256
Channels = 3
Client = false
ExportClaimedServices = read-write

[CSIS]
Encryption = false
Size = 4
Rank = 1

[AVDTP]
SessionMode = ertm
StreamMode = streaming

[AVRCP]
VolumeWithoutTarget = true
VolumeCategory = false

[AdvMon]
RSSISamplingPeriod = 42

[Policy]
AutoEnable = true
ResumeDelay = 3
ReconnectAttempts = 5
"#;
        let ini = Ini::load_from_str(config_str).unwrap();
        let mut opts = init_defaults();
        parse_config(&ini, &mut opts);

        assert_eq!(opts.name.as_deref(), Some("TestBluez"));
        assert_eq!(opts.class, 0x040424);
        assert_eq!(opts.discovto, 120);
        assert!(opts.pairable);
        assert_eq!(opts.pairto, 60);
        assert_eq!(opts.mode, BtMode::Dual);
        assert_eq!(opts.mps, MpsMode::Single);
        assert!(opts.fast_conn);
        assert_eq!(opts.secure_conn, ScMode::Only);
        assert_eq!(opts.jw_repairing, JwRepairing::Confirm);
        assert_eq!(opts.tmpto, 15);
        assert!(!opts.name_resolv);
        assert!(opts.debug_keys);
        assert!(!opts.refresh_discovery);
        assert!(opts.experimental);
        assert!(opts.testing);
        assert!(!opts.filter_discoverable);
        assert_eq!(opts.name_request_retry_delay, 600);

        assert_eq!(opts.defaults.br.page_scan_type, 1);
        assert_eq!(opts.defaults.br.page_scan_interval, 0x0100);
        assert_eq!(opts.defaults.br.idle_timeout, 1000);

        assert_eq!(opts.defaults.le.min_adv_interval, 0x0030);
        assert_eq!(opts.defaults.le.max_adv_interval, 0x0060);
        assert_eq!(opts.defaults.le.scan_interval_autoconnect, 0x0100);
        assert_eq!(opts.defaults.le.scan_win_autoconnect, 0x0020);

        assert_eq!(opts.gatt_cache, BtGattCache::No);
        assert_eq!(opts.key_size, 16);
        assert_eq!(opts.gatt_mtu, 256);
        assert_eq!(opts.gatt_channels, 3);
        assert!(!opts.gatt_client);
        assert_eq!(opts.gatt_export, BtGattExport::ReadWrite);

        assert!(!opts.csis.encrypt);
        assert_eq!(opts.csis.size, 4);
        assert_eq!(opts.csis.rank, 1);

        assert_eq!(opts.avdtp.session_mode, L2capMode::Ertm as u8);
        assert_eq!(opts.avdtp.stream_mode, L2capMode::Streaming as u8);

        assert!(opts.avrcp.volume_without_target);
        assert!(!opts.avrcp.volume_category);

        assert_eq!(opts.advmon.rssi_sampling_period, 42);

        assert!(opts.auto_enable);
        assert_eq!(opts.resume_delay, 3);
        assert_eq!(opts.reconnect_attempts, 5);
    }
}
