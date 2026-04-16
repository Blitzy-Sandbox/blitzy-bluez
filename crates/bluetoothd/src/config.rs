// SPDX-License-Identifier: GPL-2.0-or-later
//
// Configuration parsing for bluetoothd.
// Replaces btd_opts / init_defaults / parse_config from src/main.c and src/btd.h.

use ini::Ini;

// --- Enums ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtMode {
    Dual,
    Bredr,
    Le,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GattCache {
    Always,
    Yes,
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwRepairing {
    Never,
    Confirm,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpsMode {
    Off,
    Single,
    Multiple,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScMode {
    Off,
    On,
    Only,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GattExport {
    Off,
    ReadOnly,
    ReadWrite,
}

// --- Sub-config structs ---

#[derive(Debug, Clone, Default)]
pub struct BrDefaults {
    pub page_scan_type: u16,
    pub page_scan_interval: u16,
    pub page_scan_win: u16,
    pub scan_type: u16,
    pub scan_interval: u16,
    pub scan_win: u16,
    pub link_supervision_timeout: u16,
    pub page_timeout: u16,
    pub min_sniff_interval: u16,
    pub max_sniff_interval: u16,
    pub idle_timeout: u32,
}

#[derive(Debug, Clone, Default)]
pub struct LeDefaults {
    pub addr_resolution: u8,
    pub min_adv_interval: u16,
    pub max_adv_interval: u16,
    pub adv_rotation_interval: u16,
    pub scan_interval_autoconnect: u16,
    pub scan_win_autoconnect: u16,
    pub scan_interval_suspend: u16,
    pub scan_win_suspend: u16,
    pub scan_interval_discovery: u16,
    pub scan_win_discovery: u16,
    pub scan_interval_adv_monitor: u16,
    pub scan_win_adv_monitor: u16,
    pub scan_interval_connect: u16,
    pub scan_win_connect: u16,
    pub min_conn_interval: u16,
    pub max_conn_interval: u16,
    pub conn_latency: u16,
    pub conn_lsto: u16,
    pub autoconnect_timeout: u16,
    pub advmon_allowlist_scan_duration: u16,
    pub advmon_no_filter_scan_duration: u16,
    pub enable_advmon_interleave_scan: u8,
}

#[derive(Debug, Clone)]
pub struct CsisConfig {
    pub encrypt: bool,
    pub sirk: [u8; 16],
    pub size: u8,
    pub rank: u8,
}

impl Default for CsisConfig {
    fn default() -> Self {
        Self {
            encrypt: true,
            sirk: [0u8; 16],
            size: 0,
            rank: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AvdtpConfig {
    pub session_mode: u8,
    pub stream_mode: u8,
}

impl Default for AvdtpConfig {
    fn default() -> Self {
        Self {
            session_mode: BT_IO_MODE_BASIC,
            stream_mode: BT_IO_MODE_BASIC,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AvrcpConfig {
    pub volume_without_target: bool,
    pub volume_category: bool,
}

impl Default for AvrcpConfig {
    fn default() -> Self {
        Self {
            volume_without_target: false,
            volume_category: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdvMonConfig {
    pub rssi_sampling_period: u8,
}

impl Default for AdvMonConfig {
    fn default() -> Self {
        Self {
            rssi_sampling_period: 0xFF,
        }
    }
}

// --- Constants matching C defines ---

const BT_IO_MODE_BASIC: u8 = 0;
const BT_IO_MODE_ERTM: u8 = 1;
const BT_IO_MODE_STREAMING: u8 = 2;

const BT_ATT_DEFAULT_LE_MTU: u16 = 23;
const BT_ATT_MAX_LE_MTU: u16 = 517;

// --- Main config ---

#[derive(Debug, Clone)]
pub struct BtdConfig {
    pub name: String,
    pub class: u32,
    pub pairable: bool,
    pub pairto: u32,
    pub discovto: u32,
    pub tmpto: u32,
    pub privacy: u8,
    pub device_privacy: bool,
    pub name_request_retry_delay: u32,
    pub secure_conn: ScMode,

    pub br: BrDefaults,
    pub le: LeDefaults,

    pub reverse_discovery: bool,
    pub name_resolv: bool,
    pub debug_keys: bool,
    pub fast_conn: bool,
    pub refresh_discovery: bool,
    pub experimental: bool,
    pub testing: bool,
    pub filter_discoverable: bool,

    pub did_source: u16,
    pub did_vendor: u16,
    pub did_product: u16,
    pub did_version: u16,

    pub mode: BtMode,
    pub max_adapters: u16,
    pub gatt_cache: GattCache,
    pub gatt_mtu: u16,
    pub gatt_channels: u8,
    pub gatt_client: bool,
    pub gatt_export: GattExport,
    pub mps: MpsMode,

    pub avdtp: AvdtpConfig,
    pub avrcp: AvrcpConfig,

    pub key_size: u8,
    pub jw_repairing: JwRepairing,

    pub advmon: AdvMonConfig,
    pub csis: CsisConfig,
}

impl Default for BtdConfig {
    fn default() -> Self {
        Self {
            name: "BlueZ".to_string(),
            class: 0x000000,
            pairable: true,
            pairto: 0,
            discovto: 180,
            tmpto: 30,
            privacy: 0,
            device_privacy: false,
            name_request_retry_delay: 300,
            secure_conn: ScMode::On,

            br: BrDefaults {
                page_scan_type: 0xFFFF,
                scan_type: 0xFFFF,
                ..BrDefaults::default()
            },
            le: LeDefaults {
                addr_resolution: 0x01,
                enable_advmon_interleave_scan: 0xFF,
                ..LeDefaults::default()
            },

            reverse_discovery: true,
            name_resolv: true,
            debug_keys: false,
            fast_conn: false,
            refresh_discovery: true,
            experimental: false,
            testing: false,
            filter_discoverable: true,

            did_source: 0x0002,
            did_vendor: 0x1d6b,
            did_product: 0x0246,
            did_version: 0x0500,

            mode: BtMode::Dual,
            max_adapters: 0,
            gatt_cache: GattCache::Always,
            gatt_mtu: BT_ATT_MAX_LE_MTU,
            gatt_channels: 1,
            gatt_client: true,
            gatt_export: GattExport::ReadOnly,
            mps: MpsMode::Off,

            avdtp: AvdtpConfig::default(),
            avrcp: AvrcpConfig::default(),

            key_size: 0,
            jw_repairing: JwRepairing::Never,

            advmon: AdvMonConfig::default(),
            csis: CsisConfig::default(),
        }
    }
}

// --- Parsing helpers ---

fn parse_str<'a>(ini: &'a Ini, section: &str, key: &str) -> Option<&'a str> {
    ini.get_from(Some(section), key)
}

fn parse_bool(ini: &Ini, section: &str, key: &str) -> Option<bool> {
    let s = parse_str(ini, section, key)?;
    match s {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_u8(ini: &Ini, section: &str, key: &str) -> Option<u8> {
    let s = parse_str(ini, section, key)?;
    parse_int_str(s).and_then(|v| u8::try_from(v).ok())
}

fn parse_u16(ini: &Ini, section: &str, key: &str) -> Option<u16> {
    let s = parse_str(ini, section, key)?;
    parse_int_str(s).and_then(|v| u16::try_from(v).ok())
}

fn parse_u32(ini: &Ini, section: &str, key: &str) -> Option<u32> {
    let s = parse_str(ini, section, key)?;
    parse_int_str(s).and_then(|v| u32::try_from(v).ok())
}

fn parse_int_str(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn parse_mode(s: &str) -> BtMode {
    match s {
        "dual" => BtMode::Dual,
        "bredr" => BtMode::Bredr,
        "le" => BtMode::Le,
        _ => BtMode::Dual,
    }
}

fn parse_gatt_cache_str(s: &str) -> GattCache {
    match s {
        "always" => GattCache::Always,
        "yes" => GattCache::Yes,
        "no" => GattCache::No,
        _ => GattCache::Always,
    }
}

fn parse_jw_repairing_str(s: &str) -> JwRepairing {
    match s {
        "never" => JwRepairing::Never,
        "confirm" => JwRepairing::Confirm,
        "always" => JwRepairing::Always,
        _ => JwRepairing::Never,
    }
}

fn parse_sc_mode_str(s: &str) -> ScMode {
    match s {
        "off" => ScMode::Off,
        "on" => ScMode::On,
        "only" => ScMode::Only,
        _ => ScMode::On,
    }
}

fn parse_mps_str(s: &str) -> MpsMode {
    match s {
        "single" => MpsMode::Single,
        "multiple" => MpsMode::Multiple,
        _ => MpsMode::Off,
    }
}

fn parse_gatt_export_str(s: &str) -> GattExport {
    match s {
        "no" | "false" | "off" => GattExport::Off,
        "read-only" => GattExport::ReadOnly,
        "read-write" => GattExport::ReadWrite,
        _ => GattExport::ReadOnly,
    }
}

fn parse_privacy(ini: &Ini, cfg: &mut BtdConfig) {
    let Some(s) = parse_str(ini, "General", "Privacy") else {
        cfg.privacy = 0x00;
        cfg.device_privacy = true;
        return;
    };
    match s {
        "network" | "on" => {
            cfg.privacy = 0x01;
        }
        "device" => {
            cfg.privacy = 0x01;
            cfg.device_privacy = true;
        }
        "limited-network" => {
            cfg.privacy = if cfg.mode == BtMode::Dual { 0x01 } else { 0x00 };
        }
        "limited-device" => {
            if cfg.mode == BtMode::Dual {
                cfg.privacy = 0x02;
            } else {
                cfg.privacy = 0x00;
            }
            cfg.device_privacy = true;
        }
        "off" => {
            cfg.privacy = 0x00;
            cfg.device_privacy = true;
        }
        _ => {
            cfg.privacy = 0x00;
        }
    }
}

fn hex2bin(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut buf = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = char::from(chunk[0]).to_digit(16)?;
        let lo = char::from(chunk[1]).to_digit(16)?;
        buf[i] = ((hi << 4) | lo) as u8;
    }
    Some(buf)
}

// --- Main load function ---

pub fn load_config(path: &str) -> BtdConfig {
    let mut cfg = BtdConfig::default();

    let ini = match Ini::load_from_file(path) {
        Ok(ini) => ini,
        Err(_) => return cfg,
    };

    // [General]
    if let Some(s) = parse_str(&ini, "General", "Name") {
        cfg.name = s.to_string();
    }
    if let Some(s) = parse_str(&ini, "General", "Class") {
        if let Some(v) = parse_int_str(s) {
            cfg.class = v as u32;
        }
    }
    if let Some(v) = parse_u32(&ini, "General", "DiscoverableTimeout") {
        cfg.discovto = v;
    }
    if let Some(v) = parse_bool(&ini, "General", "AlwaysPairable") {
        cfg.pairable = v;
    }
    if let Some(v) = parse_u32(&ini, "General", "PairableTimeout") {
        cfg.pairto = v;
    }
    if let Some(v) = parse_bool(&ini, "General", "ReverseServiceDiscovery") {
        cfg.reverse_discovery = v;
    }
    if let Some(v) = parse_bool(&ini, "General", "NameResolving") {
        cfg.name_resolv = v;
    }
    if let Some(v) = parse_bool(&ini, "General", "DebugKeys") {
        cfg.debug_keys = v;
    }
    if let Some(s) = parse_str(&ini, "General", "ControllerMode") {
        cfg.mode = parse_mode(s);
    }
    if let Some(v) = parse_u16(&ini, "General", "MaxControllers") {
        cfg.max_adapters = v;
    }
    if let Some(s) = parse_str(&ini, "General", "MultiProfile") {
        cfg.mps = parse_mps_str(s);
    }
    if let Some(v) = parse_bool(&ini, "General", "FastConnectable") {
        cfg.fast_conn = v;
    }
    parse_privacy(&ini, &mut cfg);
    if let Some(s) = parse_str(&ini, "General", "JustWorksRepairing") {
        cfg.jw_repairing = parse_jw_repairing_str(s);
    }
    if let Some(v) = parse_u32(&ini, "General", "TemporaryTimeout") {
        cfg.tmpto = v;
    }
    if let Some(v) = parse_bool(&ini, "General", "RefreshDiscovery") {
        cfg.refresh_discovery = v;
    }
    if let Some(s) = parse_str(&ini, "General", "SecureConnections") {
        cfg.secure_conn = parse_sc_mode_str(s);
    }
    if let Some(v) = parse_bool(&ini, "General", "Experimental") {
        cfg.experimental = v;
    }
    if let Some(v) = parse_bool(&ini, "General", "Testing") {
        cfg.testing = v;
    }
    if let Some(v) = parse_u32(&ini, "General", "RemoteNameRequestRetryDelay") {
        cfg.name_request_retry_delay = v;
    }
    if let Some(v) = parse_bool(&ini, "General", "FilterDiscoverable") {
        cfg.filter_discoverable = v;
    }

    // [BR]
    if cfg.mode != BtMode::Le {
        if let Some(v) = parse_u16(&ini, "BR", "PageScanType") { cfg.br.page_scan_type = v; }
        if let Some(v) = parse_u16(&ini, "BR", "PageScanInterval") { cfg.br.page_scan_interval = v; }
        if let Some(v) = parse_u16(&ini, "BR", "PageScanWindow") { cfg.br.page_scan_win = v; }
        if let Some(v) = parse_u16(&ini, "BR", "InquiryScanType") { cfg.br.scan_type = v; }
        if let Some(v) = parse_u16(&ini, "BR", "InquiryScanInterval") { cfg.br.scan_interval = v; }
        if let Some(v) = parse_u16(&ini, "BR", "InquiryScanWindow") { cfg.br.scan_win = v; }
        if let Some(v) = parse_u16(&ini, "BR", "LinkSupervisionTimeout") { cfg.br.link_supervision_timeout = v; }
        if let Some(v) = parse_u16(&ini, "BR", "PageTimeout") { cfg.br.page_timeout = v; }
        if let Some(v) = parse_u16(&ini, "BR", "MinSniffInterval") { cfg.br.min_sniff_interval = v; }
        if let Some(v) = parse_u16(&ini, "BR", "MaxSniffInterval") { cfg.br.max_sniff_interval = v; }
        if let Some(v) = parse_u32(&ini, "BR", "IdleTimeout") { cfg.br.idle_timeout = v; }
    }

    // [LE]
    if cfg.mode != BtMode::Bredr {
        if let Some(v) = parse_u8(&ini, "LE", "CentralAddressResolution") { cfg.le.addr_resolution = v; }
        if let Some(v) = parse_u16(&ini, "LE", "MinAdvertisementInterval") { cfg.le.min_adv_interval = v; }
        if let Some(v) = parse_u16(&ini, "LE", "MaxAdvertisementInterval") { cfg.le.max_adv_interval = v; }
        if let Some(v) = parse_u16(&ini, "LE", "MultiAdvertisementRotationInterval") { cfg.le.adv_rotation_interval = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ScanIntervalAutoConnect") { cfg.le.scan_interval_autoconnect = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ScanWindowAutoConnect") { cfg.le.scan_win_autoconnect = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ScanIntervalSuspend") { cfg.le.scan_interval_suspend = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ScanWindowSuspend") { cfg.le.scan_win_suspend = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ScanIntervalDiscovery") { cfg.le.scan_interval_discovery = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ScanWindowDiscovery") { cfg.le.scan_win_discovery = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ScanIntervalAdvMonitor") { cfg.le.scan_interval_adv_monitor = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ScanWindowAdvMonitor") { cfg.le.scan_win_adv_monitor = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ScanIntervalConnect") { cfg.le.scan_interval_connect = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ScanWindowConnect") { cfg.le.scan_win_connect = v; }
        if let Some(v) = parse_u16(&ini, "LE", "MinConnectionInterval") { cfg.le.min_conn_interval = v; }
        if let Some(v) = parse_u16(&ini, "LE", "MaxConnectionInterval") { cfg.le.max_conn_interval = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ConnectionLatency") { cfg.le.conn_latency = v; }
        if let Some(v) = parse_u16(&ini, "LE", "ConnectionSupervisionTimeout") { cfg.le.conn_lsto = v; }
        if let Some(v) = parse_u16(&ini, "LE", "Autoconnecttimeout") { cfg.le.autoconnect_timeout = v; }
        if let Some(v) = parse_u16(&ini, "LE", "AdvMonAllowlistScanDuration") { cfg.le.advmon_allowlist_scan_duration = v; }
        if let Some(v) = parse_u16(&ini, "LE", "AdvMonNoFilterScanDuration") { cfg.le.advmon_no_filter_scan_duration = v; }
        if let Some(v) = parse_u8(&ini, "LE", "EnableAdvMonInterleaveScan") { cfg.le.enable_advmon_interleave_scan = v; }
    }

    // [GATT]
    if let Some(s) = parse_str(&ini, "GATT", "Cache") {
        cfg.gatt_cache = parse_gatt_cache_str(s);
    }
    if let Some(v) = parse_u8(&ini, "GATT", "KeySize") {
        cfg.key_size = v;
    }
    if let Some(v) = parse_u16(&ini, "GATT", "ExchangeMTU") {
        cfg.gatt_mtu = v.clamp(BT_ATT_DEFAULT_LE_MTU, BT_ATT_MAX_LE_MTU);
    }
    if let Some(v) = parse_u8(&ini, "GATT", "Channels") {
        cfg.gatt_channels = v.clamp(1, 6);
    }
    if let Some(v) = parse_bool(&ini, "GATT", "Client") {
        cfg.gatt_client = v;
    }
    if let Some(s) = parse_str(&ini, "GATT", "ExportClaimedServices") {
        cfg.gatt_export = parse_gatt_export_str(s);
    }

    // [CSIS]
    if let Some(s) = parse_str(&ini, "CSIS", "SIRK") {
        if let Some(bin) = hex2bin(s) {
            cfg.csis.sirk = bin;
        }
    }
    if let Some(v) = parse_bool(&ini, "CSIS", "Encryption") {
        cfg.csis.encrypt = v;
    }
    if let Some(v) = parse_u8(&ini, "CSIS", "Size") {
        cfg.csis.size = v;
    }
    if let Some(v) = parse_u8(&ini, "CSIS", "Rank") {
        cfg.csis.rank = v;
    }

    // [AVDTP]
    if let Some(s) = parse_str(&ini, "AVDTP", "SessionMode") {
        cfg.avdtp.session_mode = match s {
            "basic" => BT_IO_MODE_BASIC,
            "ertm" => BT_IO_MODE_ERTM,
            _ => BT_IO_MODE_BASIC,
        };
    }
    if let Some(s) = parse_str(&ini, "AVDTP", "StreamMode") {
        cfg.avdtp.stream_mode = match s {
            "basic" => BT_IO_MODE_BASIC,
            "streaming" => BT_IO_MODE_STREAMING,
            _ => BT_IO_MODE_BASIC,
        };
    }

    // [AVRCP]
    if let Some(v) = parse_bool(&ini, "AVRCP", "VolumeWithoutTarget") {
        cfg.avrcp.volume_without_target = v;
    }
    if let Some(v) = parse_bool(&ini, "AVRCP", "VolumeCategory") {
        cfg.avrcp.volume_category = v;
    }

    // [AdvMon]
    if let Some(v) = parse_u8(&ini, "AdvMon", "RSSISamplingPeriod") {
        cfg.advmon.rssi_sampling_period = v;
    }

    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let cfg = BtdConfig::default();
        assert_eq!(cfg.name, "BlueZ");
        assert_eq!(cfg.class, 0x000000);
        assert!(cfg.pairable);
        assert_eq!(cfg.discovto, 180);
        assert_eq!(cfg.tmpto, 30);
        assert_eq!(cfg.name_request_retry_delay, 300);
        assert!(cfg.reverse_discovery);
        assert!(cfg.name_resolv);
        assert_eq!(cfg.mode, BtMode::Dual);
        assert_eq!(cfg.max_adapters, 0);
        assert_eq!(cfg.gatt_cache, GattCache::Always);
        assert_eq!(cfg.gatt_mtu, 517);
        assert_eq!(cfg.gatt_channels, 1);
        assert!(cfg.gatt_client);
        assert_eq!(cfg.key_size, 0);
        assert_eq!(cfg.jw_repairing, JwRepairing::Never);
        assert_eq!(cfg.privacy, 0);
        assert_eq!(cfg.secure_conn, ScMode::On);
        assert!(cfg.refresh_discovery);
        assert!(cfg.filter_discoverable);
        assert_eq!(cfg.gatt_export, GattExport::ReadOnly);
        assert!(cfg.csis.encrypt);
        assert_eq!(cfg.advmon.rssi_sampling_period, 0xFF);
        assert_eq!(cfg.br.page_scan_type, 0xFFFF);
        assert_eq!(cfg.br.scan_type, 0xFFFF);
        assert_eq!(cfg.le.addr_resolution, 0x01);
        assert_eq!(cfg.le.enable_advmon_interleave_scan, 0xFF);
    }

    #[test]
    fn test_parse_mode() {
        assert_eq!(parse_mode("dual"), BtMode::Dual);
        assert_eq!(parse_mode("bredr"), BtMode::Bredr);
        assert_eq!(parse_mode("le"), BtMode::Le);
        assert_eq!(parse_mode("invalid"), BtMode::Dual);
    }

    #[test]
    fn test_parse_gatt_cache() {
        assert_eq!(parse_gatt_cache_str("always"), GattCache::Always);
        assert_eq!(parse_gatt_cache_str("yes"), GattCache::Yes);
        assert_eq!(parse_gatt_cache_str("no"), GattCache::No);
        assert_eq!(parse_gatt_cache_str("invalid"), GattCache::Always);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let cfg = load_config("/nonexistent/path/main.conf");
        assert_eq!(cfg.name, "BlueZ");
        assert_eq!(cfg.discovto, 180);
        assert_eq!(cfg.mode, BtMode::Dual);
    }

    #[test]
    fn test_load_config_from_file() {
        let dir = std::env::temp_dir().join("bluez_config_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_main.conf");

        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "[General]").unwrap();
            writeln!(f, "Name=TestBT").unwrap();
            writeln!(f, "DiscoverableTimeout=300").unwrap();
            writeln!(f, "ControllerMode=le").unwrap();
            writeln!(f, "AlwaysPairable=false").unwrap();
            writeln!(f, "SecureConnections=only").unwrap();
            writeln!(f, "").unwrap();
            writeln!(f, "[GATT]").unwrap();
            writeln!(f, "Cache=no").unwrap();
            writeln!(f, "ExchangeMTU=256").unwrap();
            writeln!(f, "Channels=3").unwrap();
            writeln!(f, "").unwrap();
            writeln!(f, "[LE]").unwrap();
            writeln!(f, "MinAdvertisementInterval=64").unwrap();
            writeln!(f, "").unwrap();
            writeln!(f, "[AVDTP]").unwrap();
            writeln!(f, "SessionMode=ertm").unwrap();
            writeln!(f, "StreamMode=streaming").unwrap();
            writeln!(f, "").unwrap();
            writeln!(f, "[AdvMon]").unwrap();
            writeln!(f, "RSSISamplingPeriod=10").unwrap();
        }

        let cfg = load_config(path.to_str().unwrap());
        assert_eq!(cfg.name, "TestBT");
        assert_eq!(cfg.discovto, 300);
        assert_eq!(cfg.mode, BtMode::Le);
        assert!(!cfg.pairable);
        assert_eq!(cfg.secure_conn, ScMode::Only);
        assert_eq!(cfg.gatt_cache, GattCache::No);
        assert_eq!(cfg.gatt_mtu, 256);
        assert_eq!(cfg.gatt_channels, 3);
        assert_eq!(cfg.le.min_adv_interval, 64);
        assert_eq!(cfg.avdtp.session_mode, BT_IO_MODE_ERTM);
        assert_eq!(cfg.avdtp.stream_mode, BT_IO_MODE_STREAMING);
        assert_eq!(cfg.advmon.rssi_sampling_period, 10);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
