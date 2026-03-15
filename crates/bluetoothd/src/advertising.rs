// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2015  Google Inc.
//
// LE Advertising Manager — Rust rewrite of `src/advertising.c` and
// `src/advertising.h`.
//
// Implements the `org.bluez.LEAdvertisingManager1` D-Bus interface, providing
// per-adapter advertising instance management with support for both legacy
// (MGMT_OP_ADD_ADVERTISING) and extended (MGMT_OP_ADD_EXT_ADV_PARAMS +
// MGMT_OP_ADD_EXT_ADV_DATA) advertising command sets.

use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, warn};

use zbus::Connection;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};
use zerocopy::{FromBytes, IntoBytes};

use bluez_shared::crypto::aes_cmac::{bt_crypto_rsi, bt_crypto_sih};
use bluez_shared::mgmt::client::MgmtSocket;
use bluez_shared::sys::mgmt::{
    MGMT_ADV_FLAG_SEC_MASK, MGMT_CAP_LE_TX_PWR, MGMT_OP_ADD_ADVERTISING, MGMT_OP_ADD_EXT_ADV_DATA,
    MGMT_OP_ADD_EXT_ADV_PARAMS, MGMT_OP_READ_ADV_FEATURES, MGMT_OP_READ_CONTROLLER_CAP,
    MGMT_OP_REMOVE_ADVERTISING, MGMT_STATUS_SUCCESS, MgmtAdvFlags, MgmtSettings,
    mgmt_cp_add_advertising, mgmt_cp_add_ext_adv_data, mgmt_cp_add_ext_adv_params,
    mgmt_cp_remove_advertising, mgmt_rp_add_ext_adv_params, mgmt_rp_read_adv_features,
};
use bluez_shared::util::ad::{
    BT_AD_CSIP_RSI, BT_AD_FLAG_GENERAL, BT_AD_FLAG_LIMITED, BT_AD_FLAG_NO_BREDR,
    BT_AD_MAX_DATA_LEN, BtAd,
};
use bluez_shared::util::uuid::BtUuid;

use crate::adapter::{BtdAdapter, KernelFeatures, btd_has_kernel_features};
use crate::config::BtdOpts;
use crate::dbus_common::btd_get_dbus_connection;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error};

// ===========================================================================
// Constants
// ===========================================================================

/// D-Bus interface name for individual advertisements.
const LE_ADVERTISEMENT_IFACE: &str = "org.bluez.LEAdvertisement1";

/// Advertisement type: non-connectable, undirected.
const AD_TYPE_BROADCAST: u8 = 0;

/// Advertisement type: connectable, undirected.
const AD_TYPE_PERIPHERAL: u8 = 1;

/// TX power sentinel indicating no preference (0x7F).
const ADV_TX_POWER_NO_PREFERENCE: i8 = 0x7F;

/// Minimum advertising interval in 0.625ms units (0x20 = 20ms).
const ADV_INTERVAL_MIN: u32 = 0x0020;

/// Maximum advertising interval in 0.625ms units (0xFFFFFF ≈ 10485s).
const ADV_INTERVAL_MAX: u32 = 0x00FF_FFFF;

// ===========================================================================
// Include / Secondary / Feature tables
// ===========================================================================

/// Mapping from SupportedIncludes string to MGMT flag and optional setter.
struct AdvInclude {
    name: &'static str,
    flag: MgmtAdvFlags,
}

/// Static table of supported include types.
const INCLUDES: &[AdvInclude] = &[
    AdvInclude { name: "tx-power", flag: MgmtAdvFlags::TX_POWER },
    AdvInclude { name: "appearance", flag: MgmtAdvFlags::APPEARANCE },
    AdvInclude { name: "local-name", flag: MgmtAdvFlags::LOCAL_NAME },
];

/// Include entry for RSI (has no MGMT flag; uses custom setter).
const RSI_INCLUDE_NAME: &str = "rsi";

/// Mapping from secondary channel name to MGMT flag.
struct AdvSecondary {
    name: &'static str,
    flag: MgmtAdvFlags,
}

const SECONDARY_CHANNELS: &[AdvSecondary] = &[
    AdvSecondary { name: "1M", flag: MgmtAdvFlags::SEC_1M },
    AdvSecondary { name: "2M", flag: MgmtAdvFlags::SEC_2M },
    AdvSecondary { name: "Coded", flag: MgmtAdvFlags::SEC_CODED },
];

/// Mapping from feature name to MGMT flag.
struct AdvFeature {
    name: &'static str,
    flag: MgmtAdvFlags,
}

const FEATURES: &[AdvFeature] = &[
    AdvFeature { name: "CanSetTxPower", flag: MgmtAdvFlags::CAN_SET_TX_POWER },
    AdvFeature { name: "HardwareOffload", flag: MgmtAdvFlags::HW_OFFLOAD },
];

// ===========================================================================
// BtdAdvClient — per-advertisement client state
// ===========================================================================

/// Represents a single registered advertisement from a D-Bus client.
///
/// Replaces C `struct btd_adv_client`.
struct BtdAdvClient {
    /// D-Bus unique sender name (e.g. ":1.42").
    owner: String,
    /// D-Bus object path of the LEAdvertisement1 object.
    path: String,
    /// Local name to include in the advertisement.
    name: Option<String>,
    /// GAP appearance value (u16::MAX means unset).
    appearance: u16,
    /// Advertising duration in seconds (0 = no limit).
    duration: u16,
    /// Client timeout in seconds (0 = no timeout).
    timeout: u16,
    /// Discoverable timeout in seconds.
    discoverable_to: u16,
    /// Advertisement type: AD_TYPE_BROADCAST or AD_TYPE_PERIPHERAL.
    ad_type: u8,
    /// MGMT advertising flags accumulated from Includes and Discoverable.
    flags: u32,
    /// Advertising data payload builder.
    data: BtAd,
    /// Scan response data payload builder.
    scan: BtAd,
    /// Allocated MGMT advertising instance ID.
    instance: u8,
    /// Minimum advertising interval (0.625ms units).
    min_interval: u32,
    /// Maximum advertising interval (0.625ms units).
    max_interval: u32,
    /// Requested TX power level (ADV_TX_POWER_NO_PREFERENCE if unset).
    tx_power: i8,
    /// Handle for the client timeout task.
    timeout_handle: Option<JoinHandle<()>>,
    /// Handle for the discoverable timeout task.
    disc_timeout_handle: Option<JoinHandle<()>>,
}

impl BtdAdvClient {
    /// Creates a new advertisement client with default values.
    fn new(owner: String, path: String) -> Self {
        Self {
            owner,
            path,
            name: None,
            appearance: u16::MAX,
            duration: 0,
            timeout: 0,
            discoverable_to: 0,
            ad_type: AD_TYPE_BROADCAST,
            flags: 0,
            data: BtAd::new(),
            scan: BtAd::new(),
            instance: 0,
            min_interval: 0,
            max_interval: 0,
            tx_power: ADV_TX_POWER_NO_PREFERENCE,
            timeout_handle: None,
            disc_timeout_handle: None,
        }
    }
}

impl Drop for BtdAdvClient {
    fn drop(&mut self) {
        // Abort any pending timeout tasks on cleanup.
        if let Some(h) = self.timeout_handle.take() {
            h.abort();
        }
        if let Some(h) = self.disc_timeout_handle.take() {
            h.abort();
        }
    }
}

// ===========================================================================
// Advertisement parsing — reads LEAdvertisement1 properties from D-Bus proxy
// ===========================================================================

/// Reads all LEAdvertisement1 properties from the D-Bus proxy and populates
/// the given `BtdAdvClient`. Returns `Ok(())` on success or an error if any
/// required property is invalid.
async fn parse_advertisement(
    conn: &Connection,
    client: &mut BtdAdvClient,
    _supported_flags: u32,
    csis_sirk: &[u8; 16],
) -> Result<(), BtdError> {
    let proxy: zbus::Proxy<'_> = zbus::proxy::Builder::new(conn)
        .destination(client.owner.as_str())
        .map_err(|e| BtdError::failed(&format!("proxy builder destination: {e}")))?
        .path(client.path.as_str())
        .map_err(|e| BtdError::failed(&format!("proxy builder path: {e}")))?
        .interface(LE_ADVERTISEMENT_IFACE)
        .map_err(|e| BtdError::failed(&format!("proxy builder interface: {e}")))?
        .build()
        .await
        .map_err(|e| BtdError::failed(&format!("proxy build: {e}")))?;

    // ---- Type ----
    if let Ok(ad_type_str) = proxy.get_property::<String>("Type").await {
        match ad_type_str.as_str() {
            "broadcast" => client.ad_type = AD_TYPE_BROADCAST,
            "peripheral" => client.ad_type = AD_TYPE_PERIPHERAL,
            _ => return Err(BtdError::invalid_args_str("Invalid Type property")),
        }
    }

    // ---- ServiceUUIDs ----
    parse_uuid_list(&proxy, "ServiceUUIDs", &mut client.data).await;

    // ---- ScanResponseServiceUUIDs ----
    parse_uuid_list(&proxy, "ScanResponseServiceUUIDs", &mut client.scan).await;

    // ---- SolicitUUIDs ----
    parse_solicit_list(&proxy, "SolicitUUIDs", &mut client.data).await;

    // ---- ScanResponseSolicitUUIDs ----
    parse_solicit_list(&proxy, "ScanResponseSolicitUUIDs", &mut client.scan).await;

    // ---- ManufacturerData ----
    parse_manufacturer_data(&proxy, "ManufacturerData", &mut client.data).await;

    // ---- ScanResponseManufacturerData ----
    parse_manufacturer_data(&proxy, "ScanResponseManufacturerData", &mut client.scan).await;

    // ---- ServiceData ----
    parse_service_data(&proxy, "ServiceData", &mut client.data).await;

    // ---- ScanResponseServiceData ----
    parse_service_data(&proxy, "ScanResponseServiceData", &mut client.scan).await;

    // ---- Data (generic AD data dictionary: ad_type -> bytes) ----
    parse_generic_data(&proxy, "Data", &mut client.data, csis_sirk).await;

    // ---- ScanResponseData ----
    parse_generic_data(&proxy, "ScanResponseData", &mut client.scan, csis_sirk).await;

    // ---- Includes ----
    if let Ok(includes) = proxy.get_property::<Vec<String>>("Includes").await {
        for inc in &includes {
            if inc == RSI_INCLUDE_NAME {
                set_rsi(csis_sirk, &mut client.data)?;
                continue;
            }
            for entry in INCLUDES {
                if entry.name == inc.as_str() {
                    client.flags |= entry.flag.bits();
                    break;
                }
            }
        }
    }

    // ---- LocalName ----
    if let Ok(name) = proxy.get_property::<String>("LocalName").await {
        if !name.is_empty() {
            client.data.add_name(&name);
            client.name = Some(name);
        }
    }

    // ---- Appearance ----
    if let Ok(appearance) = proxy.get_property::<u16>("Appearance").await {
        client.appearance = appearance;
        client.data.add_appearance(appearance);
    }

    // ---- Duration ----
    if let Ok(duration) = proxy.get_property::<u16>("Duration").await {
        client.duration = duration;
    }

    // ---- Timeout ----
    if let Ok(timeout) = proxy.get_property::<u16>("Timeout").await {
        client.timeout = timeout;
    }

    // ---- Discoverable ----
    if let Ok(discoverable) = proxy.get_property::<bool>("Discoverable").await {
        if discoverable {
            client.flags |= MgmtAdvFlags::DISCOVERABLE.bits();
        }
    }

    // ---- DiscoverableTimeout ----
    if let Ok(disc_to) = proxy.get_property::<u16>("DiscoverableTimeout").await {
        client.discoverable_to = disc_to;
    }

    // ---- SecondaryChannel ----
    if let Ok(channel) = proxy.get_property::<String>("SecondaryChannel").await {
        for sec in SECONDARY_CHANNELS {
            if sec.name == channel.as_str() {
                client.flags |= sec.flag.bits();
                break;
            }
        }
    }

    // ---- MinInterval / MaxInterval (convert ms to 0.625ms jiffies) ----
    if let Ok(min_ms) = proxy.get_property::<u32>("MinInterval").await {
        let jiffies = ms_to_adv_interval(min_ms);
        if (ADV_INTERVAL_MIN..=ADV_INTERVAL_MAX).contains(&jiffies) {
            client.min_interval = jiffies;
        }
    }
    if let Ok(max_ms) = proxy.get_property::<u32>("MaxInterval").await {
        let jiffies = ms_to_adv_interval(max_ms);
        if (ADV_INTERVAL_MIN..=ADV_INTERVAL_MAX).contains(&jiffies) {
            client.max_interval = jiffies;
        }
    }

    // ---- TxPower ----
    if let Ok(tx) = proxy.get_property::<i16>("TxPower").await {
        if (-127..=20).contains(&tx) {
            client.tx_power = tx as i8;
        }
    }

    Ok(())
}

// ===========================================================================
// Parsing helpers
// ===========================================================================

/// Parses a UUID string list property and adds to the BtAd service UUID list.
async fn parse_uuid_list(proxy: &zbus::Proxy<'_>, prop: &str, ad: &mut BtAd) {
    if let Ok(uuids) = proxy.get_property::<Vec<String>>(prop).await {
        ad.clear_service_uuid();
        for uuid_str in &uuids {
            if let Ok(uuid) = BtUuid::from_str(uuid_str) {
                ad.add_service_uuid(&uuid);
            } else {
                debug!("advertising: invalid UUID in {}: {}", prop, uuid_str);
            }
        }
    }
}

/// Parses a UUID string list property and adds to the BtAd solicit UUID list.
async fn parse_solicit_list(proxy: &zbus::Proxy<'_>, prop: &str, ad: &mut BtAd) {
    if let Ok(uuids) = proxy.get_property::<Vec<String>>(prop).await {
        ad.clear_solicit_uuid();
        for uuid_str in &uuids {
            if let Ok(uuid) = BtUuid::from_str(uuid_str) {
                ad.add_solicit_uuid(&uuid);
            } else {
                debug!("advertising: invalid UUID in {}: {}", prop, uuid_str);
            }
        }
    }
}

/// Parses ManufacturerData property (dict of u16 company ID to bytes).
async fn parse_manufacturer_data(proxy: &zbus::Proxy<'_>, prop: &str, ad: &mut BtAd) {
    if let Ok(manuf) = proxy.get_property::<HashMap<u16, OwnedValue>>(prop).await {
        ad.clear_manufacturer_data();
        for (id, value) in &manuf {
            if let Ok(bytes) = <Vec<u8>>::try_from(value.clone()) {
                ad.add_manufacturer_data(*id, &bytes);
            }
        }
    }
}

/// Parses ServiceData property (dict of UUID string to bytes).
async fn parse_service_data(proxy: &zbus::Proxy<'_>, prop: &str, ad: &mut BtAd) {
    if let Ok(svc_data) = proxy.get_property::<HashMap<String, OwnedValue>>(prop).await {
        ad.clear_service_data();
        for (uuid_str, value) in &svc_data {
            if let Ok(uuid) = BtUuid::from_str(uuid_str) {
                if let Ok(bytes) = <Vec<u8>>::try_from(value.clone()) {
                    ad.add_service_data(&uuid, &bytes);
                }
            }
        }
    }
}

/// Parses generic Data property (dict of u8 AD type to bytes).
///
/// Also validates RSI data entries against the CSIS SIRK when
/// [`BT_AD_CSIP_RSI`] is encountered.
async fn parse_generic_data(
    proxy: &zbus::Proxy<'_>,
    prop: &str,
    ad: &mut BtAd,
    csis_sirk: &[u8; 16],
) {
    if let Ok(data) = proxy.get_property::<HashMap<u8, OwnedValue>>(prop).await {
        ad.clear_data();
        for (ad_type, value) in &data {
            if let Ok(bytes) = <Vec<u8>>::try_from(value.clone()) {
                // Validate RSI data against SIRK
                if *ad_type == BT_AD_CSIP_RSI && !validate_rsi(csis_sirk, &bytes) {
                    debug!("advertising: invalid RSI data in {}", prop);
                    continue;
                }
                ad.add_data(*ad_type, &bytes);
            }
        }
    }
}

/// Converts milliseconds to advertising interval jiffies (0.625ms units).
fn ms_to_adv_interval(ms: u32) -> u32 {
    (ms as u64 * 8 / 5) as u32
}

/// Validates an RSI in the advertisement data against the CSIS SIRK.
fn validate_rsi(sirk: &[u8; 16], rsi_data: &[u8]) -> bool {
    if rsi_data.len() != 6 {
        return false;
    }
    let prand = &rsi_data[3..6];
    let hash = &rsi_data[0..3];

    if (prand[2] & 0xc0) != 0x40 {
        return false;
    }

    match bt_crypto_sih(sirk, &[prand[0], prand[1], prand[2]]) {
        Ok(computed_hash) => computed_hash == [hash[0], hash[1], hash[2]],
        Err(_) => false,
    }
}

/// Generates RSI data from SIRK and adds it to the AD builder.
fn set_rsi(sirk: &[u8; 16], ad: &mut BtAd) -> Result<(), BtdError> {
    if sirk.iter().all(|&b| b == 0) {
        return Ok(());
    }

    match bt_crypto_rsi(sirk) {
        Ok(rsi) => {
            ad.add_data(BT_AD_CSIP_RSI, &rsi);
            Ok(())
        }
        Err(e) => {
            warn!("advertising: failed to generate RSI: {:?}", e);
            Err(BtdError::failed("Failed to generate RSI"))
        }
    }
}

// ===========================================================================
// Advertising data generation and flag computation
// ===========================================================================

/// Sets LE advertising flags on the client data based on adapter state.
///
/// Mirrors C `set_flags()` from advertising.c.
fn set_flags(client: &mut BtdAdvClient, adapter_bredr_supported: bool, adapter_discoverable: bool) {
    let mut flags: u8 = 0;

    // Add NO_BREDR flag if adapter doesn't support BR/EDR or is not discoverable
    if !adapter_bredr_supported {
        flags |= BT_AD_FLAG_NO_BREDR;
    }

    // Set discoverable flags if applicable
    if client.flags & MgmtAdvFlags::DISCOVERABLE.bits() != 0 {
        flags |= BT_AD_FLAG_GENERAL;
    } else if client.flags & MgmtAdvFlags::LIMITED_DISCOVERABLE.bits() != 0 {
        flags |= BT_AD_FLAG_LIMITED;
    } else if adapter_discoverable && !adapter_bredr_supported {
        flags |= BT_AD_FLAG_GENERAL;
    }

    if flags != 0 {
        client.data.add_flags(&[flags]);
    }
}

/// Computes MGMT advertising flags for a client.
///
/// Mirrors C `get_adv_flags()` from advertising.c.
fn get_adv_flags(client: &BtdAdvClient, supported_flags: u32, adapter_discoverable: bool) -> u32 {
    let mut flags = client.flags;

    // Peripheral type implies connectable
    if client.ad_type == AD_TYPE_PERIPHERAL {
        flags |= MgmtAdvFlags::CONNECTABLE.bits();

        // Set discoverable if adapter is discoverable and no explicit flag set
        if adapter_discoverable
            && (flags
                & (MgmtAdvFlags::DISCOVERABLE.bits() | MgmtAdvFlags::LIMITED_DISCOVERABLE.bits()))
                == 0
        {
            flags |= MgmtAdvFlags::DISCOVERABLE.bits();
        }
    }

    // Only keep supported flags
    flags &= supported_flags;

    // Force SEC_1M if data exceeds legacy limit and secondary channels are supported
    if client.data.length() > BT_AD_MAX_DATA_LEN as usize
        && (supported_flags & MGMT_ADV_FLAG_SEC_MASK) != 0
    {
        flags |= MgmtAdvFlags::SEC_1M.bits();
    }

    flags
}

/// Calculates the maximum available advertising data length considering
/// flags-reserved overhead.
///
/// Mirrors C `calc_max_adv_len()` from advertising.c.
fn calc_max_adv_len(client: &BtdAdvClient, max_adv_len: u8) -> u8 {
    let mut len = max_adv_len;

    // TX_POWER flag reserves 3 bytes (1 type + 1 length + 1 value)
    if client.flags & MgmtAdvFlags::TX_POWER.bits() != 0 {
        len = len.saturating_sub(3);
    }

    // Discoverable/limited flags reserve 3 bytes for flags field
    if client.flags
        & (MgmtAdvFlags::DISCOVERABLE.bits()
            | MgmtAdvFlags::LIMITED_DISCOVERABLE.bits()
            | MgmtAdvFlags::MANAGED_FLAGS.bits())
        != 0
    {
        len = len.saturating_sub(3);
    }

    // Appearance flag reserves 4 bytes (1 type + 1 length + 2 value)
    if client.flags & MgmtAdvFlags::APPEARANCE.bits() != 0 {
        len = len.saturating_sub(4);
    }

    len
}

/// Returns true if the client has scan response data to send.
fn client_has_scan_response(client: &BtdAdvClient, _supported_flags: u32) -> bool {
    // Check if client data/scan exceed legacy limit
    if client.data.length() > BT_AD_MAX_DATA_LEN as usize {
        return true;
    }
    if !client.scan.is_empty() {
        return true;
    }

    // APPEARANCE and LOCAL_NAME go into scan response
    if client.flags & (MgmtAdvFlags::APPEARANCE.bits() | MgmtAdvFlags::LOCAL_NAME.bits()) != 0 {
        return true;
    }

    false
}

// ===========================================================================
// MGMT command builders
// ===========================================================================

/// Sends legacy MGMT_OP_ADD_ADVERTISING command.
async fn refresh_legacy_adv(
    mgmt: &MgmtSocket,
    mgmt_index: u16,
    client: &BtdAdvClient,
    flags: u32,
) -> Result<(), BtdError> {
    let adv_data = client.data.generate().unwrap_or_default();
    let scan_data = client.scan.generate().unwrap_or_default();

    let header = mgmt_cp_add_advertising {
        instance: client.instance,
        flags: flags.to_le(),
        duration: client.duration.to_le(),
        timeout: client.timeout.to_le(),
        adv_data_len: adv_data.len() as u8,
        scan_rsp_len: scan_data.len() as u8,
        data: [],
    };

    let header_bytes = header.as_bytes();
    let mut params = Vec::with_capacity(header_bytes.len() + adv_data.len() + scan_data.len());
    params.extend_from_slice(header_bytes);
    params.extend_from_slice(&adv_data);
    params.extend_from_slice(&scan_data);

    let resp = mgmt
        .send_command(MGMT_OP_ADD_ADVERTISING, mgmt_index, &params)
        .await
        .map_err(|e| BtdError::failed(&format!("MGMT ADD_ADVERTISING failed: {e}")))?;

    if resp.status != MGMT_STATUS_SUCCESS {
        return Err(BtdError::failed(&format!(
            "MGMT ADD_ADVERTISING returned status {}",
            resp.status
        )));
    }

    debug!("advertising: legacy adv instance {} programmed", client.instance);
    Ok(())
}

/// Sends extended MGMT_OP_ADD_EXT_ADV_PARAMS + MGMT_OP_ADD_EXT_ADV_DATA.
async fn refresh_extended_adv(
    mgmt: &MgmtSocket,
    mgmt_index: u16,
    client: &mut BtdAdvClient,
    flags: u32,
) -> Result<(), BtdError> {
    // Include scan response flag if client has scan response data
    let flags = if client_has_scan_response(client, flags) {
        flags | MgmtAdvFlags::PARAM_SCAN_RSP.bits()
    } else {
        flags
    };

    // Step 1: Send ADD_EXT_ADV_PARAMS
    let cp_params = mgmt_cp_add_ext_adv_params {
        instance: client.instance,
        flags: flags.to_le(),
        duration: client.duration.to_le(),
        timeout: client.timeout.to_le(),
        min_interval: client.min_interval.to_le(),
        max_interval: client.max_interval.to_le(),
        tx_power: client.tx_power,
    };

    let resp = mgmt
        .send_command(MGMT_OP_ADD_EXT_ADV_PARAMS, mgmt_index, cp_params.as_bytes())
        .await
        .map_err(|e| BtdError::failed(&format!("MGMT ADD_EXT_ADV_PARAMS failed: {e}")))?;

    if resp.status != MGMT_STATUS_SUCCESS {
        return Err(BtdError::failed(&format!(
            "MGMT ADD_EXT_ADV_PARAMS returned status {}",
            resp.status
        )));
    }

    // Parse response to get actual limits and TX power
    if let Ok((rp, _)) = mgmt_rp_add_ext_adv_params::read_from_prefix(resp.data.as_slice()) {
        client.tx_power = rp.tx_power;
        // Update max data lengths for this instance
        let max_data = rp.max_adv_data_len;
        let max_scan = rp.max_scan_rsp_len;
        client.data.set_max_len(max_data);
        client.scan.set_max_len(max_scan);
        debug!(
            "advertising: ext adv params instance={} tx_power={} max_data={} max_scan={}",
            rp.instance, rp.tx_power, max_data, max_scan
        );
    }

    // Step 2: Send ADD_EXT_ADV_DATA
    let adv_data = client.data.generate().unwrap_or_default();
    let scan_data = client.scan.generate().unwrap_or_default();

    let data_header = mgmt_cp_add_ext_adv_data {
        instance: client.instance,
        adv_data_len: adv_data.len() as u8,
        scan_rsp_len: scan_data.len() as u8,
    };

    let data_header_bytes = data_header.as_bytes();
    let mut data_params =
        Vec::with_capacity(data_header_bytes.len() + adv_data.len() + scan_data.len());
    data_params.extend_from_slice(data_header_bytes);
    data_params.extend_from_slice(&adv_data);
    data_params.extend_from_slice(&scan_data);

    let resp2 = mgmt
        .send_command(MGMT_OP_ADD_EXT_ADV_DATA, mgmt_index, &data_params)
        .await
        .map_err(|e| BtdError::failed(&format!("MGMT ADD_EXT_ADV_DATA failed: {e}")))?;

    if resp2.status != MGMT_STATUS_SUCCESS {
        return Err(BtdError::failed(&format!(
            "MGMT ADD_EXT_ADV_DATA returned status {}",
            resp2.status
        )));
    }

    debug!("advertising: ext adv instance {} programmed", client.instance);
    Ok(())
}

/// Sends MGMT_OP_REMOVE_ADVERTISING for a given instance.
async fn remove_advertising(mgmt: &MgmtSocket, mgmt_index: u16, instance: u8) {
    let cp = mgmt_cp_remove_advertising { instance };
    match mgmt.send_command(MGMT_OP_REMOVE_ADVERTISING, mgmt_index, cp.as_bytes()).await {
        Ok(resp) if resp.status == MGMT_STATUS_SUCCESS => {
            debug!("advertising: removed instance {}", instance);
        }
        Ok(resp) => {
            warn!("advertising: remove instance {} returned status {}", instance, resp.status);
        }
        Err(e) => {
            error!("advertising: remove instance {} failed: {}", instance, e);
        }
    }
}

// ===========================================================================
// AdvManagerInner — shared mutable state
// ===========================================================================

/// Internal shared state for the advertising manager.
struct AdvManagerInner {
    /// MGMT adapter index.
    mgmt_index: u16,
    /// MGMT socket for sending commands.
    mgmt: Arc<MgmtSocket>,
    /// Registered advertisement clients.
    clients: Vec<BtdAdvClient>,
    /// Maximum advertising data length.
    max_adv_len: u8,
    /// Maximum scan response data length.
    max_scan_rsp_len: u8,
    /// Maximum number of advertising instances.
    max_ads: u8,
    /// MGMT supported advertising flags bitmask.
    supported_flags: u32,
    /// Set of currently allocated MGMT instance IDs.
    allocated_instances: BTreeSet<u8>,
    /// Whether the kernel supports extended advertising commands.
    extended_add_cmds: bool,
    /// Minimum TX power supported by the controller.
    min_tx_power: i8,
    /// Maximum TX power supported by the controller.
    max_tx_power: i8,
    /// CSIS SIRK for RSI generation.
    csis_sirk: [u8; 16],
}

impl AdvManagerInner {
    /// Allocates the next available instance ID. Returns None if full.
    fn allocate_instance(&mut self) -> Option<u8> {
        for id in 1..=self.max_ads {
            if !self.allocated_instances.contains(&id) {
                self.allocated_instances.insert(id);
                return Some(id);
            }
        }
        None
    }

    /// Deallocates an instance ID, returning it to the pool.
    fn deallocate_instance(&mut self, id: u8) {
        self.allocated_instances.remove(&id);
    }

    /// Returns the number of active advertising instances.
    fn active_count(&self) -> u8 {
        self.clients.len() as u8
    }

    /// Returns the number of remaining available instances.
    fn available_count(&self) -> u8 {
        self.max_ads.saturating_sub(self.clients.len() as u8)
    }

    /// Finds the index of a client by owner and path.
    fn find_client_idx(&self, owner: &str, path: &str) -> Option<usize> {
        self.clients.iter().position(|c| c.owner == owner && c.path == path)
    }

    /// Removes all clients belonging to the given owner (D-Bus sender).
    ///
    /// Returns a vector of instance IDs that were deallocated.
    fn remove_all_by_owner(&mut self, owner: &str) -> Vec<u8> {
        let mut removed_instances = Vec::new();
        while let Some(idx) = self.clients.iter().position(|c| c.owner == owner) {
            let client = self.clients.remove(idx);
            self.deallocate_instance(client.instance);
            removed_instances.push(client.instance);
        }
        removed_instances
    }
}

// ===========================================================================
// LEAdvMgrInterface — zbus D-Bus interface handler
// ===========================================================================

/// D-Bus interface handler for `org.bluez.LEAdvertisingManager1`.
///
/// This struct is placed in the zbus ObjectServer at the adapter path
/// (e.g. `/org/bluez/hci0`) and handles incoming method calls and
/// property queries.
struct LEAdvMgrInterface {
    inner: Arc<Mutex<AdvManagerInner>>,
    adapter: Arc<Mutex<BtdAdapter>>,
}

#[zbus::interface(name = "org.bluez.LEAdvertisingManager1")]
impl LEAdvMgrInterface {
    /// RegisterAdvertisement method — registers a new advertisement.
    ///
    /// The `advertisement` parameter is the D-Bus object path of the
    /// `org.bluez.LEAdvertisement1` object exposed by the calling application.
    async fn register_advertisement(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
        advertisement: ObjectPath<'_>,
        _options: HashMap<String, Value<'_>>,
    ) -> Result<(), BtdError> {
        let sender = header.sender().map(|s| s.as_str().to_owned()).unwrap_or_default();
        let adv_path = advertisement.as_str().to_owned();

        let mut inner = self.inner.lock().await;
        let adapter = self.adapter.lock().await;

        debug!("advertising: RegisterAdvertisement from {} path {}", sender, adv_path);
        btd_debug(
            inner.mgmt_index,
            &format!("RegisterAdvertisement from {} path {}", sender, adv_path),
        );

        // Check for duplicate registration
        if inner.find_client_idx(&sender, &adv_path).is_some() {
            return Err(BtdError::already_exists());
        }

        // Check capacity
        if inner.available_count() == 0 {
            return Err(BtdError::not_permitted("Maximum advertisements reached"));
        }

        // Allocate instance ID
        let instance = inner
            .allocate_instance()
            .ok_or_else(|| BtdError::not_permitted("No available advertising instance"))?;

        // Create client and parse properties
        let mut client = BtdAdvClient::new(sender.clone(), adv_path.clone());
        client.instance = instance;

        let supported_flags = inner.supported_flags;
        let csis_sirk = inner.csis_sirk;
        let conn = btd_get_dbus_connection();

        // Must drop locks before the proxy call to avoid holding across D-Bus round-trip
        let adapter_discoverable = adapter.discoverable;
        let adapter_bredr = adapter.supported_settings & MgmtSettings::BREDR.bits() != 0;
        let mgmt = Arc::clone(&inner.mgmt);
        let mgmt_index = inner.mgmt_index;
        let extended = inner.extended_add_cmds;
        let max_adv_len = inner.max_adv_len;
        drop(adapter);
        drop(inner);

        // Parse advertisement properties from the client's D-Bus object
        parse_advertisement(conn, &mut client, supported_flags, &csis_sirk).await?;

        // Set advertising flags based on adapter state
        set_flags(&mut client, adapter_bredr, adapter_discoverable);

        // Compute MGMT flags
        let adv_flags = get_adv_flags(&client, supported_flags, adapter_discoverable);

        // Set max data length based on computed flags
        let effective_max = calc_max_adv_len(&client, max_adv_len);
        client.data.set_max_len(effective_max);

        // Program advertising via MGMT
        if extended {
            refresh_extended_adv(&mgmt, mgmt_index, &mut client, adv_flags).await?;
        } else {
            refresh_legacy_adv(&mgmt, mgmt_index, &client, adv_flags).await?;
        }

        // Set up client timeout if configured
        if client.timeout > 0 {
            let inner_clone = Arc::clone(&self.inner);
            let mgmt_clone = Arc::clone(&mgmt);
            let timeout_secs = client.timeout;
            let client_owner = sender.clone();
            let client_path = adv_path.clone();
            let idx = mgmt_index;

            let handle = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(timeout_secs as u64)).await;
                let mut inner = inner_clone.lock().await;
                if let Some(pos) = inner.find_client_idx(&client_owner, &client_path) {
                    let removed = inner.clients.remove(pos);
                    inner.deallocate_instance(removed.instance);
                    remove_advertising(&mgmt_clone, idx, removed.instance).await;
                    debug!(
                        "advertising: client timeout expired for {} {}",
                        client_owner, client_path
                    );
                }
            });
            client.timeout_handle = Some(handle);
        }

        // Store client in the manager
        let mut inner = self.inner.lock().await;
        inner.clients.push(client);

        // Emit property change signals
        let _ = self.active_instances_changed(&ctxt).await;
        let _ = self.supported_instances_changed(&ctxt).await;

        debug!(
            "advertising: registered {} ({} active, {} available)",
            adv_path,
            inner.active_count(),
            inner.available_count()
        );

        Ok(())
    }

    /// UnregisterAdvertisement method — unregisters a previously registered advertisement.
    async fn unregister_advertisement(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
        advertisement: ObjectPath<'_>,
    ) -> Result<(), BtdError> {
        let sender = header.sender().map(|s| s.as_str().to_owned()).unwrap_or_default();
        let adv_path = advertisement.as_str();

        let mut inner = self.inner.lock().await;

        debug!("advertising: UnregisterAdvertisement from {} path {}", sender, adv_path);
        btd_debug(
            inner.mgmt_index,
            &format!("UnregisterAdvertisement from {} path {}", sender, adv_path),
        );

        let idx = inner.find_client_idx(&sender, adv_path).ok_or_else(BtdError::does_not_exist)?;

        let removed = inner.clients.remove(idx);
        inner.deallocate_instance(removed.instance);

        let mgmt = Arc::clone(&inner.mgmt);
        let mgmt_index = inner.mgmt_index;
        let instance = removed.instance;
        drop(inner);

        // Remove advertising from kernel
        remove_advertising(&mgmt, mgmt_index, instance).await;

        // Emit property change signals
        let _ = self.active_instances_changed(&ctxt).await;
        let _ = self.supported_instances_changed(&ctxt).await;

        Ok(())
    }

    // ---- Properties ----

    /// Number of currently active advertising instances.
    #[zbus(property)]
    async fn active_instances(&self) -> u8 {
        let inner = self.inner.lock().await;
        inner.active_count()
    }

    /// Number of available advertising instances (remaining capacity).
    #[zbus(property)]
    async fn supported_instances(&self) -> u8 {
        let inner = self.inner.lock().await;
        inner.available_count()
    }

    /// List of supported include types.
    #[zbus(property)]
    async fn supported_includes(&self) -> Vec<String> {
        let inner = self.inner.lock().await;
        let mut result = Vec::new();
        for inc in INCLUDES {
            if inner.supported_flags & inc.flag.bits() != 0 {
                result.push(inc.name.to_owned());
            }
        }
        // RSI is always supported if SIRK is configured
        if !inner.csis_sirk.iter().all(|&b| b == 0) {
            result.push(RSI_INCLUDE_NAME.to_owned());
        }
        result
    }

    /// List of supported secondary advertising channels.
    #[zbus(property)]
    async fn supported_secondary_channels(&self) -> Vec<String> {
        let inner = self.inner.lock().await;
        let mut result = Vec::new();
        for sec in SECONDARY_CHANNELS {
            if inner.supported_flags & sec.flag.bits() != 0 {
                result.push(sec.name.to_owned());
            }
        }
        result
    }

    /// Supported capabilities dictionary (experimental).
    ///
    /// Returns entries such as MinTxPower, MaxTxPower, MaxAdvLen, MaxScnRspLen.
    #[zbus(property)]
    async fn supported_capabilities(&self) -> HashMap<String, OwnedValue> {
        let inner = self.inner.lock().await;
        let mut caps: HashMap<String, OwnedValue> = HashMap::new();

        if inner.min_tx_power != ADV_TX_POWER_NO_PREFERENCE {
            if let Ok(v) = OwnedValue::try_from(Value::I16(inner.min_tx_power as i16)) {
                caps.insert("MinTxPower".to_owned(), v);
            }
        }
        if inner.max_tx_power != ADV_TX_POWER_NO_PREFERENCE {
            if let Ok(v) = OwnedValue::try_from(Value::I16(inner.max_tx_power as i16)) {
                caps.insert("MaxTxPower".to_owned(), v);
            }
        }
        if inner.max_adv_len > 0 {
            if let Ok(v) = OwnedValue::try_from(Value::U8(inner.max_adv_len)) {
                caps.insert("MaxAdvLen".to_owned(), v);
            }
        }
        if inner.max_scan_rsp_len > 0 {
            if let Ok(v) = OwnedValue::try_from(Value::U8(inner.max_scan_rsp_len)) {
                caps.insert("MaxScnRspLen".to_owned(), v);
            }
        }

        caps
    }

    /// Supported features list (experimental).
    #[zbus(property)]
    async fn supported_features(&self) -> Vec<String> {
        let inner = self.inner.lock().await;
        let mut result = Vec::new();
        for feat in FEATURES {
            if inner.supported_flags & feat.flag.bits() != 0 {
                result.push(feat.name.to_owned());
            }
        }
        result
    }
}

// ===========================================================================
// AdvManager — public facade
// ===========================================================================

/// Per-adapter LE Advertising Manager.
///
/// Manages advertisement registration, MGMT programming, and D-Bus interface
/// lifecycle. Created by [`btd_adv_manager_new`] and destroyed by
/// [`btd_adv_manager_destroy`].
///
/// Replaces C `struct btd_adv_manager`.
pub struct AdvManager {
    /// Shared inner state (accessed from D-Bus handlers and timeouts).
    inner: Arc<Mutex<AdvManagerInner>>,
    /// Reference to the owning adapter.
    adapter: Arc<Mutex<BtdAdapter>>,
    /// Adapter D-Bus path (for interface registration/removal).
    adapter_path: String,
}

impl AdvManager {
    /// Creates a new advertising manager for the given adapter.
    ///
    /// Sends MGMT_OP_READ_ADV_FEATURES to query controller capabilities,
    /// optionally queries controller TX power range, then registers the
    /// `org.bluez.LEAdvertisingManager1` D-Bus interface at the adapter path.
    ///
    /// Returns `None` if the controller does not support advertising.
    pub async fn new(
        adapter: Arc<Mutex<BtdAdapter>>,
        mgmt: Arc<MgmtSocket>,
        opts: &BtdOpts,
    ) -> Option<Self> {
        let (mgmt_index, adapter_path) = {
            let a = adapter.lock().await;
            (a.index, a.path.clone())
        };

        let extended = btd_has_kernel_features(KernelFeatures::HAS_EXT_ADV_ADD_CMDS).await;
        let has_cap_cmd = btd_has_kernel_features(KernelFeatures::HAS_CONTROLLER_CAP_CMD).await;

        // Query advertising features from kernel
        let resp = mgmt.send_command(MGMT_OP_READ_ADV_FEATURES, mgmt_index, &[]).await.ok()?;

        if resp.status != MGMT_STATUS_SUCCESS {
            btd_error(
                mgmt_index,
                &format!("Failed to read advertising features: status={}", resp.status),
            );
            return None;
        }

        let (rp, _) = mgmt_rp_read_adv_features::read_from_prefix(resp.data.as_slice()).ok()?;

        let supported_flags = u32::from_le(rp.supported_flags);
        let max_adv_len = rp.max_adv_data_len;
        let max_scan_rsp = rp.max_scan_rsp_len;
        let max_ads = rp.max_instances;

        btd_debug(
            mgmt_index,
            &format!(
                "advertising: features flags=0x{:08x} max_data={} max_scan={} max_ads={}",
                supported_flags, max_adv_len, max_scan_rsp, max_ads
            ),
        );

        let mut min_tx: i8 = ADV_TX_POWER_NO_PREFERENCE;
        let mut max_tx: i8 = ADV_TX_POWER_NO_PREFERENCE;

        // Optionally query TX power range
        if has_cap_cmd {
            if let Ok(cap_resp) =
                mgmt.send_command(MGMT_OP_READ_CONTROLLER_CAP, mgmt_index, &[]).await
            {
                if cap_resp.status == MGMT_STATUS_SUCCESS {
                    parse_controller_cap(&cap_resp.data, &mut min_tx, &mut max_tx);
                }
            }
        }

        let inner = AdvManagerInner {
            mgmt_index,
            mgmt: Arc::clone(&mgmt),
            clients: Vec::new(),
            max_adv_len,
            max_scan_rsp_len: max_scan_rsp,
            max_ads,
            supported_flags,
            allocated_instances: BTreeSet::new(),
            extended_add_cmds: extended,
            min_tx_power: min_tx,
            max_tx_power: max_tx,
            csis_sirk: opts.csis.sirk,
        };

        let inner_arc = Arc::new(Mutex::new(inner));

        // Register D-Bus interface
        let conn = btd_get_dbus_connection();
        let iface =
            LEAdvMgrInterface { inner: Arc::clone(&inner_arc), adapter: Arc::clone(&adapter) };

        if let Err(e) = conn.object_server().at(adapter_path.as_str(), iface).await {
            btd_error(mgmt_index, &format!("Failed to register LEAdvertisingManager1: {}", e));
            return None;
        }

        btd_debug(
            mgmt_index,
            &format!("advertising: LEAdvertisingManager1 registered at {}", adapter_path),
        );

        Some(AdvManager { inner: inner_arc, adapter, adapter_path })
    }

    /// Removes all advertisements and unregisters the D-Bus interface.
    pub async fn destroy(&self) {
        let mut inner = self.inner.lock().await;
        let mgmt = Arc::clone(&inner.mgmt);
        let mgmt_index = inner.mgmt_index;

        // Remove all active advertisements
        let instances: Vec<u8> = inner.clients.iter().map(|c| c.instance).collect();
        inner.clients.clear();
        inner.allocated_instances.clear();
        drop(inner);

        for inst in instances {
            remove_advertising(&mgmt, mgmt_index, inst).await;
        }

        // Unregister D-Bus interface
        let conn = btd_get_dbus_connection();
        let _ =
            conn.object_server().remove::<LEAdvMgrInterface, _>(self.adapter_path.as_str()).await;

        btd_debug(
            mgmt_index,
            &format!("advertising: LEAdvertisingManager1 destroyed at {}", self.adapter_path),
        );
    }

    /// Refreshes all active advertisements (e.g., after adapter settings change).
    ///
    /// Re-programs each advertisement with updated flags based on current
    /// adapter state (discoverable, BR/EDR support, etc.).
    pub async fn refresh(&self) {
        let mut inner = self.inner.lock().await;
        let adapter = self.adapter.lock().await;

        let adapter_discoverable = adapter.discoverable;
        let adapter_bredr = adapter.supported_settings & MgmtSettings::BREDR.bits() != 0;
        let mgmt = Arc::clone(&inner.mgmt);
        let mgmt_index = inner.mgmt_index;
        let supported_flags = inner.supported_flags;
        let extended = inner.extended_add_cmds;
        let max_adv_len = inner.max_adv_len;
        let csis_sirk = inner.csis_sirk;

        drop(adapter);

        btd_debug(mgmt_index, "advertising: refreshing all advertisements");

        for client in inner.clients.iter_mut() {
            // Re-set flags for current adapter state
            client.data.clear_flags();
            set_flags(client, adapter_bredr, adapter_discoverable);

            // Re-generate RSI if applicable
            if client
                .data
                .has_data(&bluez_shared::util::ad::AdData {
                    ad_type: BT_AD_CSIP_RSI,
                    data: Vec::new(),
                })
                .is_some()
            {
                let _ = set_rsi(&csis_sirk, &mut client.data);
            }

            let adv_flags = get_adv_flags(client, supported_flags, adapter_discoverable);
            let effective_max = calc_max_adv_len(client, max_adv_len);
            client.data.set_max_len(effective_max);

            if extended {
                if let Err(e) = refresh_extended_adv(&mgmt, mgmt_index, client, adv_flags).await {
                    btd_error(
                        mgmt_index,
                        &format!(
                            "advertising: refresh extended failed for instance {}: {}",
                            client.instance, e
                        ),
                    );
                }
            } else if let Err(e) = refresh_legacy_adv(&mgmt, mgmt_index, client, adv_flags).await {
                btd_error(
                    mgmt_index,
                    &format!(
                        "advertising: refresh legacy failed for instance {}: {}",
                        client.instance, e
                    ),
                );
            }
        }
    }

    /// Returns the number of active advertising instances.
    pub async fn active_instances(&self) -> u8 {
        let inner = self.inner.lock().await;
        inner.active_count()
    }

    /// Returns the number of remaining available advertising instances.
    pub async fn supported_instances(&self) -> u8 {
        let inner = self.inner.lock().await;
        inner.available_count()
    }

    /// Removes all advertisements owned by the given D-Bus sender.
    ///
    /// Called when a D-Bus client disconnects (NameOwnerChanged) to clean up
    /// its advertisements. Returns the number of removed advertisements.
    pub async fn remove_client_by_owner(&self, owner: &str) -> usize {
        let mut inner = self.inner.lock().await;
        let removed = inner.remove_all_by_owner(owner);
        let count = removed.len();

        if count > 0 {
            let mgmt = Arc::clone(&inner.mgmt);
            let mgmt_index = inner.mgmt_index;
            drop(inner);

            for inst in removed {
                remove_advertising(&mgmt, mgmt_index, inst).await;
            }

            debug!(
                "advertising: removed {} advertisements for disconnected owner {}",
                count, owner
            );
        }

        count
    }
}

// ===========================================================================
// Controller capability TLV parsing
// ===========================================================================

/// Parses MGMT_OP_READ_CONTROLLER_CAP response TLVs for TX power range.
fn parse_controller_cap(data: &[u8], min_tx: &mut i8, max_tx: &mut i8) {
    // Response starts with mgmt_rp_read_controller_cap { cap_len: u16 }
    if data.len() < 2 {
        return;
    }
    let cap_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let tlv_data = &data[2..];
    if tlv_data.len() < cap_len {
        return;
    }

    let mut offset = 0;
    while offset + 3 <= cap_len {
        let tlv_type = u16::from_le_bytes([tlv_data[offset], tlv_data[offset + 1]]);
        let tlv_len = tlv_data[offset + 2] as usize;
        offset += 3;

        if offset + tlv_len > cap_len {
            break;
        }

        if tlv_type == MGMT_CAP_LE_TX_PWR as u16 && tlv_len >= 2 {
            *min_tx = tlv_data[offset] as i8;
            *max_tx = tlv_data[offset + 1] as i8;
            debug!("advertising: controller TX power range: {} to {} dBm", *min_tx, *max_tx);
        }

        offset += tlv_len;
    }
}

// ===========================================================================
// Public API — module-level functions
// ===========================================================================

/// Creates a new advertising manager for the given adapter.
///
/// This is the primary entry point called from adapter initialization.
/// Returns `None` if the controller does not support advertising.
///
/// Replaces C `btd_adv_manager_new()`.
pub async fn btd_adv_manager_new(
    adapter: Arc<Mutex<BtdAdapter>>,
    mgmt: Arc<MgmtSocket>,
    opts: &BtdOpts,
) -> Option<AdvManager> {
    AdvManager::new(adapter, mgmt, opts).await
}

/// Destroys an advertising manager, removing all advertisements and
/// unregistering the D-Bus interface.
///
/// Replaces C `btd_adv_manager_destroy()`.
pub async fn btd_adv_manager_destroy(manager: &AdvManager) {
    manager.destroy().await;
}

/// Refreshes all active advertisements after adapter state changes.
///
/// Replaces C `btd_adv_manager_refresh()`.
pub async fn btd_adv_manager_refresh(manager: &AdvManager) {
    manager.refresh().await;
}
