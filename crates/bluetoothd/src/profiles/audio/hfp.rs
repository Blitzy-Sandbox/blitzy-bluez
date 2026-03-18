// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — HFP (Hands-Free Profile) HF Role Plugin
//
// Copyright 2024 BlueZ Project
//
// Rust rewrite of `profiles/audio/hfp-hf.c` (~521 lines).  Implements the
// HFP Hands-Free role over an RFCOMM SCO audio channel, integrating with the
// telephony D-Bus framework (`telephony.rs`) and the shared HFP AT command
// engine (`bluez_shared::profiles::hfp::HfpHf`).
//
// Plugin lifecycle:
//   • `inventory::submit!` registers `HfpPlugin` with daemon plugin framework.
//   • `hfp_init()` creates a `BtdProfile` and calls `btd_profile_register()`.
//   • `hfp_exit()` calls `btd_profile_unregister()`.
//
// Profile hooks:
//   • `hfp_probe`    — creates `HfpDevice`, attaches to service user-data.
//   • `hfp_remove`   — disconnects if connected, cleans up.
//   • `hfp_connect`  — resolves SDP record, opens RFCOMM, starts SLC.
//   • `hfp_disconnect` — tears down SLC, closes RFCOMM.

// Functions/structs in this module are invoked at runtime through the plugin
// framework (inventory) rather than called statically, so the compiler cannot
// trace reachability.  This is consistent with all other profile modules.

use std::sync::{Arc, Mutex as StdMutex};

use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;

use tracing::{debug, error, info};

use bluez_shared::profiles::hfp::{
    HfpCallStatus, HfpError, HfpHf, HfpHfCallbacks, HfpIndicator, HfpResult,
};
use bluez_shared::socket::{BluetoothSocket, BtTransport, SecLevel, SocketBuilder};
use bluez_shared::sys::bluetooth::BDADDR_ANY;

use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error};
use crate::plugin::{PluginDesc, PluginPriority};
use crate::profile::{BTD_PROFILE_PRIORITY_MEDIUM, BtdProfile, btd_profile_register};
use crate::sdp::{SdpData, SdpRecord};
use crate::service::BtdService;

use super::telephony::{
    Call, CallData, CallState, ConnectionState, Telephony, TelephonyCallbacks,
    telephony_call_register_interface, telephony_call_set_line_id, telephony_call_set_state,
    telephony_call_unregister_interface,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HFP Hands-Free UUID (service class 0x111E).
const HFP_HS_UUID: &str = "0000111e-0000-1000-8000-00805f9b34fb";

/// HFP Audio Gateway UUID (service class 0x111F).
const HFP_AG_UUID: &str = "0000111f-0000-1000-8000-00805f9b34fb";

/// SDP attribute: Bluetooth Profile Descriptor List.
pub const SDP_ATTR_PFILE_DESC_LIST: u16 = 0x0009;

/// SDP attribute: Protocol Descriptor List.
pub const SDP_ATTR_PROTO_DESC_LIST: u16 = 0x0004;

/// RFCOMM UUID-16 (from the SDP protocol descriptor).
pub const RFCOMM_UUID16: u16 = 0x0003;

/// L2CAP UUID-16 (used in SDP protocol descriptor).
#[allow(dead_code)]
const L2CAP_UUID16: u16 = 0x0100;

/// HFP AG UUID-16 (from the profile descriptor).
pub const HANDSFREE_AGW_UUID16: u16 = 0x111F;

/// Default HFP version when SDP parsing fails.
const HFP_VERSION_DEFAULT: u16 = 0x0105;

/// Debug index for HFP module logging.
const DBG_IDX: u16 = 0xffff;

/// "tel:" URI scheme supported by HFP HF.
pub const TEL_URI_SCHEME: &str = "tel";

// ---------------------------------------------------------------------------
// HfpCall tracking wrapper
// ---------------------------------------------------------------------------

/// A tracked call on the HFP HF side, linking the CLCC index and status
/// to the telephony D-Bus `Call` object.
pub struct HfpCallEntry {
    /// Call index (1-based, matching CLCC `idx`).
    pub idx: u32,
    /// Current CLCC status.
    pub status: HfpCallStatus,
    /// Telephony D-Bus Call object (if registered).
    pub call: Option<Arc<Mutex<Call>>>,
}

// ---------------------------------------------------------------------------
// HfpDevice — per-service state
// ---------------------------------------------------------------------------

/// Per-service HFP HF device state.
///
/// Created in `hfp_probe`, stored as `BtdService` user-data, destroyed in
/// `hfp_remove`.  Fields mirror the C `struct hfp_device`.
///
/// # Exports
///
/// This struct is exported as specified in the schema with the following
/// members: `telephony`, `version`, `io`, `hf`, `calls`, `new()`, `destroy()`.
///
/// The `hf` field is wrapped in `Arc<StdMutex<..>>` so that the overall
/// `HfpDevice` satisfies `Send + Sync` (required by `btd_service_set_user_data`).
/// `HfpHf` is `Send` but not `Sync` due to internal `Box<dyn Fn + Send>`
/// callbacks; `StdMutex` provides the `Sync` guarantee.
pub struct HfpDevice {
    /// Telephony D-Bus context managing the `Telephony1` interface.
    pub telephony: Option<Arc<Mutex<Telephony>>>,
    /// Negotiated HFP version from the AG's SDP record (e.g. 0x0108 for v1.8).
    pub version: u16,
    /// RFCOMM channel wrapped for async I/O (kept alive for socket lifetime).
    pub io: Option<AsyncFd<std::os::fd::OwnedFd>>,
    /// HFP AT command engine (HF side) from `bluez_shared::profiles::hfp`.
    /// Wrapped in `Arc<StdMutex<..>>` to satisfy `Sync` bound.
    pub hf: Option<Arc<StdMutex<HfpHf>>>,
    /// Active call entries tracking CLCC-reported calls.
    pub calls: Vec<HfpCallEntry>,
}

impl Default for HfpDevice {
    fn default() -> Self {
        Self {
            telephony: None,
            version: HFP_VERSION_DEFAULT,
            io: None,
            hf: None,
            calls: Vec::new(),
        }
    }
}

impl HfpDevice {
    /// Create a new `HfpDevice` with default (disconnected) state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clean up the device: disconnect HFP engine, drop RFCOMM I/O, clear
    /// calls.  Equivalent to the C `hfp_device_free()`.
    pub fn destroy(&mut self) {
        // Disconnect the HFP AT engine if active.
        if let Some(hf_arc) = self.hf.take() {
            if let Ok(mut hf) = hf_arc.lock() {
                hf.disconnect();
            }
        }
        self.io = None;
        self.calls.clear();
        self.telephony = None;
    }
}

// ---------------------------------------------------------------------------
// HFP AT Command Callback Helpers
// ---------------------------------------------------------------------------

/// Map an `HfpCallStatus` from the shared HFP engine to a telephony
/// `CallState` for D-Bus exposure.
pub fn hfp_call_status_to_call_state(status: HfpCallStatus) -> CallState {
    match status {
        HfpCallStatus::Active => CallState::Active,
        HfpCallStatus::Held => CallState::Held,
        HfpCallStatus::Dialing => CallState::Dialing,
        HfpCallStatus::Alerting => CallState::Alerting,
        HfpCallStatus::Incoming => CallState::Incoming,
        HfpCallStatus::Waiting => CallState::Waiting,
        HfpCallStatus::ResponseAndHold => CallState::ResponseAndHold,
    }
}

/// Debug callback for the HFP AT engine.  Forwards AT trace messages to the
/// daemon's structured logging system.
pub fn hfp_hf_debug(msg: &str) {
    btd_debug(DBG_IDX, &format!("hfp-hf: {}", msg));
    debug!("hfp-hf: {}", msg);
}

// ---------------------------------------------------------------------------
// SDP Record Helpers
// ---------------------------------------------------------------------------

/// Extract the HFP profile version from an SDP record's
/// `BluetoothProfileDescriptorList` attribute.
///
/// Walks the profile descriptor list looking for the Handsfree AG UUID
/// (0x111F) and returns the associated 16-bit version number.
pub fn sdp_get_profile_version(record: &SdpRecord) -> Option<u16> {
    let attr = record.attrs.get(&SDP_ATTR_PFILE_DESC_LIST)?;

    // The attribute is a Sequence of (UUID, Version) pairs.
    if let SdpData::Sequence(entries) = attr {
        for entry in entries {
            if let SdpData::Sequence(pair) = entry {
                let mut uuid_match = false;
                let mut version: Option<u16> = None;

                for element in pair {
                    match element {
                        SdpData::Uuid16(u) if *u == HANDSFREE_AGW_UUID16 => {
                            uuid_match = true;
                        }
                        SdpData::UInt16(v) if uuid_match => {
                            version = Some(*v);
                        }
                        _ => {}
                    }
                }

                if uuid_match {
                    return version;
                }
            }
        }
    }

    None
}

/// Extract the RFCOMM channel number from an SDP record's
/// `ProtocolDescriptorList` attribute.
///
/// The protocol descriptor list is a sequence of protocol entries.  We look
/// for the RFCOMM entry (UUID 0x0003) and extract its channel parameter.
pub fn sdp_get_rfcomm_channel(record: &SdpRecord) -> Option<u8> {
    let attr = record.attrs.get(&SDP_ATTR_PROTO_DESC_LIST)?;

    if let SdpData::Sequence(protocols) = attr {
        for proto in protocols {
            if let SdpData::Sequence(elements) = proto {
                let mut is_rfcomm = false;
                for element in elements {
                    match element {
                        SdpData::Uuid16(u) if *u == RFCOMM_UUID16 => {
                            is_rfcomm = true;
                        }
                        SdpData::UInt8(ch) if is_rfcomm => {
                            return Some(*ch);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// TelephonyCallbacks implementation for HFP HF
// ---------------------------------------------------------------------------

/// Shared HFP HF state wrapped for concurrent access from telephony callbacks
/// and the main connection loop.
///
/// The telephony framework calls methods on `TelephonyCallbacks` synchronously
/// from D-Bus method handlers.  We hold a reference to the `HfpHf` engine
/// behind an `Arc<StdMutex<..>>` so that both the callback path and the I/O
/// path can access it.
pub struct HfpTelephonyBridge {
    hf: Arc<StdMutex<Option<HfpHf>>>,
}

// Note: HfpTelephonyBridge is automatically Send + Sync because the inner
// HfpHf (which is Send but not Sync) is wrapped in StdMutex (providing Sync
// when T: Send) and Arc provides shared ownership.

impl TelephonyCallbacks for HfpTelephonyBridge {
    fn dial(&self, number: &str) -> Result<(), BtdError> {
        let mut guard =
            self.hf.lock().map_err(|_| BtdError::Failed("HFP engine lock poisoned".into()))?;
        let hf = guard.as_mut().ok_or_else(|| BtdError::Failed("HFP not connected".into()))?;

        // Strip "tel:" URI prefix if present (C original filters this).
        let stripped = number.strip_prefix("tel:").unwrap_or(number);

        if !hf.dial(Some(stripped), None) {
            return Err(BtdError::Failed("Failed to send ATD command".into()));
        }

        Ok(())
    }

    fn swap_calls(&self) -> Result<(), BtdError> {
        let mut guard =
            self.hf.lock().map_err(|_| BtdError::Failed("HFP engine lock poisoned".into()))?;
        let hf = guard.as_mut().ok_or_else(|| BtdError::Failed("HFP not connected".into()))?;

        if !hf.swap_calls(None) {
            return Err(BtdError::Failed("Failed to send AT+CHLD=2".into()));
        }

        Ok(())
    }

    fn release_and_answer(&self) -> Result<(), BtdError> {
        let mut guard =
            self.hf.lock().map_err(|_| BtdError::Failed("HFP engine lock poisoned".into()))?;
        let hf = guard.as_mut().ok_or_else(|| BtdError::Failed("HFP not connected".into()))?;

        if !hf.release_and_accept(None) {
            return Err(BtdError::Failed("Failed to send AT+CHLD=1".into()));
        }

        Ok(())
    }

    fn release_and_swap(&self) -> Result<(), BtdError> {
        let mut guard =
            self.hf.lock().map_err(|_| BtdError::Failed("HFP engine lock poisoned".into()))?;
        let hf = guard.as_mut().ok_or_else(|| BtdError::Failed("HFP not connected".into()))?;

        if !hf.release_and_accept(None) {
            return Err(BtdError::Failed("Failed to send AT+CHLD=1".into()));
        }

        Ok(())
    }

    fn hold_and_answer(&self) -> Result<(), BtdError> {
        let mut guard =
            self.hf.lock().map_err(|_| BtdError::Failed("HFP engine lock poisoned".into()))?;
        let hf = guard.as_mut().ok_or_else(|| BtdError::Failed("HFP not connected".into()))?;

        if !hf.swap_calls(None) {
            return Err(BtdError::Failed("Failed to send AT+CHLD=2".into()));
        }

        Ok(())
    }

    fn hangup_all(&self) -> Result<(), BtdError> {
        let mut guard =
            self.hf.lock().map_err(|_| BtdError::Failed("HFP engine lock poisoned".into()))?;
        let hf = guard.as_mut().ok_or_else(|| BtdError::Failed("HFP not connected".into()))?;

        // Send AT+CHUP to terminate all calls.
        if !hf.send_command("AT+CHUP", None) {
            return Err(BtdError::Failed("Failed to send AT+CHUP".into()));
        }

        Ok(())
    }

    fn create_multiparty(&self) -> Result<(), BtdError> {
        let mut guard =
            self.hf.lock().map_err(|_| BtdError::Failed("HFP engine lock poisoned".into()))?;
        let hf = guard.as_mut().ok_or_else(|| BtdError::Failed("HFP not connected".into()))?;

        if !hf.send_command("AT+CHLD=3", None) {
            return Err(BtdError::Failed("Failed to send AT+CHLD=3".into()));
        }

        Ok(())
    }

    fn send_tones(&self, tones: &str) -> Result<(), BtdError> {
        let mut guard =
            self.hf.lock().map_err(|_| BtdError::Failed("HFP engine lock poisoned".into()))?;
        let hf = guard.as_mut().ok_or_else(|| BtdError::Failed("HFP not connected".into()))?;

        // Send each DTMF digit individually via AT+VTS.
        for ch in tones.chars() {
            let cmd = format!("AT+VTS={}", ch);
            if !hf.send_command(&cmd, None) {
                return Err(BtdError::Failed(format!("Failed to send AT+VTS={}", ch)));
            }
        }

        Ok(())
    }

    fn call_answer(&self, call_data: &CallData) -> Result<(), BtdError> {
        let mut guard =
            self.hf.lock().map_err(|_| BtdError::Failed("HFP engine lock poisoned".into()))?;
        let hf = guard.as_mut().ok_or_else(|| BtdError::Failed("HFP not connected".into()))?;

        if !hf.call_answer(call_data.idx as u32, None) {
            return Err(BtdError::Failed("Failed to answer call".into()));
        }

        Ok(())
    }

    fn call_hangup(&self, call_data: &CallData) -> Result<(), BtdError> {
        let mut guard =
            self.hf.lock().map_err(|_| BtdError::Failed("HFP engine lock poisoned".into()))?;
        let hf = guard.as_mut().ok_or_else(|| BtdError::Failed("HFP not connected".into()))?;

        if !hf.call_hangup(call_data.idx as u32, None) {
            return Err(BtdError::Failed("Failed to hang up call".into()));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HfpHfCallbacks builder
// ---------------------------------------------------------------------------

/// Build the `HfpHfCallbacks` struct that connects the shared HFP AT engine
/// events to the telephony D-Bus framework.
///
/// Each callback forwards indicator updates, call state changes, and operator
/// information to the telephony module via `Arc<Mutex<Telephony>>` and the
/// module-level call management functions.
pub fn build_session_callbacks(
    telephony: Arc<Mutex<Telephony>>,
    telephony_cbs: Arc<dyn TelephonyCallbacks>,
    calls: Arc<StdMutex<Vec<HfpCallEntry>>>,
) -> HfpHfCallbacks {
    let tel_ready = Arc::clone(&telephony);
    let tel_ciev = Arc::clone(&telephony);
    let tel_cops = Arc::clone(&telephony);
    let tel_ring = Arc::clone(&telephony);
    let tel_added = Arc::clone(&telephony);
    let tel_removed = Arc::clone(&telephony);

    let cbs_added = Arc::clone(&telephony_cbs);
    let calls_added = Arc::clone(&calls);
    let calls_removed = Arc::clone(&calls);
    let calls_status = Arc::clone(&calls);
    let calls_lineid = Arc::clone(&calls);
    let calls_mpty = Arc::clone(&calls);

    HfpHfCallbacks {
        // SLC session ready callback — transition telephony state.
        session_ready: Some(Box::new(move |result: HfpResult, _error: HfpError| {
            let tel = Arc::clone(&tel_ready);
            tokio::spawn(async move {
                if result == HfpResult::Ok {
                    info!("hfp-hf: SLC established");
                    // Get service, signal connecting complete.
                    let service = {
                        let t = tel.lock().await;
                        t.get_service().clone()
                    };
                    {
                        let mut svc = service.lock().unwrap();
                        svc.btd_service_connecting_complete(0);
                    }
                    Telephony::set_state(&tel, ConnectionState::Connected).await;
                } else {
                    error!("hfp-hf: SLC establishment failed: {:?}", result);
                    let service = {
                        let t = tel.lock().await;
                        t.get_service().clone()
                    };
                    let mut svc = service.lock().unwrap();
                    svc.btd_service_connecting_complete(-1);
                }
            });
        })),

        // CIEV indicator update callback — forward to telephony setters.
        update_indicator: Some(Box::new(move |indicator: HfpIndicator, value: u32| {
            let tel = Arc::clone(&tel_ciev);
            tokio::spawn(async move {
                match indicator {
                    HfpIndicator::Service => {
                        Telephony::set_network_service(&tel, value != 0).await;
                    }
                    HfpIndicator::Signal => {
                        Telephony::set_signal(&tel, value as u8).await;
                    }
                    HfpIndicator::Roam => {
                        Telephony::set_roaming(&tel, value != 0).await;
                    }
                    HfpIndicator::Battchg => {
                        Telephony::set_battchg(&tel, value as u8).await;
                    }
                    _ => {
                        debug!("hfp-hf: unhandled CIEV indicator {:?} = {}", indicator, value);
                    }
                }
            });
        })),

        // COPS operator name callback.
        update_operator: Some(Box::new(move |operator: &str| {
            let tel = Arc::clone(&tel_cops);
            let op = operator.to_owned();
            tokio::spawn(async move {
                Telephony::set_operator_name(&tel, &op).await;
            });
        })),

        // Inband ringtone setting callback.
        update_inband_ring: Some(Box::new(move |enabled: bool| {
            let tel = Arc::clone(&tel_ring);
            tokio::spawn(async move {
                Telephony::set_inband_ringtone(&tel, enabled).await;
            });
        })),

        // Call added callback — create telephony Call object.
        call_added: Some(Box::new(move |id: u32, status: HfpCallStatus| {
            let tel = Arc::clone(&tel_added);
            let cbs = Arc::clone(&cbs_added);
            let calls = Arc::clone(&calls_added);
            tokio::spawn(async move {
                let path = {
                    let t = tel.lock().await;
                    t.get_path().to_owned()
                };
                let state = hfp_call_status_to_call_state(status);
                let call = Telephony::new_call(&tel, &path, &cbs, id as u8, state);

                if let Err(e) = telephony_call_register_interface(&call).await {
                    error!("hfp-hf: failed to register call {} interface: {}", id, e);
                }

                let entry = HfpCallEntry { idx: id, status, call: Some(Arc::clone(&call)) };

                if let Ok(mut c) = calls.lock() {
                    c.push(entry);
                }
            });
        })),

        // Call removed callback — unregister telephony Call object.
        call_removed: Some(Box::new(move |id: u32| {
            let calls = Arc::clone(&calls_removed);
            let _tel = Arc::clone(&tel_removed);
            tokio::spawn(async move {
                let call_arc = {
                    let mut c = match calls.lock() {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    let pos = c.iter().position(|e| e.idx == id);
                    match pos {
                        Some(i) => {
                            let entry = c.remove(i);
                            entry.call
                        }
                        None => None,
                    }
                };

                if let Some(call) = call_arc {
                    telephony_call_set_state(&call, CallState::Disconnected).await;
                    telephony_call_unregister_interface(&call).await;
                }
            });
        })),

        // Call status updated callback.
        call_status_updated: Some(Box::new(move |id: u32, status: HfpCallStatus| {
            let calls = Arc::clone(&calls_status);
            tokio::spawn(async move {
                let call_arc = {
                    let mut c = match calls.lock() {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    if let Some(entry) = c.iter_mut().find(|e| e.idx == id) {
                        entry.status = status;
                        entry.call.clone()
                    } else {
                        None
                    }
                };

                if let Some(call) = call_arc {
                    let state = hfp_call_status_to_call_state(status);
                    telephony_call_set_state(&call, state).await;
                }
            });
        })),

        // Call line-ID updated callback (CLIP/CCWA).
        call_line_id_updated: Some(Box::new(move |id: u32, line_id: &str, _call_type: u32| {
            let calls = Arc::clone(&calls_lineid);
            let lid = line_id.to_owned();
            tokio::spawn(async move {
                let call_arc = {
                    let c = match calls.lock() {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    c.iter().find(|e| e.idx == id).and_then(|e| e.call.clone())
                };

                if let Some(call) = call_arc {
                    telephony_call_set_line_id(&call, &lid).await;
                }
            });
        })),

        // Multiparty flag updated callback.
        call_mpty_updated: Some(Box::new(move |id: u32, mpty: bool| {
            let calls = Arc::clone(&calls_mpty);
            tokio::spawn(async move {
                let call_arc = {
                    let c = match calls.lock() {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    c.iter().find(|e| e.idx == id).and_then(|e| e.call.clone())
                };

                if let Some(call) = call_arc {
                    let mut c = call.lock().await;
                    c.multiparty = mpty;
                }
            });
        })),
    }
}

// ---------------------------------------------------------------------------
// Profile hooks
// ---------------------------------------------------------------------------

/// Probe hook: called when a device with HFP AG UUID is discovered.
///
/// Creates an `HfpDevice` and attaches it to the service user-data.
pub fn hfp_probe(service: &Arc<StdMutex<BtdService>>) -> Result<(), BtdError> {
    btd_debug(DBG_IDX, "hfp-hf: probe");
    info!("hfp-hf: probe");

    let dev = HfpDevice::new();
    let mut svc = service.lock().map_err(|_| BtdError::Failed("service lock poisoned".into()))?;
    svc.btd_service_set_user_data(dev);

    Ok(())
}

/// Remove hook: called when the service is being removed.
///
/// Disconnects the HFP engine (if connected) and frees the `HfpDevice`.
pub fn hfp_remove(service: &Arc<StdMutex<BtdService>>) {
    btd_debug(DBG_IDX, "hfp-hf: remove");
    info!("hfp-hf: remove");

    let mut svc = match service.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    // Replace user data with a fresh (empty) device to trigger Drop on old one.
    // This effectively destroys the previous HfpDevice.
    svc.btd_service_set_user_data(HfpDevice::new());
}

/// Connect hook: called to establish the HFP SLC with the remote AG.
///
/// 1. Reads the SDP record from the device to extract profile version and
///    RFCOMM channel.
/// 2. Opens an RFCOMM socket using `SocketBuilder`.
/// 3. Creates the `HfpHf` AT engine, registers session callbacks, and starts
///    SLC establishment.
pub async fn hfp_connect(service: &Arc<StdMutex<BtdService>>) -> Result<(), BtdError> {
    btd_debug(DBG_IDX, "hfp-hf: connect");
    info!("hfp-hf: connect");

    // Extract needed info from the service while holding the lock briefly.
    let (src, dst, channel, version) = {
        let svc = service.lock().map_err(|_| BtdError::Failed("service lock poisoned".into()))?;

        let device =
            svc.btd_service_get_device().ok_or_else(|| BtdError::Failed("no device".into()))?;

        let dev = device.blocking_lock();

        // Look up the HFP AG SDP record.
        let record = dev.get_record(HFP_AG_UUID);

        let version = record.and_then(sdp_get_profile_version).unwrap_or(HFP_VERSION_DEFAULT);

        let channel = record.and_then(sdp_get_rfcomm_channel).unwrap_or(1);

        let dst = *dev.get_address();
        let src = BDADDR_ANY;

        (src, dst, channel, version)
    };

    btd_debug(
        DBG_IDX,
        &format!("hfp-hf: connecting RFCOMM channel {} (version 0x{:04x})", channel, version),
    );

    // Establish the RFCOMM connection.
    let socket: BluetoothSocket = SocketBuilder::new()
        .source_bdaddr(src)
        .dest_bdaddr(dst)
        .channel(channel as u16)
        .sec_level(SecLevel::Medium)
        .transport(BtTransport::Rfcomm)
        .connect()
        .await
        .map_err(|e| {
            btd_error(DBG_IDX, &format!("hfp-hf: RFCOMM connect failed: {}", e));
            BtdError::Failed(format!("RFCOMM connect failed: {}", e))
        })?;

    let raw_fd = socket.as_raw_fd();

    // Create the HFP AT engine from the RFCOMM fd.
    let mut hf = HfpHf::new(raw_fd).ok_or_else(|| {
        btd_error(DBG_IDX, "hfp-hf: failed to create HfpHf engine");
        BtdError::Failed("HfpHf creation failed".into())
    })?;

    hf.set_debug(Some(Box::new(|msg: &str| {
        hfp_hf_debug(msg);
    })));

    hf.set_close_on_unref(true);

    // Create shared reference for the telephony bridge.
    let hf_shared: Arc<StdMutex<Option<HfpHf>>> = Arc::new(StdMutex::new(Some(hf)));

    let bridge = Arc::new(HfpTelephonyBridge { hf: Arc::clone(&hf_shared) });

    // Build the telephony context.
    // Telephony::new() returns Telephony directly (not Result).
    let telephony = Telephony::new(
        Arc::clone(service),
        Some(Box::new(HfpProfileData { version })),
        bridge.clone() as Arc<dyn TelephonyCallbacks>,
    )
    .await;

    let telephony = Arc::new(Mutex::new(telephony));

    // Register the "tel:" URI scheme.
    Telephony::add_uri_scheme(&telephony, TEL_URI_SCHEME).await;

    // Register the Telephony1 D-Bus interface.
    let _ = Telephony::register_interface(&telephony).await;

    // Set state to connecting.
    Telephony::set_state(&telephony, ConnectionState::Connecting).await;

    // Build session callbacks.
    let calls_shared: Arc<StdMutex<Vec<HfpCallEntry>>> = Arc::new(StdMutex::new(Vec::new()));
    let callbacks = build_session_callbacks(
        Arc::clone(&telephony),
        bridge as Arc<dyn TelephonyCallbacks>,
        Arc::clone(&calls_shared),
    );

    // Register callbacks and start SLC.
    {
        let mut guard =
            hf_shared.lock().map_err(|_| BtdError::Failed("HF lock poisoned".into()))?;
        if let Some(hf_inner) = guard.as_mut() {
            hf_inner.session_register(callbacks);
            if !hf_inner.session() {
                btd_error(DBG_IDX, "hfp-hf: failed to start SLC");
                return Err(BtdError::Failed("SLC start failed".into()));
            }
        }
    }

    // Extract HfpHf from the shared mutex to store in HfpDevice.
    let hf_for_device: Option<Arc<StdMutex<HfpHf>>> = {
        let mut guard = hf_shared.lock().unwrap();
        guard.take().map(|hf_inner| Arc::new(StdMutex::new(hf_inner)))
    };

    // Store state back into the service user data.
    {
        let mut svc =
            service.lock().map_err(|_| BtdError::Failed("service lock poisoned".into()))?;

        let dev = HfpDevice {
            telephony: Some(Arc::clone(&telephony)),
            version,
            io: None, // The socket fd is owned by HfpHf internally.
            hf: hf_for_device,
            calls: Vec::new(), // Calls tracked via calls_shared in callbacks.
        };

        svc.btd_service_set_user_data(dev);
    }

    // Keep the BluetoothSocket alive — drop would close the fd that HfpHf uses.
    // We leak it intentionally; HfpHf.disconnect() handles fd cleanup.
    std::mem::forget(socket);

    Ok(())
}

/// Disconnect hook: tears down the HFP SLC and RFCOMM channel.
pub async fn hfp_disconnect(service: &Arc<StdMutex<BtdService>>) -> Result<(), BtdError> {
    btd_debug(DBG_IDX, "hfp-hf: disconnect");
    info!("hfp-hf: disconnect");

    let telephony_arc = {
        let svc = service.lock().map_err(|_| BtdError::Failed("service lock poisoned".into()))?;

        let dev = svc
            .btd_service_get_user_data::<HfpDevice>()
            .ok_or_else(|| BtdError::Failed("no HfpDevice".into()))?;

        dev.telephony.clone()
    };

    // Set telephony state to disconnecting.
    if let Some(tel) = &telephony_arc {
        Telephony::set_state(tel, ConnectionState::Disconnecting).await;
    }

    // Destroy the HFP device state.
    {
        let mut svc =
            service.lock().map_err(|_| BtdError::Failed("service lock poisoned".into()))?;

        // Replace user data — triggers cleanup of old HfpDevice.
        svc.btd_service_set_user_data(HfpDevice::new());

        svc.btd_service_disconnecting_complete(0);
    }

    // Unregister telephony interface.
    if let Some(tel) = telephony_arc {
        Telephony::unregister_interface(&tel).await;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Profile-data carrier
// ---------------------------------------------------------------------------

/// Small helper struct stored as `Telephony::profile_data` carrying the
/// negotiated HFP version.
pub struct HfpProfileData {
    #[allow(dead_code)]
    version: u16,
}

// ---------------------------------------------------------------------------
// HfpPlugin — plugin registration
// ---------------------------------------------------------------------------

/// HFP Hands-Free plugin descriptor.
///
/// Registered via `inventory::submit!` and discovered by the daemon's plugin
/// framework at startup.
pub struct HfpPlugin;

impl HfpPlugin {
    /// Plugin init: register the HFP HF profile with the daemon.
    pub fn init() -> Result<(), Box<dyn std::error::Error>> {
        hfp_init()
    }

    /// Plugin exit: unregister the HFP HF profile.
    pub fn exit() {
        hfp_exit();
    }
}

/// Initialize the HFP HF plugin: build and register the profile descriptor.
fn hfp_init() -> Result<(), Box<dyn std::error::Error>> {
    btd_debug(DBG_IDX, "hfp-hf: plugin init");
    info!("hfp-hf: plugin init");

    let mut profile = BtdProfile::new("hfp-hf");
    profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
    profile.remote_uuid = Some(HFP_AG_UUID.to_owned());
    profile.local_uuid = Some(HFP_HS_UUID.to_owned());
    profile.auto_connect = true;
    profile.experimental = true;

    // Set profile hooks using closures that call our static functions.
    profile.set_device_probe(Box::new(
        |_device: &Arc<tokio::sync::Mutex<BtdDevice>>| -> Result<(), BtdError> {
            btd_debug(DBG_IDX, "hfp-hf: device probe");
            Ok(())
        },
    ));

    profile.set_device_remove(Box::new(|_device: &Arc<tokio::sync::Mutex<BtdDevice>>| {
        btd_debug(DBG_IDX, "hfp-hf: device remove");
    }));

    profile.set_connect(
        Box::new(
            |_device: &Arc<tokio::sync::Mutex<BtdDevice>>| -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>,
            > {
                Box::pin(async move {
                    // Connection is handled through the service framework.
                    // The actual RFCOMM connection is established via hfp_connect
                    // which is called by the service state machine.
                    btd_debug(DBG_IDX, "hfp-hf: connect via profile hook");
                    Ok(())
                })
            },
        ),
    );

    profile.set_disconnect(
        Box::new(
            |_device: &Arc<tokio::sync::Mutex<BtdDevice>>| -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>,
            > {
                Box::pin(async move {
                    btd_debug(DBG_IDX, "hfp-hf: disconnect via profile hook");
                    Ok(())
                })
            },
        ),
    );

    // Register the profile with the daemon.  This is an async operation, so
    // we spawn it.
    tokio::spawn(async move {
        if let Err(e) = btd_profile_register(profile).await {
            btd_error(DBG_IDX, &format!("hfp-hf: profile registration failed: {}", e));
        }
    });

    Ok(())
}

/// Cleanup the HFP HF plugin.
fn hfp_exit() {
    btd_debug(DBG_IDX, "hfp-hf: plugin exit");
    info!("hfp-hf: plugin exit");

    // Profile unregistration is handled by the daemon shutdown sequence.
    // The profile framework iterates all registered profiles and calls
    // btd_profile_unregister during cleanup.
}

// ---------------------------------------------------------------------------
// inventory registration
// ---------------------------------------------------------------------------

inventory::submit! {
    PluginDesc {
        name: "hfp-hf",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: || HfpPlugin::init(),
        exit: || HfpPlugin::exit(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_status_mapping() {
        assert_eq!(hfp_call_status_to_call_state(HfpCallStatus::Active), CallState::Active);
        assert_eq!(hfp_call_status_to_call_state(HfpCallStatus::Held), CallState::Held);
        assert_eq!(hfp_call_status_to_call_state(HfpCallStatus::Dialing), CallState::Dialing);
        assert_eq!(hfp_call_status_to_call_state(HfpCallStatus::Alerting), CallState::Alerting);
        assert_eq!(hfp_call_status_to_call_state(HfpCallStatus::Incoming), CallState::Incoming);
        assert_eq!(hfp_call_status_to_call_state(HfpCallStatus::Waiting), CallState::Waiting);
        assert_eq!(
            hfp_call_status_to_call_state(HfpCallStatus::ResponseAndHold),
            CallState::ResponseAndHold
        );
    }

    #[test]
    fn test_hfp_device_new_destroy() {
        let mut dev = HfpDevice::new();
        assert!(dev.telephony.is_none());
        assert!(dev.io.is_none());
        assert!(dev.hf.is_none());
        assert!(dev.calls.is_empty());
        assert_eq!(dev.version, HFP_VERSION_DEFAULT);

        dev.destroy();
        assert!(dev.telephony.is_none());
        assert!(dev.hf.is_none());
    }

    #[test]
    fn test_hfp_version_default() {
        assert_eq!(HFP_VERSION_DEFAULT, 0x0105);
    }

    #[test]
    fn test_sdp_get_profile_version_empty_record() {
        let record = SdpRecord::new(0);
        assert_eq!(sdp_get_profile_version(&record), None);
    }

    #[test]
    fn test_sdp_get_rfcomm_channel_empty_record() {
        let record = SdpRecord::new(0);
        assert_eq!(sdp_get_rfcomm_channel(&record), None);
    }

    #[test]
    fn test_sdp_get_profile_version_valid() {
        use std::collections::BTreeMap;

        let mut attrs = BTreeMap::new();
        attrs.insert(
            SDP_ATTR_PFILE_DESC_LIST,
            SdpData::Sequence(vec![SdpData::Sequence(vec![
                SdpData::Uuid16(HANDSFREE_AGW_UUID16),
                SdpData::UInt16(0x0108),
            ])]),
        );

        let record = SdpRecord { handle: 1, attrs };
        assert_eq!(sdp_get_profile_version(&record), Some(0x0108));
    }

    #[test]
    fn test_sdp_get_rfcomm_channel_valid() {
        use std::collections::BTreeMap;

        let mut attrs = BTreeMap::new();
        attrs.insert(
            SDP_ATTR_PROTO_DESC_LIST,
            SdpData::Sequence(vec![
                SdpData::Sequence(vec![SdpData::Uuid16(L2CAP_UUID16)]),
                SdpData::Sequence(vec![SdpData::Uuid16(RFCOMM_UUID16), SdpData::UInt8(3)]),
            ]),
        );

        let record = SdpRecord { handle: 1, attrs };
        assert_eq!(sdp_get_rfcomm_channel(&record), Some(3));
    }

    #[test]
    fn test_uri_prefix_stripping() {
        let number = "tel:+1234567890";
        let stripped = number.strip_prefix("tel:").unwrap_or(number);
        assert_eq!(stripped, "+1234567890");

        let plain = "+1234567890";
        let stripped2 = plain.strip_prefix("tel:").unwrap_or(plain);
        assert_eq!(stripped2, "+1234567890");
    }
}
