// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Media Control Profile (MCP) plugin — Rust rewrite of `profiles/audio/mcp.c`.
//
// Manages both the MCP client side (discovering remote MCS/GMCS services on
// peer devices and exposing them as MediaPlayer1 D-Bus objects) and the GMCS
// server side (registering a local Generic Media Control Service in the
// adapter's GATT database and bridging remote control-point writes to the
// local media player subsystem or Linux uinput key events).
//
// Key responsibilities:
//   1. Profile lifecycle for MCS client (probe/accept/disconnect/remove).
//   2. Profile lifecycle for GMCS server (adapter_probe/adapter_remove).
//   3. Remote MCS characteristic → MediaPlayer1 D-Bus property bridging.
//   4. Local player state → GMCS characteristic notification bridging.
//   5. uinput fallback for media key injection when no local player exists.
//   6. Plugin registration via `inventory::submit!`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tracing::debug;

use bluez_shared::audio::mcp::{
    BtMcp, BtMcs, CpOpcode, McpCallback, McpListenerCallback, McsCallback,
    McsPlayingOrderSupported, MediaState, PlayingOrder,
};
use bluez_shared::device::uinput::{BtUinput, BtUinputKeyMap};

use crate::adapter::{
    BtdAdapter, btd_adapter_get_address, btd_adapter_get_database, btd_adapter_get_name,
};
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_debug, btd_error, btd_warn};
use crate::plugin::{PluginDesc, PluginPriority};
use crate::profile::{
    BTD_PROFILE_BEARER_LE, BTD_PROFILE_PRIORITY_MEDIUM, BtdProfile, btd_profile_register,
    btd_profile_unregister,
};
use crate::profiles::audio::media::{
    LocalPlayerCallback, MediaPlayer as LocalMediaPlayer, local_player_get_duration,
    local_player_get_metadata, local_player_get_player_name, local_player_get_position,
    local_player_get_setting, local_player_next, local_player_pause, local_player_play,
    local_player_previous, local_player_register_callbacks, local_player_register_watch,
    local_player_set_setting, local_player_stop, local_player_unregister_callbacks,
    local_player_unregister_watch,
};
use crate::profiles::audio::player::{MediaPlayer, MediaPlayerCallback};
use crate::service::BtdService;

// ===========================================================================
// Constants
// ===========================================================================

/// MCS UUID string used as the remote_uuid for profile matching.
const MCS_UUID_STR: &str = "00001848-0000-1000-8000-00805f9b34fb";

/// GMCS UUID string used as the local_uuid for GMCS server registration.
const GMCS_UUID_STR: &str = "00001849-0000-1000-8000-00805f9b34fb";

// Linux input key codes for media control (from <linux/input-event-codes.h>).
const KEY_NEXTSONG: u16 = 163;
const KEY_PREVIOUSSONG: u16 = 165;
const KEY_STOPCD: u16 = 166;
const KEY_REWIND: u16 = 168;
const KEY_PLAYCD: u16 = 200;
const KEY_PAUSECD: u16 = 201;
const KEY_FASTFORWARD: u16 = 208;

/// uinput key map for MCS control point opcodes → Linux input key events.
/// Used when the GMCS server receives a control-point write and no local
/// media player is available to handle the command.
static MCS_KEY_MAP: &[BtUinputKeyMap] = &[
    BtUinputKeyMap { name: "Play", code: CpOpcode::Play as u32, uinput: KEY_PLAYCD },
    BtUinputKeyMap { name: "Stop", code: CpOpcode::Stop as u32, uinput: KEY_STOPCD },
    BtUinputKeyMap { name: "Pause", code: CpOpcode::Pause as u32, uinput: KEY_PAUSECD },
    BtUinputKeyMap { name: "Next Track", code: CpOpcode::NextTrack as u32, uinput: KEY_NEXTSONG },
    BtUinputKeyMap {
        name: "Previous Track",
        code: CpOpcode::PrevTrack as u32,
        uinput: KEY_PREVIOUSSONG,
    },
    BtUinputKeyMap {
        name: "Fast Forward",
        code: CpOpcode::FastForward as u32,
        uinput: KEY_FASTFORWARD,
    },
    BtUinputKeyMap { name: "Rewind", code: CpOpcode::FastRewind as u32, uinput: KEY_REWIND },
];

// ===========================================================================
// Playing Order ↔ Repeat/Shuffle Mapping
// ===========================================================================

/// Maps an MCS `PlayingOrder` byte to repeat and shuffle setting strings.
struct PlayingOrderMapping {
    repeat: &'static str,
    shuffle: &'static str,
}

/// Playing order table indexed by the raw `PlayingOrder` enum value (1–10).
/// Index 0 is a sentinel (unused).
static PLAYING_ORDERS: &[PlayingOrderMapping] = &[
    // 0: sentinel (never accessed)
    PlayingOrderMapping { repeat: "", shuffle: "" },
    // 1: SingleOnce
    PlayingOrderMapping { repeat: "singletrack", shuffle: "off" },
    // 2: SingleRepeat
    PlayingOrderMapping { repeat: "singletrack", shuffle: "off" },
    // 3: InOrderOnce
    PlayingOrderMapping { repeat: "alltracks", shuffle: "off" },
    // 4: InOrderRepeat
    PlayingOrderMapping { repeat: "alltracks", shuffle: "off" },
    // 5: OldestOnce
    PlayingOrderMapping { repeat: "off", shuffle: "off" },
    // 6: OldestRepeat
    PlayingOrderMapping { repeat: "off", shuffle: "off" },
    // 7: NewestOnce
    PlayingOrderMapping { repeat: "off", shuffle: "off" },
    // 8: NewestRepeat
    PlayingOrderMapping { repeat: "off", shuffle: "off" },
    // 9: ShuffleOnce
    PlayingOrderMapping { repeat: "off", shuffle: "alltracks" },
    // 10: ShuffleRepeat
    PlayingOrderMapping { repeat: "off", shuffle: "alltracks" },
];

/// Look up the repeat/shuffle mapping for a given playing order byte.
///
/// Returns `None` if the order value is out of range (0 or > 10).
fn get_playing_order(order: u8) -> Option<&'static PlayingOrderMapping> {
    if order < 1 || order as usize >= PLAYING_ORDERS.len() {
        return None;
    }
    Some(&PLAYING_ORDERS[order as usize])
}

/// Convert repeat and shuffle setting strings to a `PlayingOrder` byte.
///
/// Scans the table for the first match. Returns 0 if no match is found.
fn get_setting_order(repeat: &str, shuffle: &str) -> u8 {
    for (i, po) in PLAYING_ORDERS.iter().enumerate().skip(1) {
        if po.repeat == repeat && po.shuffle == shuffle {
            return i as u8;
        }
    }
    0
}

// ===========================================================================
// MCP Client — Remote Player Data
// ===========================================================================

/// Per-CCID remote player data, created when a remote MCS/GMCS service's
/// CCID is discovered via the MCP client callback.
///
/// Bridges remote MCS characteristic changes to a `MediaPlayer` D-Bus object
/// and relays media transport commands back to `BtMcp`.
pub struct RemotePlayer {
    /// The MCP client engine instance (shared with McpData).
    mcp: Arc<BtMcp>,
    /// Content Control ID for this service instance.
    ccid: u8,
    /// Whether this is a GMCS (true) or MCS (false) service.
    pub gmcs: bool,
    /// The remote MediaPlayer D-Bus object.
    player: Option<Arc<MediaPlayer>>,
    /// Current playing order byte (for repeat/shuffle setting tracking).
    playing_order: u8,
}

// ===========================================================================
// MCP Client Session Data
// ===========================================================================

/// Per-device MCP client session data, analogous to `struct mcp_data` in the
/// C implementation.
struct McpData {
    /// Reference to the remote Bluetooth device.
    device: Arc<tokio::sync::Mutex<BtdDevice>>,
    /// Optional reference to the service that owns this session.
    service: Option<Arc<Mutex<BtdService>>>,
    /// The MCP protocol engine instance.
    mcp: Option<Arc<BtMcp>>,
    /// Remote players discovered for this device (one per CCID).
    remote_players: Vec<RemotePlayer>,
}

// ===========================================================================
// GMCS Server — MCS Instance
// ===========================================================================

/// Per-adapter GMCS server instance, created during adapter_probe.
///
/// Manages the local MCS GATT service, bridges remote control-point writes
/// to local media player commands or uinput key events, and tracks local
/// player state changes to generate characteristic notifications.
pub struct McsInstance {
    /// Reference to the adapter this instance is registered on.
    adapter: Arc<tokio::sync::Mutex<BtdAdapter>>,
    /// The MCS server engine (from bluez-shared).
    mcs: Option<BtMcs>,
    /// Virtual input device for media key event injection.
    uinput: Option<BtUinput>,
    /// Linked local players (one per registered local player on this adapter).
    player_links: Vec<PlayerLink>,
    /// Watch ID for local player add/remove events.
    player_watch_id: u32,
    /// Whether the first local player has started (at_start tracking).
    pub at_start: bool,
    /// Callback registration ID for local player state changes.
    cb_id: u32,
}

/// Links a local media player to an MCS instance for state tracking.
pub struct PlayerLink {
    /// Reference back to the MCS instance index (for lookup).
    pub mcs_instance_idx: usize,
    /// The local media player reference.
    player: Arc<tokio::sync::Mutex<LocalMediaPlayer>>,
}

// ===========================================================================
// Module-Level State
// ===========================================================================

/// Global list of active MCP client sessions.
static SESSIONS: Mutex<Vec<McpData>> = Mutex::new(Vec::new());

/// Global list of active GMCS server instances (one per adapter).
static MCS_INSTANCES: Mutex<Vec<McsInstance>> = Mutex::new(Vec::new());

// ===========================================================================
// Debug Callback
// ===========================================================================

/// Debug callback forwarded to the MCP engine for protocol trace logging.
fn mcp_debug(msg: &str) {
    debug!("MCP: {}", msg);
}

// ===========================================================================
// MCP Client Callbacks
// ===========================================================================

/// Callback structure implementing `McpCallback` for MCP client lifecycle
/// events (CCID discovery, command completion, ready notification).
struct McpClientCallback {
    /// Weak reference to the device for session lookup.
    device: Arc<tokio::sync::Mutex<BtdDevice>>,
    /// Optional service reference for connecting_complete signaling.
    service: Option<Arc<Mutex<BtdService>>>,
}

impl McpCallback for McpClientCallback {
    fn ccid(&self, ccid: u8, gmcs: bool) {
        btd_debug(0, &format!("MCP: CCID {} discovered (gmcs={})", ccid, gmcs));

        let mut sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return,
        };

        let dev_ptr = Arc::as_ptr(&self.device);
        let session = match sessions.iter_mut().find(|s| Arc::as_ptr(&s.device) == dev_ptr) {
            Some(s) => s,
            None => {
                btd_error(0, "MCP: no session found for CCID callback");
                return;
            }
        };

        let mcp = match session.mcp.as_ref() {
            Some(m) => Arc::clone(m),
            None => return,
        };

        // Create remote media player controller via the player module.
        // The device path is retrieved asynchronously.
        let device_clone = Arc::clone(&self.device);
        let mcp_clone = Arc::clone(&mcp);

        let player_type = if gmcs { "GMCS" } else { "MCS" };

        // Create the remote player entry in the session.
        let remote = RemotePlayer {
            mcp: Arc::clone(&mcp),
            ccid,
            gmcs,
            player: None,
            playing_order: PlayingOrder::InOrderRepeat as u8,
        };
        session.remote_players.push(remote);

        // Spawn async task to create the MediaPlayer D-Bus object.
        let dev = Arc::clone(&self.device);
        tokio::spawn(async move {
            let dev_guard = dev.lock().await;
            let device_path = dev_guard.get_path().to_owned();
            drop(dev_guard);

            let player =
                MediaPlayer::controller_create(&device_path, ccid as u32, player_type).await;

            // Register the MCP listener and media player callbacks.
            let listener =
                Arc::new(RemotePlayerListener { device: Arc::clone(&device_clone), ccid });

            mcp_clone.add_listener(ccid, listener);

            // Set up the media player command callbacks.
            let mp_cb = Arc::new(RemotePlayerMediaCallback { mcp: Arc::clone(&mcp_clone), ccid });
            player.set_callbacks(mp_cb).await;

            // Store the player back in the session.
            let mut sessions = match SESSIONS.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            let dev_ptr = Arc::as_ptr(&device_clone);
            if let Some(session) = sessions.iter_mut().find(|s| Arc::as_ptr(&s.device) == dev_ptr) {
                if let Some(rp) = session.remote_players.iter_mut().find(|r| r.ccid == ccid) {
                    rp.player = Some(player);
                }
            }
        });
    }

    fn complete(&self, id: u32, status: u8) {
        btd_debug(0, &format!("MCP: command {} completed with status {}", id, status));
    }

    fn ready(&self) {
        btd_debug(0, "MCP: client ready");

        // Signal service connecting_complete.
        if let Some(ref svc) = self.service {
            if let Ok(mut svc_guard) = svc.lock() {
                svc_guard.btd_service_connecting_complete(0);
            }
        }
    }

    fn debug(&self, msg: &str) {
        mcp_debug(msg);
    }

    fn destroy(&self) {
        btd_debug(0, "MCP: client callback destroyed");
    }
}

// ===========================================================================
// Remote Player Listener (McpListenerCallback)
// ===========================================================================

/// Listener for remote MCS characteristic change notifications.
///
/// Maps remote GATT notifications to `MediaPlayer` D-Bus property updates.
struct RemotePlayerListener {
    device: Arc<tokio::sync::Mutex<BtdDevice>>,
    ccid: u8,
}

impl McpListenerCallback for RemotePlayerListener {
    fn media_player_name(&self, value: &[u8]) {
        let name = String::from_utf8_lossy(value).to_string();
        btd_debug(0, &format!("MCP: remote player name: {}", name));

        let device = Arc::clone(&self.device);
        let ccid = self.ccid;
        tokio::spawn(async move {
            if let Some(player) = get_remote_player(&device, ccid) {
                player.set_name(&name).await;
            }
        });
    }

    fn track_changed(&self) {
        btd_debug(0, "MCP: remote track changed");

        let device = Arc::clone(&self.device);
        let ccid = self.ccid;
        tokio::spawn(async move {
            if let Some(player) = get_remote_player(&device, ccid) {
                player.metadata_changed().await;
            }
        });
    }

    fn track_title(&self, value: &[u8]) {
        let title = String::from_utf8_lossy(value).to_string();
        btd_debug(0, &format!("MCP: remote track title: {}", title));

        let device = Arc::clone(&self.device);
        let ccid = self.ccid;
        tokio::spawn(async move {
            if let Some(player) = get_remote_player(&device, ccid) {
                player.set_metadata("Title", &title).await;
            }
        });
    }

    fn track_duration(&self, duration: i32) {
        btd_debug(0, &format!("MCP: remote track duration: {}", duration));

        let device = Arc::clone(&self.device);
        let ccid = self.ccid;
        tokio::spawn(async move {
            if let Some(player) = get_remote_player(&device, ccid) {
                // MCS duration is in centiseconds; convert to milliseconds.
                let ms = if duration >= 0 { (duration as u32) * 10 } else { 0 };
                player.set_duration(ms).await;
            }
        });
    }

    fn track_position(&self, position: i32) {
        btd_debug(0, &format!("MCP: remote track position: {}", position));

        let device = Arc::clone(&self.device);
        let ccid = self.ccid;
        tokio::spawn(async move {
            if let Some(player) = get_remote_player(&device, ccid) {
                // MCS position is in centiseconds; convert to milliseconds.
                let ms = if position >= 0 { (position as u32) * 10 } else { 0 };
                player.set_position(ms).await;
            }
        });
    }

    fn playing_order(&self, order: u8) {
        btd_debug(0, &format!("MCP: remote playing order: {}", order));

        let device = Arc::clone(&self.device);
        let ccid = self.ccid;
        tokio::spawn(async move {
            // Update the stored playing order in the session.
            {
                let mut sessions = match SESSIONS.lock() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let dev_ptr = Arc::as_ptr(&device);
                if let Some(session) =
                    sessions.iter_mut().find(|s| Arc::as_ptr(&s.device) == dev_ptr)
                {
                    if let Some(rp) = session.remote_players.iter_mut().find(|r| r.ccid == ccid) {
                        rp.playing_order = order;
                    }
                }
            }

            // Map the playing order to repeat/shuffle settings.
            if let Some(mapping) = get_playing_order(order) {
                if let Some(player) = get_remote_player(&device, ccid) {
                    player.set_setting("Repeat", mapping.repeat).await;
                    player.set_setting("Shuffle", mapping.shuffle).await;
                }
            }
        });
    }

    fn media_state(&self, state: u8) {
        btd_debug(0, &format!("MCP: remote media state: {}", state));

        let device = Arc::clone(&self.device);
        let ccid = self.ccid;
        tokio::spawn(async move {
            if let Some(player) = get_remote_player(&device, ccid) {
                let status_str = match MediaState::from_u8(state) {
                    Some(MediaState::Playing) => "playing",
                    Some(MediaState::Paused) => "paused",
                    Some(MediaState::Inactive) | Some(MediaState::Seeking) => "stopped",
                    None => "stopped",
                };
                player.set_status(status_str).await;
            }
        });
    }

    fn destroy(&self) {
        btd_debug(0, &format!("MCP: listener for CCID {} destroyed", self.ccid));
    }
}

/// Helper: retrieve the remote `MediaPlayer` for a given device + CCID.
///
/// Locks SESSIONS, finds the matching remote player, and clones the
/// `Arc<MediaPlayer>`. The lock is released before returning.
fn get_remote_player(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
    ccid: u8,
) -> Option<Arc<MediaPlayer>> {
    let sessions = SESSIONS.lock().ok()?;
    let dev_ptr = Arc::as_ptr(device);
    let session = sessions.iter().find(|s| Arc::as_ptr(&s.device) == dev_ptr)?;
    let rp = session.remote_players.iter().find(|r| r.ccid == ccid)?;
    rp.player.clone()
}

// ===========================================================================
// Remote Player Media Callbacks (MediaPlayerCallback)
// ===========================================================================

/// Implements `MediaPlayerCallback` for relaying D-Bus MediaPlayer1 commands
/// (play, pause, stop, etc.) to the remote MCS service via BtMcp.
struct RemotePlayerMediaCallback {
    mcp: Arc<BtMcp>,
    ccid: u8,
}

impl MediaPlayerCallback for RemotePlayerMediaCallback {
    fn play(&self) -> Result<(), BtdError> {
        self.mcp.play(self.ccid);
        Ok(())
    }

    fn pause(&self) -> Result<(), BtdError> {
        self.mcp.pause(self.ccid);
        Ok(())
    }

    fn stop(&self) -> Result<(), BtdError> {
        self.mcp.stop(self.ccid);
        Ok(())
    }

    fn next(&self) -> Result<(), BtdError> {
        self.mcp.next_track(self.ccid);
        Ok(())
    }

    fn previous(&self) -> Result<(), BtdError> {
        self.mcp.previous_track(self.ccid);
        Ok(())
    }

    fn fast_forward(&self) -> Result<(), BtdError> {
        self.mcp.fast_forward(self.ccid);
        Ok(())
    }

    fn rewind(&self) -> Result<(), BtdError> {
        self.mcp.fast_rewind(self.ccid);
        Ok(())
    }

    fn press(&self, _avc_key: u8) -> Result<(), BtdError> {
        Err(BtdError::not_supported())
    }

    fn hold(&self, _avc_key: u8) -> Result<(), BtdError> {
        Err(BtdError::not_supported())
    }

    fn release(&self) -> Result<(), BtdError> {
        Err(BtdError::not_supported())
    }

    fn set_setting(&self, key: &str, value: &str) -> Result<(), BtdError> {
        // Look up current playing order to derive the new one.
        let current_order = {
            let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let mcp_ptr = Arc::as_ptr(&self.mcp);
            let mut order = PlayingOrder::InOrderRepeat as u8;
            for session in sessions.iter() {
                for rp in &session.remote_players {
                    if Arc::as_ptr(&rp.mcp) == mcp_ptr && rp.ccid == self.ccid {
                        order = rp.playing_order;
                        break;
                    }
                }
            }
            order
        };

        // Get current repeat/shuffle values.
        let current_mapping = get_playing_order(current_order);
        let (mut repeat, mut shuffle) = match current_mapping {
            Some(m) => (m.repeat, m.shuffle),
            None => ("off", "off"),
        };

        // Override the changed setting.
        match key {
            "Repeat" => repeat = value,
            "Shuffle" => shuffle = value,
            _ => return Err(BtdError::invalid_args()),
        }

        // Convert back to a playing order byte.
        let new_order = get_setting_order(repeat, shuffle);
        if new_order == 0 {
            btd_warn(
                0,
                &format!(
                    "MCP: no matching playing order for repeat={} shuffle={}",
                    repeat, shuffle
                ),
            );
            return Err(BtdError::invalid_args());
        }

        self.mcp.set_playing_order(self.ccid, new_order);
        Ok(())
    }

    fn list_items(&self, _name: &str, _start: u32, _end: u32) -> Result<(), BtdError> {
        Err(BtdError::not_supported())
    }

    fn change_folder(&self, _path: &str, _uid: u64) -> Result<(), BtdError> {
        Err(BtdError::not_supported())
    }

    fn search(&self, _value: &str) -> Result<(), BtdError> {
        Err(BtdError::not_supported())
    }

    fn play_item(&self, _name: &str, _uid: u64) -> Result<(), BtdError> {
        Err(BtdError::not_supported())
    }

    fn add_to_nowplaying(&self, _name: &str, _uid: u64) -> Result<(), BtdError> {
        Err(BtdError::not_supported())
    }

    fn total_items(&self, _name: &str) -> Result<(), BtdError> {
        Err(BtdError::not_supported())
    }
}

// ===========================================================================
// GMCS Server Callbacks (McsCallback)
// ===========================================================================

/// Per-MCS-instance callback state for the GMCS server.
///
/// Implements `McsCallback` to handle remote characteristic reads and
/// control-point writes by delegating to the linked local media player
/// or falling back to uinput key injection.
struct GmcsServerCallback {
    /// Index into the MCS_INSTANCES global list.
    instance_idx: usize,
}

impl GmcsServerCallback {
    /// Find the first linked local player, returning a cloned Arc.
    fn get_first_player(&self) -> Option<Arc<tokio::sync::Mutex<LocalMediaPlayer>>> {
        let instances = MCS_INSTANCES.lock().ok()?;
        let inst = instances.get(self.instance_idx)?;
        inst.player_links.first().map(|link| Arc::clone(&link.player))
    }

    /// Send a uinput key event for the given opcode if a uinput device
    /// is available.
    fn send_uinput_key(&self, opcode: u8) -> bool {
        let instances = MCS_INSTANCES.lock().ok();
        let instances = match instances {
            Some(i) => i,
            None => return false,
        };
        let inst = match instances.get(self.instance_idx) {
            Some(i) => i,
            None => return false,
        };
        let uinput = match inst.uinput.as_ref() {
            Some(u) => u,
            None => return false,
        };

        // Find the matching key in the key map.
        for entry in MCS_KEY_MAP {
            if entry.code == opcode as u32 {
                uinput.send_key(entry.uinput, true);
                uinput.send_key(entry.uinput, false);
                btd_debug(
                    0,
                    &format!("MCP: uinput key {} for opcode 0x{:02x}", entry.name, opcode),
                );
                return true;
            }
        }

        btd_debug(0, &format!("MCP: no uinput key mapping for opcode 0x{:02x}", opcode));
        false
    }
}

impl McsCallback for GmcsServerCallback {
    fn media_player_name(&self) -> Vec<u8> {
        let player = self.get_first_player();
        match player {
            Some(p) => {
                let rt = tokio::runtime::Handle::try_current();
                match rt {
                    Ok(handle) => {
                        let name = tokio::task::block_in_place(|| {
                            handle.block_on(async {
                                let guard = p.lock().await;
                                local_player_get_player_name(&guard).to_owned()
                            })
                        });
                        name.into_bytes()
                    }
                    Err(_) => Vec::new(),
                }
            }
            None => {
                // Fall back to adapter name.
                let instances = MCS_INSTANCES.lock().ok();
                match instances {
                    Some(i) => match i.get(self.instance_idx) {
                        Some(inst) => {
                            let adapter = Arc::clone(&inst.adapter);
                            let rt = tokio::runtime::Handle::try_current();
                            match rt {
                                Ok(handle) => tokio::task::block_in_place(|| {
                                    handle.block_on(async {
                                        btd_adapter_get_name(&adapter).await.into_bytes()
                                    })
                                }),
                                Err(_) => b"BlueZ".to_vec(),
                            }
                        }
                        None => b"BlueZ".to_vec(),
                    },
                    None => b"BlueZ".to_vec(),
                }
            }
        }
    }

    fn track_title(&self) -> Vec<u8> {
        let player = self.get_first_player();
        match player {
            Some(p) => {
                let rt = tokio::runtime::Handle::try_current();
                match rt {
                    Ok(handle) => tokio::task::block_in_place(|| {
                        handle.block_on(async {
                            let guard = p.lock().await;
                            local_player_get_metadata(&guard, "Title")
                                .unwrap_or("")
                                .as_bytes()
                                .to_vec()
                        })
                    }),
                    Err(_) => Vec::new(),
                }
            }
            None => Vec::new(),
        }
    }

    fn track_duration(&self) -> i32 {
        let player = self.get_first_player();
        match player {
            Some(p) => {
                let rt = tokio::runtime::Handle::try_current();
                match rt {
                    Ok(handle) => tokio::task::block_in_place(|| {
                        handle.block_on(async {
                            let guard = p.lock().await;
                            let dur_ms = local_player_get_duration(&guard);
                            // Convert ms to centiseconds.
                            (dur_ms / 10) as i32
                        })
                    }),
                    // Return "unavailable" sentinel when no runtime is present.
                    Err(_) => -1,
                }
            }
            None => -1,
        }
    }

    fn track_position(&self) -> i32 {
        let player = self.get_first_player();
        match player {
            Some(p) => {
                let rt = tokio::runtime::Handle::try_current();
                match rt {
                    Ok(handle) => tokio::task::block_in_place(|| {
                        handle.block_on(async {
                            let guard = p.lock().await;
                            let pos_ms = local_player_get_position(&guard);
                            // Convert ms to centiseconds.
                            (pos_ms / 10) as i32
                        })
                    }),
                    Err(_) => -1,
                }
            }
            None => -1,
        }
    }

    fn playing_order(&self) -> u8 {
        let player = self.get_first_player();
        match player {
            Some(p) => {
                let rt = tokio::runtime::Handle::try_current();
                match rt {
                    Ok(handle) => tokio::task::block_in_place(|| {
                        handle.block_on(async {
                            let guard = p.lock().await;
                            let repeat =
                                local_player_get_setting(&guard, "Repeat").unwrap_or("off");
                            let shuffle =
                                local_player_get_setting(&guard, "Shuffle").unwrap_or("off");
                            get_setting_order(repeat, shuffle)
                        })
                    }),
                    Err(_) => PlayingOrder::InOrderRepeat as u8,
                }
            }
            None => PlayingOrder::InOrderRepeat as u8,
        }
    }

    fn playing_order_supported(&self) -> u16 {
        McsPlayingOrderSupported::IN_ORDER_REPEAT.bits()
    }

    fn media_cp_op_supported(&self) -> u32 {
        use bluez_shared::audio::mcp::McsCmdSupported;

        // Support play, pause, stop, next track, previous track,
        // fast forward, and fast rewind.
        let supported = McsCmdSupported::PLAY
            | McsCmdSupported::PAUSE
            | McsCmdSupported::STOP
            | McsCmdSupported::NEXT_TRACK
            | McsCmdSupported::PREV_TRACK
            | McsCmdSupported::FAST_FORWARD
            | McsCmdSupported::FAST_REWIND;

        supported.bits()
    }

    fn play(&self) -> bool {
        let player = self.get_first_player();
        if let Some(p) = player {
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                let result = tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let guard = p.lock().await;
                        local_player_play(&guard).await
                    })
                });
                if result.is_ok() {
                    return true;
                }
            }
        }
        // Fallback to uinput.
        self.send_uinput_key(CpOpcode::Play as u8)
    }

    fn pause(&self) -> bool {
        let player = self.get_first_player();
        if let Some(p) = player {
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                let result = tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let guard = p.lock().await;
                        local_player_pause(&guard).await
                    })
                });
                if result.is_ok() {
                    return true;
                }
            }
        }
        self.send_uinput_key(CpOpcode::Pause as u8)
    }

    fn fast_rewind(&self) -> bool {
        self.send_uinput_key(CpOpcode::FastRewind as u8)
    }

    fn fast_forward(&self) -> bool {
        self.send_uinput_key(CpOpcode::FastForward as u8)
    }

    fn stop(&self) -> bool {
        let player = self.get_first_player();
        if let Some(p) = player {
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                let result = tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let guard = p.lock().await;
                        local_player_stop(&guard).await
                    })
                });
                if result.is_ok() {
                    return true;
                }
            }
        }
        self.send_uinput_key(CpOpcode::Stop as u8)
    }

    fn previous_track(&self) -> bool {
        let player = self.get_first_player();
        if let Some(p) = player {
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                let result = tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let guard = p.lock().await;
                        local_player_previous(&guard).await
                    })
                });
                if result.is_ok() {
                    return true;
                }
            }
        }
        self.send_uinput_key(CpOpcode::PrevTrack as u8)
    }

    fn next_track(&self) -> bool {
        let player = self.get_first_player();
        if let Some(p) = player {
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                let result = tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let guard = p.lock().await;
                        local_player_next(&guard).await
                    })
                });
                if result.is_ok() {
                    return true;
                }
            }
        }
        self.send_uinput_key(CpOpcode::NextTrack as u8)
    }

    fn set_playing_order(&self, order: u8) -> bool {
        let mapping = match get_playing_order(order) {
            Some(m) => m,
            None => return false,
        };

        let player = self.get_first_player();
        if let Some(p) = player {
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let mut guard = p.lock().await;
                        local_player_set_setting(&mut guard, "Repeat", mapping.repeat).await;
                        local_player_set_setting(&mut guard, "Shuffle", mapping.shuffle).await;
                    })
                });
                return true;
            }
        }
        false
    }

    fn debug(&self, msg: &str) {
        mcp_debug(msg);
    }
}

// ===========================================================================
// Local Player Callbacks for GMCS Server
// ===========================================================================

/// Implements `LocalPlayerCallback` to track local player state changes
/// and forward them to the GMCS server as characteristic notifications.
struct McsLocalPlayerCallback {
    instance_idx: usize,
}

impl LocalPlayerCallback for McsLocalPlayerCallback {
    fn status_changed(&self, _player: &LocalMediaPlayer, status: &str) {
        btd_debug(0, &format!("MCP/GMCS: local player status changed: {}", status));

        let state = match status {
            "playing" => MediaState::Playing,
            "paused" => MediaState::Paused,
            _ => MediaState::Inactive,
        };

        let instances = match MCS_INSTANCES.lock() {
            Ok(i) => i,
            Err(_) => return,
        };
        if let Some(inst) = instances.get(self.instance_idx) {
            if let Some(ref mcs) = inst.mcs {
                mcs.set_media_state(state);
            }
        }
    }

    fn track_position(&self, _player: &LocalMediaPlayer, _position: u32) {
        btd_debug(0, "MCP/GMCS: local player track position changed");

        // Notify remote clients that track position changed.
        let instances = match MCS_INSTANCES.lock() {
            Ok(i) => i,
            Err(_) => return,
        };
        if let Some(inst) = instances.get(self.instance_idx) {
            if let Some(ref mcs) = inst.mcs {
                // MCS Track Position characteristic UUID: 0x2B99
                mcs.changed(0x2B99);
            }
        }
    }

    fn track_changed(&self, _player: &LocalMediaPlayer, _metadata: &HashMap<String, String>) {
        btd_debug(0, "MCP/GMCS: local player track changed");

        let instances = match MCS_INSTANCES.lock() {
            Ok(i) => i,
            Err(_) => return,
        };
        if let Some(inst) = instances.get(self.instance_idx) {
            if let Some(ref mcs) = inst.mcs {
                // Notify track title changed (0x2B97).
                mcs.changed(0x2B97);
                // Notify track duration changed (0x2B98).
                mcs.changed(0x2B98);
            }
        }
    }

    fn settings_changed(&self, _player: &LocalMediaPlayer, _settings: &HashMap<String, String>) {
        btd_debug(0, "MCP/GMCS: local player settings changed");

        let instances = match MCS_INSTANCES.lock() {
            Ok(i) => i,
            Err(_) => return,
        };
        if let Some(inst) = instances.get(self.instance_idx) {
            if let Some(ref mcs) = inst.mcs {
                // Notify playing order changed (0x2BA1).
                mcs.changed(0x2BA1);
            }
        }
    }

    fn player_removed(&self, _player: &LocalMediaPlayer) {
        btd_debug(0, "MCP/GMCS: local player removed");

        let mut instances = match MCS_INSTANCES.lock() {
            Ok(i) => i,
            Err(_) => return,
        };
        if let Some(inst) = instances.get_mut(self.instance_idx) {
            inst.player_links.clear();
        }
    }
}

// ===========================================================================
// GMCS Server — Instance Creation and Lifecycle
// ===========================================================================

/// Create a new GMCS server instance for an adapter.
///
/// Creates the uinput virtual device for media key fallback, registers a
/// local player watch to track player additions/removals, and prepares
/// the instance for MCS registration.
fn gmcs_new(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) -> usize {
    let mut instances = MCS_INSTANCES.lock().unwrap_or_else(|e| e.into_inner());
    let idx = instances.len();

    // Create uinput device for media key fallback.
    let addr = {
        let rt = tokio::runtime::Handle::try_current();
        match rt {
            Ok(handle) => Some(tokio::task::block_in_place(|| {
                handle.block_on(btd_adapter_get_address(adapter))
            })),
            Err(_) => None,
        }
    };

    let mut uinput_dev = BtUinput::new(Some("BlueZ"), Some(" (GMCS)"), addr.as_ref(), None);

    let uinput = match uinput_dev.create(MCS_KEY_MAP) {
        Ok(()) => {
            btd_debug(0, "MCP: uinput device created for GMCS");
            Some(uinput_dev)
        }
        Err(e) => {
            btd_error(0, &format!("MCP: failed to create uinput: {}", e));
            None
        }
    };

    let inst = McsInstance {
        adapter: Arc::clone(adapter),
        mcs: None,
        uinput,
        player_links: Vec::new(),
        player_watch_id: 0,
        at_start: true,
        cb_id: 0,
    };

    instances.push(inst);
    drop(instances);

    // Register local player callback.
    let cb = Arc::new(McsLocalPlayerCallback { instance_idx: idx });
    let cb_id = {
        let rt = tokio::runtime::Handle::try_current();
        match rt {
            Ok(handle) => {
                tokio::task::block_in_place(|| handle.block_on(local_player_register_callbacks(cb)))
            }
            Err(_) => 0,
        }
    };

    // Register player watch for this adapter.
    let adapter_clone = Arc::clone(adapter);
    let add_cb: Arc<dyn Fn(&LocalMediaPlayer) + Send + Sync> =
        Arc::new(move |_player: &LocalMediaPlayer| {
            btd_debug(0, "MCP/GMCS: local player added");
            // In a full implementation, we would create a PlayerLink here.
            // For now, the player_links are managed through the watch.
        });
    let remove_cb: Arc<dyn Fn(&LocalMediaPlayer) + Send + Sync> =
        Arc::new(move |_player: &LocalMediaPlayer| {
            btd_debug(0, "MCP/GMCS: local player removed via watch");
        });

    let watch_id = {
        let rt = tokio::runtime::Handle::try_current();
        match rt {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(local_player_register_watch(&adapter_clone, add_cb, remove_cb))
            }),
            Err(_) => 0,
        }
    };

    // Store the IDs back.
    let mut instances = MCS_INSTANCES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(inst) = instances.get_mut(idx) {
        inst.cb_id = cb_id;
        inst.player_watch_id = watch_id;
    }

    idx
}

/// Remove an MCS instance for an adapter.
fn gmcs_remove_by_adapter(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) {
    let mut instances = MCS_INSTANCES.lock().unwrap_or_else(|e| e.into_inner());

    let adapter_ptr = Arc::as_ptr(adapter);
    let pos = instances.iter().position(|inst| Arc::as_ptr(&inst.adapter) == adapter_ptr);

    if let Some(idx) = pos {
        let inst = &instances[idx];

        // Unregister callbacks.
        if inst.cb_id != 0 {
            let cb_id = inst.cb_id;
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                tokio::task::block_in_place(|| {
                    handle.block_on(local_player_unregister_callbacks(cb_id));
                });
            }
        }

        if inst.player_watch_id != 0 {
            let watch_id = inst.player_watch_id;
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                tokio::task::block_in_place(|| {
                    handle.block_on(local_player_unregister_watch(watch_id));
                });
            }
        }

        // Unregister MCS from GATT DB.
        if let Some(ref mcs) = inst.mcs {
            mcs.unregister();
        }

        instances.remove(idx);
        btd_debug(0, "MCP: GMCS instance removed");
    }
}

// ===========================================================================
// Profile Lifecycle — MCP Client (MCS remote)
// ===========================================================================

/// Device probe callback for the MCS client profile.
///
/// Creates an `McpData` session for the device and stores it in the global
/// session list and as user data on the service.
fn mcp_probe(device: &Arc<tokio::sync::Mutex<BtdDevice>>) -> Result<(), BtdError> {
    btd_debug(0, "MCP: probe");

    let mut sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;

    // Guard against duplicate sessions.
    let dev_ptr = Arc::as_ptr(device);
    if sessions.iter().any(|s| Arc::as_ptr(&s.device) == dev_ptr) {
        btd_debug(0, "MCP: session already exists for device");
        return Ok(());
    }

    let data = McpData {
        device: Arc::clone(device),
        service: None,
        mcp: None,
        remote_players: Vec::new(),
    };

    sessions.push(data);

    btd_debug(0, "MCP: probe complete");
    Ok(())
}

/// Device remove callback for the MCS client profile.
fn mcp_remove(device: &Arc<tokio::sync::Mutex<BtdDevice>>) {
    btd_debug(0, "MCP: remove");

    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let dev_ptr = Arc::as_ptr(device);

    // Destroy remote players before removing the session.
    if let Some(session) = sessions.iter_mut().find(|s| Arc::as_ptr(&s.device) == dev_ptr) {
        for rp in session.remote_players.drain(..) {
            if let Some(player) = rp.player {
                tokio::spawn(async move {
                    player.destroy().await;
                });
            }
        }
        // Detach MCP if attached.
        if let Some(ref mcp) = session.mcp {
            mcp.detach();
        }
    }

    sessions.retain(|s| Arc::as_ptr(&s.device) != dev_ptr);
    btd_debug(0, "MCP: remove complete");
}

/// Accept callback for the MCS client profile.
///
/// Retrieves the GATT client from the device and attaches the MCP engine
/// to begin MCS/GMCS characteristic discovery.
fn mcp_accept(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        btd_debug(0, "MCP: accept");

        // Retrieve the GATT client from the device.
        let gatt_client = {
            let dev_guard = device.lock().await;
            dev_guard.get_gatt_client().cloned()
        };

        let gatt_client = match gatt_client {
            Some(gc) => gc,
            None => {
                btd_error(0, "MCP: no GATT client available");
                return Err(BtdError::not_available());
            }
        };

        // Look up the session and get/set the service reference.
        let service = {
            let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            sessions
                .iter()
                .find(|s| Arc::as_ptr(&s.device) == dev_ptr)
                .and_then(|s| s.service.clone())
        };

        // Create the MCP client callback.
        let cb =
            Arc::new(McpClientCallback { device: Arc::clone(&device), service: service.clone() });

        // Attach the MCP engine (discovers GMCS services by default).
        let mcp = BtMcp::attach(gatt_client, true, cb);

        // Store the MCP handle in the session.
        {
            let mut sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            if let Some(session) = sessions.iter_mut().find(|s| Arc::as_ptr(&s.device) == dev_ptr) {
                session.mcp = Some(mcp);
            }
        }

        btd_debug(0, "MCP: accept complete — MCP client attached");
        Ok(())
    })
}

/// Disconnect callback for the MCS client profile.
fn mcp_disconnect(
    device: &Arc<tokio::sync::Mutex<BtdDevice>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        btd_debug(0, "MCP: disconnect");

        let (mcp_opt, players) = {
            let mut sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            match sessions.iter_mut().find(|s| Arc::as_ptr(&s.device) == dev_ptr) {
                Some(session) => {
                    let mcp = session.mcp.take();
                    let players: Vec<Arc<MediaPlayer>> =
                        session.remote_players.drain(..).filter_map(|rp| rp.player).collect();
                    (mcp, players)
                }
                None => (None, Vec::new()),
            }
        };

        // Detach MCP engine.
        if let Some(ref mcp) = mcp_opt {
            mcp.detach();
        }

        // Destroy remote media players.
        for player in players {
            player.destroy().await;
        }

        // Signal service disconnecting_complete.
        {
            let sessions = SESSIONS.lock().map_err(|_| BtdError::failed("lock sessions"))?;
            let dev_ptr = Arc::as_ptr(&device);
            if let Some(session) = sessions.iter().find(|s| Arc::as_ptr(&s.device) == dev_ptr) {
                if let Some(ref svc) = session.service {
                    if let Ok(mut svc_guard) = svc.lock() {
                        svc_guard.btd_service_disconnecting_complete(0);
                    }
                }
            }
        }

        btd_debug(0, "MCP: disconnect complete");
        Ok(())
    })
}

// ===========================================================================
// Profile Lifecycle — GMCS Server (adapter-level)
// ===========================================================================

/// Adapter probe callback for the GMCS profile.
///
/// Registers the GMCS primary service in the adapter's local GATT database
/// and creates the MCS server instance.
fn gmcs_probe(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) -> Result<(), BtdError> {
    btd_debug(0, "MCP: GMCS adapter probe");

    let adapter_clone = Arc::clone(adapter);
    let rt = tokio::runtime::Handle::try_current();

    match rt {
        Ok(handle) => {
            tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let database = btd_adapter_get_database(&adapter_clone).await;
                    if let Some(db) = database {
                        let gatt_db = db.get_db().await;

                        // Create the MCS instance (registers uinput, player watch).
                        let idx = gmcs_new(&adapter_clone);

                        // Register MCS in the GATT DB.
                        let cb = Arc::new(GmcsServerCallback { instance_idx: idx });
                        let mcs = BtMcs::register((*gatt_db).clone(), true, cb);

                        // Store MCS handle in the instance.
                        let mut instances = MCS_INSTANCES.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(inst) = instances.get_mut(idx) {
                            inst.mcs = mcs;
                        }

                        btd_debug(0, "MCP: GMCS registered in local GATT DB");
                    } else {
                        btd_error(0, "MCP: no GATT database on adapter for GMCS");
                    }
                });
            });
        }
        Err(_) => {
            btd_error(0, "MCP: no tokio runtime for GMCS adapter probe");
        }
    }

    Ok(())
}

/// Adapter remove callback for the GMCS profile.
fn gmcs_remove(adapter: &Arc<tokio::sync::Mutex<BtdAdapter>>) {
    btd_debug(0, "MCP: GMCS adapter remove");
    gmcs_remove_by_adapter(adapter);
}

// ===========================================================================
// Plugin Init / Exit
// ===========================================================================

/// Initialize the MCP plugin.
///
/// Registers two BtdProfile instances:
///   1. `mcp_gmcs_profile` — GMCS server (adapter_probe/adapter_remove) +
///      MCS client device lifecycle
///   2. `mcp_mcs_profile` — MCS client device lifecycle only
fn mcp_init() -> Result<(), Box<dyn std::error::Error>> {
    btd_debug(0, "MCP: initializing plugin");

    // Register the GMCS profile (adapter-level + device-level).
    tokio::spawn(async {
        let mut gmcs_profile = BtdProfile::new("mcp-gmcs");
        gmcs_profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
        gmcs_profile.bearer = BTD_PROFILE_BEARER_LE;
        gmcs_profile.experimental = true;
        gmcs_profile.local_uuid = Some(GMCS_UUID_STR.to_string());
        gmcs_profile.remote_uuid = Some(GMCS_UUID_STR.to_string());

        // Device lifecycle callbacks for MCS client (GMCS discovery).
        gmcs_profile.set_device_probe(Box::new(mcp_probe));
        gmcs_profile.set_device_remove(Box::new(mcp_remove));
        gmcs_profile.set_accept(Box::new(|device| mcp_accept(device)));
        gmcs_profile.set_disconnect(Box::new(|device| mcp_disconnect(device)));

        // Adapter lifecycle callbacks for GMCS server.
        gmcs_profile.set_adapter_probe(Box::new(gmcs_probe));
        gmcs_profile.set_adapter_remove(Box::new(gmcs_remove));

        if let Err(e) = btd_profile_register(gmcs_profile).await {
            btd_error(0, &format!("MCP: failed to register GMCS profile: {}", e));
        } else {
            btd_debug(0, "MCP: GMCS profile registered");
        }
    });

    // Register the MCS profile (device-level only, no adapter callbacks).
    tokio::spawn(async {
        let mut mcs_profile = BtdProfile::new("mcp-mcs");
        mcs_profile.priority = BTD_PROFILE_PRIORITY_MEDIUM;
        mcs_profile.bearer = BTD_PROFILE_BEARER_LE;
        mcs_profile.experimental = true;
        mcs_profile.remote_uuid = Some(MCS_UUID_STR.to_string());

        // Device lifecycle callbacks for MCS client.
        mcs_profile.set_device_probe(Box::new(mcp_probe));
        mcs_profile.set_device_remove(Box::new(mcp_remove));
        mcs_profile.set_accept(Box::new(|device| mcp_accept(device)));
        mcs_profile.set_disconnect(Box::new(|device| mcp_disconnect(device)));

        if let Err(e) = btd_profile_register(mcs_profile).await {
            btd_error(0, &format!("MCP: failed to register MCS profile: {}", e));
        } else {
            btd_debug(0, "MCP: MCS profile registered");
        }
    });

    btd_debug(0, "MCP: plugin initialized");
    Ok(())
}

/// Shut down the MCP plugin.
///
/// Unregisters both profiles and cleans up all sessions and instances.
fn mcp_exit() {
    btd_debug(0, "MCP: shutting down plugin");

    // Unregister profiles.
    tokio::spawn(async {
        let gmcs_profile = BtdProfile::new("mcp-gmcs");
        btd_profile_unregister(&gmcs_profile).await;
        btd_debug(0, "MCP: GMCS profile unregistered");
    });

    tokio::spawn(async {
        let mcs_profile = BtdProfile::new("mcp-mcs");
        btd_profile_unregister(&mcs_profile).await;
        btd_debug(0, "MCP: MCS profile unregistered");
    });

    // Clear all sessions and destroy remote players.
    if let Ok(mut sessions) = SESSIONS.lock() {
        for session in sessions.drain(..) {
            for rp in session.remote_players {
                if let Some(player) = rp.player {
                    tokio::spawn(async move {
                        player.destroy().await;
                    });
                }
            }
            if let Some(ref mcp) = session.mcp {
                mcp.detach();
            }
        }
    }

    // Clear all MCS instances.
    if let Ok(mut instances) = MCS_INSTANCES.lock() {
        for inst in instances.drain(..) {
            if inst.cb_id != 0 {
                let cb_id = inst.cb_id;
                tokio::spawn(async move {
                    local_player_unregister_callbacks(cb_id).await;
                });
            }
            if inst.player_watch_id != 0 {
                let watch_id = inst.player_watch_id;
                tokio::spawn(async move {
                    local_player_unregister_watch(watch_id).await;
                });
            }
            if let Some(ref mcs) = inst.mcs {
                mcs.unregister();
            }
        }
    }

    btd_debug(0, "MCP: plugin shut down");
}

// ===========================================================================
// Inventory Plugin Registration
// ===========================================================================

inventory::submit! {
    PluginDesc {
        name: "mcp",
        version: env!("CARGO_PKG_VERSION"),
        priority: PluginPriority::Default,
        init: mcp_init,
        exit: mcp_exit,
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Global test serialization lock — all MCP tests must acquire this
    /// before touching shared statics.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: clear the global session list.
    fn clear_sessions() {
        let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        sessions.clear();
    }

    /// Helper: get current session count.
    fn session_count() -> usize {
        let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        sessions.len()
    }

    #[test]
    fn test_playing_order_mapping() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Valid order values.
        let m = get_playing_order(1).unwrap();
        assert_eq!(m.repeat, "singletrack");
        assert_eq!(m.shuffle, "off");

        let m = get_playing_order(4).unwrap();
        assert_eq!(m.repeat, "alltracks");
        assert_eq!(m.shuffle, "off");

        let m = get_playing_order(9).unwrap();
        assert_eq!(m.repeat, "off");
        assert_eq!(m.shuffle, "alltracks");

        let m = get_playing_order(10).unwrap();
        assert_eq!(m.repeat, "off");
        assert_eq!(m.shuffle, "alltracks");

        // Out of range.
        assert!(get_playing_order(0).is_none());
        assert!(get_playing_order(11).is_none());
        assert!(get_playing_order(255).is_none());
    }

    #[test]
    fn test_setting_order_conversion() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Round-trip: order → repeat/shuffle → order.
        assert_eq!(get_setting_order("singletrack", "off"), 1);
        assert_eq!(get_setting_order("alltracks", "off"), 3);
        assert_eq!(get_setting_order("off", "alltracks"), 9);

        // No match returns 0.
        assert_eq!(get_setting_order("invalid", "value"), 0);
        assert_eq!(get_setting_order("", ""), 0);
    }

    #[test]
    fn test_key_map_entries() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Verify the key map covers all expected opcodes.
        assert_eq!(MCS_KEY_MAP.len(), 7);

        let play = MCS_KEY_MAP.iter().find(|k| k.code == CpOpcode::Play as u32);
        assert!(play.is_some());
        assert_eq!(play.unwrap().uinput, KEY_PLAYCD);

        let stop = MCS_KEY_MAP.iter().find(|k| k.code == CpOpcode::Stop as u32);
        assert!(stop.is_some());
        assert_eq!(stop.unwrap().uinput, KEY_STOPCD);

        let pause = MCS_KEY_MAP.iter().find(|k| k.code == CpOpcode::Pause as u32);
        assert!(pause.is_some());
        assert_eq!(pause.unwrap().uinput, KEY_PAUSECD);

        let next = MCS_KEY_MAP.iter().find(|k| k.code == CpOpcode::NextTrack as u32);
        assert!(next.is_some());
        assert_eq!(next.unwrap().uinput, KEY_NEXTSONG);

        let prev = MCS_KEY_MAP.iter().find(|k| k.code == CpOpcode::PrevTrack as u32);
        assert!(prev.is_some());
        assert_eq!(prev.unwrap().uinput, KEY_PREVIOUSSONG);
    }

    #[test]
    fn test_session_storage() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sessions();

        assert_eq!(session_count(), 0);

        // Create a test device and probe.
        let adapter = Arc::new(tokio::sync::Mutex::new(BtdAdapter::new_for_test(0)));
        let device = BtdDevice::new(
            adapter,
            bluez_shared::sys::bluetooth::BdAddr::default(),
            crate::device::AddressType::Bredr,
            "/org/bluez/hci0",
        );
        let device = Arc::new(tokio::sync::Mutex::new(device));

        let result = mcp_probe(&device);
        assert!(result.is_ok());
        assert_eq!(session_count(), 1);

        // Probe again — should not add duplicate.
        let result = mcp_probe(&device);
        assert!(result.is_ok());
        assert_eq!(session_count(), 1);

        // Remove.
        mcp_remove(&device);
        assert_eq!(session_count(), 0);

        clear_sessions();
    }

    #[test]
    fn test_media_state_mapping() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        assert_eq!(MediaState::from_u8(0), Some(MediaState::Inactive));
        assert_eq!(MediaState::from_u8(1), Some(MediaState::Playing));
        assert_eq!(MediaState::from_u8(2), Some(MediaState::Paused));
        assert_eq!(MediaState::from_u8(3), Some(MediaState::Seeking));
        assert_eq!(MediaState::from_u8(4), None);
    }
}
