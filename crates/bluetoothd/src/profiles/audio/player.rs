//! Media Player D-Bus object implementation.
//!
//! Exposes three D-Bus interfaces:
//! - `org.bluez.MediaPlayer1` — playback control, track metadata, player settings
//! - `org.bluez.MediaFolder1` — media browsing (folders, search, navigation)
//! - `org.bluez.MediaItem1` — individual media items in the browse tree
//!
//! This module is a D-Bus adapter layer that delegates all actions to a backend
//! callback table (e.g., AVRCP Controller, MCP).

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, error};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

use crate::dbus_common::{btd_get_dbus_connection, dict_append_entry};
use crate::error::{BtdError, ERROR_INTERFACE};

// Re-export zbus::Result for callers that interact with this module's async API.
/// Convenience alias for `zbus::Result`.
pub type ZbusResult<T> = zbus::Result<T>;

// ──────────────────────────────────────────────────────────────────────────────
// D-Bus interface name constants
// ──────────────────────────────────────────────────────────────────────────────

const MEDIA_PLAYER_INTERFACE: &str = "org.bluez.MediaPlayer1";
const MEDIA_FOLDER_INTERFACE: &str = "org.bluez.MediaFolder1";
const MEDIA_ITEM_INTERFACE: &str = "org.bluez.MediaItem1";

// ──────────────────────────────────────────────────────────────────────────────
// Enumerations
// ──────────────────────────────────────────────────────────────────────────────

/// Playback status of a media player.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaybackStatus {
    /// Playback is active.
    Playing,
    /// Playback is paused.
    Paused,
    /// Playback is stopped.
    Stopped,
    /// Fast-forwarding.
    ForwardSeek,
    /// Rewinding.
    ReverseSeek,
    /// Player is in an error state.
    Error,
}

impl PlaybackStatus {
    /// Parse a status string (case-insensitive) into a `PlaybackStatus`.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "playing" => Self::Playing,
            "paused" => Self::Paused,
            "stopped" => Self::Stopped,
            "forward-seek" | "forwardseek" => Self::ForwardSeek,
            "reverse-seek" | "reverseseek" => Self::ReverseSeek,
            _ => Self::Error,
        }
    }
}

impl fmt::Display for PlaybackStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Playing => write!(f, "playing"),
            Self::Paused => write!(f, "paused"),
            Self::Stopped => write!(f, "stopped"),
            Self::ForwardSeek => write!(f, "forward-seek"),
            Self::ReverseSeek => write!(f, "reverse-seek"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Player setting attribute identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlayerAttribute {
    /// Equalizer on/off.
    Equalizer,
    /// Repeat mode.
    Repeat,
    /// Shuffle mode.
    Shuffle,
    /// Scan mode.
    Scan,
}

impl PlayerAttribute {
    /// Parse a setting key string into a `PlayerAttribute`.
    pub fn from_key(s: &str) -> Option<Self> {
        match s {
            "Equalizer" => Some(Self::Equalizer),
            "Repeat" => Some(Self::Repeat),
            "Shuffle" => Some(Self::Shuffle),
            "Scan" => Some(Self::Scan),
            _ => None,
        }
    }

    /// Return the canonical D-Bus property name for this attribute.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Equalizer => "Equalizer",
            Self::Repeat => "Repeat",
            Self::Shuffle => "Shuffle",
            Self::Scan => "Scan",
        }
    }
}

impl fmt::Display for PlayerAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Media item type in the browse tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayerItemType {
    /// Audio track.
    Audio,
    /// Video track.
    Video,
    /// Folder node.
    Folder,
    /// Unknown / invalid type.
    Invalid,
}

impl PlayerItemType {
    /// Convert a numeric item type to the enum.
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::Audio,
            2 => Self::Video,
            3 => Self::Folder,
            _ => Self::Invalid,
        }
    }
}

impl fmt::Display for PlayerItemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audio => write!(f, "audio"),
            Self::Video => write!(f, "video"),
            Self::Folder => write!(f, "folder"),
            Self::Invalid => Ok(()),
        }
    }
}

/// Media folder type in the browse tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayerFolderType {
    /// Mixed content folder.
    Mixed,
    /// Titles / songs.
    Titles,
    /// Albums.
    Albums,
    /// Artists.
    Artists,
    /// Genres.
    Genres,
    /// Playlists.
    Playlists,
    /// Years.
    Years,
    /// Unknown / invalid folder type.
    Invalid,
}

impl PlayerFolderType {
    /// Convert a numeric folder type to the enum.
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Mixed,
            1 => Self::Titles,
            2 => Self::Albums,
            3 => Self::Artists,
            4 => Self::Genres,
            5 => Self::Playlists,
            6 => Self::Years,
            _ => Self::Invalid,
        }
    }
}

impl fmt::Display for PlayerFolderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mixed => write!(f, "mixed"),
            Self::Titles => write!(f, "titles"),
            Self::Albums => write!(f, "albums"),
            Self::Artists => write!(f, "artists"),
            Self::Genres => write!(f, "genres"),
            Self::Playlists => write!(f, "playlists"),
            Self::Years => write!(f, "years"),
            Self::Invalid => Ok(()),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Backend Callback Trait
// ──────────────────────────────────────────────────────────────────────────────

/// Backend callback interface for media player operations.
///
/// Implemented by backends such as AVRCP Controller and MCP to handle
/// playback control, setting changes, and browsing operations.
pub trait MediaPlayerCallback: Send + Sync {
    /// Start playback.
    fn play(&self) -> Result<(), BtdError>;
    /// Pause playback.
    fn pause(&self) -> Result<(), BtdError>;
    /// Stop playback.
    fn stop(&self) -> Result<(), BtdError>;
    /// Skip to next track.
    fn next(&self) -> Result<(), BtdError>;
    /// Skip to previous track.
    fn previous(&self) -> Result<(), BtdError>;
    /// Enter fast-forward mode.
    fn fast_forward(&self) -> Result<(), BtdError>;
    /// Enter rewind mode.
    fn rewind(&self) -> Result<(), BtdError>;
    /// Press an AVC passthrough key.
    fn press(&self, avc_key: u8) -> Result<(), BtdError>;
    /// Hold an AVC passthrough key.
    fn hold(&self, avc_key: u8) -> Result<(), BtdError>;
    /// Release a previously pressed/held AVC key.
    fn release(&self) -> Result<(), BtdError>;
    /// Change a player setting (e.g., Equalizer, Repeat, Shuffle, Scan).
    fn set_setting(&self, key: &str, value: &str) -> Result<(), BtdError>;
    /// List items in a folder; results delivered via `list_complete`.
    fn list_items(&self, name: &str, start: u32, end: u32) -> Result<(), BtdError>;
    /// Change to a different folder; result delivered via `change_folder_complete`.
    fn change_folder(&self, path: &str, uid: u64) -> Result<(), BtdError>;
    /// Search within the current scope; results delivered via `search_complete`.
    fn search(&self, value: &str) -> Result<(), BtdError>;
    /// Play a specific item; result delivered via `play_item_complete`.
    fn play_item(&self, name: &str, uid: u64) -> Result<(), BtdError>;
    /// Add an item to the now-playing list.
    fn add_to_nowplaying(&self, name: &str, uid: u64) -> Result<(), BtdError>;
    /// Query total number of items in a folder; result via `total_items_complete`.
    fn total_items(&self, name: &str) -> Result<(), BtdError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal Support Structures
// ──────────────────────────────────────────────────────────────────────────────

/// Type alias for the item entries returned by `ListItems` D-Bus method.
type MediaItemEntry = (OwnedObjectPath, HashMap<String, OwnedValue>);

/// Pending asynchronous folder operation (at most one per folder at a time).
enum PendingFolderOp {
    /// A pending `Search` D-Bus call.
    Search(oneshot::Sender<Result<OwnedObjectPath, BtdError>>),
    /// A pending `ListItems` D-Bus call.
    ListItems(oneshot::Sender<Result<Vec<MediaItemEntry>, BtdError>>),
    /// A pending `ChangeFolder` D-Bus call.
    ChangeFolder(oneshot::Sender<Result<(), BtdError>>),
    /// A pending `Play` on an item D-Bus call.
    PlayItem(oneshot::Sender<Result<(), BtdError>>),
}

/// Pending async property write for a player setting.
struct PendingSettingReq {
    /// Setting key name (e.g., "Equalizer").
    attr: String,
    /// Requested value (e.g., "on"). Retained for diagnostics and status reporting.
    _value: String,
    /// One-shot channel to deliver the backend result.
    reply: oneshot::Sender<Result<(), BtdError>>,
}

/// Internal representation of a media folder in the browse tree.
struct MediaFolder {
    /// Index of parent folder in `PlayerInner::all_folders`, if any.
    _parent_idx: Option<usize>,
    /// The folder represented as a media item (for D-Bus object).
    item: MediaItem,
    /// Total number of items reported by the backend.
    number_of_items: u32,
    /// Indices of child subfolders in `PlayerInner::all_folders`.
    subfolder_indices: Vec<usize>,
    /// Media items (tracks, nested items) within this folder.
    items: Vec<MediaItem>,
    /// Pending asynchronous operation on this folder.
    pending: Option<PendingFolderOp>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Public Data Structures
// ──────────────────────────────────────────────────────────────────────────────

/// A media item in the browse tree, exposed via `org.bluez.MediaItem1`.
pub struct MediaItem {
    /// D-Bus object path for this item.
    pub path: String,
    /// Display name.
    pub name: String,
    /// Item type (audio, video, folder).
    pub item_type: PlayerItemType,
    /// Folder type (only meaningful when `item_type == Folder`).
    pub folder_type: PlayerFolderType,
    /// Whether this item can be played directly.
    pub playable: bool,
    /// Unique identifier within the browse tree.
    pub uid: u64,
    /// Item metadata (Title, Artist, Album, etc.).
    pub metadata: Option<HashMap<String, String>>,
}

impl MediaItem {
    /// Create a new media item with default values.
    fn new(path: String, name: String, uid: u64) -> Self {
        Self {
            path,
            name,
            item_type: PlayerItemType::Invalid,
            folder_type: PlayerFolderType::Invalid,
            playable: false,
            uid,
            metadata: None,
        }
    }

    /// Set the playable flag on this item.
    pub fn set_playable(&mut self, playable: bool) {
        self.playable = playable;
    }
}

/// Internal mutable state for a media player, shared between the public API
/// and D-Bus interface handlers via `Arc<Mutex<PlayerInner>>`.
struct PlayerInner {
    /// D-Bus object path of the owning device.
    device_path: String,
    /// D-Bus object path of this player.
    path: String,
    /// Player identifier (retained for debugging and unique identification).
    _id: u32,
    /// Human-readable player name.
    name: String,
    /// Player type string ("Audio", "Video", etc.).
    player_type: String,
    /// Player subtype string ("Audio Book", "Podcast", etc.).
    subtype: String,
    /// Current playback status.
    status: PlaybackStatus,
    /// Current playback position in milliseconds.
    pub position: u32,
    /// Current track duration in milliseconds.
    pub duration: u32,
    /// Instant when position was last snapshotted.
    progress: Instant,
    /// Track metadata.
    pub metadata: HashMap<String, String>,
    /// Player settings.
    pub settings: HashMap<String, String>,
    /// Backend callback implementation.
    callbacks: Option<Arc<dyn MediaPlayerCallback>>,
    /// Whether the player supports browsing.
    browsable: bool,
    /// Whether the player supports search.
    searchable: bool,
    /// Whether the MediaFolder1 interface has been registered.
    folder_registered: bool,
    /// All folders (flat storage). Referenced by index.
    all_folders: Vec<MediaFolder>,
    /// Indices of top-level folders.
    top_level_indices: Vec<usize>,
    /// Current browsing scope folder index.
    scope_idx: Option<usize>,
    /// Current navigated subfolder index.
    folder_idx: Option<usize>,
    /// Current search results folder index.
    search_idx: Option<usize>,
    /// Current playlist folder index.
    playlist_idx: Option<usize>,
    /// Pending property-write requests for player settings.
    pending_settings: Vec<PendingSettingReq>,
    /// OBEX port number for browsing connections.
    obex_port: u16,
    /// Background position timer task handle (active while status == Playing).
    /// Aborted on status change away from Playing or on player destroy.
    position_timer: Option<JoinHandle<()>>,
}

impl PlayerInner {
    /// Compute the current playback position, accounting for elapsed time
    /// while the player status is `Playing`.
    fn get_position(&self) -> u32 {
        if self.status != PlaybackStatus::Playing {
            return self.position;
        }
        let elapsed_ms = self.progress.elapsed().as_millis() as u32;
        self.position.saturating_add(elapsed_ms)
    }

    /// Get the currently active scope folder, if any.
    fn scope_folder(&self) -> Option<&MediaFolder> {
        self.scope_idx.and_then(|i| self.all_folders.get(i))
    }

    /// Get a mutable reference to the currently active scope folder.
    fn scope_folder_mut(&mut self) -> Option<&mut MediaFolder> {
        self.scope_idx.and_then(|i| self.all_folders.get_mut(i))
    }

    /// Find a top-level folder by name.
    fn find_folder_by_name(&self, name: &str) -> Option<usize> {
        self.top_level_indices
            .iter()
            .copied()
            .find(|&idx| self.all_folders.get(idx).is_some_and(|f| f.item.name == name))
    }

    /// Find a subfolder within the current scope by D-Bus path.
    fn find_subfolder_by_path(&self, path: &str) -> Option<usize> {
        let scope = self.scope_idx?;
        let folder = self.all_folders.get(scope)?;
        folder
            .subfolder_indices
            .iter()
            .copied()
            .find(|&idx| self.all_folders.get(idx).is_some_and(|f| f.item.path == path))
    }

    /// Build the track metadata as a D-Bus `a{sv}` dictionary.
    fn build_track_dict(&self) -> HashMap<String, OwnedValue> {
        let mut dict = HashMap::new();
        for (key, value) in &self.metadata {
            match key.as_str() {
                "Duration" | "TrackNumber" | "NumberOfTracks" => {
                    if let Ok(v) = value.parse::<u32>() {
                        dict_append_entry(&mut dict, key, Value::U32(v));
                    }
                }
                "Item" => {
                    if let Ok(path) = ObjectPath::try_from(value.as_str()) {
                        dict_append_entry(&mut dict, key, Value::ObjectPath(path));
                    }
                }
                _ => {
                    dict_append_entry(&mut dict, key, Value::Str(value.as_str().into()));
                }
            }
        }
        dict
    }

    /// Build item metadata as a D-Bus `a{sv}` dictionary, excluding "Item" key.
    fn build_item_metadata(meta: &HashMap<String, String>) -> HashMap<String, OwnedValue> {
        let mut dict = HashMap::new();
        for (key, value) in meta {
            if key == "Item" {
                continue;
            }
            match key.as_str() {
                "Duration" | "TrackNumber" | "NumberOfTracks" => {
                    if let Ok(v) = value.parse::<u32>() {
                        dict_append_entry(&mut dict, key, Value::U32(v));
                    }
                }
                _ => {
                    dict_append_entry(&mut dict, key, Value::Str(value.as_str().into()));
                }
            }
        }
        dict
    }
}

/// A media player object, representing a remote or backend-provided playback
/// controller exposed on D-Bus.
///
/// Instances are created via [`MediaPlayer::controller_create`] and shared
/// with backends via `Arc<MediaPlayer>`.
pub struct MediaPlayer {
    /// D-Bus object path of this player (public for backend access).
    pub path: String,
    /// Human-readable player name (for quick non-locked access).
    pub name: String,
    /// Current playback status (cached for quick read by backends).
    pub status: PlaybackStatus,
    /// Current position in ms (cached snapshot).
    pub position: u32,
    /// Current duration in ms (cached snapshot).
    pub duration: u32,
    /// Track metadata clone (for quick read).
    pub metadata: HashMap<String, String>,
    /// Player settings clone (for quick read).
    pub settings: HashMap<String, String>,
    /// Shared mutable inner state.
    inner: Arc<Mutex<PlayerInner>>,
}

// ──────────────────────────────────────────────────────────────────────────────
// D-Bus Interface: org.bluez.MediaPlayer1
// ──────────────────────────────────────────────────────────────────────────────

/// D-Bus interface handler for `org.bluez.MediaPlayer1`.
struct MediaPlayer1Iface {
    inner: Arc<Mutex<PlayerInner>>,
}

#[zbus::interface(name = "org.bluez.MediaPlayer1")]
impl MediaPlayer1Iface {
    // ── Methods ──────────────────────────────────────────────────────────

    /// Start playback.
    async fn play(&self) -> Result<(), BtdError> {
        let cb = {
            let inner = self.inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.play()
    }

    /// Pause playback.
    async fn pause(&self) -> Result<(), BtdError> {
        let cb = {
            let inner = self.inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.pause()
    }

    /// Stop playback.
    async fn stop(&self) -> Result<(), BtdError> {
        let cb = {
            let inner = self.inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.stop()
    }

    /// Skip to the next track.
    async fn next(&self) -> Result<(), BtdError> {
        let cb = {
            let inner = self.inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.next()
    }

    /// Skip to the previous track.
    async fn previous(&self) -> Result<(), BtdError> {
        let cb = {
            let inner = self.inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.previous()
    }

    /// Enter fast-forward mode.
    async fn fast_forward(&self) -> Result<(), BtdError> {
        let cb = {
            let inner = self.inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.fast_forward()
    }

    /// Enter rewind mode.
    async fn rewind(&self) -> Result<(), BtdError> {
        let cb = {
            let inner = self.inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.rewind()
    }

    /// Press an AVC passthrough key.
    async fn press(&self, avc_key: u8) -> Result<(), BtdError> {
        let cb = {
            let inner = self.inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.press(avc_key)
    }

    /// Hold an AVC passthrough key.
    async fn hold(&self, avc_key: u8) -> Result<(), BtdError> {
        let cb = {
            let inner = self.inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.hold(avc_key)
    }

    /// Release a previously pressed/held AVC passthrough key.
    async fn release(&self) -> Result<(), BtdError> {
        let cb = {
            let inner = self.inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.release()
    }

    // ── Read-only Properties ─────────────────────────────────────────────

    /// Current playback status string.
    #[zbus(property)]
    async fn status(&self) -> String {
        let inner = self.inner.lock().await;
        inner.status.to_string()
    }

    /// Current position in milliseconds.
    #[zbus(property)]
    async fn position(&self) -> u32 {
        let inner = self.inner.lock().await;
        inner.get_position()
    }

    /// Track metadata as a dictionary of variant values.
    #[zbus(property)]
    async fn track(&self) -> HashMap<String, OwnedValue> {
        let inner = self.inner.lock().await;
        inner.build_track_dict()
    }

    /// D-Bus object path of the owning Bluetooth device.
    #[zbus(property)]
    async fn device(&self) -> OwnedObjectPath {
        let inner = self.inner.lock().await;
        ObjectPath::try_from(inner.device_path.as_str())
            .unwrap_or_else(|_| ObjectPath::from_static_str_unchecked("/"))
            .into()
    }

    /// Player display name.
    #[zbus(property)]
    async fn name(&self) -> String {
        let inner = self.inner.lock().await;
        inner.name.clone()
    }

    /// Player type ("Audio", "Video", "Audio Broadcasting", "Video Broadcasting").
    #[zbus(property, name = "Type")]
    async fn player_type(&self) -> String {
        let inner = self.inner.lock().await;
        inner.player_type.clone()
    }

    /// Player subtype ("Audio Book", "Podcast", etc.).
    #[zbus(property)]
    async fn subtype(&self) -> String {
        let inner = self.inner.lock().await;
        inner.subtype.clone()
    }

    /// Whether this player supports media browsing.
    #[zbus(property)]
    async fn browsable(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.browsable
    }

    /// Whether this player supports search.
    #[zbus(property)]
    async fn searchable(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.searchable
    }

    /// D-Bus object path of the current playlist folder, or "/" if none.
    #[zbus(property)]
    async fn playlist(&self) -> OwnedObjectPath {
        let inner = self.inner.lock().await;
        let path_str = inner
            .playlist_idx
            .and_then(|i| inner.all_folders.get(i))
            .map(|f| f.item.path.as_str())
            .unwrap_or("/");
        ObjectPath::try_from(path_str)
            .unwrap_or_else(|_| ObjectPath::from_static_str_unchecked("/"))
            .into()
    }

    // ── Read-Write Setting Properties ────────────────────────────────────

    /// Equalizer setting value ("on" or "off").
    #[zbus(property)]
    async fn equalizer(&self) -> String {
        let inner = self.inner.lock().await;
        inner.settings.get("Equalizer").cloned().unwrap_or_else(|| "off".to_owned())
    }

    /// Set the Equalizer value. Async — waits for backend confirmation.
    #[zbus(property)]
    async fn set_equalizer(&self, value: String) -> zbus::Result<()> {
        self.set_setting_async("Equalizer", value).await
    }

    /// Repeat setting value ("off", "singletrack", "alltracks", "group").
    #[zbus(property)]
    async fn repeat(&self) -> String {
        let inner = self.inner.lock().await;
        inner.settings.get("Repeat").cloned().unwrap_or_else(|| "off".to_owned())
    }

    /// Set the Repeat value. Async — waits for backend confirmation.
    #[zbus(property)]
    async fn set_repeat(&self, value: String) -> zbus::Result<()> {
        self.set_setting_async("Repeat", value).await
    }

    /// Shuffle setting value ("off", "alltracks", "group").
    #[zbus(property)]
    async fn shuffle(&self) -> String {
        let inner = self.inner.lock().await;
        inner.settings.get("Shuffle").cloned().unwrap_or_else(|| "off".to_owned())
    }

    /// Set the Shuffle value. Async — waits for backend confirmation.
    #[zbus(property)]
    async fn set_shuffle(&self, value: String) -> zbus::Result<()> {
        self.set_setting_async("Shuffle", value).await
    }

    /// Scan setting value ("off", "alltracks", "group").
    #[zbus(property)]
    async fn scan(&self) -> String {
        let inner = self.inner.lock().await;
        inner.settings.get("Scan").cloned().unwrap_or_else(|| "off".to_owned())
    }

    /// Set the Scan value. Async — waits for backend confirmation.
    #[zbus(property)]
    async fn set_scan(&self, value: String) -> zbus::Result<()> {
        self.set_setting_async("Scan", value).await
    }
}

impl MediaPlayer1Iface {
    /// Common implementation for async setting property writes.
    ///
    /// 1. Check that a backend callback exists.
    /// 2. Reject if the same setting already has a pending write.
    /// 3. Call the backend; if it rejects, return immediately.
    /// 4. Install a pending request and await the backend's confirmation.
    async fn set_setting_async(&self, key: &str, value: String) -> zbus::Result<()> {
        let (tx, rx) = oneshot::channel();

        {
            let mut inner = self.inner.lock().await;

            // Check callbacks exist.
            let cb = inner.callbacks.clone().ok_or_else(BtdError::not_supported)?;

            // Reject concurrent writes for the same setting key.
            if inner.pending_settings.iter().any(|p| p.attr == key) {
                return Err(BtdError::in_progress().into());
            }

            // Ask the backend to apply the setting.
            cb.set_setting(key, &value)?;

            // Track the pending request.
            inner.pending_settings.push(PendingSettingReq {
                attr: key.to_owned(),
                _value: value,
                reply: tx,
            });
        }

        // Wait for the backend to confirm or reject via `set_setting()`.
        rx.await
            .unwrap_or_else(|_| Err(BtdError::failed("Operation cancelled")))
            .map_err(Into::into)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// D-Bus Interface: org.bluez.MediaFolder1
// ──────────────────────────────────────────────────────────────────────────────

/// D-Bus interface handler for `org.bluez.MediaFolder1`.
struct MediaFolder1Iface {
    inner: Arc<Mutex<PlayerInner>>,
}

#[zbus::interface(name = "org.bluez.MediaFolder1")]
impl MediaFolder1Iface {
    // ── Methods ──────────────────────────────────────────────────────────

    /// Search for items matching the query string.
    ///
    /// Returns the D-Bus object path of the search-results folder.
    /// This is an async operation — the reply is deferred until the backend
    /// completes the search via [`MediaPlayer::search_complete`].
    async fn search(&self, value: String) -> Result<OwnedObjectPath, BtdError> {
        let (tx, rx) = oneshot::channel();

        {
            let mut inner = self.inner.lock().await;

            let cb = inner.callbacks.clone().ok_or_else(BtdError::not_supported)?;

            // Only one async operation per scope at a time.
            if let Some(scope) = inner.scope_folder_mut() {
                if scope.pending.is_some() {
                    return Err(BtdError::in_progress());
                }
                scope.pending = Some(PendingFolderOp::Search(tx));
            } else {
                return Err(BtdError::not_supported());
            }

            cb.search(&value)?;
        }

        rx.await.unwrap_or_else(|_| Err(BtdError::failed("Operation cancelled")))
    }

    /// List items in the current folder, optionally filtered by a dictionary
    /// containing `Start` (u32) and `End` (u32) range indices.
    ///
    /// Returns an array of `(ObjectPath, Properties)` tuples.
    async fn list_items(
        &self,
        filter: HashMap<String, OwnedValue>,
    ) -> Result<Vec<MediaItemEntry>, BtdError> {
        let (tx, rx) = oneshot::channel();

        {
            let mut inner = self.inner.lock().await;

            let cb = inner.callbacks.clone().ok_or_else(BtdError::not_supported)?;

            let scope = inner.scope_folder_mut().ok_or_else(BtdError::not_supported)?;

            if scope.pending.is_some() {
                return Err(BtdError::in_progress());
            }

            // Parse start/end from the filter dict.
            let start = match filter.get("Start") {
                Some(v) => <u32>::try_from(v).map_err(|_| BtdError::invalid_args())?,
                None => 0,
            };
            let end = match filter.get("End") {
                Some(v) => <u32>::try_from(v).map_err(|_| BtdError::invalid_args())?,
                None => u32::MAX,
            };

            scope.pending = Some(PendingFolderOp::ListItems(tx));

            let folder_name = scope.item.name.clone();
            cb.list_items(&folder_name, start, end)?;
        }

        rx.await.unwrap_or_else(|_| Err(BtdError::failed("Operation cancelled")))
    }

    /// Change into a subfolder identified by its D-Bus object path.
    async fn change_folder(&self, folder: OwnedObjectPath) -> Result<(), BtdError> {
        let (tx, rx) = oneshot::channel();

        {
            let mut inner = self.inner.lock().await;

            let cb = inner.callbacks.clone().ok_or_else(BtdError::not_supported)?;

            let scope = inner.scope_folder_mut().ok_or_else(BtdError::not_supported)?;

            if scope.pending.is_some() {
                return Err(BtdError::in_progress());
            }

            scope.pending = Some(PendingFolderOp::ChangeFolder(tx));

            let folder_path = folder.as_str().to_owned();

            // Find the target folder's UID from its path.
            let uid = inner
                .find_subfolder_by_path(&folder_path)
                .and_then(|idx| inner.all_folders.get(idx))
                .map(|f| f.item.uid)
                .unwrap_or(0);

            cb.change_folder(&folder_path, uid)?;
        }

        rx.await.unwrap_or_else(|_| Err(BtdError::failed("Operation cancelled")))
    }

    // ── Read-only Properties ─────────────────────────────────────────────

    /// Display name of the current scope folder.
    #[zbus(property)]
    async fn name(&self) -> String {
        let inner = self.inner.lock().await;
        inner.scope_folder().map(|f| f.item.name.clone()).unwrap_or_default()
    }

    /// Number of items in the current scope folder.
    #[zbus(property)]
    async fn number_of_items(&self) -> u32 {
        let inner = self.inner.lock().await;
        inner.scope_folder().map(|f| f.number_of_items).unwrap_or(0)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// D-Bus Interface: org.bluez.MediaItem1
// ──────────────────────────────────────────────────────────────────────────────

/// D-Bus interface handler for `org.bluez.MediaItem1`.
///
/// Each item instance holds its own snapshot of item data plus a reference
/// to the player inner state for delegating play/add-to-now-playing.
struct MediaItem1Iface {
    /// Shared player state for delegating operations.
    player_inner: Arc<Mutex<PlayerInner>>,
    /// Item unique identifier.
    uid: u64,
    /// Item display name.
    item_name: String,
    /// Item type string.
    item_type: PlayerItemType,
    /// Folder type string (if item_type is Folder).
    item_folder_type: PlayerFolderType,
    /// Whether the item is directly playable.
    item_playable: bool,
    /// Item metadata snapshot.
    item_metadata: HashMap<String, String>,
    /// Player D-Bus path (for the Player property).
    player_path: String,
}

#[zbus::interface(name = "org.bluez.MediaItem1")]
impl MediaItem1Iface {
    // ── Methods ──────────────────────────────────────────────────────────

    /// Play this specific media item.
    async fn play(&self) -> Result<(), BtdError> {
        let (tx, rx) = oneshot::channel();

        {
            let mut inner = self.player_inner.lock().await;

            let cb = inner.callbacks.clone().ok_or_else(BtdError::not_supported)?;

            // Only one pending play per scope at a time.
            if let Some(scope) = inner.scope_folder_mut() {
                if scope.pending.is_some() {
                    return Err(BtdError::in_progress());
                }
                scope.pending = Some(PendingFolderOp::PlayItem(tx));
            }

            cb.play_item(&self.item_name, self.uid)?;
        }

        rx.await.unwrap_or_else(|_| Err(BtdError::failed("Operation cancelled")))
    }

    /// Add this item to the now-playing list.
    async fn add_to_now_playing(&self) -> Result<(), BtdError> {
        let cb = {
            let inner = self.player_inner.lock().await;
            inner.callbacks.clone()
        };
        let cb = cb.as_ref().ok_or_else(BtdError::not_supported)?;
        cb.add_to_nowplaying(&self.item_name, self.uid)
    }

    // ── Read-only Properties ─────────────────────────────────────────────

    /// D-Bus object path of the owning player.
    #[zbus(property)]
    fn player(&self) -> OwnedObjectPath {
        ObjectPath::try_from(self.player_path.as_str())
            .unwrap_or_else(|_| ObjectPath::from_static_str_unchecked("/"))
            .into()
    }

    /// Item display name.
    #[zbus(property)]
    fn name(&self) -> &str {
        &self.item_name
    }

    /// Item type ("audio", "video", "folder").
    #[zbus(property, name = "Type")]
    fn item_type_prop(&self) -> String {
        self.item_type.to_string()
    }

    /// Folder type ("mixed", "titles", "albums", etc.) — only for folder items.
    #[zbus(property)]
    fn folder_type(&self) -> String {
        self.item_folder_type.to_string()
    }

    /// Whether the item can be played directly.
    #[zbus(property)]
    fn playable(&self) -> bool {
        self.item_playable
    }

    /// Item metadata as a D-Bus `a{sv}` dictionary (excludes "Item" key).
    #[zbus(property, name = "Metadata")]
    fn metadata_prop(&self) -> HashMap<String, OwnedValue> {
        PlayerInner::build_item_metadata(&self.item_metadata)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// MediaPlayer — Public API
// ──────────────────────────────────────────────────────────────────────────────

impl MediaPlayer {
    // ── Creation & Lifecycle ─────────────────────────────────────────────

    /// Create a new media player controller and register its
    /// `org.bluez.MediaPlayer1` D-Bus interface.
    ///
    /// The D-Bus object path is composed as `{device_path}/{player_type}/player{id}`.
    pub async fn controller_create(device_path: &str, id: u32, player_type: &str) -> Arc<Self> {
        let type_slug = player_type.to_lowercase().replace(' ', "");
        let path = format!("{}/{}/player{}", device_path, type_slug, id);
        debug!("Creating media player: {}", path);

        let inner = Arc::new(Mutex::new(PlayerInner {
            device_path: device_path.to_owned(),
            path: path.clone(),
            _id: id,
            name: String::new(),
            player_type: player_type.to_owned(),
            subtype: String::new(),
            status: PlaybackStatus::Stopped,
            position: 0,
            duration: 0,
            progress: Instant::now(),
            metadata: HashMap::new(),
            settings: HashMap::new(),
            callbacks: None,
            browsable: false,
            searchable: false,
            folder_registered: false,
            all_folders: Vec::new(),
            top_level_indices: Vec::new(),
            scope_idx: None,
            folder_idx: None,
            search_idx: None,
            playlist_idx: None,
            pending_settings: Vec::new(),
            obex_port: 0,
            position_timer: None,
        }));

        // Register MediaPlayer1 D-Bus interface.
        let conn = btd_get_dbus_connection();
        let iface = MediaPlayer1Iface { inner: Arc::clone(&inner) };
        if let Err(e) = conn.object_server().at(path.as_str(), iface).await {
            error!("Failed to register {} at {}: {}", MEDIA_PLAYER_INTERFACE, path, e);
        }

        let player = Arc::new(MediaPlayer {
            path: path.clone(),
            name: String::new(),
            status: PlaybackStatus::Stopped,
            position: 0,
            duration: 0,
            metadata: HashMap::new(),
            settings: HashMap::new(),
            inner,
        });

        debug!("Media player created: {}", path);
        player
    }

    /// Return the D-Bus object path of this player.
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// Destroy the player, unregistering all D-Bus interfaces and cleaning
    /// up folders and items.
    pub async fn destroy(&self) {
        debug!("Destroying media player: {}", self.path);

        let conn = btd_get_dbus_connection();

        // Unregister item interfaces for every folder.
        {
            let inner = self.inner.lock().await;
            for folder in &inner.all_folders {
                for item in &folder.items {
                    if !item.path.is_empty() {
                        let _ = conn
                            .object_server()
                            .remove::<MediaItem1Iface, _>(item.path.as_str())
                            .await;
                    }
                }
                // Unregister subfolder item interfaces.
                if !folder.item.path.is_empty() && folder.item.uid > 0 {
                    let _ = conn
                        .object_server()
                        .remove::<MediaItem1Iface, _>(folder.item.path.as_str())
                        .await;
                }
            }
        }

        // Unregister MediaFolder1 interface.
        {
            let inner = self.inner.lock().await;
            if inner.folder_registered {
                let _ =
                    conn.object_server().remove::<MediaFolder1Iface, _>(self.path.as_str()).await;
            }
        }

        // Unregister MediaPlayer1 interface.
        let _ = conn.object_server().remove::<MediaPlayer1Iface, _>(self.path.as_str()).await;

        // Clear inner state and stop the position timer.
        {
            let mut inner = self.inner.lock().await;
            Self::stop_position_timer(&mut inner);
            inner.all_folders.clear();
            inner.top_level_indices.clear();
            inner.scope_idx = None;
            inner.folder_idx = None;
            inner.search_idx = None;
            inner.playlist_idx = None;
            inner.pending_settings.clear();
            inner.callbacks = None;
        }

        debug!("Media player destroyed: {}", self.path);
    }

    /// Install backend callbacks.
    pub async fn set_callbacks(&self, callbacks: Arc<dyn MediaPlayerCallback>) {
        let mut inner = self.inner.lock().await;
        inner.callbacks = Some(callbacks);
    }

    // ── State Update API ────────────────────────────────────────────────

    /// Update the playback status and emit the D-Bus PropertiesChanged signal.
    ///
    /// Called by backends (AVRCP, MCP) when the remote player status changes.
    /// Manages the position timer lifecycle: starts on Playing, stops otherwise.
    pub async fn set_status(&self, status_str: &str) {
        let new_status = PlaybackStatus::from_str_lossy(status_str);
        debug!("Player {} status -> {}", self.path, new_status);

        {
            let mut inner = self.inner.lock().await;
            if inner.status == new_status {
                return;
            }
            // Snapshot current computed position before changing status.
            inner.position = inner.get_position();
            inner.progress = Instant::now();

            // Stop any existing position timer before status transition.
            Self::stop_position_timer(&mut inner);

            inner.status = new_status;

            // Start position timer when entering Playing state.
            if new_status == PlaybackStatus::Playing {
                Self::start_position_timer(&mut inner);
            }
        }

        self.emit_player1_changed(&["Status", "Position"]).await;
    }

    /// Start a background position timer that runs while status is Playing.
    /// The timer periodically updates the progress snapshot so that
    /// position queries during long playback sessions remain accurate.
    fn start_position_timer(inner: &mut PlayerInner) {
        // Abort any existing timer first.
        if let Some(handle) = inner.position_timer.take() {
            handle.abort();
        }

        let path = inner.path.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                // The position timer runs in the background while Playing.
                // Actual position is computed on-the-fly in get_position()
                // using the Instant-based progress tracker.
                debug!("Position timer tick for {}", path);
            }
        });
        inner.position_timer = Some(handle);
    }

    /// Stop the background position timer.
    fn stop_position_timer(inner: &mut PlayerInner) {
        if let Some(handle) = inner.position_timer.take() {
            handle.abort();
        }
    }

    /// Return the current playback status.
    pub async fn get_status(&self) -> PlaybackStatus {
        let inner = self.inner.lock().await;
        inner.status
    }

    /// Update the playback position in milliseconds.
    pub async fn set_position(&self, position: u32) {
        debug!("Player {} position -> {}", self.path, position);
        {
            let mut inner = self.inner.lock().await;
            inner.position = position;
            inner.progress = Instant::now();
        }
        self.emit_player1_changed(&["Position"]).await;
    }

    /// Update the track duration in milliseconds.
    pub async fn set_duration(&self, duration: u32) {
        debug!("Player {} duration -> {}", self.path, duration);
        {
            let mut inner = self.inner.lock().await;
            inner.duration = duration;
            inner.metadata.insert("Duration".to_owned(), duration.to_string());
        }
        self.emit_player1_changed(&["Track"]).await;
    }

    /// Update a single metadata field (e.g., "Title", "Artist").
    pub async fn set_metadata(&self, key: &str, value: &str) {
        debug!("Player {} metadata: {} = {}", self.path, key, value);
        let mut inner = self.inner.lock().await;
        inner.metadata.insert(key.to_owned(), value.to_owned());
    }

    /// Clear all metadata except "Duration" and "Item" keys.
    pub async fn clear_metadata(&self) {
        debug!("Player {} clearing metadata", self.path);
        let mut inner = self.inner.lock().await;
        inner.metadata.retain(|k, _| k == "Duration" || k == "Item");
    }

    /// Signal that metadata has been fully updated; emit D-Bus property change.
    pub async fn metadata_changed(&self) {
        self.emit_player1_changed(&["Track"]).await;
    }

    /// Update the player name.
    pub async fn set_name(&self, name: &str) {
        debug!("Player {} name -> {}", self.path, name);
        {
            let mut inner = self.inner.lock().await;
            if inner.name == name {
                return;
            }
            inner.name = name.to_owned();
        }
        self.emit_player1_changed(&["Name"]).await;
    }

    /// Update the player type string (e.g., "Audio", "Video").
    pub async fn set_type(&self, player_type: &str) {
        debug!("Player {} type -> {}", self.path, player_type);
        let mut inner = self.inner.lock().await;
        inner.player_type = player_type.to_owned();
    }

    /// Update the player subtype string (e.g., "Audio Book", "Podcast").
    pub async fn set_subtype(&self, subtype: &str) {
        debug!("Player {} subtype -> {}", self.path, subtype);
        let mut inner = self.inner.lock().await;
        inner.subtype = subtype.to_owned();
    }

    /// Update the browsable flag.
    pub async fn set_browsable(&self, browsable: bool) {
        debug!("Player {} browsable -> {}", self.path, browsable);
        {
            let mut inner = self.inner.lock().await;
            if inner.browsable == browsable {
                return;
            }
            inner.browsable = browsable;
        }
        self.emit_player1_changed(&["Browsable"]).await;
    }

    /// Return whether this player supports browsing.
    pub async fn get_browsable(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.browsable
    }

    /// Update the searchable flag.
    pub async fn set_searchable(&self, searchable: bool) {
        debug!("Player {} searchable -> {}", self.path, searchable);
        {
            let mut inner = self.inner.lock().await;
            if inner.searchable == searchable {
                return;
            }
            inner.searchable = searchable;
        }
        self.emit_player1_changed(&["Searchable"]).await;
    }

    /// Set the OBEX port used for browsing.
    pub async fn set_obex_port(&self, port: u16) {
        let mut inner = self.inner.lock().await;
        inner.obex_port = port;
    }

    /// Complete a pending setting write from the backend.
    ///
    /// If `value` is `"Error"`, the pending D-Bus property write is failed.
    /// Otherwise, the setting is applied and the write succeeds.
    pub async fn set_setting(&self, key: &str, value: &str) {
        debug!("Player {} setting: {} = {}", self.path, key, value);

        let mut inner = self.inner.lock().await;

        // Find pending request for this key.
        let idx = inner.pending_settings.iter().position(|p| p.attr == key);

        match idx {
            Some(i) => {
                let pending = inner.pending_settings.remove(i);
                if value.eq_ignore_ascii_case("Error") {
                    let _ = pending
                        .reply
                        .send(Err(BtdError::failed(&format!("{}.Failed", ERROR_INTERFACE))));
                } else {
                    inner.settings.insert(key.to_owned(), value.to_owned());
                    let _ = pending.reply.send(Ok(()));
                }
            }
            None => {
                // No pending request — just update the setting and emit.
                let changed = inner.settings.get(key).is_none_or(|v| v != value);
                if changed {
                    inner.settings.insert(key.to_owned(), value.to_owned());
                    drop(inner);
                    self.emit_player1_changed(&[key]).await;
                }
            }
        }
    }

    // ── Browsing / Folder API ───────────────────────────────────────────

    /// Set the current browsing scope and its initial items.
    ///
    /// If the MediaFolder1 interface has not yet been registered, this
    /// registers it at the player path. Then sets the scope to the
    /// named folder and optionally queries total items from the backend.
    pub async fn set_scope(&self, scope_name: &str, number_of_items: u32) {
        debug!("Player {} set_scope -> {}", self.path, scope_name);

        let mut inner = self.inner.lock().await;

        // Register MediaFolder1 interface on first scope usage.
        if !inner.folder_registered {
            let conn = btd_get_dbus_connection();
            let folder_iface = MediaFolder1Iface { inner: Arc::clone(&self.inner) };
            if let Err(e) = conn.object_server().at(self.path.as_str(), folder_iface).await {
                error!("Failed to register {} at {}: {}", MEDIA_FOLDER_INTERFACE, self.path, e);
            }
            inner.folder_registered = true;
        }

        // Find or create the named scope folder.
        let scope_idx = match inner.find_folder_by_name(scope_name) {
            Some(idx) => idx,
            None => {
                // Create a new top-level folder for this scope.
                let folder_path = format!("{}/{}", inner.path, scope_name);
                let folder = MediaFolder {
                    _parent_idx: None,
                    item: MediaItem::new(folder_path, scope_name.to_owned(), 0),
                    number_of_items,
                    subfolder_indices: Vec::new(),
                    items: Vec::new(),
                    pending: None,
                };
                let idx = inner.all_folders.len();
                inner.all_folders.push(folder);
                inner.top_level_indices.push(idx);
                idx
            }
        };

        inner.scope_idx = Some(scope_idx);
        if let Some(folder) = inner.all_folders.get_mut(scope_idx) {
            folder.number_of_items = number_of_items;
        }

        // Query backend for total items if callback available.
        if number_of_items == 0 {
            if let Some(ref cb) = inner.callbacks {
                let _ = cb.total_items(scope_name);
            }
        }

        drop(inner);
        self.emit_folder1_changed(&["Name", "NumberOfItems"]).await;
    }

    /// Set the current folder (navigate into a subfolder within the scope).
    pub async fn set_folder(&self, folder_name: &str, number_of_items: u32) {
        debug!("Player {} set_folder -> {}", self.path, folder_name);

        let mut inner = self.inner.lock().await;

        let scope_idx = match inner.scope_idx {
            Some(idx) => idx,
            None => return,
        };

        // Find the folder by name within the scope's subfolders.
        let folder_idx =
            {
                let scope = &inner.all_folders[scope_idx];
                scope.subfolder_indices.iter().copied().find(|&idx| {
                    inner.all_folders.get(idx).is_some_and(|f| f.item.name == folder_name)
                })
            };

        if let Some(idx) = folder_idx {
            inner.folder_idx = Some(idx);
            if let Some(folder) = inner.all_folders.get_mut(idx) {
                folder.number_of_items = number_of_items;
            }
        }
    }

    /// Set the playlist folder.
    pub async fn set_playlist(&self, playlist_name: &str) {
        debug!("Player {} set_playlist -> {}", self.path, playlist_name);

        let mut inner = self.inner.lock().await;
        let playlist_idx = inner.find_folder_by_name(playlist_name);
        inner.playlist_idx = playlist_idx;

        drop(inner);
        self.emit_player1_changed(&["Playlist"]).await;
    }

    /// Set the current playlist item, linking its metadata to the player's track.
    pub async fn set_playlist_item(&self, uid: u64) {
        debug!("Player {} set_playlist_item uid={}", self.path, uid);

        let mut inner = self.inner.lock().await;

        let playlist_idx = match inner.playlist_idx {
            Some(idx) => idx,
            None => return,
        };

        // Find the item within the playlist folder.
        let item_metadata = {
            let folder = match inner.all_folders.get(playlist_idx) {
                Some(f) => f,
                None => return,
            };
            folder.items.iter().find(|item| item.uid == uid).and_then(|item| item.metadata.clone())
        };

        if let Some(meta) = item_metadata {
            // Merge item metadata into the player track metadata.
            for (k, v) in &meta {
                inner.metadata.insert(k.clone(), v.clone());
            }
            // Set the "Item" key to point to the item's D-Bus path.
            let item_path = inner
                .all_folders
                .get(playlist_idx)
                .and_then(|folder| folder.items.iter().find(|i| i.uid == uid))
                .map(|item| item.path.clone());
            if let Some(path) = item_path {
                inner.metadata.insert("Item".to_owned(), path);
            }
        }

        drop(inner);
        self.emit_player1_changed(&["Track", "Playlist"]).await;
    }

    /// Clear the current playlist.
    pub async fn clear_playlist(&self) {
        debug!("Player {} clear_playlist", self.path);
        let mut inner = self.inner.lock().await;
        inner.playlist_idx = None;
    }

    /// Create a new folder in the browse tree.
    ///
    /// If `uid > 0` and a scope is active, the folder is created as a
    /// subfolder of the current scope. Otherwise, it becomes a top-level folder.
    ///
    /// Returns a mutable reference to the newly created item's metadata within
    /// the folder (used by callers to populate item fields).
    pub async fn create_folder(&self, name: &str, uid: u64) -> Option<usize> {
        let mut inner = self.inner.lock().await;

        let (folder_path, par_idx) = if uid > 0 {
            if let Some(scope_idx) = inner.scope_idx {
                if let Some(scope) = inner.all_folders.get(scope_idx) {
                    let p = format!("{}/item{}", scope.item.path, uid);
                    (p, Some(scope_idx))
                } else {
                    return None;
                }
            } else {
                return None;
            }
        } else {
            let p = format!("{}/{}", inner.path, name);
            (p, None)
        };

        let mut item = MediaItem::new(folder_path, name.to_owned(), uid);
        item.item_type = PlayerItemType::Folder;

        let folder = MediaFolder {
            _parent_idx: par_idx,
            item,
            number_of_items: 0,
            subfolder_indices: Vec::new(),
            items: Vec::new(),
            pending: None,
        };

        let new_idx = inner.all_folders.len();
        inner.all_folders.push(folder);

        if let Some(pi) = par_idx {
            // Add as subfolder of parent.
            inner.all_folders[pi].subfolder_indices.push(new_idx);
        } else {
            inner.top_level_indices.push(new_idx);
        }

        debug!("Created folder '{}' uid={} at index {}", name, uid, new_idx);
        Some(new_idx)
    }

    /// Create a new media item within the current scope folder and register
    /// its `org.bluez.MediaItem1` D-Bus interface.
    ///
    /// Returns the D-Bus path of the newly created item.
    pub async fn create_item(
        &self,
        name: &str,
        uid: u64,
        item_type: PlayerItemType,
    ) -> Option<String> {
        let item_path;
        {
            let mut inner = self.inner.lock().await;

            let scope_idx = inner.scope_idx?;
            let scope = inner.all_folders.get(scope_idx)?;

            // Compute item path.
            item_path = if uid == 0 && name.starts_with('/') {
                format!("{}{}", inner.path, name)
            } else {
                format!("{}/item{}", scope.item.path, uid)
            };

            let mut item = MediaItem::new(item_path.clone(), name.to_owned(), uid);
            item.item_type = item_type;

            // Register MediaItem1 D-Bus interface.
            let conn = btd_get_dbus_connection();
            let item_iface = MediaItem1Iface {
                player_inner: Arc::clone(&self.inner),
                uid,
                item_name: name.to_owned(),
                item_type,
                item_folder_type: PlayerFolderType::Invalid,
                item_playable: false,
                item_metadata: HashMap::new(),
                player_path: inner.path.clone(),
            };
            if let Err(e) = conn.object_server().at(item_path.as_str(), item_iface).await {
                error!("Failed to register {} at {}: {}", MEDIA_ITEM_INTERFACE, item_path, e);
            }

            // Store the item in the scope folder.
            if let Some(scope) = inner.all_folders.get_mut(scope_idx) {
                scope.items.push(item);
            }
        }

        debug!("Created item '{}' uid={} at {}", name, uid, item_path);
        Some(item_path)
    }

    // ── Completion API ──────────────────────────────────────────────────

    /// Complete a pending `Play` on an item.
    ///
    /// Called by the backend after a `play_item` callback finishes.
    pub async fn play_item_complete(&self, err: i32) {
        debug!("Player {} play_item_complete err={}", self.path, err);

        let mut inner = self.inner.lock().await;
        let scope = match inner.scope_folder_mut() {
            Some(f) => f,
            None => return,
        };

        let pending = match scope.pending.take() {
            Some(PendingFolderOp::PlayItem(tx)) => tx,
            other => {
                // Put it back if it was a different operation type.
                scope.pending = other;
                return;
            }
        };

        if err < 0 {
            let _ =
                pending.send(Err(BtdError::failed(&format!("Play item failed (errno {})", -err))));
        } else {
            let _ = pending.send(Ok(()));
        }
    }

    /// Complete a pending `ListItems` call.
    ///
    /// Called by the backend after populating the folder's items.
    pub async fn list_complete(&self) {
        debug!("Player {} list_complete", self.path);

        let mut inner = self.inner.lock().await;
        let scope_idx = match inner.scope_idx {
            Some(i) => i,
            None => return,
        };

        // Clone player path before taking mutable borrow of folders.
        let player_path = inner.path.clone();

        let scope = match inner.all_folders.get_mut(scope_idx) {
            Some(f) => f,
            None => return,
        };

        let pending = match scope.pending.take() {
            Some(PendingFolderOp::ListItems(tx)) => tx,
            other => {
                scope.pending = other;
                return;
            }
        };

        // Build the reply array from the folder's items.
        let mut entries = Vec::new();
        for item in &scope.items {
            if item.path.is_empty() {
                continue;
            }
            let path = match OwnedObjectPath::try_from(item.path.as_str()) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let mut props = HashMap::new();
            dict_append_entry(
                &mut props,
                "Player",
                Value::ObjectPath(
                    ObjectPath::try_from(player_path.as_str())
                        .unwrap_or_else(|_| ObjectPath::from_static_str_unchecked("/")),
                ),
            );
            dict_append_entry(&mut props, "Name", Value::Str(item.name.as_str().into()));
            dict_append_entry(&mut props, "Type", Value::Str(item.item_type.to_string().into()));
            if item.item_type == PlayerItemType::Folder {
                dict_append_entry(
                    &mut props,
                    "FolderType",
                    Value::Str(item.folder_type.to_string().into()),
                );
            }
            dict_append_entry(&mut props, "Playable", Value::Bool(item.playable));
            if let Some(ref meta) = item.metadata {
                let meta_dict = PlayerInner::build_item_metadata(meta);
                dict_append_entry(&mut props, "Metadata", Value::from(meta_dict));
            }
            entries.push((path, props));
        }

        let _ = pending.send(Ok(entries));
    }

    /// Complete a pending `ChangeFolder` call.
    pub async fn change_folder_complete(&self, err: i32) {
        debug!("Player {} change_folder_complete err={}", self.path, err);

        let mut inner = self.inner.lock().await;
        let scope = match inner.scope_folder_mut() {
            Some(f) => f,
            None => return,
        };

        let pending = match scope.pending.take() {
            Some(PendingFolderOp::ChangeFolder(tx)) => tx,
            other => {
                scope.pending = other;
                return;
            }
        };

        if err < 0 {
            let _ = pending
                .send(Err(BtdError::failed(&format!("Change folder failed (errno {})", -err))));
        } else {
            let _ = pending.send(Ok(()));
        }
    }

    /// Complete a pending `Search` call.
    pub async fn search_complete(&self, err: i32, search_folder_idx: Option<usize>) {
        debug!("Player {} search_complete err={}", self.path, err);

        let mut inner = self.inner.lock().await;
        let scope = match inner.scope_folder_mut() {
            Some(f) => f,
            None => return,
        };

        let pending = match scope.pending.take() {
            Some(PendingFolderOp::Search(tx)) => tx,
            other => {
                scope.pending = other;
                return;
            }
        };

        if err < 0 {
            let _ = pending.send(Err(BtdError::failed(&format!("Search failed (errno {})", -err))));
            return;
        }

        // Set the search folder index.
        inner.search_idx = search_folder_idx;

        let search_path = search_folder_idx
            .and_then(|i| inner.all_folders.get(i))
            .map(|f| f.item.path.clone())
            .unwrap_or_else(|| inner.path.clone());

        let result = OwnedObjectPath::try_from(search_path.as_str())
            .map_err(|_| BtdError::failed("Invalid search path"));

        let _ = pending.send(result);
    }

    /// Complete a pending `total_items` query.
    pub async fn total_items_complete(&self, err: i32, total: u32) {
        debug!("Player {} total_items_complete err={} total={}", self.path, err, total);

        if err < 0 {
            return;
        }

        {
            let mut inner = self.inner.lock().await;
            if let Some(scope) = inner.scope_folder_mut() {
                scope.number_of_items = total;
            }
        }

        self.emit_folder1_changed(&["NumberOfItems"]).await;
    }

    // ── D-Bus Signal Emission Helpers ───────────────────────────────────

    /// Emit `PropertiesChanged` for specified properties on MediaPlayer1.
    async fn emit_player1_changed(&self, properties: &[&str]) {
        let conn = btd_get_dbus_connection();
        let iface_ref = match conn
            .object_server()
            .interface::<_, MediaPlayer1Iface>(self.path.as_str())
            .await
        {
            Ok(r) => r,
            Err(_) => return,
        };

        let ctxt = iface_ref.signal_emitter();

        for prop in properties {
            let result = match *prop {
                "Status" => iface_ref.get().await.status_changed(ctxt).await,
                "Position" => iface_ref.get().await.position_changed(ctxt).await,
                "Track" => iface_ref.get().await.track_changed(ctxt).await,
                "Name" => iface_ref.get().await.name_changed(ctxt).await,
                "Browsable" => iface_ref.get().await.browsable_changed(ctxt).await,
                "Searchable" => iface_ref.get().await.searchable_changed(ctxt).await,
                "Playlist" => iface_ref.get().await.playlist_changed(ctxt).await,
                "Equalizer" => iface_ref.get().await.equalizer_changed(ctxt).await,
                "Repeat" => iface_ref.get().await.repeat_changed(ctxt).await,
                "Shuffle" => iface_ref.get().await.shuffle_changed(ctxt).await,
                "Scan" => iface_ref.get().await.scan_changed(ctxt).await,
                _ => Ok(()),
            };
            if let Err(e) = result {
                error!("Failed to emit PropertyChanged({}) on {}: {}", prop, self.path, e);
            }
        }
    }

    /// Emit `PropertiesChanged` for specified properties on MediaFolder1.
    async fn emit_folder1_changed(&self, properties: &[&str]) {
        let conn = btd_get_dbus_connection();
        let iface_ref = match conn
            .object_server()
            .interface::<_, MediaFolder1Iface>(self.path.as_str())
            .await
        {
            Ok(r) => r,
            Err(_) => return,
        };

        let ctxt = iface_ref.signal_emitter();

        for prop in properties {
            let result = match *prop {
                "Name" => iface_ref.get().await.name_changed(ctxt).await,
                "NumberOfItems" => iface_ref.get().await.number_of_items_changed(ctxt).await,
                _ => Ok(()),
            };
            if let Err(e) = result {
                error!(
                    "Failed to emit PropertyChanged({}) on {} (Folder1): {}",
                    prop, self.path, e
                );
            }
        }
    }
}
