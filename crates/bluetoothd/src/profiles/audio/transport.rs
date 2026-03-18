// SPDX-License-Identifier: GPL-2.0-or-later
//! MediaTransport1 D-Bus interface implementation.
//!
//! Rust rewrite of `profiles/audio/transport.c`.  Implements the
//! `org.bluez.MediaTransport1` D-Bus objects with ownership model,
//! Acquire/TryAcquire/Release lifecycle, per-profile transport ops
//! (A2DP source/sink, BAP unicast/broadcast, ASHA), and state machine
//! management.

use std::any::Any;
use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

use bluez_shared::audio::asha::{AshaState, BtAsha};
use bluez_shared::audio::bap::{
    BapBcastQos, BapIoQos, BapQos, BapStreamState, BapUcastQos, BtBapStream, bt_bap_stream_statestr,
};
use bluez_shared::audio::bass::BASS_BCAST_CODE_SIZE;
use bluez_shared::socket::BluetoothSocket;
use bluez_shared::util::uuid::{A2DP_SINK_UUID, A2DP_SOURCE_UUID};

use crate::adapter::BtdAdapter;
use crate::dbus_common::{btd_get_dbus_connection, dict_append_entry};
use crate::device::BtdDevice;
use crate::error::{BtdError, ERROR_INTERFACE};
use crate::profiles::audio::a2dp::{
    A2dpSep, a2dp_avdtp_get, a2dp_cancel, a2dp_resume, a2dp_sep_lock, a2dp_sep_unlock, a2dp_suspend,
};
use crate::profiles::audio::avdtp::{
    AvdtpSession, AvdtpStream, avdtp_delay_report, avdtp_stream_has_delay_reporting,
    avdtp_unref_session,
};
use crate::profiles::audio::avrcp;
use crate::profiles::audio::media::{
    MediaEndpoint, media_endpoint_get_btd_adapter, media_endpoint_get_codec,
    media_endpoint_get_delay_reporting, media_endpoint_get_sep, media_endpoint_get_uuid,
    media_endpoint_is_broadcast,
};
use crate::profiles::audio::sink::{SinkState, sink_add_state_cb, sink_remove_state_cb};
use crate::profiles::audio::source::{SourceState, source_add_state_cb, source_remove_state_cb};
// VCP volume control is managed at a higher layer — the transport holds
// Arc<BtdDevice> while VCP requires Arc<tokio::sync::Mutex<BtdDevice>>
// for pointer-identity matching.  Volume integration is driven by
// media_transport_volume_changed callbacks instead of direct VCP calls.
#[allow(unused_imports)]
use crate::profiles::audio::vcp::{bt_audio_vcp_get_volume, bt_audio_vcp_set_volume};

// ===================================================================
// Constants
// ===================================================================

/// D-Bus interface name.
const MEDIA_TRANSPORT_INTERFACE: &str = "org.bluez.MediaTransport1";

// UUID constants (local copies — private in media.rs)
const PAC_SINK_UUID: &str = "00001850-0000-1000-8000-00805f9b34fb";
const PAC_SOURCE_UUID: &str = "00001851-0000-1000-8000-00805f9b34fb";
const BCAA_SERVICE_UUID: &str = "00001852-0000-1000-8000-00805f9b34fb";
const BAA_SERVICE_UUID: &str = "00001853-0000-1000-8000-00805f9b34fb";
const ASHA_PROFILE_UUID: &str = "0000FDF0-0000-1000-8000-00805f9b34fb";

/// Maximum broadcast code size used by BASS (16 bytes).
const MAX_BCAST_CODE_SIZE: usize = BASS_BCAST_CODE_SIZE;

// ===================================================================
// Globals
// ===================================================================

static TRANSPORTS: std::sync::LazyLock<std::sync::Mutex<Vec<Arc<Mutex<MediaTransport>>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

static TRANSPORT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ===================================================================
// TransportState
// ===================================================================

/// Transport states exposed via D-Bus ("idle" / "pending" / "active").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    Idle,
    Pending,
    Active,
}

impl TransportState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Pending => "pending",
            Self::Active => "active",
        }
    }

    pub fn in_use(&self) -> bool {
        matches!(self, Self::Pending | Self::Active)
    }
}

impl std::fmt::Display for TransportState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ===================================================================
// TransportOps — per-profile operations trait
// ===================================================================

/// Per-profile operations for media transports.
///
/// All mutating methods receive `&mut TransportInner` (the mutable
/// state) rather than `&mut MediaTransport`, so that the caller can
/// split the borrow between `ops` and `inner` fields.
pub trait TransportOps: Send + Sync {
    /// Resume (start streaming).
    fn resume(&self, inner: &mut TransportInner) -> Result<(), BtdError>;
    /// Suspend (stop streaming).
    fn suspend(&self, inner: &mut TransportInner) -> Result<(), BtdError>;
    /// Cancel pending operations.
    fn cancel(&self, inner: &mut TransportInner);
    /// Set volume level.
    fn set_volume(&self, inner: &mut TransportInner, volume: u8) -> Result<(), BtdError>;
    /// Get the underlying stream handle.
    fn get_stream(&self) -> Option<Arc<dyn Any + Send + Sync>>;
    /// Get the current volume from the profile layer.
    fn get_volume(&self, inner: &TransportInner) -> Option<u8>;
    /// Set delay reporting value.
    fn set_delay(&self, inner: &mut TransportInner, delay: u16) -> Result<(), BtdError>;
    /// Update linked transports (BAP).
    fn update_links(&self, inner: &mut TransportInner);
    /// Profile-specific initialisation.
    fn init(&mut self, inner: &mut TransportInner);
    /// Profile-specific teardown.
    fn destroy(&mut self, inner: &mut TransportInner);
    /// Inject an ASHA protocol engine into ASHA-type transport ops.
    /// Default implementation does nothing (non-ASHA transports).
    fn set_asha_engine(&self, _asha: BtAsha) {}
    /// Return the BAP stream associated with this transport, if any.
    /// Used by `update_links()` to match linked streams against transports.
    fn get_bap_stream(&self) -> Option<BtBapStream> {
        None
    }
}

// ===================================================================
// TransportOwner
// ===================================================================

pub(crate) struct TransportOwner {
    sender: String,
    #[allow(dead_code)]
    acquired: bool,
    pending_reply: Option<tokio::sync::oneshot::Sender<AcquireResult>>,
}

type AcquireResult = Result<(OwnedFd, u16, u16), BtdError>;

// ===================================================================
// TransportInner  — mutable state split from `ops`
// ===================================================================

/// All mutable transport state, separate from `ops` so that the borrow
/// checker allows `transport.ops.method(&mut transport.inner)`.
pub struct TransportInner {
    pub path: String,
    pub device: Arc<BtdDevice>,
    pub endpoint: Arc<std::sync::Mutex<MediaEndpoint>>,
    pub configuration: Vec<u8>,
    pub state: TransportState,
    pub volume: Option<i16>,
    pub delay: Option<u16>,
    pub(crate) owner: Option<TransportOwner>,
    pub fd: Option<OwnedFd>,
    pub read_mtu: u16,
    pub write_mtu: u16,
    pub links: Vec<Arc<Mutex<MediaTransport>>>,
    pub uuid: String,
    pub codec: u8,
    pub suspending: bool,
    pub broadcasting: bool,
    pub registered: bool,
    /// The adapter for this transport (tokio mutex, matching crate convention).
    pub adapter: Option<Arc<tokio::sync::Mutex<BtdAdapter>>>,
    /// Audio location bitmask (LE Audio).
    pub location: u32,
    /// LTV metadata blob (LE Audio).
    pub metadata: Vec<u8>,
}

// ===================================================================
// MediaTransport
// ===================================================================

/// A media transport D-Bus object (`org.bluez.MediaTransport1`).
pub struct MediaTransport {
    pub inner: TransportInner,
    ops: Box<dyn TransportOps>,
}

impl MediaTransport {
    // -- accessors -------------------------------------------------------

    pub fn path(&self) -> &str {
        &self.inner.path
    }
    pub fn device(&self) -> &Arc<BtdDevice> {
        &self.inner.device
    }
    pub fn endpoint(&self) -> &Arc<std::sync::Mutex<MediaEndpoint>> {
        &self.inner.endpoint
    }
    pub fn configuration(&self) -> &[u8] {
        &self.inner.configuration
    }
    pub fn state(&self) -> TransportState {
        self.inner.state
    }
    pub fn volume(&self) -> Option<i16> {
        self.inner.volume
    }
    pub fn delay(&self) -> Option<u16> {
        self.inner.delay
    }
    pub fn fd(&self) -> Option<RawFd> {
        self.inner.fd.as_ref().map(|f| f.as_raw_fd())
    }
    pub fn read_mtu(&self) -> u16 {
        self.inner.read_mtu
    }
    pub fn write_mtu(&self) -> u16 {
        self.inner.write_mtu
    }
    pub fn links(&self) -> &[Arc<Mutex<MediaTransport>>] {
        &self.inner.links
    }
}

// ===================================================================
// D-Bus interface  —  MediaTransport1
// ===================================================================

pub struct MediaTransport1 {
    transport: Arc<Mutex<MediaTransport>>,
}

impl MediaTransport1 {
    fn new(transport: Arc<Mutex<MediaTransport>>) -> Self {
        Self { transport }
    }
}

/// Safely duplicate an `OwnedFd` into a `zbus::zvariant::OwnedFd`.
fn clone_fd_for_dbus(fd: &OwnedFd) -> Result<zbus::zvariant::OwnedFd, BtdError> {
    let cloned = fd.try_clone().map_err(|e| BtdError::failed(&format!("fd clone: {e}")))?;
    Ok(zbus::zvariant::OwnedFd::from(cloned))
}

/// Build the `(fd, imtu, omtu)` reply for an already-active transport.
fn active_fd_reply(
    inner: &TransportInner,
) -> Result<(zbus::zvariant::OwnedFd, u16, u16), BtdError> {
    let fd = inner.fd.as_ref().ok_or_else(BtdError::not_available)?;
    let zfd = clone_fd_for_dbus(fd)?;
    Ok((zfd, inner.read_mtu, inner.write_mtu))
}

#[zbus::interface(name = "org.bluez.MediaTransport1")]
impl MediaTransport1 {
    // -- Methods ---------------------------------------------------------

    /// Acquire transport, resume the stream, return (fd, imtu, omtu).
    async fn acquire(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(zbus::zvariant::OwnedFd, u16, u16), BtdError> {
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();
        let mut guard = self.transport.lock().await;
        let t = &mut *guard;
        debug!("Acquire {} by {}", t.inner.path, sender);

        // Already owned by somebody else?
        if let Some(ref owner) = t.inner.owner {
            if owner.sender != sender {
                return Err(BtdError::not_authorized());
            }
            if t.inner.state == TransportState::Active {
                return active_fd_reply(&t.inner);
            }
            return Err(BtdError::in_progress());
        }

        // Set owner
        t.inner.owner =
            Some(TransportOwner { sender: sender.clone(), acquired: true, pending_reply: None });

        // Already active (e.g. TryAcquire succeeded earlier)
        if t.inner.state == TransportState::Active {
            return active_fd_reply(&t.inner);
        }

        // Resume the stream — ops borrows `t.ops`, inner borrows `t.inner`
        let resume_res = t.ops.resume(&mut t.inner);
        if let Err(e) = resume_res {
            t.inner.owner = None;
            return Err(e);
        }

        // If the fd appeared synchronously, we are done
        if t.inner.state == TransportState::Active {
            return active_fd_reply(&t.inner);
        }

        // Async path: set Pending, wait for fd delivery
        set_state(&mut t.inner, TransportState::Pending);
        let (tx, rx) = tokio::sync::oneshot::channel();
        if let Some(ref mut owner) = t.inner.owner {
            owner.pending_reply = Some(tx);
        }
        drop(guard);

        match rx.await {
            Ok(result) => result.map(|(fd, r, w)| (zbus::zvariant::OwnedFd::from(fd), r, w)),
            Err(_) => Err(BtdError::failed("Acquire cancelled")),
        }
    }

    /// TryAcquire — acquire only if the stream is already ready.
    async fn try_acquire(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(zbus::zvariant::OwnedFd, u16, u16), BtdError> {
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();
        let mut guard = self.transport.lock().await;
        let t = &mut *guard;
        debug!("TryAcquire {} by {}", t.inner.path, sender);

        match t.inner.state {
            TransportState::Active | TransportState::Pending => {
                if t.inner.fd.is_none() {
                    return Err(BtdError::not_available());
                }
                if let Some(ref owner) = t.inner.owner {
                    if owner.sender != sender {
                        return Err(BtdError::not_authorized());
                    }
                } else {
                    t.inner.owner =
                        Some(TransportOwner { sender, acquired: false, pending_reply: None });
                }
                active_fd_reply(&t.inner)
            }
            TransportState::Idle => Err(BtdError::not_available()),
        }
    }

    /// Release — suspend the stream and give up ownership.
    async fn release(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), BtdError> {
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();
        let mut guard = self.transport.lock().await;
        let t = &mut *guard;
        debug!("Release {} by {}", t.inner.path, sender);

        let owner_sender = t.inner.owner.as_ref().map(|o| o.sender.clone());
        match owner_sender {
            Some(ref s) if *s == sender => {}
            _ => return Err(BtdError::not_authorized()),
        }

        // Cancel any pending reply
        if let Some(ref mut owner) = t.inner.owner {
            if let Some(tx) = owner.pending_reply.take() {
                let _ = tx.send(Err(BtdError::failed("Released")));
            }
        }

        // Cancel + suspend (split borrow: ops vs inner)
        t.ops.cancel(&mut t.inner);
        let _ = t.ops.suspend(&mut t.inner);

        // Save linked transports for release outside lock
        let linked = t.inner.links.clone();

        // Clear own state
        t.inner.fd = None;
        t.inner.owner = None;
        t.inner.suspending = true;
        set_state(&mut t.inner, TransportState::Idle);
        t.inner.suspending = false;
        drop(guard);

        // Release linked transports — each lock is independent
        for link in &linked {
            let mut lg = link.lock().await;
            let lt = &mut *lg;
            lt.inner.owner = None;
            lt.ops.cancel(&mut lt.inner);
            let _ = lt.ops.suspend(&mut lt.inner);
            lt.inner.fd = None;
            set_state(&mut lt.inner, TransportState::Idle);
        }
        Ok(())
    }

    /// Select this transport for streaming.
    ///
    /// Selects this transport as the preferred endpoint for the associated
    /// device.  Only applicable when multiple transports share the same
    /// endpoint.  Returns `NotSupported` if the profile layer does not
    /// support selection.
    async fn select(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
    ) -> Result<(), BtdError> {
        let guard = self.transport.lock().await;
        debug!("Select {}", guard.inner.path);
        // Selection is profile-specific; the default response is
        // NotSupported, matching the C implementation for non-BAP
        // transports.
        Err(BtdError::not_supported())
    }

    /// Unselect (deselect) this transport.
    ///
    /// Reverts a previous `Select()` call.  Returns `NotSupported` if the
    /// profile layer does not support selection.
    async fn unselect(
        &self,
        #[zbus(header)] _header: zbus::message::Header<'_>,
    ) -> Result<(), BtdError> {
        let guard = self.transport.lock().await;
        debug!("Unselect {}", guard.inner.path);
        Err(BtdError::not_supported())
    }

    // -- Properties ------------------------------------------------------

    #[zbus(property)]
    async fn device(&self) -> String {
        self.transport.lock().await.inner.device.get_path().to_owned()
    }

    #[zbus(property, name = "UUID")]
    async fn uuid(&self) -> String {
        self.transport.lock().await.inner.uuid.clone()
    }

    #[zbus(property)]
    async fn codec(&self) -> u8 {
        self.transport.lock().await.inner.codec
    }

    #[zbus(property)]
    async fn configuration(&self) -> Vec<u8> {
        self.transport.lock().await.inner.configuration.clone()
    }

    #[zbus(property)]
    async fn state(&self) -> String {
        self.transport.lock().await.inner.state.as_str().to_owned()
    }

    #[zbus(property)]
    async fn delay(&self) -> u16 {
        self.transport.lock().await.inner.delay.unwrap_or(0)
    }

    #[zbus(property)]
    async fn set_delay(&self, value: u16) -> Result<(), zbus::Error> {
        let mut g = self.transport.lock().await;
        let t = &mut *g;
        t.ops.set_delay(&mut t.inner, value).map_err(zbus::Error::from)
    }

    /// Audio location bitmask (LE Audio transports).
    #[zbus(property)]
    async fn location(&self) -> u32 {
        self.transport.lock().await.inner.location
    }

    /// LTV metadata blob (LE Audio transports).
    #[zbus(property, name = "Metadata")]
    async fn metadata(&self) -> Vec<u8> {
        self.transport.lock().await.inner.metadata.clone()
    }

    #[zbus(property)]
    async fn volume(&self) -> u16 {
        let g = self.transport.lock().await;
        if let Some(v) = g.ops.get_volume(&g.inner) {
            return u16::from(v);
        }
        g.inner.volume.map(|v| v.max(0) as u16).unwrap_or(0)
    }

    #[zbus(property)]
    async fn set_volume(&self, value: u16) -> Result<(), zbus::Error> {
        let mut g = self.transport.lock().await;
        let vol = value.min(127) as u8;
        let t = &mut *g;
        t.ops.set_volume(&mut t.inner, vol).map_err(zbus::Error::from)
    }

    #[zbus(property)]
    async fn endpoint(&self) -> String {
        let g = self.transport.lock().await;
        let ep = g.inner.endpoint.lock().unwrap_or_else(|p| p.into_inner());
        ep.path().to_owned()
    }
}

// ===================================================================
// Internal helpers
// ===================================================================

/// Transition state and log.
fn set_state(inner: &mut TransportInner, new: TransportState) {
    let old = inner.state;
    if old == new {
        return;
    }
    debug!("{} state {} -> {}", inner.path, old, new);
    inner.state = new;
    if new == TransportState::Idle && !inner.suspending {
        inner.fd = None;
    }
}

/// Deliver fd to a pending Acquire caller.
fn complete_pending_acquire(inner: &mut TransportInner) {
    let tx = inner.owner.as_mut().and_then(|o| o.pending_reply.take());
    if let Some(tx) = tx {
        match inner.fd.as_ref().and_then(|f| f.try_clone().ok()) {
            Some(dup) => {
                let _ = tx.send(Ok((dup, inner.read_mtu, inner.write_mtu)));
            }
            None => {
                let _ = tx.send(Err(BtdError::not_available()));
            }
        }
    }
}

/// Extract (fd, imtu, omtu) from a `BluetoothSocket` reference.
/// Used when converting a `BluetoothSocket` from `avdtp_stream_get_transport()`
/// to the raw values needed for Acquire/TryAcquire D-Bus replies.
#[allow(dead_code)]
pub(crate) fn socket_transport_info(sock: &BluetoothSocket) -> (RawFd, u16, u16) {
    let (imtu, omtu) = sock.mtu().unwrap_or((672, 672));
    (sock.as_raw_fd(), imtu, omtu)
}

/// Check delay reporting on an `AvdtpStream`.
/// Used by A2DP transport initialization to determine whether to expose
/// the Delay D-Bus property.
#[allow(dead_code)]
pub(crate) fn a2dp_check_delay_reporting(stream: &AvdtpStream) -> bool {
    avdtp_stream_has_delay_reporting(stream)
}

// ===================================================================
// A2DP Transport Ops
// ===================================================================

struct A2dpData {
    sep: Option<Arc<tokio::sync::Mutex<A2dpSep>>>,
    session: Option<Arc<tokio::sync::Mutex<AvdtpSession>>>,
    volume: i16,
    sink_cb_id: Option<u32>,
    source_cb_id: Option<u32>,
}

// ---- A2DP Source (we produce audio, remote is sink) --------------------

struct A2dpSourceOps {
    data: std::sync::Mutex<A2dpData>,
}

impl TransportOps for A2dpSourceOps {
    fn resume(&self, _inner: &mut TransportInner) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        let sep = d.sep.as_ref().ok_or_else(BtdError::not_available)?;
        let sep_c = Arc::clone(sep);
        tokio::spawn(async move {
            a2dp_sep_lock(&sep_c).await;
            if let Err(e) = a2dp_resume(&sep_c).await {
                error!("a2dp_source resume: {:?}", e);
            }
        });
        Ok(())
    }

    fn suspend(&self, _inner: &mut TransportInner) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        if let Some(ref sep) = d.sep {
            let c = Arc::clone(sep);
            tokio::spawn(async move {
                if let Err(e) = a2dp_suspend(&c).await {
                    error!("a2dp_source suspend: {:?}", e);
                }
                a2dp_sep_unlock(&c).await;
            });
        }
        Ok(())
    }

    fn cancel(&self, inner: &mut TransportInner) {
        let dev = Arc::clone(&inner.device);
        tokio::spawn(async move {
            a2dp_cancel(&dev).await;
        });
    }

    fn set_volume(&self, inner: &mut TransportInner, volume: u8) -> Result<(), BtdError> {
        let mut d = self.data.lock().unwrap();
        let old = d.volume;
        d.volume = i16::from(volume);
        inner.volume = Some(i16::from(volume));
        if old != i16::from(volume) {
            let dev = Arc::clone(&inner.device);
            tokio::spawn(async move {
                avrcp::avrcp_set_volume(&dev, volume).await;
            });
        }
        Ok(())
    }

    fn get_stream(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        let d = self.data.lock().unwrap();
        d.sep.as_ref().map(|s| Arc::clone(s) as Arc<dyn Any + Send + Sync>)
    }

    fn get_volume(&self, _inner: &TransportInner) -> Option<u8> {
        let d = self.data.lock().unwrap();
        if d.volume < 0 { None } else { Some(d.volume as u8) }
    }

    fn set_delay(&self, _inner: &mut TransportInner, _delay: u16) -> Result<(), BtdError> {
        // A2DP source does not set delay (remote does via AVDTP)
        Err(BtdError::not_supported())
    }

    fn update_links(&self, _inner: &mut TransportInner) {}

    fn init(&mut self, inner: &mut TransportInner) {
        let mut d = self.data.lock().unwrap();
        d.volume = -1;
        inner.volume = Some(-1);

        // Get AVDTP session via a2dp helper
        let dev = Arc::clone(&inner.device);
        tokio::spawn(async move {
            match a2dp_avdtp_get(&dev).await {
                Ok(sess) => {
                    debug!("A2DP source: obtained AVDTP session");
                    drop(sess);
                }
                Err(e) => {
                    debug!("A2DP source: no session yet: {:?}", e);
                }
            }
        });

        // Watch remote sink state
        let tpath = inner.path.clone();
        let dpath = inner.device.get_path().to_owned();
        let cb = Box::new(move |new: SinkState, _old: SinkState| {
            debug!("{}: sink -> {:?}", tpath, new);
        });
        d.sink_cb_id = Some(sink_add_state_cb(&dpath, cb));
    }

    fn destroy(&mut self, _inner: &mut TransportInner) {
        let mut d = self.data.lock().unwrap();
        if let Some(id) = d.sink_cb_id.take() {
            sink_remove_state_cb(id);
        }
        d.sep = None;
        if let Some(session) = d.session.take() {
            tokio::spawn(async move {
                avdtp_unref_session(session).await;
            });
        }
    }
}

// ---- A2DP Sink (we consume audio, remote is source) --------------------

struct A2dpSinkOps {
    data: std::sync::Mutex<A2dpData>,
}

impl TransportOps for A2dpSinkOps {
    fn resume(&self, _inner: &mut TransportInner) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        let sep = d.sep.as_ref().ok_or_else(BtdError::not_available)?;
        let c = Arc::clone(sep);
        tokio::spawn(async move {
            a2dp_sep_lock(&c).await;
            if let Err(e) = a2dp_resume(&c).await {
                error!("a2dp_sink resume: {:?}", e);
            }
        });
        Ok(())
    }

    fn suspend(&self, _inner: &mut TransportInner) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        if let Some(ref sep) = d.sep {
            let c = Arc::clone(sep);
            tokio::spawn(async move {
                if let Err(e) = a2dp_suspend(&c).await {
                    error!("a2dp_sink suspend: {:?}", e);
                }
                a2dp_sep_unlock(&c).await;
            });
        }
        Ok(())
    }

    fn cancel(&self, inner: &mut TransportInner) {
        let dev = Arc::clone(&inner.device);
        tokio::spawn(async move {
            a2dp_cancel(&dev).await;
        });
    }

    fn set_volume(&self, inner: &mut TransportInner, volume: u8) -> Result<(), BtdError> {
        let mut d = self.data.lock().unwrap();
        let old = d.volume;
        d.volume = i16::from(volume);
        inner.volume = Some(i16::from(volume));
        if old != i16::from(volume) {
            let dev = Arc::clone(&inner.device);
            tokio::spawn(async move {
                avrcp::avrcp_set_volume(&dev, volume).await;
            });
        }
        Ok(())
    }

    fn get_stream(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        let d = self.data.lock().unwrap();
        d.sep.as_ref().map(|s| Arc::clone(s) as Arc<dyn Any + Send + Sync>)
    }

    fn get_volume(&self, _inner: &TransportInner) -> Option<u8> {
        let d = self.data.lock().unwrap();
        if d.volume < 0 { None } else { Some(d.volume as u8) }
    }

    fn set_delay(&self, inner: &mut TransportInner, delay: u16) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        let session = d.session.as_ref().ok_or_else(BtdError::not_available)?;
        if inner.delay.is_none() {
            return Err(BtdError::not_supported());
        }
        inner.delay = Some(delay);
        let sc = Arc::clone(session);
        tokio::spawn(async move {
            let mut s = sc.lock().await;
            let _ = avdtp_delay_report(&mut s, 0, delay);
        });
        Ok(())
    }

    fn update_links(&self, _inner: &mut TransportInner) {}

    fn init(&mut self, inner: &mut TransportInner) {
        let mut d = self.data.lock().unwrap();
        d.volume = 127;
        inner.volume = Some(127);

        // Get AVDTP session for delay reporting
        let dev = Arc::clone(&inner.device);
        tokio::spawn(async move {
            match a2dp_avdtp_get(&dev).await {
                Ok(sess) => {
                    debug!("A2DP sink: obtained AVDTP session");
                    drop(sess);
                }
                Err(e) => {
                    debug!("A2DP sink: no session yet: {:?}", e);
                }
            }
        });

        // Watch remote source state
        let tpath = inner.path.clone();
        let dpath = inner.device.get_path().to_owned();
        let cb = Box::new(move |new: SourceState, _old: SourceState| {
            debug!("{}: source -> {:?}", tpath, new);
        });
        d.source_cb_id = Some(source_add_state_cb(&dpath, cb));
    }

    fn destroy(&mut self, _inner: &mut TransportInner) {
        let mut d = self.data.lock().unwrap();
        if let Some(id) = d.source_cb_id.take() {
            source_remove_state_cb(id);
        }
        d.sep = None;
        if let Some(session) = d.session.take() {
            tokio::spawn(async move {
                avdtp_unref_session(session).await;
            });
        }
    }
}

// ===================================================================
// BAP Transport Ops
// ===================================================================

struct BapData {
    stream: Option<BtBapStream>,
    #[allow(dead_code)]
    state_cb_id: Option<u32>,
    #[allow(dead_code)]
    bcast_code: [u8; MAX_BCAST_CODE_SIZE],
}

// ---- BAP Unicast -------------------------------------------------------

struct BapUnicastOps {
    data: std::sync::Mutex<BapData>,
}

impl TransportOps for BapUnicastOps {
    fn resume(&self, inner: &mut TransportInner) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        let stream = d.stream.as_ref().ok_or_else(BtdError::not_available)?;
        let st = stream.get_state();
        match st {
            BapStreamState::Enabling | BapStreamState::Streaming => Ok(()),
            BapStreamState::Qos => {
                let md = stream.get_metadata();
                stream.enable(true, &md, None);
                Ok(())
            }
            _ => {
                warn!(
                    "{}: BAP cannot resume from {}",
                    inner.path,
                    bt_bap_stream_statestr(st as u8)
                );
                Err(BtdError::not_available())
            }
        }
    }

    fn suspend(&self, _inner: &mut TransportInner) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        if let Some(ref s) = d.stream {
            let st = s.get_state();
            if matches!(st, BapStreamState::Enabling | BapStreamState::Streaming) {
                s.disable(true, None);
            }
        }
        Ok(())
    }

    fn cancel(&self, _inner: &mut TransportInner) {
        let d = self.data.lock().unwrap();
        if let Some(ref s) = d.stream {
            s.cancel(0);
        }
    }

    fn set_volume(&self, inner: &mut TransportInner, volume: u8) -> Result<(), BtdError> {
        // BAP unicast: VCP volume is managed via bt_audio_vcp_set_volume,
        // which requires Arc<tokio::sync::Mutex<BtdDevice>>.  We hold
        // Arc<BtdDevice> (no tokio mutex wrapper) so we cannot directly
        // call VCP functions from the transport.  Volume is stored locally
        // and VCP integration is handled at a higher layer (media.rs /
        // device volume changed callbacks).
        inner.volume = Some(i16::from(volume));
        debug!("{}: BAP unicast volume set to {}", inner.path, volume);
        Ok(())
    }

    fn get_stream(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        let d = self.data.lock().unwrap();
        d.stream.as_ref().map(|s| Arc::new(s.clone()) as Arc<dyn Any + Send + Sync>)
    }

    fn get_volume(&self, inner: &TransportInner) -> Option<u8> {
        inner.volume.and_then(|v| if v >= 0 { Some(v as u8) } else { None })
    }

    fn set_delay(&self, inner: &mut TransportInner, delay: u16) -> Result<(), BtdError> {
        inner.delay = Some(delay);
        Ok(())
    }

    fn update_links(&self, inner: &mut TransportInner) {
        let d = self.data.lock().unwrap();
        if let Some(ref stream) = d.stream {
            let linked = stream.io_get_links();
            if linked.is_empty() {
                inner.links.clear();
                return;
            }
            // Resolve links against the global transport list — only include
            // transports whose BAP stream matches one of the linked streams.
            let globals = TRANSPORTS.lock().unwrap();
            let mut new_links = Vec::new();
            for trc in globals.iter() {
                if let Ok(tg) = trc.try_lock() {
                    if tg.inner.path != inner.path {
                        if let Some(ref other_stream) = tg.ops.get_bap_stream() {
                            if linked.iter().any(|ls| ls.same_stream(other_stream)) {
                                new_links.push(Arc::clone(trc));
                            }
                        }
                    }
                }
            }
            inner.links = new_links;
        }
    }

    fn init(&mut self, inner: &mut TransportInner) {
        debug!("{}: BAP unicast init", inner.path);
    }

    fn destroy(&mut self, inner: &mut TransportInner) {
        let mut d = self.data.lock().unwrap();
        d.stream = None;
        d.state_cb_id = None;
        debug!("{}: BAP unicast destroyed", inner.path);
    }

    fn get_bap_stream(&self) -> Option<BtBapStream> {
        let d = self.data.lock().ok()?;
        d.stream.clone()
    }
}

// ---- BAP Broadcast -----------------------------------------------------

struct BapBroadcastOps {
    data: std::sync::Mutex<BapData>,
}

impl TransportOps for BapBroadcastOps {
    fn resume(&self, inner: &mut TransportInner) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        let stream = d.stream.as_ref().ok_or_else(BtdError::not_available)?;
        let st = stream.get_state();
        match st {
            BapStreamState::Enabling | BapStreamState::Streaming => Ok(()),
            BapStreamState::Qos => {
                let md = stream.get_metadata();
                stream.enable(true, &md, None);
                inner.broadcasting = true;
                Ok(())
            }
            _ => {
                warn!(
                    "{}: BAP bcast cannot resume from {}",
                    inner.path,
                    bt_bap_stream_statestr(st as u8)
                );
                Err(BtdError::not_available())
            }
        }
    }

    fn suspend(&self, inner: &mut TransportInner) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        if let Some(ref s) = d.stream {
            s.disable(true, None);
        }
        inner.broadcasting = false;
        Ok(())
    }

    fn cancel(&self, inner: &mut TransportInner) {
        let d = self.data.lock().unwrap();
        if let Some(ref s) = d.stream {
            s.cancel(0);
        }
        inner.broadcasting = false;
    }

    fn set_volume(&self, inner: &mut TransportInner, volume: u8) -> Result<(), BtdError> {
        inner.volume = Some(i16::from(volume));
        Ok(())
    }

    fn get_stream(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        let d = self.data.lock().unwrap();
        d.stream.as_ref().map(|s| Arc::new(s.clone()) as Arc<dyn Any + Send + Sync>)
    }

    fn get_volume(&self, inner: &TransportInner) -> Option<u8> {
        inner.volume.and_then(|v| if v >= 0 { Some(v as u8) } else { None })
    }

    fn set_delay(&self, inner: &mut TransportInner, delay: u16) -> Result<(), BtdError> {
        inner.delay = Some(delay);
        Ok(())
    }

    fn update_links(&self, inner: &mut TransportInner) {
        let d = self.data.lock().unwrap();
        if let Some(ref stream) = d.stream {
            let linked = stream.io_get_links();
            if linked.is_empty() {
                inner.links.clear();
                return;
            }
            // Only include transports whose BAP stream matches a linked
            // stream — prevents adding all unrelated transports as links.
            let globals = TRANSPORTS.lock().unwrap();
            let mut new_links = Vec::new();
            for trc in globals.iter() {
                if let Ok(tg) = trc.try_lock() {
                    if tg.inner.path != inner.path {
                        if let Some(ref other_stream) = tg.ops.get_bap_stream() {
                            if linked.iter().any(|ls| ls.same_stream(other_stream)) {
                                new_links.push(Arc::clone(trc));
                            }
                        }
                    }
                }
            }
            inner.links = new_links;
        }
    }

    fn init(&mut self, inner: &mut TransportInner) {
        inner.broadcasting = false;
        debug!("{}: BAP broadcast init", inner.path);
    }

    fn destroy(&mut self, inner: &mut TransportInner) {
        let mut d = self.data.lock().unwrap();
        d.stream = None;
        d.state_cb_id = None;
        inner.broadcasting = false;
        debug!("{}: BAP broadcast destroyed", inner.path);
    }

    fn get_bap_stream(&self) -> Option<BtBapStream> {
        let d = self.data.lock().ok()?;
        d.stream.clone()
    }
}

// ===================================================================
// ASHA Transport Ops
// ===================================================================

struct AshaData {
    asha: Option<BtAsha>,
}

struct AshaOps {
    data: std::sync::Mutex<AshaData>,
}

/// Map `AshaState` to `TransportState`.
fn asha_to_transport_state(asha: AshaState) -> TransportState {
    match asha {
        AshaState::Stopped => TransportState::Idle,
        AshaState::Starting => TransportState::Pending,
        AshaState::Started => TransportState::Active,
    }
}

impl TransportOps for AshaOps {
    fn resume(&self, inner: &mut TransportInner) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        let asha = d.asha.as_ref().ok_or_else(BtdError::not_available)?;
        let st = asha.state();
        debug!(
            "{}: ASHA resume (asha_state={:?}, transport_state={})",
            inner.path,
            st,
            asha_to_transport_state(st)
        );
        asha.start().map_err(|e| BtdError::failed(&format!("ASHA start: {e}")))
    }

    fn suspend(&self, _inner: &mut TransportInner) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        if let Some(ref asha) = d.asha {
            asha.stop().map_err(|e| BtdError::failed(&format!("ASHA stop: {e}")))?;
        }
        Ok(())
    }

    fn cancel(&self, _inner: &mut TransportInner) {
        let d = self.data.lock().unwrap();
        if let Some(ref asha) = d.asha {
            let _ = asha.stop();
        }
    }

    fn set_volume(&self, inner: &mut TransportInner, volume: u8) -> Result<(), BtdError> {
        let d = self.data.lock().unwrap();
        let asha = d.asha.as_ref().ok_or_else(BtdError::not_available)?;
        // Convert 0..127 → -128..0  (ASHA range is -128..0)
        let asha_vol = (volume as i8).wrapping_sub(127);
        asha.set_volume(asha_vol);
        inner.volume = Some(i16::from(volume));
        Ok(())
    }

    fn get_stream(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        let d = self.data.lock().unwrap();
        d.asha.as_ref().map(|a| Arc::new(a.clone()) as Arc<dyn Any + Send + Sync>)
    }

    fn get_volume(&self, _inner: &TransportInner) -> Option<u8> {
        let d = self.data.lock().unwrap();
        d.asha.as_ref().map(|a| {
            let v = a.volume();
            (i16::from(v) + 128).clamp(0, 127) as u8
        })
    }

    fn set_delay(&self, inner: &mut TransportInner, delay: u16) -> Result<(), BtdError> {
        inner.delay = Some(delay);
        Ok(())
    }

    fn update_links(&self, _inner: &mut TransportInner) {}

    fn init(&mut self, inner: &mut TransportInner) {
        let d = self.data.lock().unwrap();
        if let Some(ref asha) = d.asha {
            inner.delay = Some(asha.render_delay().saturating_mul(10));
            let v = asha.volume();
            inner.volume = Some((i16::from(v) + 128).clamp(0, 127));
        }
        debug!("{}: ASHA init", inner.path);
    }

    fn destroy(&mut self, _inner: &mut TransportInner) {
        let mut d = self.data.lock().unwrap();
        d.asha = None;
    }

    fn set_asha_engine(&self, asha: BtAsha) {
        let mut d = self.data.lock().unwrap();
        d.asha = Some(asha);
    }
}

// ===================================================================
// Ops factory
// ===================================================================

fn find_ops(uuid: &str, ep: &MediaEndpoint) -> Option<Box<dyn TransportOps>> {
    let u = uuid.to_lowercase();
    let src_uuid = A2DP_SOURCE_UUID.to_lowercase();
    let snk_uuid = A2DP_SINK_UUID.to_lowercase();
    let pac_snk = PAC_SINK_UUID.to_lowercase();
    let pac_src = PAC_SOURCE_UUID.to_lowercase();
    let bcaa = BCAA_SERVICE_UUID.to_lowercase();
    let baa = BAA_SERVICE_UUID.to_lowercase();
    let asha = ASHA_PROFILE_UUID.to_lowercase();

    let empty_bcast_code = [0u8; MAX_BCAST_CODE_SIZE];

    if u == src_uuid {
        Some(Box::new(A2dpSourceOps {
            data: std::sync::Mutex::new(A2dpData {
                sep: media_endpoint_get_sep(ep).cloned(),
                session: None,
                volume: -1,
                sink_cb_id: None,
                source_cb_id: None,
            }),
        }))
    } else if u == snk_uuid {
        Some(Box::new(A2dpSinkOps {
            data: std::sync::Mutex::new(A2dpData {
                sep: media_endpoint_get_sep(ep).cloned(),
                session: None,
                volume: 127,
                sink_cb_id: None,
                source_cb_id: None,
            }),
        }))
    } else if u == pac_snk || u == pac_src {
        Some(Box::new(BapUnicastOps {
            data: std::sync::Mutex::new(BapData {
                stream: None,
                state_cb_id: None,
                bcast_code: empty_bcast_code,
            }),
        }))
    } else if u == bcaa || u == baa {
        if media_endpoint_is_broadcast(ep) {
            Some(Box::new(BapBroadcastOps {
                data: std::sync::Mutex::new(BapData {
                    stream: None,
                    state_cb_id: None,
                    bcast_code: empty_bcast_code,
                }),
            }))
        } else {
            Some(Box::new(BapUnicastOps {
                data: std::sync::Mutex::new(BapData {
                    stream: None,
                    state_cb_id: None,
                    bcast_code: empty_bcast_code,
                }),
            }))
        }
    } else if u == asha {
        Some(Box::new(AshaOps { data: std::sync::Mutex::new(AshaData { asha: None }) }))
    } else {
        warn!("No transport ops for UUID {uuid}");
        None
    }
}

// ===================================================================
// Transport QoS D-Bus properties helper
// ===================================================================

/// Append BAP QoS data to a property dictionary.
fn append_bap_qos(d: &mut HashMap<String, OwnedValue>, stream: &BtBapStream) {
    let qos = stream.get_qos();
    match qos {
        BapQos::Ucast(ref uqos) => {
            dict_append_entry(d, "StreamType", Value::from("unicast"));
            append_ucast_qos(d, uqos);
        }
        BapQos::Bcast(ref bqos) => {
            dict_append_entry(d, "StreamType", Value::from("broadcast"));
            append_bcast_qos(d, bqos);
        }
    }
}

fn append_ucast_qos(d: &mut HashMap<String, OwnedValue>, q: &BapUcastQos) {
    dict_append_entry(d, "CIG", Value::from(q.cig_id));
    dict_append_entry(d, "CIS", Value::from(q.cis_id));
    append_io_qos(d, &q.io_qos);
}

fn append_bcast_qos(d: &mut HashMap<String, OwnedValue>, q: &BapBcastQos) {
    dict_append_entry(d, "BIG", Value::from(q.big));
    dict_append_entry(d, "BIS", Value::from(q.bis));
    append_io_qos(d, &q.io_qos);
}

fn append_io_qos(d: &mut HashMap<String, OwnedValue>, q: &BapIoQos) {
    dict_append_entry(d, "Interval", Value::from(q.interval));
    dict_append_entry(d, "Latency", Value::from(q.latency));
    dict_append_entry(d, "SDU", Value::from(q.sdu));
    dict_append_entry(d, "PHY", Value::from(q.phys));
    dict_append_entry(d, "Retransmissions", Value::from(q.rtn));
}

// ===================================================================
// Public API
// ===================================================================

/// Create a new media transport for the given device and endpoint.
pub async fn media_transport_create(
    device: Arc<BtdDevice>,
    endpoint: Arc<std::sync::Mutex<MediaEndpoint>>,
    configuration: Vec<u8>,
    _stream: Option<Box<dyn Any + Send + Sync>>,
) -> Option<Arc<Mutex<MediaTransport>>> {
    let (uuid, codec, adapter_arc) = {
        let ep = endpoint.lock().unwrap();
        (
            media_endpoint_get_uuid(&ep).to_owned(),
            media_endpoint_get_codec(&ep),
            media_endpoint_get_btd_adapter(&ep).clone(),
        )
    };

    let mut ops = {
        let ep = endpoint.lock().unwrap();
        find_ops(&uuid, &ep)
    }?;

    let n = TRANSPORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = format!("{}/fd{}", device.get_path(), n);

    let delay = {
        let ep = endpoint.lock().unwrap();
        if media_endpoint_get_delay_reporting(&ep) { Some(0u16) } else { None }
    };

    let mut inner = TransportInner {
        path: path.clone(),
        device: Arc::clone(&device),
        endpoint: Arc::clone(&endpoint),
        configuration,
        state: TransportState::Idle,
        volume: None,
        delay,
        owner: None,
        fd: None,
        read_mtu: 0,
        write_mtu: 0,
        links: Vec::new(),
        uuid: uuid.clone(),
        codec,
        suspending: false,
        broadcasting: false,
        registered: false,
        adapter: Some(adapter_arc),
        location: 0,
        metadata: Vec::new(),
    };

    ops.init(&mut inner);

    let transport = MediaTransport { inner, ops };
    let arc = Arc::new(Mutex::new(transport));

    // Register D-Bus interface
    let conn = btd_get_dbus_connection().clone();
    let iface = MediaTransport1::new(Arc::clone(&arc));
    match conn.object_server().at(&*path, iface).await {
        Ok(_) => {
            arc.lock().await.inner.registered = true;
            debug!("Registered {MEDIA_TRANSPORT_INTERFACE} at {path}");
        }
        Err(e) => {
            error!("Register {} {}: {}", MEDIA_TRANSPORT_INTERFACE, path, e);
            return None;
        }
    }

    TRANSPORTS.lock().unwrap().push(Arc::clone(&arc));
    info!("Created transport {path} UUID {uuid}");
    Some(arc)
}

/// Destroy a media transport.
pub async fn media_transport_destroy(transport: Arc<Mutex<MediaTransport>>) {
    let path = {
        let mut g = transport.lock().await;
        // Force-cancel pending acquire
        if let Some(ref mut owner) = g.inner.owner {
            if let Some(tx) = owner.pending_reply.take() {
                let _ = tx.send(Err(BtdError::failed("Destroyed")));
            }
        }
        g.inner.owner = None;
        let t = &mut *g;
        t.ops.destroy(&mut t.inner);
        t.inner.fd = None;
        t.inner.links.clear();
        t.inner.state = TransportState::Idle;
        t.inner.path.clone()
    };

    let conn = btd_get_dbus_connection().clone();
    let _ = conn.object_server().remove::<MediaTransport1, _>(&*path).await;

    TRANSPORTS.lock().unwrap().retain(|t| t.try_lock().map_or(true, |g| g.inner.path != path));
    info!("Destroyed transport {path}");
}

/// Get the D-Bus path.
pub async fn media_transport_get_path(transport: &Arc<Mutex<MediaTransport>>) -> String {
    transport.lock().await.inner.path.clone()
}

/// Get the underlying stream handle from the transport's ops.
pub async fn media_transport_get_stream(
    transport: &Arc<Mutex<MediaTransport>>,
) -> Option<Arc<dyn Any + Send + Sync>> {
    transport.lock().await.ops.get_stream()
}

/// Get the device associated with a transport.
pub async fn media_transport_get_dev(transport: &Arc<Mutex<MediaTransport>>) -> Arc<BtdDevice> {
    Arc::clone(&transport.lock().await.inner.device)
}

/// Update delay reporting value.
pub async fn media_transport_update_delay(transport: &Arc<Mutex<MediaTransport>>, delay: u16) {
    let mut g = transport.lock().await;
    let old = g.inner.delay;
    g.inner.delay = Some(delay);
    if old != Some(delay) {
        debug!("{} delay {:?} -> {}", g.inner.path, old, delay);
    }
}

/// Update volume on a specific transport.
pub async fn media_transport_update_volume(transport: &Arc<Mutex<MediaTransport>>, volume: u8) {
    let mut g = transport.lock().await;
    let old = g.inner.volume;
    g.inner.volume = Some(i16::from(volume));
    if old != Some(i16::from(volume)) {
        debug!("{} vol {:?} -> {}", g.inner.path, old, volume);
    }
}

/// Notify all transports for a device that volume changed.
pub fn media_transport_volume_changed(device: &Arc<BtdDevice>) {
    let dpath = device.get_path().to_owned();
    let list = TRANSPORTS.lock().unwrap();
    for t in list.iter() {
        if let Ok(g) = t.try_lock() {
            if g.inner.device.get_path() == dpath {
                debug!("Volume changed on {} for {}", g.inner.path, dpath);
            }
        }
    }
}

/// Get the A2DP volume for a device from its transports.
pub fn media_transport_get_a2dp_volume(device: &BtdDevice) -> i8 {
    let dpath = device.get_path();
    let list = TRANSPORTS.lock().unwrap();
    for t in list.iter() {
        if let Ok(g) = t.try_lock() {
            if g.inner.device.get_path() != dpath {
                continue;
            }
            let uu = g.inner.uuid.to_lowercase();
            if uu == A2DP_SOURCE_UUID.to_lowercase() || uu == A2DP_SINK_UUID.to_lowercase() {
                if let Some(v) = g.ops.get_volume(&g.inner) {
                    return v as i8;
                }
            }
        }
    }
    device.get_volume().unwrap_or(-1)
}

/// Set the A2DP volume on all A2DP transports for a device.
pub fn media_transport_set_a2dp_volume(device: &mut BtdDevice, volume: u8) {
    let dpath = device.get_path().to_owned();
    let list = TRANSPORTS.lock().unwrap();
    for t in list.iter() {
        if let Ok(mut g) = t.try_lock() {
            if g.inner.device.get_path() != dpath {
                continue;
            }
            let uu = g.inner.uuid.to_lowercase();
            if uu == A2DP_SOURCE_UUID.to_lowercase() || uu == A2DP_SINK_UUID.to_lowercase() {
                g.inner.volume = Some(i16::from(volume));
                debug!("Set A2DP vol {} on {}", volume, g.inner.path);
            }
        }
    }
    device.set_volume(volume as i8);
}

/// Get all transport properties as a D-Bus dictionary.
pub async fn transport_get_properties(
    transport: &Arc<Mutex<MediaTransport>>,
) -> HashMap<String, OwnedValue> {
    let g = transport.lock().await;
    let mut d = HashMap::new();

    if let Ok(p) = ObjectPath::try_from(g.inner.device.get_path().to_owned()) {
        dict_append_entry(&mut d, "Device", Value::from(p));
    }
    dict_append_entry(&mut d, "UUID", Value::from(g.inner.uuid.clone()));
    dict_append_entry(&mut d, "Codec", Value::from(g.inner.codec));
    dict_append_entry(&mut d, "Configuration", Value::from(g.inner.configuration.clone()));
    dict_append_entry(&mut d, "State", Value::from(g.inner.state.as_str()));

    if let Some(delay) = g.inner.delay {
        dict_append_entry(&mut d, "Delay", Value::from(delay));
    }
    if let Some(vol) = g.inner.volume {
        if vol >= 0 {
            dict_append_entry(&mut d, "Volume", Value::from(vol as u16));
        }
    }
    // Endpoint path (uses accessor method)
    {
        let ep = g.inner.endpoint.lock().unwrap_or_else(|p| p.into_inner());
        let ep_path = ep.path().to_owned();
        if !ep_path.is_empty() {
            if let Ok(op) = ObjectPath::try_from(ep_path) {
                dict_append_entry(&mut d, "Endpoint", Value::from(op));
            }
        }
    }

    // Append BAP QoS if the transport carries a BAP stream
    if let Some(s_arc) = g.ops.get_stream() {
        if let Some(bap) = s_arc.downcast_ref::<BtBapStream>() {
            append_bap_qos(&mut d, bap);
        }
    }

    // Error interface string used for D-Bus error property replies
    let _err_iface = ERROR_INTERFACE;
    d
}

/// Find the transport D-Bus path for a BAP stream by matching direction,
/// location, and stream state.
pub fn media_transport_stream_path(stream: &BtBapStream) -> Option<String> {
    let target_dir = stream.get_dir();
    let target_loc = stream.get_location();
    let target_state = stream.get_state();

    let list = TRANSPORTS.lock().unwrap();
    for t in list.iter() {
        if let Ok(g) = t.try_lock() {
            if let Some(s_arc) = g.ops.get_stream() {
                if let Some(bap) = s_arc.downcast_ref::<BtBapStream>() {
                    if bap.get_dir() == target_dir
                        && bap.get_location() == target_loc
                        && bap.get_state() == target_state
                    {
                        return Some(g.inner.path.clone());
                    }
                }
            }
        }
    }
    None
}

/// Set the file descriptor and MTUs on a transport (called when stream ready).
pub async fn media_transport_set_fd(
    transport: &Arc<Mutex<MediaTransport>>,
    fd: OwnedFd,
    read_mtu: u16,
    write_mtu: u16,
) {
    let mut g = transport.lock().await;
    debug!("{} fd={}, imtu={}, omtu={}", g.inner.path, fd.as_raw_fd(), read_mtu, write_mtu);
    g.inner.fd = Some(fd);
    g.inner.read_mtu = read_mtu;
    g.inner.write_mtu = write_mtu;

    if g.inner.state == TransportState::Pending {
        set_state(&mut g.inner, TransportState::Active);
        complete_pending_acquire(&mut g.inner);
    }
}

/// Update transport state externally.
pub async fn media_transport_update_state(
    transport: &Arc<Mutex<MediaTransport>>,
    state: TransportState,
) {
    let mut g = transport.lock().await;
    set_state(&mut g.inner, state);
    if state == TransportState::Active {
        complete_pending_acquire(&mut g.inner);
    }
}

/// Inject a [`BtAsha`] protocol engine into an ASHA-type transport's ops.
///
/// This allows the ASHA profile plugin to provide the `BtAsha` instance
/// after the transport has been created (since `media_transport_create`
/// creates ops with `asha: None`).
pub async fn media_transport_set_asha(transport: &Arc<Mutex<MediaTransport>>, asha: BtAsha) {
    let g = transport.lock().await;
    g.ops.set_asha_engine(asha);
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_state_strings() {
        assert_eq!(TransportState::Idle.as_str(), "idle");
        assert_eq!(TransportState::Pending.as_str(), "pending");
        assert_eq!(TransportState::Active.as_str(), "active");
    }

    #[test]
    fn transport_state_in_use() {
        assert!(!TransportState::Idle.in_use());
        assert!(TransportState::Pending.in_use());
        assert!(TransportState::Active.in_use());
    }

    #[test]
    fn transport_state_display() {
        assert_eq!(format!("{}", TransportState::Idle), "idle");
        assert_eq!(format!("{}", TransportState::Pending), "pending");
        assert_eq!(format!("{}", TransportState::Active), "active");
    }

    #[test]
    fn asha_volume_conversion() {
        // ASHA: -128..0 maps to 0..127
        let check = |v: i8, expect: u8| {
            let mapped = (i16::from(v) + 128).clamp(0, 127) as u8;
            assert_eq!(mapped, expect, "asha vol {v}");
        };
        check(-128, 0);
        check(0, 127);
        check(-64, 64);
        check(-1, 127);
    }

    #[test]
    fn uuid_constants_valid() {
        assert!(PAC_SINK_UUID.contains("1850"));
        assert!(PAC_SOURCE_UUID.contains("1851"));
        assert!(BCAA_SERVICE_UUID.contains("1852"));
        assert!(BAA_SERVICE_UUID.contains("1853"));
        assert!(ASHA_PROFILE_UUID.to_lowercase().contains("fdf0"));
    }

    #[test]
    fn max_bcast_code_matches_bass() {
        assert_eq!(MAX_BCAST_CODE_SIZE, BASS_BCAST_CODE_SIZE);
    }

    #[test]
    fn asha_state_mapping() {
        assert_eq!(asha_to_transport_state(AshaState::Stopped), TransportState::Idle);
        assert_eq!(asha_to_transport_state(AshaState::Starting), TransportState::Pending);
        assert_eq!(asha_to_transport_state(AshaState::Started), TransportState::Active);
    }
}
