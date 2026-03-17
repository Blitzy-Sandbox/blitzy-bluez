// SPDX-License-Identifier: GPL-2.0-or-later
//! A2DP Sink role management.
//!
//! Rust rewrite of `profiles/audio/sink.c` (~448 lines) and
//! `profiles/audio/sink.h`.  Manages the A2DP Sink endpoint state and
//! AVDTP stream lifecycle for incoming audio streams (remote Source →
//! local Sink).
//!
//! # Key conversions from C
//!
//! - `struct sink` → [`Sink`] (stored as `Arc<std::sync::Mutex<Sink>>`
//!   in the service's user-data slot).
//! - `sink_state_t` enum → [`SinkState`] (public, `#[derive(Debug, Clone, Copy)]`).
//! - `struct sink_state_callback` + `sink_callbacks` GSList →
//!   [`SinkStateCbEntry`] in a global `LazyLock<Mutex<Vec<...>>>`.
//! - `avdtp_state_callback` (session state) and `stream_state_changed`
//!   (per-stream) → unified AVDTP stream-state callback registered via
//!   [`avdtp_add_state_cb`] and per-stream via [`avdtp_stream_add_cb`].
//! - `callback_t + void *user_data` → closures captured over `Arc` clones.
//! - `btd_service_ref` / `btd_service_unref` → `Arc` shared ownership.
//! - GLib `DBG()` / `error()` → `tracing::debug!` / `tracing::error!` +
//!   [`btd_debug`] / [`btd_error`] for btmon-channel logging.

use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::sync::Mutex;

use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, warn};

use crate::device::BtdDevice;
use crate::log::btd_debug;
use crate::profiles::audio::a2dp::{
    a2dp_avdtp_get, a2dp_cancel, a2dp_config, a2dp_discover, a2dp_get_channel,
    a2dp_select_capabilities,
};
use crate::profiles::audio::avdtp::{
    avdtp_add_state_cb, avdtp_close, avdtp_remove_state_cb, avdtp_stream_add_cb,
    avdtp_stream_remove_cb, AvdtpSepType, AvdtpSession, AvdtpSessionState,
    AvdtpStreamState,
};
use crate::service::BtdService;

// ===========================================================================
// SinkState Enum
// ===========================================================================

/// States of an A2DP Sink endpoint, mirroring `sink_state_t` in C.
///
/// State transitions follow the same rules as the C implementation:
///
/// ```text
/// Disconnected ──► Connecting ──► Connected ──► Playing
///       ▲                              │           │
///       └──────────────────────────────┴───────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinkState {
    /// No AVDTP session or stream is associated.
    Disconnected,
    /// AVDTP session establishment or stream negotiation is in progress.
    Connecting,
    /// AVDTP stream is open (configured) but not streaming.
    Connected,
    /// AVDTP stream is actively streaming audio data.
    Playing,
}

impl fmt::Display for SinkState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SinkState::Disconnected => f.write_str("disconnected"),
            SinkState::Connecting => f.write_str("connecting"),
            SinkState::Connected => f.write_str("connected"),
            SinkState::Playing => f.write_str("playing"),
        }
    }
}

// ===========================================================================
// State Callback System
// ===========================================================================

/// Signature for a sink state change observer.
///
/// Called with `(old_state, new_state)` whenever the sink endpoint
/// transitions between [`SinkState`] values.
pub type SinkStateCb = Box<dyn Fn(SinkState, SinkState) + Send + Sync>;

/// A registered sink-state observer.
struct SinkStateCbEntry {
    /// Unique identifier returned by [`sink_add_state_cb`].
    id: u32,
    /// D-Bus object path of the service this callback is scoped to.
    /// If empty, the callback fires for all sink state changes.
    service_path: String,
    /// The actual callback closure.
    cb: SinkStateCb,
}

/// Monotonically increasing callback ID generator.
static NEXT_CB_ID: AtomicU32 = AtomicU32::new(1);

/// Global list of registered sink-state callbacks.
///
/// Uses `std::sync::Mutex` (not tokio) because callbacks are invoked from
/// synchronous AVDTP state change handlers.
static SINK_CALLBACKS: std::sync::LazyLock<Mutex<Vec<SinkStateCbEntry>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

/// Register a sink-state change callback scoped to a specific service.
///
/// Returns a unique identifier that can be passed to
/// [`sink_remove_state_cb`] to unregister the callback.
///
/// Replaces C `sink_add_state_cb(service, cb, user_data)`.
pub fn sink_add_state_cb(service_path: &str, cb: SinkStateCb) -> u32 {
    let id = NEXT_CB_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut cbs) = SINK_CALLBACKS.lock() {
        cbs.push(SinkStateCbEntry {
            id,
            service_path: service_path.to_owned(),
            cb,
        });
        debug!(id, path = %service_path, "sink: registered state callback");
        btd_debug(0, &format!("sink: registered state callback id={id}"));
    }
    id
}

/// Unregister a previously registered sink-state callback.
///
/// Returns `true` if a callback with the given `id` was found and removed.
///
/// Replaces C `sink_remove_state_cb(id)`.
pub fn sink_remove_state_cb(id: u32) -> bool {
    if let Ok(mut cbs) = SINK_CALLBACKS.lock() {
        let before = cbs.len();
        cbs.retain(|e| e.id != id);
        let removed = cbs.len() < before;
        if removed {
            debug!(id, "sink: removed state callback");
            btd_debug(0, &format!("sink: removed state callback id={id}"));
        }
        return removed;
    }
    false
}

// ===========================================================================
// Sink Internal State
// ===========================================================================

/// Internal state of an A2DP Sink endpoint for a single device.
///
/// Stored as `Arc<std::sync::Mutex<Sink>>` in the `BtdService` user-data
/// slot.  Uses `std::sync::Mutex` (not tokio) so that synchronous AVDTP
/// callbacks can lock it without requiring an async runtime context.
///
/// Fields mirror the C `struct sink` exactly:
/// - `service` → device reference from service layer
/// - `session` → AVDTP session (None when disconnected)
/// - `stream` → stream index within session (None when no stream)
/// - `state` → current sink state
/// - `delay_reporting` → whether delay reporting is supported
/// - `cb_id` → per-stream callback ID (0 when no stream callback)
/// - `session_state` → last known AVDTP session state
/// - `stream_state` → last known AVDTP stream state
/// - `connect_id` → connect completion channel sender
/// - `disconnect_id` → disconnect completion channel sender
/// - `avdtp_callback_id` → global AVDTP state callback registration ID
pub struct Sink {
    /// Weak back-reference to the owning service instance.
    /// Stored as `Weak` to avoid circular reference (Sink is stored inside
    /// the service's user-data slot).  Mirrors C `struct sink { struct
    /// btd_service *service; }` without creating a reference cycle.
    pub service: Weak<TokioMutex<BtdService>>,

    /// The remote Bluetooth device (service-layer reference).
    pub device: Arc<TokioMutex<BtdDevice>>,

    /// A protocol-layer device reference (`Arc<BtdDevice>`) obtained from
    /// the AVDTP session.  Used for a2dp-layer API calls that require
    /// pointer-identity matching with the a2dp channel's stored device.
    /// Populated when the first AVDTP session is associated.
    proto_device: Option<Arc<BtdDevice>>,

    /// The AVDTP session (if connected).
    pub session: Option<Arc<TokioMutex<AvdtpSession>>>,

    /// Stream index within the AVDTP session (if a stream has been opened).
    pub stream: Option<usize>,

    /// Current sink state.
    pub state: SinkState,

    /// Whether delay reporting is supported for the current stream.
    pub delay_reporting: bool,

    /// Per-stream callback tracking flag.  In the C code this is
    /// `sink->cb_id` (non-zero when a stream callback is registered).
    /// Here we track it as a boolean since the Rust AVDTP API uses
    /// `avdtp_stream_remove_cb` which clears all callbacks on a stream.
    pub cb_id: u32,

    /// Last known AVDTP session state.
    pub session_state: AvdtpSessionState,

    /// Last known AVDTP stream state.
    pub stream_state: AvdtpStreamState,

    /// Completion sender for an in-progress connect operation.
    /// When the stream transitions to Open, the sender fires with 0.
    /// On failure/disconnect, it fires with a negative errno.
    pub connect_id: Option<tokio::sync::oneshot::Sender<i32>>,

    /// Completion sender for an in-progress disconnect operation.
    pub disconnect_id: Option<tokio::sync::oneshot::Sender<i32>>,

    /// ID of the global AVDTP stream-state callback registered in
    /// [`sink_init`].
    pub avdtp_callback_id: u64,

    /// D-Bus object path of the device (cached for log messages).
    device_path: String,
}

// ===========================================================================
// Internal Helpers
// ===========================================================================

/// Retrieve the `Arc<std::sync::Mutex<Sink>>` stored in the service's
/// user-data slot.
fn get_sink(service: &BtdService) -> Option<Arc<Mutex<Sink>>> {
    service
        .btd_service_get_user_data::<Arc<Mutex<Sink>>>()
        .cloned()
}

/// Transition the sink to `new_state`, logging the change and notifying
/// all registered callbacks that match this sink's device path.
///
/// Replaces C `sink_set_state()`.
fn sink_set_state(sink: &mut Sink, new_state: SinkState) {
    let old_state = sink.state;
    if old_state == new_state {
        return;
    }

    sink.state = new_state;

    debug!(
        device = %sink.device_path,
        old = %old_state,
        new = %new_state,
        "sink: state changed"
    );
    btd_debug(
        0,
        &format!(
            "sink: State changed {}: {} -> {}",
            sink.device_path, old_state, new_state
        ),
    );

    // Notify all registered callbacks scoped to this device path (or global).
    if let Ok(cbs) = SINK_CALLBACKS.lock() {
        for entry in cbs.iter() {
            if entry.service_path.is_empty() || entry.service_path == sink.device_path {
                (entry.cb)(old_state, new_state);
            }
        }
    }

    // When transitioning to disconnected, release the session reference.
    // This matches the C code in sink_set_state() which does:
    //   if (new_state != SINK_STATE_DISCONNECTED) return;
    //   avdtp_unref(sink->session); sink->session = NULL;
    if new_state == SinkState::Disconnected {
        sink.session = None;
        sink.proto_device = None;
    }
}

/// Handle a stream state transition observed through the AVDTP
/// stream-state callback.
///
/// Maps AVDTP stream states to [`SinkState`] transitions:
///
/// | AVDTP Stream State | Sink State      | Additional Action                  |
/// |--------------------|-----------------|------------------------------------|
/// | `Open`             | `Connected`      | Signal connect completion (0)      |
/// | `Streaming`        | `Playing`        | —                                  |
/// | `Idle`             | (cleanup)        | Cancel pending ops, drop refs      |
/// | `Closing`/`Abort`  | —                | No direct state change             |
/// | Other              | —                | No change                          |
///
/// Replaces C `stream_state_changed()`.
fn handle_stream_state_change(
    sink: &mut Sink,
    _old_state: AvdtpStreamState,
    new_state: AvdtpStreamState,
) {
    match new_state {
        AvdtpStreamState::Idle => {
            // Stream tore down — full cleanup.
            // Cancel pending connect.
            if let Some(tx) = sink.connect_id.take() {
                let _ = tx.send(-libc::ECONNRESET);
            }
            // Cancel pending disconnect.
            if let Some(tx) = sink.disconnect_id.take() {
                let _ = tx.send(0);
            }
            // Release session and stream references.
            sink.session = None;
            sink.stream = None;
            sink.proto_device = None;
            sink.cb_id = 0;
        }
        AvdtpStreamState::Open => {
            // Stream opened — signal connect completion and transition to Connected.
            if let Some(tx) = sink.connect_id.take() {
                let _ = tx.send(0);
            }
            sink_set_state(sink, SinkState::Connected);
        }
        AvdtpStreamState::Streaming => {
            sink_set_state(sink, SinkState::Playing);
        }
        AvdtpStreamState::Configured
        | AvdtpStreamState::Closing
        | AvdtpStreamState::Aborting => {
            // No direct sink state change for these AVDTP states.
        }
    }

    sink.stream_state = new_state;
}

// ===========================================================================
// Public Lifecycle Functions
// ===========================================================================

/// Initialise the A2DP Sink endpoint for `service`.
///
/// Allocates the internal [`Sink`] state, registers a global AVDTP
/// stream-state callback, and stores the state in the service's user-data
/// slot.
///
/// Replaces C `sink_init(service)`.
pub async fn sink_init(service: &mut BtdService) -> Result<(), i32> {
    let device_arc = service
        .btd_service_get_device()
        .ok_or(-libc::EINVAL)?
        .clone();

    let device_path = {
        let dev = device_arc.lock().await;
        dev.get_path().to_owned()
    };

    debug!(path = %device_path, "sink_init");
    btd_debug(0, &format!("sink_init: {device_path}"));

    let sink = Arc::new(Mutex::new(Sink {
        service: Weak::new(),
        device: device_arc,
        proto_device: None,
        session: None,
        stream: None,
        state: SinkState::Disconnected,
        delay_reporting: false,
        cb_id: 0,
        session_state: AvdtpSessionState::Idle,
        stream_state: AvdtpStreamState::Idle,
        connect_id: None,
        disconnect_id: None,
        avdtp_callback_id: 0,
        device_path: device_path.clone(),
    }));

    // Register the global AVDTP stream-state callback.  The closure captures
    // a weak reference to Sink so that the callback does not prevent Sink
    // from being dropped when the service is torn down.
    let sink_weak = Arc::downgrade(&sink);
    let cb_id = avdtp_add_state_cb(Box::new(move |_stream, old_state, new_state| {
        if let Some(sink_arc) = sink_weak.upgrade() {
            if let Ok(mut snk) = sink_arc.lock() {
                // Only process if we actually have an active stream.
                if snk.stream.is_some() {
                    handle_stream_state_change(&mut snk, old_state, new_state);
                }
            }
        }
    }));

    {
        let mut snk = sink.lock().unwrap();
        snk.avdtp_callback_id = cb_id;
    }

    service.btd_service_set_user_data(sink);
    Ok(())
}

/// Unregister the A2DP Sink endpoint for `service`.
///
/// Cleans up the AVDTP callback, drops the session and stream references,
/// and removes the sink state from the service's user-data.
///
/// Replaces C `sink_unregister(service)`.
pub async fn sink_unregister(service: &mut BtdService) {
    let sink_arc = match get_sink(service) {
        Some(s) => s,
        None => return,
    };

    let (device_path, cb_id, proto_device, device_ref) = {
        let snk = sink_arc.lock().unwrap();
        (
            snk.device_path.clone(),
            snk.avdtp_callback_id,
            snk.proto_device.clone(),
            Arc::clone(&snk.device),
        )
    };

    // Verify the device is still accessible before cleanup.
    let _dev_guard = device_ref.lock().await;
    drop(_dev_guard);

    debug!(path = %device_path, "sink_unregister");
    btd_debug(0, &format!("sink_unregister: {device_path}"));

    // Cancel any pending A2DP operations.
    if let Some(ref dev) = proto_device {
        a2dp_cancel(dev).await;
    }

    // Unregister the AVDTP stream-state callback.
    if cb_id != 0 {
        avdtp_remove_state_cb(cb_id);
    }

    // Clear session and stream references, signal any pending completions.
    {
        let mut snk = sink_arc.lock().unwrap();

        // Cancel pending connect.
        if let Some(tx) = snk.connect_id.take() {
            let _ = tx.send(-libc::ECANCELED);
        }

        // Cancel pending disconnect.
        if let Some(tx) = snk.disconnect_id.take() {
            let _ = tx.send(-libc::ECANCELED);
        }

        // Remove per-stream callbacks before dropping the session.
        if let (Some(sess_arc), Some(idx)) = (snk.session.as_ref(), snk.stream) {
            // Best-effort cleanup: lock the session and remove stream cbs.
            if let Ok(mut sess) = sess_arc.try_lock() {
                if let Some(stream) = sess.streams_mut().get_mut(idx) {
                    avdtp_stream_remove_cb(stream);
                }
            }
        }

        snk.session = None;
        snk.stream = None;
        snk.proto_device = None;
        snk.connect_id = None;
        snk.disconnect_id = None;
        sink_set_state(&mut snk, SinkState::Disconnected);
    }

    // Remove sink from service user-data (store a dummy value to clear it).
    service.btd_service_set_user_data(0u8);
}

/// Initiate connection of the A2DP Sink endpoint.
///
/// If no AVDTP session exists, calls [`sink_setup_stream`] to create one
/// and begin the discovery/configuration flow.  If a stream already exists
/// and is open, the connection is already established.
///
/// Signals `btd_service_connecting_complete` with the result before
/// returning.
///
/// Replaces C `sink_connect(service)`.
pub async fn sink_connect(service: &mut BtdService) -> Result<(), i32> {
    let sink_arc = get_sink(service).ok_or(-libc::EINVAL)?;

    let device_path = {
        let snk = sink_arc.lock().unwrap();
        snk.device_path.clone()
    };
    debug!(path = %device_path, "sink_connect");
    btd_debug(0, &format!("sink_connect: {device_path}"));

    // Check current state — mirror the C sink_connect() checks.
    {
        let snk = sink_arc.lock().unwrap();
        match snk.state {
            SinkState::Connecting => {
                debug!(path = %device_path, "sink_connect: already connecting");
                return Err(-libc::EBUSY);
            }
            SinkState::Connected | SinkState::Playing => {
                debug!(path = %device_path, "sink_connect: already connected/playing");
                return Err(-libc::EALREADY);
            }
            SinkState::Disconnected => { /* proceed */ }
        }
        // Check if connect or disconnect operations are in progress.
        if snk.connect_id.is_some() || snk.disconnect_id.is_some() {
            debug!(path = %device_path, "sink_connect: operation in progress");
            return Err(-libc::EBUSY);
        }
    }

    // Create a oneshot channel to await connection completion from the
    // stream-state callback.
    let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
    {
        let mut snk = sink_arc.lock().unwrap();
        snk.connect_id = Some(tx);
        sink_set_state(&mut snk, SinkState::Connecting);
    }

    // Initiate stream setup.
    let setup_ok = sink_setup_stream(service, None).await;

    if !setup_ok {
        error!(path = %device_path, "sink_connect: stream setup failed");
        btd_debug(
            0,
            &format!("sink_connect: Failed to create a stream for {device_path}"),
        );
        {
            let mut snk = sink_arc.lock().unwrap();
            snk.connect_id = None;
            sink_set_state(&mut snk, SinkState::Disconnected);
        }
        service.btd_service_connecting_complete(-libc::EIO);
        return Err(-libc::EIO);
    }

    debug!(path = %device_path, "sink_connect: stream creation in progress");
    btd_debug(0, "sink_connect: stream creation in progress");

    // Await the stream-state callback signalling Open or failure.
    let err = match rx.await {
        Ok(code) => code,
        Err(_) => -libc::EIO, // sender dropped without sending
    };

    service.btd_service_connecting_complete(err);
    if err == 0 {
        Ok(())
    } else {
        Err(err)
    }
}

/// Initiate disconnection of the A2DP Sink endpoint.
///
/// Cancels any pending A2DP operations, closes the active AVDTP stream
/// (if any), and signals `btd_service_disconnecting_complete` upon
/// completion.
///
/// Replaces C `sink_disconnect(service)`.
pub async fn sink_disconnect(service: &mut BtdService) -> Result<(), i32> {
    let sink_arc = get_sink(service).ok_or(-libc::EINVAL)?;

    let (device_path, proto_device, session, stream_idx, state) = {
        let snk = sink_arc.lock().unwrap();
        (
            snk.device_path.clone(),
            snk.proto_device.clone(),
            snk.session.clone(),
            snk.stream,
            snk.state,
        )
    };

    debug!(path = %device_path, state = %state, "sink_disconnect");
    btd_debug(
        0,
        &format!("sink_disconnect: {device_path} (state={state})"),
    );

    // If already disconnected, signal completion immediately.
    if state == SinkState::Disconnected {
        debug!(path = %device_path, "sink_disconnect: already disconnected");
        service.btd_service_disconnecting_complete(0);
        return Ok(());
    }

    // If no session exists, we're not connected at protocol level.
    if session.is_none() {
        warn!(path = %device_path, "sink_disconnect: no session");
        service.btd_service_disconnecting_complete(-libc::ENOTCONN);
        return Err(-libc::ENOTCONN);
    }

    // Check if a connect operation is pending — cancel it and signal
    // disconnect completion.  This mirrors the C code's handling:
    //   if (sink->connect_id > 0) { cancel; complete(0); return 0; }
    let connect_pending = {
        let snk = sink_arc.lock().unwrap();
        snk.connect_id.is_some()
    };
    if connect_pending {
        // Cancel pending A2DP operations.
        if let Some(ref dev) = proto_device {
            a2dp_cancel(dev).await;
        }
        {
            let mut snk = sink_arc.lock().unwrap();
            snk.connect_id = None;
            snk.session = None;
            snk.proto_device = None;
        }
        service.btd_service_disconnecting_complete(0);
        return Ok(());
    }

    // Check for already-in-progress disconnect.
    {
        let snk = sink_arc.lock().unwrap();
        if snk.disconnect_id.is_some() {
            debug!(path = %device_path, "sink_disconnect: already disconnecting");
            return Err(-libc::EBUSY);
        }
    }

    // If no stream exists, return not connected.
    if stream_idx.is_none() {
        warn!(path = %device_path, "sink_disconnect: no stream");
        service.btd_service_disconnecting_complete(-libc::ENOTCONN);
        return Err(-libc::ENOTCONN);
    }

    // Close the AVDTP stream.
    let session_arc = session.unwrap();
    let idx = stream_idx.unwrap();

    // Create a channel to await close completion from the stream-state
    // callback (stream → Idle).
    let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
    {
        let mut snk = sink_arc.lock().unwrap();
        snk.disconnect_id = Some(tx);
    }

    {
        let mut sess = session_arc.lock().await;
        if let Err(e) = avdtp_close(&mut sess, idx) {
            error!(
                path = %device_path,
                error = %e,
                "sink_disconnect: avdtp_close failed"
            );
            btd_debug(
                0,
                &format!("sink_disconnect: avdtp_close failed: {e}"),
            );
            // Fall through — force disconnect anyway.
        }
    }

    // Wait for the stream to reach Idle (or timeout).
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), rx).await;

    // Ensure final cleanup.
    {
        let mut snk = sink_arc.lock().unwrap();
        snk.session = None;
        snk.stream = None;
        snk.proto_device = None;
        snk.disconnect_id = None;
        sink_set_state(&mut snk, SinkState::Disconnected);
    }

    service.btd_service_disconnecting_complete(0);
    Ok(())
}

/// Set up an AVDTP stream for the A2DP Sink role.
///
/// If `session` is `None`, obtains a session via the A2DP layer.  Then
/// runs the discovery → capability-selection → configuration flow using
/// the A2DP helper functions.
///
/// Returns `true` if the setup process was initiated (or already complete),
/// `false` on error.
///
/// Replaces C `sink_setup_stream(service, session)`.
pub async fn sink_setup_stream(
    service: &mut BtdService,
    session: Option<Arc<TokioMutex<AvdtpSession>>>,
) -> bool {
    let sink_arc = match get_sink(service) {
        Some(s) => s,
        None => {
            error!("sink_setup_stream: no sink state");
            btd_debug(0, "sink_setup_stream: no sink state");
            return false;
        }
    };

    let device_path = {
        let snk = sink_arc.lock().unwrap();
        snk.device_path.clone()
    };
    debug!(path = %device_path, "sink_setup_stream");
    btd_debug(0, &format!("sink_setup_stream: {device_path}"));

    // Check that no connect/disconnect is already pending.
    {
        let snk = sink_arc.lock().unwrap();
        if snk.connect_id.is_some() || snk.disconnect_id.is_some() {
            debug!(
                path = %device_path,
                "sink_setup_stream: operation already in progress"
            );
            return false;
        }
    }

    // Obtain or reuse the AVDTP session.
    let session_arc = if let Some(s) = session {
        // Use the provided session.
        {
            let mut snk = sink_arc.lock().unwrap();
            if snk.session.is_none() {
                snk.session = Some(Arc::clone(&s));
            }
        }
        s
    } else {
        // Try to reuse an existing session from Sink.
        let existing = {
            let snk = sink_arc.lock().unwrap();
            snk.session.clone()
        };
        if let Some(s) = existing {
            s
        } else {
            // Attempt to get/create a session via the A2DP layer.
            let proto_dev = {
                let snk = sink_arc.lock().unwrap();
                snk.proto_device.clone()
            };
            match proto_dev {
                Some(dev) => match a2dp_avdtp_get(&dev).await {
                    Ok(s) => {
                        {
                            let mut snk = sink_arc.lock().unwrap();
                            snk.session = Some(Arc::clone(&s));
                        }
                        s
                    }
                    Err(e) => {
                        error!(
                            path = %device_path,
                            error = %e,
                            "sink_setup_stream: a2dp_avdtp_get failed"
                        );
                        btd_debug(
                            0,
                            &format!("sink_setup_stream: Unable to get a session: {e}"),
                        );
                        return false;
                    }
                },
                None => {
                    error!(
                        path = %device_path,
                        "sink_setup_stream: no protocol device available"
                    );
                    btd_debug(
                        0,
                        &format!(
                            "sink_setup_stream: Unable to get a session for {device_path}"
                        ),
                    );
                    return false;
                }
            }
        }
    };

    // Extract the protocol-layer device from the session and cache it.
    {
        let sess = session_arc.lock().await;
        let dev = sess.device().clone();
        let mut snk = sink_arc.lock().unwrap();
        if snk.proto_device.is_none() {
            snk.proto_device = Some(dev);
        }
    }

    // Get the protocol device for a2dp calls.
    let proto_dev = {
        let snk = sink_arc.lock().unwrap();
        match snk.proto_device.clone() {
            Some(d) => d,
            None => {
                error!(
                    path = %device_path,
                    "sink_setup_stream: missing proto device"
                );
                btd_debug(0, "sink_setup_stream: missing proto device");
                return false;
            }
        }
    };

    // Retrieve the A2DP channel for this device.
    let channel = match a2dp_get_channel(&proto_dev).await {
        Some(ch) => ch,
        None => {
            error!(
                path = %device_path,
                "sink_setup_stream: no A2DP channel found"
            );
            btd_debug(
                0,
                &format!("sink_setup_stream: no A2DP channel for {device_path}"),
            );
            return false;
        }
    };

    // Step 1: Discover remote SEPs.
    let remote_seps = match a2dp_discover(&channel).await {
        Ok(seps) => seps,
        Err(e) => {
            error!(
                path = %device_path,
                error = %e,
                "sink_setup_stream: discovery failed"
            );
            btd_debug(
                0,
                &format!("sink_setup_stream: discovery failed: {e}"),
            );
            return false;
        }
    };

    debug!(
        path = %device_path,
        count = remote_seps.len(),
        "sink_setup_stream: Discovery complete"
    );
    btd_debug(
        0,
        &format!(
            "sink_setup_stream: Discovery complete, {} remote SEPs",
            remote_seps.len()
        ),
    );

    if remote_seps.is_empty() {
        error!(
            path = %device_path,
            "sink_setup_stream: no remote SEPs discovered"
        );
        btd_debug(
            0,
            &format!("sink_setup_stream: no remote SEPs for {device_path}"),
        );
        return false;
    }

    // Step 2: Find a matching local Sink SEP and select capabilities.
    //
    // Iterate the A2DP server's SEPs, filtering for Sink-type only, and
    // attempt codec negotiation via a2dp_select_capabilities.
    let server_arc = {
        let ch = channel.lock().await;
        ch.server().clone()
    };

    let mut configured = false;

    let seps: Vec<_> = {
        let srv = server_arc.lock().await;
        srv.seps().iter().map(Arc::clone).collect()
    };

    for sep_candidate in &seps {
        // Check if this is a Sink SEP.
        let is_sink = {
            let sep_guard = sep_candidate.lock().await;
            sep_guard.sep_type() == AvdtpSepType::Sink
        };
        if !is_sink {
            continue;
        }

        // Attempt to select capabilities.
        let caps = match a2dp_select_capabilities(&channel, sep_candidate).await {
            Ok(c) => c,
            Err(_) => continue, // No matching remote SEP for this codec.
        };

        // Determine the matching remote SEID.
        let rsep_seid = {
            let sep_guard = sep_candidate.lock().await;
            let codec = sep_guard.codec;
            let ch_guard = channel.lock().await;
            ch_guard
                .remote_seps()
                .iter()
                .find(|r| r.codec == codec)
                .map(|r| r.seid)
                .unwrap_or(1)
        };

        debug!(
            path = %device_path,
            rsep_seid,
            caps_len = caps.len(),
            "sink_setup_stream: configuring stream"
        );

        // Step 3: Configure the stream.
        match a2dp_config(&channel, sep_candidate, rsep_seid, &caps).await {
            Ok(stream_idx) => {
                debug!(
                    path = %device_path,
                    stream_idx,
                    "sink_setup_stream: stream configured"
                );
                btd_debug(
                    0,
                    &format!("sink_setup_stream: stream configured idx={stream_idx}"),
                );

                // Store the stream index.
                {
                    let mut snk = sink_arc.lock().unwrap();
                    snk.stream = Some(stream_idx);
                }

                // Register a per-stream callback for authoritative state
                // tracking.
                {
                    let mut sess = session_arc.lock().await;
                    if let Some(stream) = sess.streams_mut().get_mut(stream_idx) {
                        let weak = Arc::downgrade(&sink_arc);
                        avdtp_stream_add_cb(
                            stream,
                            Box::new(move |old_st, new_st| {
                                if let Some(snk_arc) = weak.upgrade() {
                                    if let Ok(mut snk) = snk_arc.lock() {
                                        handle_stream_state_change(
                                            &mut snk, old_st, new_st,
                                        );
                                    }
                                }
                            }),
                        );
                    }
                }

                configured = true;
                break;
            }
            Err(e) => {
                error!(
                    path = %device_path,
                    error = %e,
                    "sink_setup_stream: a2dp_config failed for SEP"
                );
                btd_debug(
                    0,
                    &format!("sink_setup_stream: a2dp_config failed: {e}"),
                );
                continue; // Try next SEP.
            }
        }
    }

    if !configured {
        error!(
            path = %device_path,
            "sink_setup_stream: no SEP could be configured"
        );
        btd_debug(
            0,
            &format!("sink_setup_stream: Failed to create a stream for {device_path}"),
        );
    }

    configured
}

/// Associate a new AVDTP stream with the A2DP Sink endpoint.
///
/// Called by the A2DP/media layer when a remote source connects and an AVDTP
/// stream is established.  Stores the session and stream reference, and
/// registers a per-stream state callback.
///
/// Returns `true` on success.
///
/// Replaces C `sink_new_stream(service, session, stream)`.
pub async fn sink_new_stream(
    service: &mut BtdService,
    session: Arc<TokioMutex<AvdtpSession>>,
    stream_idx: usize,
) -> bool {
    let sink_arc = match get_sink(service) {
        Some(s) => s,
        None => {
            error!("sink_new_stream: no sink state");
            btd_debug(0, "sink_new_stream: no sink state");
            return false;
        }
    };

    let device_path = {
        let snk = sink_arc.lock().unwrap();
        snk.device_path.clone()
    };
    debug!(
        path = %device_path,
        stream_idx,
        "sink_new_stream"
    );
    btd_debug(
        0,
        &format!("sink_new_stream: {device_path} stream_idx={stream_idx}"),
    );

    // Check if a stream is already associated.
    {
        let snk = sink_arc.lock().unwrap();
        if snk.stream.is_some() {
            warn!(
                path = %device_path,
                "sink_new_stream: stream already exists"
            );
            return false;
        }
    }

    // Extract the protocol-layer device from the session and cache it.
    let proto_dev = {
        let sess = session.lock().await;
        sess.device().clone()
    };

    // Store the session and stream index.
    {
        let mut snk = sink_arc.lock().unwrap();
        snk.session = Some(Arc::clone(&session));
        snk.stream = Some(stream_idx);
        if snk.proto_device.is_none() {
            snk.proto_device = Some(proto_dev);
        }
    }

    // Register a per-stream state callback.
    {
        let mut sess = session.lock().await;
        if let Some(stream) = sess.streams_mut().get_mut(stream_idx) {
            let weak = Arc::downgrade(&sink_arc);
            avdtp_stream_add_cb(
                stream,
                Box::new(move |old_st, new_st| {
                    if let Some(snk_arc) = weak.upgrade() {
                        if let Ok(mut snk) = snk_arc.lock() {
                            handle_stream_state_change(&mut snk, old_st, new_st);
                        }
                    }
                }),
            );
        } else {
            error!(
                path = %device_path,
                stream_idx,
                "sink_new_stream: invalid stream index"
            );
            btd_debug(
                0,
                &format!("sink_new_stream: invalid stream index {stream_idx}"),
            );
            return false;
        }
    }

    true
}

/// Check whether the A2DP Sink has an active AVDTP session.
///
/// Returns `true` if the sink has an active session (even if not streaming).
/// This is the Rust equivalent of C `sink_is_active()` which returns TRUE
/// if `sink->session` is non-NULL.
///
/// Replaces C `sink_is_active(service)`.
pub fn sink_is_active(service: &BtdService) -> bool {
    match get_sink(service) {
        Some(sink_arc) => {
            let snk = match sink_arc.lock() {
                Ok(s) => s,
                Err(_) => return false,
            };
            snk.session.is_some()
        }
        None => false,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_state_display() {
        assert_eq!(format!("{}", SinkState::Disconnected), "disconnected");
        assert_eq!(format!("{}", SinkState::Connecting), "connecting");
        assert_eq!(format!("{}", SinkState::Connected), "connected");
        assert_eq!(format!("{}", SinkState::Playing), "playing");
    }

    #[test]
    fn sink_state_equality() {
        assert_eq!(SinkState::Disconnected, SinkState::Disconnected);
        assert_ne!(SinkState::Disconnected, SinkState::Connecting);
        assert_ne!(SinkState::Connected, SinkState::Playing);
    }

    #[test]
    fn sink_state_clone() {
        let state = SinkState::Playing;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    #[test]
    fn sink_state_debug() {
        let state = SinkState::Connected;
        let debug_str = format!("{:?}", state);
        assert_eq!(debug_str, "Connected");
    }

    #[test]
    fn sink_add_remove_state_cb() {
        let id = sink_add_state_cb("test/path", Box::new(|_old, _new| {}));
        assert!(id > 0);
        assert!(sink_remove_state_cb(id));
        // Removing again should fail.
        assert!(!sink_remove_state_cb(id));
    }

    #[test]
    fn sink_add_state_cb_multiple() {
        let id1 = sink_add_state_cb("test/path1", Box::new(|_old, _new| {}));
        let id2 = sink_add_state_cb("test/path2", Box::new(|_old, _new| {}));
        assert_ne!(id1, id2);
        assert!(sink_remove_state_cb(id1));
        assert!(sink_remove_state_cb(id2));
    }

    #[test]
    fn sink_remove_nonexistent_cb() {
        assert!(!sink_remove_state_cb(999_999));
    }

    #[test]
    fn sink_state_callback_invocation() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let id = sink_add_state_cb(
            "test/callback_invoke",
            Box::new(move |old, new| {
                assert_eq!(old, SinkState::Disconnected);
                assert_eq!(new, SinkState::Connecting);
                called_clone.store(true, Ordering::SeqCst);
            }),
        );

        // Simulate state change notification by calling sink_set_state
        // through SINK_CALLBACKS manually.
        if let Ok(cbs) = SINK_CALLBACKS.lock() {
            for entry in cbs.iter() {
                if entry.service_path == "test/callback_invoke" {
                    (entry.cb)(SinkState::Disconnected, SinkState::Connecting);
                }
            }
        }

        assert!(called.load(Ordering::SeqCst));
        sink_remove_state_cb(id);
    }
}
