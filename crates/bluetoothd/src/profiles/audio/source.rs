// SPDX-License-Identifier: GPL-2.0-or-later
//! A2DP Source role management.
//!
//! Rust rewrite of `profiles/audio/source.c` (~440 lines) and
//! `profiles/audio/source.h`.  Manages the A2DP Source endpoint state and
//! AVDTP stream lifecycle for outgoing audio streams, mirroring the Sink
//! module but for the local-to-remote direction.
//!
//! # Key conversions from C
//!
//! - `struct source` → [`Source`] (private, stored as `Arc<std::sync::Mutex<Source>>`
//!   in the service's user-data slot).
//! - `source_state_t` enum → [`SourceState`] (public, `#[derive(Debug, Clone, Copy)]`).
//! - `struct source_state_callback` + `source_callbacks` GSList →
//!   [`SourceStateCbEntry`] in a global `LazyLock<Mutex<Vec<...>>>`.
//! - `avdtp_state_callback` (session state) and `stream_state_changed`
//!   (per-stream) → unified AVDTP stream-state callback registered via
//!   [`avdtp_add_state_cb`] and per-stream via [`avdtp_stream_add_cb`].
//! - `callback_t + void *user_data` → closures captured over `Arc` clones.
//! - `btd_service_ref` / `btd_service_unref` → `Arc` shared ownership.
//! - GLib `DBG()` / `error()` → `tracing::debug!` / `tracing::error!` +
//!   [`btd_debug`] / [`btd_error`] for btmon-channel logging.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error};

use crate::device::BtdDevice;
use crate::log::{btd_debug, btd_error};
use crate::profiles::audio::a2dp::{
    a2dp_avdtp_get, a2dp_cancel, a2dp_config, a2dp_discover, a2dp_get_channel,
    a2dp_select_capabilities,
};
use crate::profiles::audio::avdtp::{
    AvdtpSepType, AvdtpSession, AvdtpStreamState, avdtp_add_state_cb, avdtp_close,
    avdtp_remove_state_cb, avdtp_stream_add_cb,
};
use crate::service::BtdService;

// ===========================================================================
// SourceState Enum
// ===========================================================================

/// States of an A2DP Source endpoint, mirroring `source_state_t` in C.
///
/// State transitions follow the same rules as the C implementation:
///
/// ```text
/// Disconnected ──► Connecting ──► Connected ──► Playing
///       ▲                              │           │
///       └──────────────────────────────┴───────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceState {
    /// No AVDTP session or stream is associated.
    Disconnected,
    /// AVDTP session establishment or stream negotiation is in progress.
    Connecting,
    /// AVDTP stream is open (configured) but not streaming.
    Connected,
    /// AVDTP stream is actively streaming audio data.
    Playing,
}

impl fmt::Display for SourceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceState::Disconnected => f.write_str("disconnected"),
            SourceState::Connecting => f.write_str("connecting"),
            SourceState::Connected => f.write_str("connected"),
            SourceState::Playing => f.write_str("playing"),
        }
    }
}

// ===========================================================================
// State Callback System
// ===========================================================================

/// Signature for a source state change observer.
///
/// Called with `(old_state, new_state)` whenever the source endpoint
/// transitions between [`SourceState`] values.
pub type SourceStateCbFn = Box<dyn Fn(SourceState, SourceState) + Send + Sync>;

/// A registered source-state observer.
struct SourceStateCbEntry {
    /// Unique identifier returned by [`source_add_state_cb`].
    id: u32,
    /// D-Bus object path of the service this callback is scoped to.
    /// If empty, the callback fires for all source state changes.
    service_path: String,
    /// The actual callback closure.
    cb: SourceStateCbFn,
}

/// Monotonically increasing callback ID generator.
static NEXT_CB_ID: AtomicU32 = AtomicU32::new(1);

/// Global list of registered source-state callbacks.
///
/// Uses `std::sync::Mutex` (not tokio) because callbacks are invoked from
/// synchronous AVDTP state change handlers.
static SOURCE_CALLBACKS: std::sync::LazyLock<std::sync::Mutex<Vec<SourceStateCbEntry>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// Register a source-state change callback scoped to a specific service.
///
/// Returns a unique identifier that can be passed to
/// [`source_remove_state_cb`] to unregister the callback.
///
/// Replaces C `source_add_state_cb(service, cb, user_data)`.
pub fn source_add_state_cb(service_path: &str, cb: SourceStateCbFn) -> u32 {
    let id = NEXT_CB_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut cbs) = SOURCE_CALLBACKS.lock() {
        cbs.push(SourceStateCbEntry { id, service_path: service_path.to_owned(), cb });
        debug!(id, path = %service_path, "source: registered state callback");
        btd_debug(0, &format!("source: registered state callback id={id}"));
    }
    id
}

/// Unregister a previously registered source-state callback.
///
/// Returns `true` if a callback with the given `id` was found and removed.
///
/// Replaces C `source_remove_state_cb(id)`.
pub fn source_remove_state_cb(id: u32) -> bool {
    if let Ok(mut cbs) = SOURCE_CALLBACKS.lock() {
        let before = cbs.len();
        cbs.retain(|e| e.id != id);
        let removed = cbs.len() < before;
        if removed {
            debug!(id, "source: removed state callback");
            btd_debug(0, &format!("source: removed state callback id={id}"));
        }
        return removed;
    }
    false
}

// ===========================================================================
// Source Internal State
// ===========================================================================

/// Internal state of an A2DP Source endpoint for a single device.
///
/// Stored as `Arc<std::sync::Mutex<Source>>` in the `BtdService` user-data
/// slot.  Uses `std::sync::Mutex` (not tokio) so that synchronous AVDTP
/// callbacks can lock it without requiring an async runtime context.
struct Source {
    /// The remote Bluetooth device (service-layer reference).
    device: Arc<TokioMutex<BtdDevice>>,

    /// A protocol-layer device reference (`Arc<BtdDevice>`) obtained from
    /// the AVDTP session.  Used for a2dp-layer API calls that require
    /// pointer-identity matching with the a2dp channel's stored device.
    /// Populated when the first AVDTP session is associated.
    proto_device: Option<Arc<BtdDevice>>,

    /// The AVDTP session (if connected).
    session: Option<Arc<TokioMutex<AvdtpSession>>>,

    /// Stream index within the AVDTP session (if a stream has been opened).
    stream_idx: Option<usize>,

    /// Current source state.
    state: SourceState,

    /// ID of the global AVDTP stream-state callback registered in
    /// [`source_init`].
    avdtp_callback_id: u64,

    /// D-Bus object path of the device (cached for log messages).
    device_path: String,

    /// Completion sender for an in-progress connect operation.
    /// When the stream transitions to Open, the sender fires with 0.
    /// On failure/disconnect, it fires with a negative errno.
    connect_tx: Option<tokio::sync::oneshot::Sender<i32>>,

    /// Completion sender for an in-progress disconnect operation.
    disconnect_tx: Option<tokio::sync::oneshot::Sender<i32>>,
}

// ===========================================================================
// Internal Helpers
// ===========================================================================

/// Retrieve the `Arc<std::sync::Mutex<Source>>` stored in the service's
/// user-data slot.
fn get_source(service: &BtdService) -> Option<Arc<std::sync::Mutex<Source>>> {
    service.btd_service_get_user_data::<Arc<std::sync::Mutex<Source>>>().cloned()
}

/// Transition the source to `new_state`, logging the change and notifying
/// all registered callbacks that match this source's device path.
fn source_set_state(source: &mut Source, new_state: SourceState) {
    let old_state = source.state;
    if old_state == new_state {
        return;
    }

    source.state = new_state;

    debug!(
        device = %source.device_path,
        old = %old_state,
        new = %new_state,
        "source: state changed"
    );
    btd_debug(
        0,
        &format!("source: State changed {}: {} -> {}", source.device_path, old_state, new_state),
    );

    // Notify all registered callbacks scoped to this device path (or global).
    if let Ok(cbs) = SOURCE_CALLBACKS.lock() {
        for entry in cbs.iter() {
            if entry.service_path.is_empty() || entry.service_path == source.device_path {
                (entry.cb)(old_state, new_state);
            }
        }
    }
}

/// Handle a stream state transition observed through the AVDTP
/// stream-state callback.
///
/// Maps AVDTP stream states to [`SourceState`] transitions:
///
/// | AVDTP Stream State | Source State     | Additional Action                  |
/// |--------------------|-----------------|------------------------------------|
/// | `Open`             | `Connected`      | Signal connect completion (0)      |
/// | `Streaming`        | `Playing`        | —                                  |
/// | `Idle`             | `Disconnected`   | Signal connect failure or cleanup  |
/// | `Closing`          | `Connected`      | Transition back from Playing       |
/// | Other              | —                | No change                          |
fn handle_stream_state_change(
    source: &mut Source,
    _old_state: AvdtpStreamState,
    new_state: AvdtpStreamState,
) {
    match new_state {
        AvdtpStreamState::Open => {
            source_set_state(source, SourceState::Connected);
            // Signal successful connection to the awaiting source_connect.
            if let Some(tx) = source.connect_tx.take() {
                let _ = tx.send(0);
            }
        }
        AvdtpStreamState::Streaming => {
            source_set_state(source, SourceState::Playing);
        }
        AvdtpStreamState::Closing | AvdtpStreamState::Aborting
            if source.state == SourceState::Playing =>
        {
            // Stream is closing — if we were playing, go back to connected
            // until the close completes (idle).
            source_set_state(source, SourceState::Connected);
        }
        AvdtpStreamState::Idle => {
            // Stream tore down — full disconnect.
            source_set_state(source, SourceState::Disconnected);
            source.stream_idx = None;
            source.session = None;
            source.proto_device = None;

            // Signal connect failure if still pending.
            if let Some(tx) = source.connect_tx.take() {
                let _ = tx.send(-libc::ECONNRESET);
            }
            // Signal disconnect completion if pending.
            if let Some(tx) = source.disconnect_tx.take() {
                let _ = tx.send(0);
            }
        }
        _ => {}
    }
}

// ===========================================================================
// Public Lifecycle Functions
// ===========================================================================

/// Initialise the A2DP Source endpoint for `service`.
///
/// Allocates the internal [`Source`] state, registers a global AVDTP
/// stream-state callback, and stores the state in the service's user-data
/// slot.
///
/// Replaces C `source_init(service)`.
pub async fn source_init(service: &mut BtdService) -> Result<(), i32> {
    let device_arc = service.btd_service_get_device().ok_or(-libc::EINVAL)?.clone();

    let device_path = {
        let dev = device_arc.lock().await;
        dev.get_path().to_owned()
    };

    debug!(path = %device_path, "source_init");
    btd_debug(0, &format!("source_init: {device_path}"));

    let source = Arc::new(std::sync::Mutex::new(Source {
        device: device_arc,
        proto_device: None,
        session: None,
        stream_idx: None,
        state: SourceState::Disconnected,
        avdtp_callback_id: 0,
        device_path: device_path.clone(),
        connect_tx: None,
        disconnect_tx: None,
    }));

    // Register the global AVDTP stream-state callback.  The closure captures
    // a weak reference to Source so that the callback does not prevent Source
    // from being dropped when the service is torn down.
    let source_weak = Arc::downgrade(&source);
    let cb_id = avdtp_add_state_cb(Box::new(move |_stream, old_state, new_state| {
        if let Some(src_arc) = source_weak.upgrade() {
            if let Ok(mut src) = src_arc.lock() {
                // Only process if we actually have an active stream.
                if src.stream_idx.is_some() {
                    handle_stream_state_change(&mut src, old_state, new_state);
                }
            }
        }
    }));

    {
        let mut src = source.lock().unwrap();
        src.avdtp_callback_id = cb_id;
    }

    service.btd_service_set_user_data(source);
    Ok(())
}

/// Unregister the A2DP Source endpoint for `service`.
///
/// Cleans up the AVDTP callback, drops the session and stream references,
/// and removes the source state from the service's user-data.
///
/// Replaces C `source_unregister(service)`.
pub async fn source_unregister(service: &mut BtdService) {
    let source_arc = match get_source(service) {
        Some(s) => s,
        None => return,
    };

    let (device_path, cb_id, proto_device, device_ref) = {
        let src = source_arc.lock().unwrap();
        (
            src.device_path.clone(),
            src.avdtp_callback_id,
            src.proto_device.clone(),
            Arc::clone(&src.device),
        )
    };

    // Verify the device is still accessible before cleanup.
    let _dev_guard = device_ref.lock().await;
    drop(_dev_guard);

    debug!(path = %device_path, "source_unregister");
    btd_debug(0, &format!("source_unregister: {device_path}"));

    // Cancel any pending A2DP operations.
    if let Some(ref dev) = proto_device {
        a2dp_cancel(dev).await;
    }

    // Unregister the AVDTP stream-state callback.
    if cb_id != 0 {
        avdtp_remove_state_cb(cb_id);
    }

    // Clear session and stream references.
    {
        let mut src = source_arc.lock().unwrap();
        src.session = None;
        src.stream_idx = None;
        src.proto_device = None;
        src.connect_tx = None;
        src.disconnect_tx = None;
        source_set_state(&mut src, SourceState::Disconnected);
    }

    // Remove source from service user-data.
    service.btd_service_set_user_data(0u8);
}

/// Initiate connection of the A2DP Source endpoint.
///
/// If no AVDTP session exists, calls [`source_setup_stream`] to create one
/// and begin the discovery/configuration flow.  If a stream already exists
/// and is open, the connection is already established.
///
/// Signals `btd_service_connecting_complete` with the result before
/// returning.
///
/// Replaces C `source_connect(service)`.
pub async fn source_connect(service: &mut BtdService) -> Result<(), i32> {
    let source_arc = get_source(service).ok_or(-libc::EINVAL)?;

    let device_path = {
        let src = source_arc.lock().unwrap();
        src.device_path.clone()
    };
    debug!(path = %device_path, "source_connect");
    btd_debug(0, &format!("source_connect: {device_path}"));

    // Check current state.
    {
        let src = source_arc.lock().unwrap();
        match src.state {
            SourceState::Connecting => {
                debug!(path = %device_path, "source_connect: already connecting");
                return Err(-libc::EBUSY);
            }
            SourceState::Connected | SourceState::Playing => {
                debug!(path = %device_path, "source_connect: already connected");
                return Ok(());
            }
            SourceState::Disconnected => { /* proceed */ }
        }
    }

    // Create a oneshot channel to await connection completion from the
    // stream-state callback.
    let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
    {
        let mut src = source_arc.lock().unwrap();
        src.connect_tx = Some(tx);
        source_set_state(&mut src, SourceState::Connecting);
    }

    // Initiate stream setup.
    let setup_ok = source_setup_stream(service, None).await;

    if !setup_ok {
        error!(path = %device_path, "source_connect: stream setup failed");
        btd_error(0, &format!("source_connect: stream setup failed for {device_path}"));
        {
            let mut src = source_arc.lock().unwrap();
            src.connect_tx = None;
            source_set_state(&mut src, SourceState::Disconnected);
        }
        service.btd_service_connecting_complete(-libc::EIO);
        return Err(-libc::EIO);
    }

    // Await the stream-state callback signalling Open or failure.
    let err = match rx.await {
        Ok(code) => code,
        Err(_) => -libc::EIO, // sender dropped without sending
    };

    service.btd_service_connecting_complete(err);
    if err == 0 { Ok(()) } else { Err(err) }
}

/// Initiate disconnection of the A2DP Source endpoint.
///
/// Cancels any pending A2DP operations, closes the active AVDTP stream
/// (if any), and signals `btd_service_disconnecting_complete` upon
/// completion.
///
/// Replaces C `source_disconnect(service)`.
pub async fn source_disconnect(service: &mut BtdService) -> Result<(), i32> {
    let source_arc = get_source(service).ok_or(-libc::EINVAL)?;

    let (device_path, proto_device, session, stream_idx, state) = {
        let src = source_arc.lock().unwrap();
        (
            src.device_path.clone(),
            src.proto_device.clone(),
            src.session.clone(),
            src.stream_idx,
            src.state,
        )
    };

    debug!(path = %device_path, state = %state, "source_disconnect");
    btd_debug(0, &format!("source_disconnect: {device_path} (state={state})"));

    if state == SourceState::Disconnected {
        debug!(path = %device_path, "source_disconnect: already disconnected");
        service.btd_service_disconnecting_complete(0);
        return Ok(());
    }

    // Cancel any pending A2DP operations on this device.
    if let Some(ref dev) = proto_device {
        a2dp_cancel(dev).await;
    }

    // If we have a stream, close it via AVDTP.
    if let (Some(session_arc), Some(idx)) = (session, stream_idx) {
        // Create a channel to await close completion from the stream-state
        // callback (stream → Idle).
        let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
        {
            let mut src = source_arc.lock().unwrap();
            src.disconnect_tx = Some(tx);
        }

        {
            let mut sess = session_arc.lock().await;
            if let Err(e) = avdtp_close(&mut sess, idx) {
                error!(
                    path = %device_path,
                    error = %e,
                    "source_disconnect: avdtp_close failed"
                );
                btd_error(0, &format!("source_disconnect: avdtp_close failed: {e}"));
                // Fall through — force disconnect anyway.
            }
        }

        // Wait for the stream to reach Idle (or timeout).
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), rx).await;
    }

    // Ensure final cleanup.
    {
        let mut src = source_arc.lock().unwrap();
        src.session = None;
        src.stream_idx = None;
        src.proto_device = None;
        src.disconnect_tx = None;
        source_set_state(&mut src, SourceState::Disconnected);
    }

    service.btd_service_disconnecting_complete(0);
    Ok(())
}

/// Set up an AVDTP stream for the A2DP Source role.
///
/// If `session` is `None`, obtains a session via the A2DP layer.  Then
/// runs the discovery → capability-selection → configuration flow using
/// the A2DP helper functions.
///
/// Returns `true` if the setup process was initiated (or already complete),
/// `false` on error.
///
/// Replaces C `source_setup_stream(service, session)`.
pub async fn source_setup_stream(
    service: &mut BtdService,
    session: Option<Arc<TokioMutex<AvdtpSession>>>,
) -> bool {
    let source_arc = match get_source(service) {
        Some(s) => s,
        None => {
            error!("source_setup_stream: no source state");
            btd_error(0, "source_setup_stream: no source state");
            return false;
        }
    };

    let device_path = {
        let src = source_arc.lock().unwrap();
        src.device_path.clone()
    };
    debug!(path = %device_path, "source_setup_stream");
    btd_debug(0, &format!("source_setup_stream: {device_path}"));

    // Obtain or reuse the AVDTP session.
    let session_arc = if let Some(s) = session {
        // Use the provided session.
        {
            let mut src = source_arc.lock().unwrap();
            if src.session.is_none() {
                src.session = Some(Arc::clone(&s));
            }
        }
        s
    } else {
        // Try to reuse an existing session from Source.
        let existing = {
            let src = source_arc.lock().unwrap();
            src.session.clone()
        };
        if let Some(s) = existing {
            s
        } else {
            // Attempt to get/create a session via the A2DP layer.
            // This requires the protocol-layer Arc<BtdDevice>.
            let proto_dev = {
                let src = source_arc.lock().unwrap();
                src.proto_device.clone()
            };
            match proto_dev {
                Some(dev) => match a2dp_avdtp_get(&dev).await {
                    Ok(s) => {
                        {
                            let mut src = source_arc.lock().unwrap();
                            src.session = Some(Arc::clone(&s));
                        }
                        s
                    }
                    Err(e) => {
                        error!(
                            path = %device_path,
                            error = %e,
                            "source_setup_stream: a2dp_avdtp_get failed"
                        );
                        btd_error(0, &format!("source_setup_stream: a2dp_avdtp_get failed: {e}"));
                        return false;
                    }
                },
                None => {
                    error!(
                        path = %device_path,
                        "source_setup_stream: no protocol device available"
                    );
                    btd_error(
                        0,
                        &format!("source_setup_stream: no protocol device for {device_path}"),
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
        let mut src = source_arc.lock().unwrap();
        if src.proto_device.is_none() {
            src.proto_device = Some(dev);
        }
    }

    // Get the protocol device for a2dp calls.
    let proto_dev = {
        let src = source_arc.lock().unwrap();
        match src.proto_device.clone() {
            Some(d) => d,
            None => {
                error!(path = %device_path, "source_setup_stream: missing proto device");
                btd_error(0, "source_setup_stream: missing proto device");
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
                "source_setup_stream: no A2DP channel found"
            );
            btd_error(0, &format!("source_setup_stream: no A2DP channel for {device_path}"));
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
                "source_setup_stream: discovery failed"
            );
            btd_error(0, &format!("source_setup_stream: discovery failed: {e}"));
            return false;
        }
    };

    debug!(
        path = %device_path,
        count = remote_seps.len(),
        "source_setup_stream: discovered remote SEPs"
    );

    if remote_seps.is_empty() {
        error!(
            path = %device_path,
            "source_setup_stream: no remote SEPs discovered"
        );
        btd_error(0, &format!("source_setup_stream: no remote SEPs for {device_path}"));
        return false;
    }

    // Step 2: Find a matching local Source SEP and select capabilities.
    //
    // Iterate the A2DP server's SEPs, filtering for Source-type only, and
    // attempt codec negotiation via a2dp_select_capabilities.  This call
    // finds the best matching remote SEP for the local SEP's codec.
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
        // Check if this is a Source SEP.
        let is_source = {
            let sep_guard = sep_candidate.lock().await;
            sep_guard.sep_type() == AvdtpSepType::Source
        };
        if !is_source {
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
            ch_guard.remote_seps().iter().find(|r| r.codec == codec).map(|r| r.seid).unwrap_or(1)
        };

        debug!(
            path = %device_path,
            rsep_seid,
            caps_len = caps.len(),
            "source_setup_stream: configuring stream"
        );

        // Step 3: Configure the stream.
        match a2dp_config(&channel, sep_candidate, rsep_seid, &caps).await {
            Ok(stream_idx) => {
                debug!(
                    path = %device_path,
                    stream_idx,
                    "source_setup_stream: stream configured"
                );
                btd_debug(0, &format!("source_setup_stream: stream configured idx={stream_idx}"));

                // Store the stream index.
                {
                    let mut src = source_arc.lock().unwrap();
                    src.stream_idx = Some(stream_idx);
                }

                // Register a per-stream callback for authoritative state
                // tracking.
                {
                    let mut sess = session_arc.lock().await;
                    if let Some(stream) = sess.streams_mut().get_mut(stream_idx) {
                        let weak = Arc::downgrade(&source_arc);
                        avdtp_stream_add_cb(
                            stream,
                            Box::new(move |old_st, new_st| {
                                if let Some(src_arc) = weak.upgrade() {
                                    if let Ok(mut src) = src_arc.lock() {
                                        handle_stream_state_change(&mut src, old_st, new_st);
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
                    "source_setup_stream: a2dp_config failed for SEP"
                );
                btd_error(0, &format!("source_setup_stream: a2dp_config failed: {e}"));
                continue; // Try next SEP.
            }
        }
    }

    if !configured {
        error!(
            path = %device_path,
            "source_setup_stream: no SEP could be configured"
        );
        btd_error(0, &format!("source_setup_stream: no SEP configured for {device_path}"));
    }

    configured
}

/// Associate a new AVDTP stream with the A2DP Source endpoint.
///
/// Called by the A2DP/media layer when a remote sink connects and an AVDTP
/// stream is established.  Stores the session and stream reference, and
/// registers a per-stream state callback.
///
/// Returns `true` on success.
///
/// Replaces C `source_new_stream(service, session, stream)`.
pub async fn source_new_stream(
    service: &mut BtdService,
    session: Arc<TokioMutex<AvdtpSession>>,
    stream_idx: usize,
) -> bool {
    let source_arc = match get_source(service) {
        Some(s) => s,
        None => {
            error!("source_new_stream: no source state");
            btd_error(0, "source_new_stream: no source state");
            return false;
        }
    };

    let device_path = {
        let src = source_arc.lock().unwrap();
        src.device_path.clone()
    };
    debug!(
        path = %device_path,
        stream_idx,
        "source_new_stream"
    );
    btd_debug(0, &format!("source_new_stream: {device_path} stream_idx={stream_idx}"));

    // Extract the protocol-layer device from the session and cache it.
    let proto_dev = {
        let sess = session.lock().await;
        sess.device().clone()
    };

    // Store the session and stream index.
    {
        let mut src = source_arc.lock().unwrap();
        src.session = Some(Arc::clone(&session));
        src.stream_idx = Some(stream_idx);
        if src.proto_device.is_none() {
            src.proto_device = Some(proto_dev);
        }
    }

    // Register a per-stream state callback.
    {
        let mut sess = session.lock().await;
        if let Some(stream) = sess.streams_mut().get_mut(stream_idx) {
            let weak = Arc::downgrade(&source_arc);
            avdtp_stream_add_cb(
                stream,
                Box::new(move |old_st, new_st| {
                    if let Some(src_arc) = weak.upgrade() {
                        if let Ok(mut src) = src_arc.lock() {
                            handle_stream_state_change(&mut src, old_st, new_st);
                        }
                    }
                }),
            );
        } else {
            error!(
                path = %device_path,
                stream_idx,
                "source_new_stream: invalid stream index"
            );
            btd_error(0, &format!("source_new_stream: invalid stream index {stream_idx}"));
            return false;
        }
    }

    true
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_state_display() {
        assert_eq!(format!("{}", SourceState::Disconnected), "disconnected");
        assert_eq!(format!("{}", SourceState::Connecting), "connecting");
        assert_eq!(format!("{}", SourceState::Connected), "connected");
        assert_eq!(format!("{}", SourceState::Playing), "playing");
    }

    #[test]
    fn source_state_eq() {
        assert_eq!(SourceState::Disconnected, SourceState::Disconnected);
        assert_ne!(SourceState::Disconnected, SourceState::Playing);
    }

    #[test]
    fn callback_add_remove() {
        let id = source_add_state_cb("/test/device", Box::new(|_old, _new| {}));
        assert!(id > 0);
        assert!(source_remove_state_cb(id));
        assert!(!source_remove_state_cb(id)); // already removed
    }

    #[test]
    fn callback_remove_nonexistent() {
        assert!(!source_remove_state_cb(999_999));
    }
}
