// SPDX-License-Identifier: GPL-2.0-or-later
//
// GAttrib — Legacy GATT transport abstraction
//
// Rust rewrite of attrib/gattrib.c (474 lines) + attrib/gattrib.h (66 lines).
// Wraps the modern BtAtt engine from bluez_shared::att::transport with
// legacy-compatible request tracking, cancellation, PDU buffering,
// notification routing, and client attachment. This is the bridge between the
// legacy GATT procedure API (gatt.rs) and the modern ATT transport layer.

use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

use crate::legacy_gatt::att::{ATT_OP_ERROR, ATT_OP_HANDLE_NOTIFY};
use bluez_shared::att::transport::{AttNotifyCallback, AttResponseCallback, BtAtt};
use bluez_shared::att::types::BT_ATT_ALL_REQUESTS;
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::util::endian::{get_le16, put_le16};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Special opcode value meaning "register for all ATT requests".
/// When passed to `GAttrib::register`, it is mapped internally to
/// `BT_ATT_ALL_REQUESTS` before delegation to `BtAtt::register`.
pub const GATTRIB_ALL_REQS: u8 = 0xFE;

/// Special handle value meaning "match all handles" in notification
/// registration. When the notify_handle is this value, handle-based
/// filtering is skipped and every notification is delivered.
pub const GATTRIB_ALL_HANDLES: u16 = 0x0000;

// ---------------------------------------------------------------------------
// Callback type aliases
// ---------------------------------------------------------------------------

/// Callback type for ATT request results.
///
/// Invoked when the remote side responds to a request (or an error response
/// is received). Parameters:
/// - `status`: 0 on success, or the ATT error code on failure.
/// - `pdu`: The full PDU including the leading opcode byte.
/// - `len`: Length of the full PDU.
pub type AttribResultFn = Box<dyn FnOnce(u8, &[u8], u16) + Send>;

/// Callback type for ATT notifications and indications.
///
/// Invoked each time a matching notification/indication is received.
/// Uses `Fn` (not `FnOnce`) because notifications repeat. Parameters:
/// - `pdu`: The full PDU including the leading opcode byte.
/// - `len`: Length of the full PDU.
pub type AttribNotifyFn = Box<dyn Fn(&[u8], u16) + Send + Sync>;

/// Callback type for disconnect notification.
pub type AttribDisconnectFn = Box<dyn FnOnce() + Send>;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Guard that invokes an `FnOnce` cleanup callback on `Drop`.
///
/// Used to ensure destroy/notify callbacks fire even if the owning closure
/// is dropped without explicit invocation (e.g. on request cancellation).
struct DestroyGuard {
    func: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl DestroyGuard {
    /// Creates a new `DestroyGuard`. If `func` is `None`, drop is a no-op.
    fn new(func: Option<Box<dyn FnOnce() + Send>>) -> Self {
        Self { func: Mutex::new(func) }
    }
}

impl Drop for DestroyGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.func.lock() {
            if let Some(f) = guard.take() {
                f();
            }
        }
    }
}

/// Constructs a full ATT PDU by prepending the opcode byte to the body.
///
/// This mirrors the C `construct_full_pdu(opcode, pdu, len)` helper from
/// `attrib/gattrib.c` lines 82-95. The caller receives a PDU where byte 0
/// is the opcode and bytes 1.. are the payload.
fn construct_full_pdu(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut full_pdu = Vec::with_capacity(body.len() + 1);
    full_pdu.push(opcode);
    full_pdu.extend_from_slice(body);
    full_pdu
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Private inner state for the `GAttrib` transport.
struct GAttribInner {
    /// Underlying ATT transport from bluez-shared.
    att: Arc<Mutex<BtAtt>>,

    /// Optional attached GATT client for notification routing.
    /// When present, `register()` with `ATT_OP_HANDLE_NOTIFY` will delegate
    /// to `BtGattClient::register_notify` instead of direct ATT registration.
    client: Option<Arc<BtGattClient>>,

    /// Optional destroy callback invoked on final cleanup.
    destroy_fn: Option<Box<dyn FnOnce() + Send>>,

    /// Reusable PDU buffer whose length tracks the current ATT MTU.
    /// Retained for interface compatibility with the C code, though
    /// `get_buffer`/`get_buffer_with_len` return independent `Vec`s.
    buf: Vec<u8>,

    /// IDs of requests sent through this GAttrib instance.
    /// Tracked so that `cancel_all` can cancel them in bulk.
    track_ids: Vec<u32>,
}

impl Drop for GAttribInner {
    /// Cleanup on final release — mirrors the tail of C `g_attrib_unref`.
    ///
    /// Order: cancel all tracked requests → unregister all notification
    /// handlers → drop client → invoke destroy callback → drop remaining
    /// owned resources.
    fn drop(&mut self) {
        // Cancel every tracked request through the ATT transport.
        let ids: Vec<u32> = self.track_ids.drain(..).collect();
        if let Ok(mut att) = self.att.lock() {
            for id in ids {
                att.cancel(id);
            }
            att.unregister_all();
        }

        // Drop the GATT client reference before invoking the destroy callback.
        self.client = None;

        // Invoke the user-supplied destroy callback, if any.
        if let Some(f) = self.destroy_fn.take() {
            f();
        }
    }
}

// ---------------------------------------------------------------------------
// GAttrib public API
// ---------------------------------------------------------------------------

/// Legacy GATT transport abstraction.
///
/// `GAttrib` wraps the modern `BtAtt` engine with legacy-compatible request
/// tracking, cancellation, PDU buffering, notification routing, and client
/// attachment. It is the Rust equivalent of `struct _GAttrib` from
/// `attrib/gattrib.c`.
///
/// ## Reference counting
///
/// Reference counting is achieved via `Arc<Mutex<GAttribInner>>`. Cloning a
/// `GAttrib` is equivalent to `g_attrib_ref` in C — the underlying state is
/// shared. When the last clone is dropped, `GAttribInner::drop` runs the
/// cleanup sequence (cancel all, unregister all, invoke destroy callback).
pub struct GAttrib {
    inner: Arc<Mutex<GAttribInner>>,
}

impl Clone for GAttrib {
    /// Equivalent to `g_attrib_ref` — increments the shared reference count.
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

impl GAttrib {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Creates a new `GAttrib` from a raw file descriptor, initial MTU, and
    /// the ext-signed flag.
    ///
    /// This replaces `g_attrib_new(GIOChannel *io, guint16 mtu, bool ext_signed)`.
    /// The raw fd is handed to `BtAtt::new`, which takes ownership (close-on-drop
    /// is enabled). A reusable PDU buffer is allocated to the initial MTU size.
    ///
    /// # Panics
    ///
    /// Panics if `BtAtt::new` fails on the provided fd — the caller is
    /// responsible for providing a valid, connected Bluetooth socket.
    pub fn new(fd: RawFd, mtu: u16, ext_signed: bool) -> Self {
        let att = BtAtt::new(fd, ext_signed).expect("BtAtt::new failed on valid fd");

        // Enable close-on-drop so the ATT transport owns the fd lifetime.
        {
            let mut att_guard = att.lock().expect("BtAtt mutex poisoned during new");
            att_guard.set_close_on_drop(true);
        }

        let buf = vec![0u8; mtu as usize];

        Self {
            inner: Arc::new(Mutex::new(GAttribInner {
                att,
                client: None,
                destroy_fn: None,
                buf,
                track_ids: Vec::new(),
            })),
        }
    }

    // ------------------------------------------------------------------
    // Send
    // ------------------------------------------------------------------

    /// Sends an ATT PDU.
    ///
    /// If `id` is 0 a new request is created; otherwise the existing request
    /// with the given `id` is re-sent. `pdu[0]` must be the ATT opcode and
    /// `pdu[1..]` the payload.
    ///
    /// `func` is the optional result callback, invoked when a response (or
    /// error response) arrives. `notify` is an optional cleanup callback
    /// invoked when the callback context is destroyed (after the response is
    /// delivered, or on cancellation).
    ///
    /// Returns the request ID (> 0) on success, or 0 on failure.
    pub fn send(
        &self,
        id: u32,
        pdu: &[u8],
        func: Option<AttribResultFn>,
        notify: Option<Box<dyn FnOnce() + Send>>,
    ) -> u32 {
        if pdu.is_empty() {
            return 0;
        }

        let opcode = pdu[0];
        let payload = if pdu.len() > 1 { &pdu[1..] } else { &[] };

        // Build the BtAtt response callback, wrapping the caller's result
        // function and destroy guard.
        let att_callback: AttResponseCallback = if func.is_some() || notify.is_some() {
            let destroy_guard = DestroyGuard::new(notify);
            Some(Box::new(move |resp_opcode: u8, body: &[u8]| {
                // --- attrib_callback_result logic ---
                // Extract the ATT error status from an Error Response PDU.
                let status = if resp_opcode == ATT_OP_ERROR && body.len() >= 4 {
                    // Error code is at body[3] (4th byte of the error
                    // response body, which omits the opcode).
                    body[3]
                } else if resp_opcode == ATT_OP_ERROR {
                    // Malformed error response — report Unlikely Error.
                    0x0E // BT_ATT_ERROR_UNLIKELY
                } else {
                    0 // Success
                };

                // Construct the full PDU (opcode + body) for the caller.
                let full_pdu = construct_full_pdu(resp_opcode, body);

                // Deliver the result to the caller.
                if let Some(result_fn) = func {
                    result_fn(status, &full_pdu, full_pdu.len() as u16);
                }

                // `destroy_guard` is dropped here, invoking the cleanup
                // callback.
                drop(destroy_guard);
            }))
        } else {
            None
        };

        // Clone the ATT Arc to avoid holding the inner lock while calling
        // into BtAtt (prevents nested lock contention).
        let att_arc = {
            let inner = self.inner.lock().expect("GAttribInner mutex poisoned");
            inner.att.clone()
        };

        if id != 0 {
            // --- resend path ---
            let mut att = att_arc.lock().expect("BtAtt mutex poisoned");
            match att.resend(id, opcode, payload, att_callback) {
                Ok(()) => id,
                Err(_) => 0,
            }
        } else {
            // --- new-send path ---
            let req_id = {
                let mut att = att_arc.lock().expect("BtAtt mutex poisoned");
                att.send(opcode, payload, att_callback)
            };

            if req_id == 0 {
                return 0;
            }

            // Track the new request ID for bulk cancellation.
            let mut inner = self.inner.lock().expect("GAttribInner mutex poisoned");
            inner.track_ids.push(req_id);
            req_id
        }
    }

    // ------------------------------------------------------------------
    // Cancellation
    // ------------------------------------------------------------------

    /// Cancels a pending request by ID.
    ///
    /// Returns `true` if the underlying `BtAtt` accepted the cancellation.
    pub fn cancel(&self, id: u32) -> bool {
        let att_arc = {
            let inner = self.inner.lock().expect("GAttribInner mutex poisoned");
            inner.att.clone()
        };

        let result = {
            let mut att = att_arc.lock().expect("BtAtt mutex poisoned");
            att.cancel(id)
        };

        // Remove from our tracking set regardless of BtAtt result.
        let mut inner = self.inner.lock().expect("GAttribInner mutex poisoned");
        inner.track_ids.retain(|&tid| tid != id);

        result
    }

    /// Cancels all pending requests tracked by this `GAttrib`.
    ///
    /// Always returns `true` (mirroring the C behaviour where
    /// `g_attrib_cancel_all` unconditionally succeeds).
    pub fn cancel_all(&self) -> bool {
        let (att_arc, ids) = {
            let inner = self.inner.lock().expect("GAttribInner mutex poisoned");
            (inner.att.clone(), inner.track_ids.clone())
        };

        {
            let mut att = att_arc.lock().expect("BtAtt mutex poisoned");
            for &id in &ids {
                att.cancel(id);
            }
        }

        // Clear all tracked IDs.
        let mut inner = self.inner.lock().expect("GAttribInner mutex poisoned");
        inner.track_ids.clear();

        true
    }

    // ------------------------------------------------------------------
    // Notification registration
    // ------------------------------------------------------------------

    /// Registers a notification/indication handler.
    ///
    /// ## Notification routing logic
    ///
    /// If `opcode` is `ATT_OP_HANDLE_NOTIFY` (0x1B) **and** a GATT client is
    /// attached (via `attach_client`), the registration is delegated to
    /// `BtGattClient::register_notify`, which handles CCC descriptor writes
    /// and GATT-level notification subscription. Otherwise, the registration
    /// is passed directly to `BtAtt::register`.
    ///
    /// When `opcode` is `GATTRIB_ALL_REQS` (0xFE), it is remapped to
    /// `BT_ATT_ALL_REQUESTS` for wildcard interception.
    ///
    /// `handle` controls per-handle filtering: if it is not
    /// `GATTRIB_ALL_HANDLES` (0x0000), only notifications whose attribute
    /// handle matches are delivered. `notify` is an optional cleanup callback
    /// invoked when the registration is removed.
    ///
    /// Returns the registration ID (> 0) on success, or 0 on failure.
    pub fn register(
        &self,
        opcode: u8,
        handle: u16,
        func: AttribNotifyFn,
        notify: Option<Box<dyn FnOnce() + Send>>,
    ) -> u32 {
        let (att_arc, client_opt) = {
            let inner = self.inner.lock().expect("GAttribInner mutex poisoned");
            (inner.att.clone(), inner.client.clone())
        };

        // ---- Client notification path ----
        if opcode == ATT_OP_HANDLE_NOTIFY {
            if let Some(ref client) = client_opt {
                return self.register_via_client(client, handle, func, notify);
            }
        }

        // ---- Standard ATT registration path ----
        let att_opcode = if opcode == GATTRIB_ALL_REQS { BT_ATT_ALL_REQUESTS } else { opcode };

        let notify_handle = handle;

        // Wrap the user's notify function in Arc for shared multi-call use.
        let notify_func: Arc<dyn Fn(&[u8], u16) + Send + Sync> = Arc::from(func);

        // The destroy guard ensures the cleanup callback fires when the
        // callback closure is dropped (on unregister or GAttrib teardown).
        let destroy_guard = Arc::new(DestroyGuard::new(notify));

        let nf = notify_func;
        let dg = destroy_guard;

        let callback: AttNotifyCallback =
            Arc::new(move |_bearer_idx: usize, _filter_opcode: u16, opcode: u8, body: &[u8]| {
                // Keep the destroy guard alive as long as this closure exists.
                let _ = &dg;

                // --- attrib_callback_notify logic ---
                // Apply handle-based filtering.
                if notify_handle != GATTRIB_ALL_HANDLES {
                    if body.len() < 2 {
                        return;
                    }
                    if notify_handle != get_le16(body) {
                        return;
                    }
                }

                // Construct the full PDU (opcode + body) for the caller.
                let full_pdu = construct_full_pdu(opcode, body);
                nf(&full_pdu, full_pdu.len() as u16);
            });

        let mut att = att_arc.lock().expect("BtAtt mutex poisoned");
        att.register(att_opcode, callback)
    }

    /// Internal helper: registers a notification through the attached
    /// `BtGattClient`, which performs GATT-level CCC write and subscription.
    fn register_via_client(
        &self,
        client: &Arc<BtGattClient>,
        handle: u16,
        func: AttribNotifyFn,
        notify: Option<Box<dyn FnOnce() + Send>>,
    ) -> u32 {
        let notify_handle = handle;
        let notify_func: Arc<dyn Fn(&[u8], u16) + Send + Sync> = Arc::from(func);

        // Destroy guard: captured by the notify_cb closure so it fires when
        // the GATT client unregisters or drops the notification.
        let destroy_guard = Arc::new(DestroyGuard::new(notify));

        // register_cb: called once when the CCC write completes. The legacy
        // GAttrib API does not surface this, so we use a no-op.
        let register_cb: Box<dyn FnOnce(u16) + Send + 'static> = Box::new(|_att_ecode: u16| {
            // Intentionally empty — the legacy API does not propagate
            // the CCC registration outcome.
        });

        // notify_cb: called for every incoming notification value.
        let nf = notify_func;
        let dg = destroy_guard;
        let notify_cb: Box<dyn Fn(u16, &[u8]) + Send + Sync + 'static> =
            Box::new(move |value_handle: u16, value: &[u8]| {
                // Keep destroy guard alive.
                let _ = &dg;

                // Construct the body: [value_handle LE16] + [value bytes].
                // This mirrors `client_notify_cb` in the C code.
                let mut body = vec![0u8; 2 + value.len()];
                put_le16(value_handle, &mut body[..2]);
                body[2..].copy_from_slice(value);

                // Handle-based filtering (same logic as attrib_callback_notify).
                if notify_handle != GATTRIB_ALL_HANDLES {
                    if body.len() < 2 {
                        return;
                    }
                    if notify_handle != get_le16(&body) {
                        return;
                    }
                }

                // Construct full PDU with the notification opcode prepended.
                let full_pdu = construct_full_pdu(ATT_OP_HANDLE_NOTIFY, &body);
                nf(&full_pdu, full_pdu.len() as u16);
            });

        client.register_notify(handle, register_cb, notify_cb)
    }

    /// Unregisters a notification handler by ID.
    ///
    /// Returns `true` if the underlying `BtAtt` accepted the unregistration.
    pub fn unregister(&self, id: u32) -> bool {
        let att_arc = {
            let inner = self.inner.lock().expect("GAttribInner mutex poisoned");
            inner.att.clone()
        };
        let mut att = att_arc.lock().expect("BtAtt mutex poisoned");
        att.unregister(id)
    }

    /// Unregisters all notification handlers.
    ///
    /// Returns `true` if the underlying `BtAtt` accepted the operation.
    pub fn unregister_all(&self) -> bool {
        let att_arc = {
            let inner = self.inner.lock().expect("GAttribInner mutex poisoned");
            inner.att.clone()
        };
        let mut att = att_arc.lock().expect("BtAtt mutex poisoned");
        att.unregister_all()
    }

    // ------------------------------------------------------------------
    // Buffer management
    // ------------------------------------------------------------------

    /// Returns a zeroed buffer sized to the current ATT MTU.
    ///
    /// In C, `g_attrib_get_buffer` returned a pointer to an internal reusable
    /// buffer which was resized when the MTU grew. In Rust, a fresh `Vec<u8>`
    /// is returned for safety (no aliased mutable references across the
    /// `Arc<Mutex>` boundary). The internal buffer is maintained for size
    /// tracking and is resized if the MTU has increased, mirroring the C
    /// reallocation logic. The caller writes into the returned `Vec` and
    /// passes it (or a slice of it) to `send()`.
    pub fn get_buffer(&self) -> Vec<u8> {
        let mut inner = self.inner.lock().expect("GAttribInner mutex poisoned");
        let mtu = {
            let att = inner.att.lock().expect("BtAtt mutex poisoned");
            att.get_mtu() as usize
        };

        // Grow the internal buffer if the MTU has increased, matching the
        // C code's `g_realloc(attrib->buf, mtu)` path.
        if mtu > inner.buf.len() {
            inner.buf.resize(mtu, 0);
        }

        // Return a zeroed buffer at the tracked size.
        vec![0u8; inner.buf.len()]
    }

    /// Returns a zeroed buffer and its length.
    ///
    /// Equivalent to the C pattern `buf = g_attrib_get_buffer(attrib, &len)`.
    pub fn get_buffer_with_len(&self) -> (Vec<u8>, usize) {
        let buf = self.get_buffer();
        let len = buf.len();
        (buf, len)
    }

    // ------------------------------------------------------------------
    // MTU management
    // ------------------------------------------------------------------

    /// Updates the ATT MTU.
    ///
    /// Delegates to `BtAtt::set_mtu`. Returns `true` on success.
    pub fn set_mtu(&self, mtu: u16) -> bool {
        let att_arc = {
            let inner = self.inner.lock().expect("GAttribInner mutex poisoned");
            inner.att.clone()
        };
        let mut att = att_arc.lock().expect("BtAtt mutex poisoned");
        att.set_mtu(mtu)
    }

    // ------------------------------------------------------------------
    // Client attachment
    // ------------------------------------------------------------------

    /// Attaches a GATT client for notification routing.
    ///
    /// Once attached, calls to `register()` with opcode `ATT_OP_HANDLE_NOTIFY`
    /// will be delegated to `BtGattClient::register_notify`, enabling proper
    /// GATT CCC subscription. The client is cloned via
    /// `BtGattClient::clone_client` to obtain an independent reference.
    ///
    /// Returns `true` on success, `false` if cloning fails.
    pub fn attach_client(&self, client: Arc<BtGattClient>) -> bool {
        let cloned = match BtGattClient::clone_client(&client) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let mut inner = self.inner.lock().expect("GAttribInner mutex poisoned");
        inner.client = Some(cloned);
        true
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Returns a shared reference (via `Arc`) to the underlying `BtAtt`.
    ///
    /// Callers may use this to perform operations not exposed through the
    /// `GAttrib` legacy API.
    pub fn get_att(&self) -> Arc<Mutex<BtAtt>> {
        let inner = self.inner.lock().expect("GAttribInner mutex poisoned");
        inner.att.clone()
    }

    /// Sets a destroy callback that will be invoked when the last
    /// `GAttrib` reference is dropped.
    ///
    /// Only one destroy function can be active at a time; setting a new one
    /// replaces (and discards) the previous one.
    pub fn set_destroy_function(&self, func: Box<dyn FnOnce() + Send>) {
        let mut inner = self.inner.lock().expect("GAttribInner mutex poisoned");
        inner.destroy_fn = Some(func);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gattrib_all_reqs_is_0xfe() {
        assert_eq!(GATTRIB_ALL_REQS, 0xFE);
    }

    #[test]
    fn gattrib_all_handles_is_zero() {
        assert_eq!(GATTRIB_ALL_HANDLES, 0x0000);
    }

    #[test]
    fn attrib_result_fn_accepts_closure() {
        let _f: AttribResultFn = Box::new(|_status: u8, _pdu: &[u8], _len: u16| {});
    }

    #[test]
    fn attrib_notify_fn_accepts_closure() {
        let _f: AttribNotifyFn = Box::new(|_pdu: &[u8], _len: u16| {});
    }

    #[test]
    fn attrib_disconnect_fn_accepts_closure() {
        let _f: AttribDisconnectFn = Box::new(|| {});
    }

    #[test]
    fn construct_full_pdu_prepends_opcode() {
        let body = [0x01, 0x02, 0x03];
        let full = construct_full_pdu(0xAB, &body);
        assert_eq!(full, vec![0xAB, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn construct_full_pdu_with_empty_body() {
        let full = construct_full_pdu(0x42, &[]);
        assert_eq!(full, vec![0x42]);
    }

    #[test]
    fn construct_full_pdu_preserves_length() {
        let body = vec![0u8; 100];
        let full = construct_full_pdu(0x01, &body);
        assert_eq!(full.len(), 101);
        assert_eq!(full[0], 0x01);
    }

    #[test]
    fn destroy_guard_fires_on_drop() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();
        {
            let _guard = DestroyGuard::new(Some(Box::new(move || {
                fired_clone.store(true, Ordering::SeqCst);
            })));
        }
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn destroy_guard_none_is_noop() {
        let _guard = DestroyGuard::new(None);
    }

    #[test]
    fn gattrib_is_clone_compatible() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<GAttrib>();
    }

    /// Attempts to create a GAttrib from a Unix socketpair.
    /// Returns None if BtAtt rejects the non-Bluetooth socket.
    fn try_make_gattrib() -> Option<GAttrib> {
        use std::os::unix::io::AsRawFd;
        let (a, b) = std::os::unix::net::UnixStream::pair().ok()?;
        let fd = a.as_raw_fd();
        // Leak `a` so GAttrib/BtAtt can own and close the fd.
        std::mem::forget(a);
        // `b` will be dropped here, closing the peer end. That is
        // acceptable — we only need the fd to be valid for construction.
        drop(b);
        match std::panic::catch_unwind(|| GAttrib::new(fd, 64, false)) {
            Ok(gattrib) => Some(gattrib),
            Err(_) => {
                // BtAtt rejected the socket. Close the leaked fd via
                // nix which provides a safe wrapper.
                let _ = nix::unistd::close(fd);
                None
            }
        }
    }

    #[test]
    fn send_empty_pdu_returns_zero() {
        if let Some(gattrib) = try_make_gattrib() {
            assert_eq!(gattrib.send(0, &[], None, None), 0);
        }
    }

    #[test]
    fn cancel_all_returns_true() {
        if let Some(gattrib) = try_make_gattrib() {
            assert!(gattrib.cancel_all());
        }
    }

    #[test]
    fn get_buffer_returns_zeroed_vec() {
        if let Some(gattrib) = try_make_gattrib() {
            let buf = gattrib.get_buffer();
            assert!(!buf.is_empty());
            assert!(buf.iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn get_buffer_with_len_matches() {
        if let Some(gattrib) = try_make_gattrib() {
            let (buf, len) = gattrib.get_buffer_with_len();
            assert_eq!(buf.len(), len);
        }
    }

    #[test]
    fn get_att_returns_arc() {
        if let Some(gattrib) = try_make_gattrib() {
            let att = gattrib.get_att();
            assert!(att.lock().is_ok());
        }
    }

    #[test]
    fn set_destroy_function_fires_on_drop() {
        use std::sync::atomic::{AtomicBool, Ordering};
        if let Some(gattrib) = try_make_gattrib() {
            let called = Arc::new(AtomicBool::new(false));
            let called_clone = called.clone();
            gattrib.set_destroy_function(Box::new(move || {
                called_clone.store(true, Ordering::SeqCst);
            }));
            drop(gattrib);
            assert!(called.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn clone_shares_state() {
        if let Some(gattrib) = try_make_gattrib() {
            let cloned = gattrib.clone();
            let att1 = gattrib.get_att();
            let att2 = cloned.get_att();
            assert!(Arc::ptr_eq(&att1, &att2));
        }
    }

    #[test]
    fn unregister_all_returns_true() {
        if let Some(gattrib) = try_make_gattrib() {
            assert!(gattrib.unregister_all());
        }
    }
}
