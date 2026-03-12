// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ — Bluetooth protocol stack for Linux
//
// Copyright (C) 2024 BlueZ contributors
//
//! GATT Server Engine.
//!
//! Complete Rust rewrite of `src/shared/gatt-server.c` (1906 lines) and
//! `src/shared/gatt-server.h` (49 lines). This module implements the GATT
//! server that:
//!
//! - Registers ATT request handlers for all 14 ATT PDU opcodes
//! - Dispatches incoming ATT PDUs to the local [`GattDb`]
//! - Enforces attribute permissions and security requirements
//! - Sends notifications (single and batched NFY_MULT) and indications
//! - Manages the Prepare Write queue for long/reliable writes
//!
//! # Architecture
//!
//! - [`BtGattServer`] is the public handle, shared via `Arc`.
//! - Internal mutable state lives inside `Arc<Mutex<BtGattServerInner>>`.
//! - All `callback + user_data + destroy` patterns from C are replaced
//!   with Rust closures (`Box<dyn Fn(…)>`).
//! - `struct queue *prep_queue` → `Vec<PrepWriteData>`
//! - `timeout_add(NFY_MULT_TIMEOUT, …)` → `tokio::time::sleep` in a
//!   spawned task with `JoinHandle::abort()` for cancellation.
//! - Reference counting (`bt_gatt_server_ref/unref`) → `Arc`.

use std::sync::{Arc, Mutex};

use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, warn};

use crate::att::transport::{AttResponseCallback, BtAtt};
use crate::att::types::{
    AttSecurityLevel, BT_ATT_DEFAULT_LE_MTU, BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
    BT_ATT_ERROR_AUTHENTICATION, BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION,
    BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE, BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN,
    BT_ATT_ERROR_INVALID_HANDLE, BT_ATT_ERROR_INVALID_PDU, BT_ATT_ERROR_PREPARE_QUEUE_FULL,
    BT_ATT_ERROR_REQUEST_NOT_SUPPORTED, BT_ATT_ERROR_UNLIKELY, BT_ATT_ERROR_UNSUPPORTED_GROUP_TYPE,
    BT_ATT_MAX_VALUE_LEN, BT_ATT_OP_EXEC_WRITE_REQ, BT_ATT_OP_EXEC_WRITE_RSP,
    BT_ATT_OP_FIND_BY_TYPE_REQ, BT_ATT_OP_FIND_BY_TYPE_RSP, BT_ATT_OP_FIND_INFO_REQ,
    BT_ATT_OP_FIND_INFO_RSP, BT_ATT_OP_HANDLE_IND, BT_ATT_OP_HANDLE_NFY, BT_ATT_OP_HANDLE_NFY_MULT,
    BT_ATT_OP_MTU_REQ, BT_ATT_OP_MTU_RSP, BT_ATT_OP_PREP_WRITE_REQ, BT_ATT_OP_PREP_WRITE_RSP,
    BT_ATT_OP_READ_BLOB_REQ, BT_ATT_OP_READ_BLOB_RSP, BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
    BT_ATT_OP_READ_BY_GRP_TYPE_RSP, BT_ATT_OP_READ_BY_TYPE_REQ, BT_ATT_OP_READ_BY_TYPE_RSP,
    BT_ATT_OP_READ_MULT_REQ, BT_ATT_OP_READ_MULT_RSP, BT_ATT_OP_READ_MULT_VL_REQ,
    BT_ATT_OP_READ_MULT_VL_RSP, BT_ATT_OP_READ_REQ, BT_ATT_OP_READ_RSP, BT_ATT_OP_SIGNED_WRITE_CMD,
    BT_ATT_OP_WRITE_CMD, BT_ATT_OP_WRITE_REQ, BT_ATT_OP_WRITE_RSP, BT_ATT_PERM_READ_AUTHEN,
    BT_ATT_PERM_READ_ENCRYPT, BT_ATT_PERM_READ_MASK, BT_ATT_PERM_READ_SECURE,
    BT_ATT_PERM_WRITE_AUTHEN, BT_ATT_PERM_WRITE_ENCRYPT, BT_ATT_PERM_WRITE_MASK,
    BT_ATT_PERM_WRITE_SECURE, BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE,
};
use crate::gatt::db::{GattDb, GattDbAttribute};
use crate::util::endian::{get_le16, put_le16};
use crate::util::uuid::BtUuid;

// ---------------------------------------------------------------------------
// Constants (from gatt-server.c)
// ---------------------------------------------------------------------------

/// Maximum number of queued prepare-write entries (gatt-server.c line 30).
const DEFAULT_MAX_PREP_QUEUE_LEN: usize = 30;

/// Timeout for flushing batched NFY_MULT notifications (gatt-server.c line 31).
const NFY_MULT_TIMEOUT: Duration = Duration::from_millis(10);

/// GATT Primary Service Declaration UUID (0x2800).
const GATT_PRIM_SVC_UUID: u16 = 0x2800;

/// GATT Secondary Service Declaration UUID (0x2801).
const GATT_SND_SVC_UUID: u16 = 0x2801;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the GATT server engine.
#[derive(thiserror::Error, Debug)]
pub enum GattServerError {
    /// The ATT transport is invalid or unavailable.
    #[error("invalid ATT transport")]
    InvalidAtt,
    /// The GATT database reference is invalid.
    #[error("invalid GATT database")]
    InvalidDb,
    /// ATT handler registration failed.
    #[error("ATT handler registration failed")]
    RegistrationFailed,
    /// An ATT protocol error occurred.
    #[error("ATT error: {0:#04x}")]
    AttError(u8),
    /// Underlying transport I/O error.
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Internal data structures
// ---------------------------------------------------------------------------

/// A single queued prepare-write entry (gatt-server.c `struct prep_write_data`).
struct PrepWriteData {
    /// Attribute handle targeted by this write.
    handle: u16,
    /// Byte offset within the attribute value.
    offset: u16,
    /// Write data bytes.
    value: Vec<u8>,
    /// Whether the characteristic supports reliable writes (ext prop check).
    reliable_supported: bool,
}

/// Buffer accumulating multiple notifications for `BT_ATT_OP_HANDLE_NFY_MULT`.
///
/// Mirrors the C `struct nfy_mult_data` which is a single growing PDU buffer
/// with an offset cursor, **not** a queue of individual notifications.
struct NfyMultBuf {
    /// Accumulated PDU body bytes (handle + length + value tuples).
    pdu: Vec<u8>,
    /// Maximum capacity of the PDU body (ATT MTU − 1).
    capacity: usize,
}

/// Mutable internal state of the GATT server.
struct BtGattServerInner {
    /// Reference to the local GATT database.
    db: GattDb,
    /// Current server MTU.
    mtu: u16,
    /// Minimum acceptable encryption key size.
    min_enc_size: u8,
    /// ATT handler registration IDs (for cleanup on drop).
    handler_ids: Vec<u32>,
    /// Queued prepare-write entries.
    prep_queue: Vec<PrepWriteData>,
    /// Maximum number of prepare-write entries allowed.
    max_prep_queue_len: usize,
    /// Optional debug logging callback.
    debug_callback: Option<Box<dyn Fn(&str) + Send + Sync>>,
    /// Optional authorization callback: `(opcode, handle) -> error_code`.
    /// Returns 0 on success, ATT error code on failure.
    authorize: Option<Box<dyn Fn(u8, u16) -> u8 + Send + Sync>>,
    /// Batched notification buffer for NFY_MULT.
    nfy_mult: Option<NfyMultBuf>,
    /// Timer task handle for flushing the NFY_MULT buffer.
    nfy_mult_timer: Option<JoinHandle<()>>,
}

// ---------------------------------------------------------------------------
// BtGattServer — public API
// ---------------------------------------------------------------------------

/// GATT server engine.
///
/// Registers ATT request handlers, dispatches incoming PDUs to the local
/// [`GattDb`], enforces permissions and security, and sends
/// notifications/indications.
///
/// # Lifecycle
///
/// Created via [`BtGattServer::new`]. The server registers all 14 ATT
/// request handlers on the provided [`BtAtt`] transport. Handlers are
/// automatically unregistered when the server is dropped.
///
/// Shared ownership is achieved via `Arc<BtGattServer>` — callers clone
/// the `Arc` instead of calling `bt_gatt_server_ref()`.
pub struct BtGattServer {
    /// Shared mutable inner state.
    inner: Arc<Mutex<BtGattServerInner>>,
    /// ATT transport handle (shared with handler closures).
    att: Arc<Mutex<BtAtt>>,
}

impl BtGattServer {
    /// Create a new GATT server.
    ///
    /// Registers all 14 ATT request handlers on the provided ATT transport
    /// and initialises the prepare-write queue.
    ///
    /// # Arguments
    ///
    /// * `db` — The local GATT database to serve.
    /// * `att` — The ATT transport (shared via `Arc<Mutex<…>>`).
    /// * `mtu` — Server-side MTU. Clamped to at least `BT_ATT_DEFAULT_LE_MTU`.
    /// * `min_enc_size` — Minimum encryption key size required for
    ///   encrypted attribute access.
    ///
    /// # Errors
    ///
    /// Returns [`GattServerError::RegistrationFailed`] if any ATT handler
    /// registration fails.
    ///
    /// Mirrors `bt_gatt_server_new` (gatt-server.c lines 1807-1874).
    pub fn new(
        db: GattDb,
        att: Arc<Mutex<BtAtt>>,
        mtu: u16,
        min_enc_size: u8,
    ) -> Result<Arc<Self>, GattServerError> {
        let effective_mtu = mtu.max(BT_ATT_DEFAULT_LE_MTU);

        let inner = Arc::new(Mutex::new(BtGattServerInner {
            db,
            mtu: effective_mtu,
            min_enc_size,
            handler_ids: Vec::with_capacity(14),
            prep_queue: Vec::new(),
            max_prep_queue_len: DEFAULT_MAX_PREP_QUEUE_LEN,
            debug_callback: None,
            authorize: None,
            nfy_mult: None,
            nfy_mult_timer: None,
        }));

        let server = Arc::new(Self { inner: Arc::clone(&inner), att: Arc::clone(&att) });

        // Register all 14 ATT request/command handlers.
        Self::register_att_handlers(&server)?;

        debug!("GATT server created: mtu={}, min_enc_size={}", effective_mtu, min_enc_size);
        Ok(server)
    }

    /// Set the debug logging callback.
    ///
    /// Mirrors `bt_gatt_server_set_debug` (gatt-server.c lines 1883-1895).
    pub fn set_debug(&self, callback: impl Fn(&str) + Send + Sync + 'static) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.debug_callback = Some(Box::new(callback));
        true
    }

    /// Set the authorization callback.
    ///
    /// The callback receives `(opcode, handle)` and returns `0` on success
    /// or an ATT error code on failure.
    ///
    /// Mirrors `bt_gatt_server_set_authorize` (gatt-server.c lines 1897-1906).
    pub fn set_authorize(&self, func: impl Fn(u8, u16) -> u8 + Send + Sync + 'static) {
        let mut inner = self.inner.lock().unwrap();
        inner.authorize = Some(Box::new(func));
    }

    /// Return the current server MTU.
    ///
    /// Delegates to `bt_att_get_mtu` on the underlying ATT transport.
    ///
    /// Mirrors `bt_gatt_server_get_mtu` (gatt-server.c line 1876).
    pub fn get_mtu(&self) -> u16 {
        let att = self.att.lock().unwrap();
        att.get_mtu()
    }

    /// Return the underlying ATT transport handle.
    ///
    /// Mirrors `bt_gatt_server_get_att` (gatt-server.c line 1878).
    pub fn get_att(&self) -> Arc<Mutex<BtAtt>> {
        Arc::clone(&self.att)
    }

    /// Send a notification to the remote peer.
    ///
    /// If `use_nfy_mult` is `true` the notification is buffered and flushed
    /// either when the buffer fills or after the 10 ms NFY_MULT timer fires.
    /// Otherwise the notification is sent immediately as
    /// `BT_ATT_OP_HANDLE_NFY`.
    ///
    /// Mirrors `bt_gatt_server_send_notification` (gatt-server.c lines 1435-1481).
    pub fn send_notification(
        self: &Arc<Self>,
        handle: u16,
        value: &[u8],
        use_nfy_mult: bool,
    ) -> bool {
        if use_nfy_mult {
            self.send_nfy_mult(handle, value)
        } else {
            self.send_nfy_single(handle, value)
        }
    }

    /// Send an indication to the remote peer.
    ///
    /// The `callback` is invoked once the remote peer confirms the indication
    /// (or the operation times out / fails).
    ///
    /// Mirrors `bt_gatt_server_send_indication` (gatt-server.c lines 1483-1509).
    pub fn send_indication(
        &self,
        handle: u16,
        value: &[u8],
        callback: Option<Box<dyn FnOnce() + Send + 'static>>,
    ) -> bool {
        // Build the indication PDU: handle (2 LE bytes) + value
        let pdu_len = 2 + value.len();
        let mut pdu = vec![0u8; pdu_len];
        put_le16(handle, &mut pdu[0..2]);
        pdu[2..].copy_from_slice(value);

        let cb: AttResponseCallback = callback.map(|f| -> Box<dyn FnOnce(u8, &[u8]) + Send> {
            Box::new(move |_opcode: u8, _pdu: &[u8]| {
                f();
            })
        });

        let mut att = self.att.lock().unwrap();
        let id = att.send(BT_ATT_OP_HANDLE_IND, &pdu, cb);
        if id == 0 {
            error!("Failed to send indication for handle {:#06x}", handle);
            return false;
        }

        debug!("Sent indication for handle {:#06x}, len={}", handle, value.len());
        true
    }

    // ------------------------------------------------------------------
    // Private: single-notification send
    // ------------------------------------------------------------------

    /// Send a single `BT_ATT_OP_HANDLE_NFY` PDU.
    fn send_nfy_single(&self, handle: u16, value: &[u8]) -> bool {
        let pdu_len = 2 + value.len();
        let mut pdu = vec![0u8; pdu_len];
        put_le16(handle, &mut pdu[0..2]);
        pdu[2..].copy_from_slice(value);

        let mut att = self.att.lock().unwrap();
        let id = att.send(BT_ATT_OP_HANDLE_NFY, &pdu, None);
        if id == 0 {
            warn!("Failed to send notification for handle {:#06x}", handle);
            return false;
        }
        true
    }

    // ------------------------------------------------------------------
    // Private: NFY_MULT buffering
    // ------------------------------------------------------------------

    /// Buffer a notification for batched `BT_ATT_OP_HANDLE_NFY_MULT` delivery.
    fn send_nfy_mult(self: &Arc<Self>, handle: u16, value: &[u8]) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let mtu = inner.mtu;
        let capacity = (mtu as usize).saturating_sub(1);

        // Each entry: handle (2) + length (2) + value
        let entry_len = 4 + value.len();

        // Initialise the buffer on first use.
        let buf = inner
            .nfy_mult
            .get_or_insert_with(|| NfyMultBuf { pdu: Vec::with_capacity(capacity), capacity });

        // If this entry would overflow, flush first.
        if buf.pdu.len() + entry_len > buf.capacity {
            let flush_pdu = std::mem::take(&mut buf.pdu);
            buf.pdu = Vec::with_capacity(capacity);
            // Cancel existing timer since we are flushing now.
            if let Some(timer) = inner.nfy_mult_timer.take() {
                timer.abort();
            }
            drop(inner);
            Self::flush_nfy_mult_pdu(&self.att, &flush_pdu);
            // Re-lock to append the current entry.
            let mut inner = self.inner.lock().unwrap();
            let buf = inner.nfy_mult.as_mut().unwrap();
            Self::append_nfy_entry(buf, handle, value);
            Self::schedule_nfy_mult_timer(self, &mut inner);
            return true;
        }

        Self::append_nfy_entry(buf, handle, value);

        // Start the flush timer if not already running.
        if inner.nfy_mult_timer.is_none() {
            Self::schedule_nfy_mult_timer(self, &mut inner);
        }
        true
    }

    /// Append a single handle+len+value tuple to the NFY_MULT buffer.
    fn append_nfy_entry(buf: &mut NfyMultBuf, handle: u16, value: &[u8]) {
        let mut hdr = [0u8; 4];
        put_le16(handle, &mut hdr[0..2]);
        put_le16(value.len() as u16, &mut hdr[2..4]);
        buf.pdu.extend_from_slice(&hdr);
        buf.pdu.extend_from_slice(value);
    }

    /// Schedule (or reschedule) the 10 ms NFY_MULT flush timer.
    fn schedule_nfy_mult_timer(server: &Arc<Self>, inner: &mut BtGattServerInner) {
        if let Some(t) = inner.nfy_mult_timer.take() {
            t.abort();
        }
        let weak = Arc::downgrade(server);
        inner.nfy_mult_timer = Some(tokio::spawn(async move {
            tokio::time::sleep(NFY_MULT_TIMEOUT).await;
            if let Some(strong) = weak.upgrade() {
                strong.flush_nfy_mult();
            }
        }));
    }

    /// Flush the entire NFY_MULT buffer now.
    fn flush_nfy_mult(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.nfy_mult_timer = None;
        if let Some(buf) = inner.nfy_mult.as_mut() {
            if buf.pdu.is_empty() {
                return;
            }
            let flush_pdu = std::mem::take(&mut buf.pdu);
            let cap = buf.capacity;
            buf.pdu = Vec::with_capacity(cap);
            drop(inner);
            Self::flush_nfy_mult_pdu(&self.att, &flush_pdu);
        }
    }

    /// Send a `BT_ATT_OP_HANDLE_NFY_MULT` PDU with the given body bytes.
    fn flush_nfy_mult_pdu(att: &Arc<Mutex<BtAtt>>, pdu: &[u8]) {
        if pdu.is_empty() {
            return;
        }
        let mut att = att.lock().unwrap();
        let id = att.send(BT_ATT_OP_HANDLE_NFY_MULT, pdu, None);
        if id == 0 {
            warn!("Failed to send NFY_MULT PDU (len={})", pdu.len());
        }
    }

    // ------------------------------------------------------------------
    // Private: permission checking
    // ------------------------------------------------------------------

    /// Check attribute permissions against the current security context.
    ///
    /// Returns `0` on success or an ATT error code on failure.
    ///
    /// Mirrors `check_permissions` (gatt-server.c lines 1216-1327).
    fn check_permissions(
        inner: &BtGattServerInner,
        att: &BtAtt,
        attr: &GattDbAttribute,
        opcode: u8,
    ) -> u8 {
        let perm_raw = attr.get_permissions();
        let perm = perm_raw as u16;

        // Determine whether this is a read or write operation based on opcode.
        let is_write = matches!(
            opcode,
            BT_ATT_OP_WRITE_REQ
                | BT_ATT_OP_WRITE_CMD
                | BT_ATT_OP_SIGNED_WRITE_CMD
                | BT_ATT_OP_PREP_WRITE_REQ
                | BT_ATT_OP_EXEC_WRITE_REQ
        );

        let mask = if is_write { BT_ATT_PERM_WRITE_MASK } else { BT_ATT_PERM_READ_MASK };

        // If no relevant permission bits are set, access is allowed.
        if (perm & mask) == 0 {
            return 0;
        }

        // Retrieve current link security level and encryption key size.
        let mut enc_size: u8 = 0;
        let sec_result = att.get_security(&mut enc_size);
        let security = match sec_result {
            Ok(level) => level,
            Err(_) => {
                warn!("Failed to get security level from ATT");
                return BT_ATT_ERROR_UNLIKELY;
            }
        };

        // Map i32 security level to AttSecurityLevel.
        let sec_level = match security {
            4 => AttSecurityLevel::Fips,
            3 => AttSecurityLevel::High,
            2 => AttSecurityLevel::Medium,
            1 => AttSecurityLevel::Low,
            _ => AttSecurityLevel::Auto,
        };

        // Check SECURE permission (requires FIPS).
        let secure_bit = if is_write { BT_ATT_PERM_WRITE_SECURE } else { BT_ATT_PERM_READ_SECURE };
        if (perm & secure_bit) != 0 && sec_level < AttSecurityLevel::Fips {
            return BT_ATT_ERROR_AUTHENTICATION;
        }

        // Check AUTHEN permission (requires HIGH or above).
        let authen_bit = if is_write { BT_ATT_PERM_WRITE_AUTHEN } else { BT_ATT_PERM_READ_AUTHEN };
        if (perm & authen_bit) != 0 && sec_level < AttSecurityLevel::High {
            return BT_ATT_ERROR_AUTHENTICATION;
        }

        // Check ENCRYPT permission (requires MEDIUM or above).
        let encrypt_bit =
            if is_write { BT_ATT_PERM_WRITE_ENCRYPT } else { BT_ATT_PERM_READ_ENCRYPT };
        if (perm & encrypt_bit) != 0 {
            if sec_level < AttSecurityLevel::Medium {
                return BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION;
            }
            // Also check minimum encryption key size.
            if enc_size > 0 && enc_size < inner.min_enc_size {
                return BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE;
            }
        }

        // Call the authorize callback if one has been registered.
        if let Some(ref auth_fn) = inner.authorize {
            let handle = attr.get_handle();
            let err = auth_fn(opcode, handle);
            if err != 0 {
                return err;
            }
        }

        0
    }

    /// Validate that `offset + value_len` does not exceed `BT_ATT_MAX_VALUE_LEN`.
    fn check_length(offset: u16, value_len: u16) -> u8 {
        if (offset as u32 + value_len as u32) > BT_ATT_MAX_VALUE_LEN as u32 {
            return BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
        }
        0
    }

    // ------------------------------------------------------------------
    // Private: ATT handler registration
    // ------------------------------------------------------------------

    /// Register all 14 ATT request/command handlers on the ATT transport.
    ///
    /// Mirrors `bt_gatt_server_new` handler registration block
    /// (gatt-server.c lines 1832-1873).
    fn register_att_handlers(server: &Arc<Self>) -> Result<(), GattServerError> {
        let opcodes: &[u8] = &[
            BT_ATT_OP_MTU_REQ,
            BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
            BT_ATT_OP_READ_BY_TYPE_REQ,
            BT_ATT_OP_FIND_INFO_REQ,
            BT_ATT_OP_FIND_BY_TYPE_REQ,
            BT_ATT_OP_WRITE_REQ,
            BT_ATT_OP_WRITE_CMD,
            BT_ATT_OP_READ_REQ,
            BT_ATT_OP_READ_BLOB_REQ,
            BT_ATT_OP_READ_MULT_REQ,
            BT_ATT_OP_READ_MULT_VL_REQ,
            BT_ATT_OP_PREP_WRITE_REQ,
            BT_ATT_OP_EXEC_WRITE_REQ,
            BT_ATT_OP_SIGNED_WRITE_CMD,
        ];

        let mut ids = Vec::with_capacity(opcodes.len());
        let mut att_guard = server.att.lock().unwrap();

        for &opcode in opcodes {
            let srv = Arc::clone(server);
            // The callback signature from transport.rs AttNotifyCallback:
            // Box<dyn Fn(usize, u16, u8, &[u8]) + Send + Sync>
            // params: (channel_idx, filter_opcode, raw_opcode, pdu_body)
            let cb = Box::new(move |_chan_idx: usize, _filter: u16, raw_opcode: u8, pdu: &[u8]| {
                srv.dispatch_handler(raw_opcode, pdu);
            });

            let id = att_guard.register(opcode, cb);
            if id == 0 {
                // Unregister any previously registered handlers.
                for prev_id in &ids {
                    att_guard.unregister(*prev_id);
                }
                return Err(GattServerError::RegistrationFailed);
            }
            ids.push(id);
        }

        drop(att_guard);

        let mut inner = server.inner.lock().unwrap();
        inner.handler_ids = ids;

        Ok(())
    }

    /// Central dispatch for all ATT handler callbacks.
    fn dispatch_handler(&self, opcode: u8, pdu: &[u8]) {
        match opcode {
            BT_ATT_OP_MTU_REQ => self.handle_mtu_req(pdu),
            BT_ATT_OP_READ_BY_GRP_TYPE_REQ => self.handle_read_by_grp_type_req(pdu),
            BT_ATT_OP_READ_BY_TYPE_REQ => self.handle_read_by_type_req(pdu),
            BT_ATT_OP_FIND_INFO_REQ => self.handle_find_info_req(pdu),
            BT_ATT_OP_FIND_BY_TYPE_REQ => self.handle_find_by_type_value_req(pdu),
            BT_ATT_OP_WRITE_REQ => self.handle_write_req(pdu),
            BT_ATT_OP_WRITE_CMD | BT_ATT_OP_SIGNED_WRITE_CMD => self.handle_write_cmd(opcode, pdu),
            BT_ATT_OP_READ_REQ => self.handle_read_req(pdu),
            BT_ATT_OP_READ_BLOB_REQ => self.handle_read_blob_req(pdu),
            BT_ATT_OP_READ_MULT_REQ => self.handle_read_mult_req(pdu),
            BT_ATT_OP_READ_MULT_VL_REQ => self.handle_read_mult_vl_req(pdu),
            BT_ATT_OP_PREP_WRITE_REQ => self.handle_prep_write_req(pdu),
            BT_ATT_OP_EXEC_WRITE_REQ => self.handle_exec_write_req(pdu),
            _ => {
                warn!("Unhandled ATT opcode: {:#04x}", opcode);
            }
        }
    }

    // ------------------------------------------------------------------
    // Handler: MTU Exchange
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_MTU_REQ`.
    ///
    /// Validates the client's proposed MTU, responds with our server MTU,
    /// then negotiates the final MTU as `max(min(client, server), 23)`.
    ///
    /// Mirrors `mtu_req_handler` (gatt-server.c lines 77-96).
    fn handle_mtu_req(&self, pdu: &[u8]) {
        // PDU body is: client_rx_mtu (2 LE bytes).
        if pdu.len() < 2 {
            self.send_error(BT_ATT_OP_MTU_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let client_rx_mtu = get_le16(pdu);
        if client_rx_mtu < BT_ATT_DEFAULT_LE_MTU {
            self.send_error(BT_ATT_OP_MTU_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let inner = self.inner.lock().unwrap();
        let server_mtu = inner.mtu;
        drop(inner);

        // Respond with our server MTU value.
        let mut rsp = [0u8; 2];
        put_le16(server_mtu, &mut rsp);
        self.send_response(BT_ATT_OP_MTU_RSP, &rsp);

        // Final negotiated MTU.
        let final_mtu = client_rx_mtu.min(server_mtu).max(BT_ATT_DEFAULT_LE_MTU);

        // Update the ATT transport's MTU.
        let mut att = self.att.lock().unwrap();
        att.set_mtu(final_mtu);

        debug!(
            "MTU exchange: client={}, server={}, final={}",
            client_rx_mtu, server_mtu, final_mtu
        );
    }

    // ------------------------------------------------------------------
    // Handler: Read By Group Type
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_READ_BY_GRP_TYPE_REQ`.
    ///
    /// Iterates GATT services matching the requested group type UUID,
    /// building a response with handle ranges and service UUIDs.
    ///
    /// Mirrors `read_by_grp_type_cb` (gatt-server.c lines 98-193).
    fn handle_read_by_grp_type_req(&self, pdu: &[u8]) {
        // PDU: start_handle(2) + end_handle(2) + uuid(2 or 16)
        if pdu.len() < 6 {
            self.send_error(BT_ATT_OP_READ_BY_GRP_TYPE_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let start_handle = get_le16(pdu);
        let end_handle = get_le16(&pdu[2..]);

        if start_handle == 0 || start_handle > end_handle {
            self.send_error(
                BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
                start_handle,
                BT_ATT_ERROR_INVALID_HANDLE,
            );
            return;
        }

        // Parse the type UUID (either 2 or 16 bytes).
        let uuid_bytes = &pdu[4..];
        let type_uuid = match uuid_bytes.len() {
            2 => BtUuid::from_u16(get_le16(uuid_bytes)),
            16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(uuid_bytes);
                BtUuid::from_bytes(&arr)
            }
            _ => {
                self.send_error(
                    BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
                    start_handle,
                    BT_ATT_ERROR_INVALID_PDU,
                );
                return;
            }
        };

        // Only primary (0x2800) and secondary (0x2801) service types are
        // valid for Read By Group Type.
        match type_uuid {
            BtUuid::Uuid16(v) if v == GATT_PRIM_SVC_UUID || v == GATT_SND_SVC_UUID => {}
            _ => {
                self.send_error(
                    BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
                    start_handle,
                    BT_ATT_ERROR_UNSUPPORTED_GROUP_TYPE,
                );
                return;
            }
        }

        let inner = self.inner.lock().unwrap();
        let results = inner.db.read_by_group_type(start_handle, end_handle, &type_uuid);
        drop(inner);

        if results.is_empty() {
            self.send_error(
                BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
                start_handle,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            );
            return;
        }

        let mtu = self.get_current_mtu();
        let max_rsp_len = (mtu as usize).saturating_sub(2); // 1 opcode + 1 length byte

        // Build response entries. Each entry is: start_handle(2) + end_handle(2) + uuid_value.
        // The first attribute's value length determines the uniform entry length.
        let mut rsp = Vec::new();
        let mut entry_len: u8 = 0;

        for attr in &results {
            let service_data = attr.get_service_handles();
            let (svc_start, svc_end) = match service_data {
                Some(range) => range,
                None => continue,
            };

            // Get the service UUID as bytes.
            let _svc_uuid = match attr.get_type() {
                Some(u) => u,
                None => continue,
            };

            let value = attr.get_value();
            let current_entry_len = (4 + value.len()) as u8;

            if entry_len == 0 {
                entry_len = current_entry_len;
            } else if current_entry_len != entry_len {
                // All entries must have the same length; stop here.
                break;
            }

            // Check if adding this entry would exceed the MTU.
            if rsp.len() + (entry_len as usize) > max_rsp_len {
                break;
            }

            let mut entry = vec![0u8; entry_len as usize];
            put_le16(svc_start, &mut entry[0..2]);
            put_le16(svc_end, &mut entry[2..4]);
            if value.len() <= entry.len() - 4 {
                entry[4..4 + value.len()].copy_from_slice(&value);
            }
            rsp.extend_from_slice(&entry);
        }

        if rsp.is_empty() {
            self.send_error(
                BT_ATT_OP_READ_BY_GRP_TYPE_REQ,
                start_handle,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            );
            return;
        }

        // Prepend the length byte.
        let mut full_rsp = Vec::with_capacity(1 + rsp.len());
        full_rsp.push(entry_len);
        full_rsp.extend_from_slice(&rsp);

        self.send_response(BT_ATT_OP_READ_BY_GRP_TYPE_RSP, &full_rsp);
    }

    // ------------------------------------------------------------------
    // Handler: Read By Type
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_READ_BY_TYPE_REQ`.
    ///
    /// Reads attributes matching a type UUID within a handle range.
    /// For each matching attribute, permission-checks and reads the value.
    ///
    /// Mirrors `read_by_type_cb` (gatt-server.c lines 195-346).
    fn handle_read_by_type_req(&self, pdu: &[u8]) {
        // PDU: start_handle(2) + end_handle(2) + uuid(2 or 16)
        if pdu.len() < 6 {
            self.send_error(BT_ATT_OP_READ_BY_TYPE_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let start_handle = get_le16(pdu);
        let end_handle = get_le16(&pdu[2..]);

        if start_handle == 0 || start_handle > end_handle {
            self.send_error(BT_ATT_OP_READ_BY_TYPE_REQ, start_handle, BT_ATT_ERROR_INVALID_HANDLE);
            return;
        }

        let uuid_bytes = &pdu[4..];
        let type_uuid = match uuid_bytes.len() {
            2 => BtUuid::from_u16(get_le16(uuid_bytes)),
            16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(uuid_bytes);
                BtUuid::from_bytes(&arr)
            }
            _ => {
                self.send_error(BT_ATT_OP_READ_BY_TYPE_REQ, start_handle, BT_ATT_ERROR_INVALID_PDU);
                return;
            }
        };

        let inner = self.inner.lock().unwrap();
        let results = inner.db.read_by_type(start_handle, end_handle, &type_uuid);
        drop(inner);

        if results.is_empty() {
            self.send_error(
                BT_ATT_OP_READ_BY_TYPE_REQ,
                start_handle,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            );
            return;
        }

        let mtu = self.get_current_mtu();
        // Maximum response payload after opcode (1) + length (1).
        let max_rsp_len = (mtu as usize).saturating_sub(2);

        // Build response: each entry is handle(2) + value.
        // All entries must have the same length.
        let mut rsp = Vec::new();
        let mut entry_len: u8 = 0;

        let inner = self.inner.lock().unwrap();
        let att_guard = self.att.lock().unwrap();

        for attr in &results {
            let handle = attr.get_handle();

            // Permission check.
            let err = Self::check_permissions(&inner, &att_guard, attr, BT_ATT_OP_READ_BY_TYPE_REQ);
            if err != 0 {
                // If we haven't accumulated any entries yet, return the error.
                if rsp.is_empty() {
                    drop(att_guard);
                    drop(inner);
                    self.send_error(BT_ATT_OP_READ_BY_TYPE_REQ, handle, err);
                    return;
                }
                // Otherwise, stop and return what we have.
                break;
            }

            // Read value synchronously.
            let value = attr.get_value();

            let current_entry_len = (2 + value.len()).min(255) as u8;

            if entry_len == 0 {
                entry_len = current_entry_len;
            } else if current_entry_len != entry_len {
                break;
            }

            if rsp.len() + (entry_len as usize) > max_rsp_len {
                break;
            }

            let mut entry = vec![0u8; entry_len as usize];
            put_le16(handle, &mut entry[0..2]);
            let copy_len = value.len().min((entry_len as usize) - 2);
            entry[2..2 + copy_len].copy_from_slice(&value[..copy_len]);
            rsp.extend_from_slice(&entry);
        }

        drop(att_guard);
        drop(inner);

        if rsp.is_empty() {
            self.send_error(
                BT_ATT_OP_READ_BY_TYPE_REQ,
                start_handle,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            );
            return;
        }

        let mut full_rsp = Vec::with_capacity(1 + rsp.len());
        full_rsp.push(entry_len);
        full_rsp.extend_from_slice(&rsp);

        self.send_response(BT_ATT_OP_READ_BY_TYPE_RSP, &full_rsp);
    }

    // ------------------------------------------------------------------
    // Handler: Find Information
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_FIND_INFO_REQ`.
    ///
    /// Returns handle + UUID pairs for attributes in the requested range.
    /// Format 1 = UUID16, Format 2 = UUID128.
    ///
    /// Mirrors `find_info_cb` (gatt-server.c lines 348-425).
    fn handle_find_info_req(&self, pdu: &[u8]) {
        // PDU: start_handle(2) + end_handle(2)
        if pdu.len() < 4 {
            self.send_error(BT_ATT_OP_FIND_INFO_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let start_handle = get_le16(pdu);
        let end_handle = get_le16(&pdu[2..]);

        if start_handle == 0 || start_handle > end_handle {
            self.send_error(BT_ATT_OP_FIND_INFO_REQ, start_handle, BT_ATT_ERROR_INVALID_HANDLE);
            return;
        }

        let inner = self.inner.lock().unwrap();
        let results = inner.db.find_information(start_handle, end_handle);
        drop(inner);

        if results.is_empty() {
            self.send_error(
                BT_ATT_OP_FIND_INFO_REQ,
                start_handle,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            );
            return;
        }

        let mtu = self.get_current_mtu();
        // After opcode (1) + format (1).
        let max_rsp_len = (mtu as usize).saturating_sub(2);

        // Determine response format from first attribute's UUID type.
        let first_uuid = match results[0].get_type() {
            Some(u) => u,
            None => {
                self.send_error(BT_ATT_OP_FIND_INFO_REQ, start_handle, BT_ATT_ERROR_UNLIKELY);
                return;
            }
        };

        let (format, uuid_len): (u8, usize) = match first_uuid {
            BtUuid::Uuid16(_) => (0x01, 2),
            _ => (0x02, 16),
        };

        let entry_len = 2 + uuid_len; // handle + uuid

        let mut rsp = Vec::new();

        for attr in &results {
            let handle = attr.get_handle();
            let uuid = match attr.get_type() {
                Some(u) => u,
                None => continue,
            };

            // All entries must have the same format (UUID16 or UUID128).
            let this_format = match uuid {
                BtUuid::Uuid16(_) => 0x01u8,
                _ => 0x02u8,
            };
            if this_format != format {
                break;
            }

            if rsp.len() + entry_len > max_rsp_len {
                break;
            }

            let mut entry = vec![0u8; entry_len];
            put_le16(handle, &mut entry[0..2]);

            match uuid {
                BtUuid::Uuid16(v) => {
                    put_le16(v, &mut entry[2..4]);
                }
                _ => {
                    let bytes128 = uuid.to_uuid128_bytes();
                    entry[2..18].copy_from_slice(&bytes128);
                }
            }

            rsp.extend_from_slice(&entry);
        }

        if rsp.is_empty() {
            self.send_error(
                BT_ATT_OP_FIND_INFO_REQ,
                start_handle,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            );
            return;
        }

        let mut full_rsp = Vec::with_capacity(1 + rsp.len());
        full_rsp.push(format);
        full_rsp.extend_from_slice(&rsp);

        self.send_response(BT_ATT_OP_FIND_INFO_RSP, &full_rsp);
    }

    // ------------------------------------------------------------------
    // Handler: Find By Type Value
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_FIND_BY_TYPE_REQ`.
    ///
    /// Finds services matching a given type UUID and value, returning
    /// found handle + group end handle pairs.
    ///
    /// Mirrors `find_by_type_value_cb` (gatt-server.c lines 427-497).
    fn handle_find_by_type_value_req(&self, pdu: &[u8]) {
        // PDU: start_handle(2) + end_handle(2) + att_type(2) + value(variable)
        if pdu.len() < 6 {
            self.send_error(BT_ATT_OP_FIND_BY_TYPE_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let start_handle = get_le16(pdu);
        let end_handle = get_le16(&pdu[2..]);

        if start_handle == 0 || start_handle > end_handle {
            self.send_error(BT_ATT_OP_FIND_BY_TYPE_REQ, start_handle, BT_ATT_ERROR_INVALID_HANDLE);
            return;
        }

        let att_type = BtUuid::from_u16(get_le16(&pdu[4..]));
        let value = &pdu[6..];

        let inner = self.inner.lock().unwrap();
        let results = inner.db.find_by_type_value(start_handle, end_handle, &att_type, value);
        drop(inner);

        if results.is_empty() {
            self.send_error(
                BT_ATT_OP_FIND_BY_TYPE_REQ,
                start_handle,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            );
            return;
        }

        let mtu = self.get_current_mtu();
        let max_rsp_len = (mtu as usize).saturating_sub(1); // After opcode.

        let mut rsp = Vec::new();

        for attr in &results {
            let handle = attr.get_handle();
            let svc_handles = attr.get_service_handles();
            let (_svc_start, svc_end) = match svc_handles {
                Some(range) => range,
                None => (handle, handle),
            };

            // Each entry: found_handle(2) + group_end_handle(2)
            if rsp.len() + 4 > max_rsp_len {
                break;
            }

            let mut entry = [0u8; 4];
            put_le16(handle, &mut entry[0..2]);
            put_le16(svc_end, &mut entry[2..4]);
            rsp.extend_from_slice(&entry);
        }

        if rsp.is_empty() {
            self.send_error(
                BT_ATT_OP_FIND_BY_TYPE_REQ,
                start_handle,
                BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            );
            return;
        }

        self.send_response(BT_ATT_OP_FIND_BY_TYPE_RSP, &rsp);
    }

    // ------------------------------------------------------------------
    // Handler: Write Request
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_WRITE_REQ`.
    ///
    /// Validates the handle, checks permissions, writes to the database,
    /// and sends a Write Response on success.
    ///
    /// Mirrors `write_cb` (gatt-server.c lines 499-578).
    fn handle_write_req(&self, pdu: &[u8]) {
        // PDU: handle(2) + value(variable)
        if pdu.len() < 2 {
            self.send_error(BT_ATT_OP_WRITE_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let handle = get_le16(pdu);
        let value = &pdu[2..];

        if handle == 0 {
            self.send_error(BT_ATT_OP_WRITE_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
            return;
        }

        let err = Self::check_length(0, value.len() as u16);
        if err != 0 {
            self.send_error(BT_ATT_OP_WRITE_REQ, handle, err);
            return;
        }

        let inner = self.inner.lock().unwrap();
        let attr = match inner.db.get_attribute(handle) {
            Some(a) => a,
            None => {
                drop(inner);
                self.send_error(BT_ATT_OP_WRITE_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
                return;
            }
        };

        let att_guard = self.att.lock().unwrap();
        let perm_err = Self::check_permissions(&inner, &att_guard, &attr, BT_ATT_OP_WRITE_REQ);
        drop(att_guard);
        drop(inner);

        if perm_err != 0 {
            self.send_error(BT_ATT_OP_WRITE_REQ, handle, perm_err);
            return;
        }

        // Perform the write via the database. The completion callback sends
        // the response.
        let att_clone = Arc::clone(&self.att);
        let write_ok = attr.write(
            0,
            value,
            BT_ATT_OP_WRITE_REQ,
            Some(Arc::clone(&self.att)),
            Some(Box::new(move |_attr, err_code| {
                if err_code != 0 {
                    Self::send_error_static(
                        &att_clone,
                        BT_ATT_OP_WRITE_REQ,
                        handle,
                        err_code as u8,
                    );
                } else {
                    Self::send_response_static(&att_clone, BT_ATT_OP_WRITE_RSP, &[]);
                }
            })),
        );

        if !write_ok {
            self.send_error(BT_ATT_OP_WRITE_REQ, handle, BT_ATT_ERROR_UNLIKELY);
        }
    }

    // ------------------------------------------------------------------
    // Handler: Write Command (no response)
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_WRITE_CMD` and `BT_ATT_OP_SIGNED_WRITE_CMD`.
    ///
    /// Writes to the attribute without sending any response.
    ///
    /// Mirrors the write-command path in `write_cb` (gatt-server.c lines 580-630).
    fn handle_write_cmd(&self, opcode: u8, pdu: &[u8]) {
        if pdu.len() < 2 {
            return; // No response for commands.
        }

        let handle = get_le16(pdu);
        let value = &pdu[2..];

        if handle == 0 {
            return;
        }

        if Self::check_length(0, value.len() as u16) != 0 {
            return;
        }

        let inner = self.inner.lock().unwrap();
        let attr = match inner.db.get_attribute(handle) {
            Some(a) => a,
            None => return,
        };

        let att_guard = self.att.lock().unwrap();
        let perm_err = Self::check_permissions(&inner, &att_guard, &attr, opcode);
        drop(att_guard);
        drop(inner);

        if perm_err != 0 {
            return; // No response for commands.
        }

        // Fire-and-forget write. No completion callback sends a response.
        let _ = attr.write(0, value, opcode, Some(Arc::clone(&self.att)), None);
    }

    // ------------------------------------------------------------------
    // Handler: Read Request
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_READ_REQ`.
    ///
    /// Reads a single attribute's value and returns it.
    ///
    /// Mirrors `read_cb` (gatt-server.c lines 632-701).
    fn handle_read_req(&self, pdu: &[u8]) {
        if pdu.len() < 2 {
            self.send_error(BT_ATT_OP_READ_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let handle = get_le16(pdu);

        if handle == 0 {
            self.send_error(BT_ATT_OP_READ_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
            return;
        }

        let inner = self.inner.lock().unwrap();
        let attr = match inner.db.get_attribute(handle) {
            Some(a) => a,
            None => {
                drop(inner);
                self.send_error(BT_ATT_OP_READ_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
                return;
            }
        };

        let att_guard = self.att.lock().unwrap();
        let perm_err = Self::check_permissions(&inner, &att_guard, &attr, BT_ATT_OP_READ_REQ);
        drop(att_guard);
        drop(inner);

        if perm_err != 0 {
            self.send_error(BT_ATT_OP_READ_REQ, handle, perm_err);
            return;
        }

        // Read via the database. The completion callback sends the response.
        let att_clone = Arc::clone(&self.att);
        let mtu = self.get_current_mtu();
        let read_ok = attr.read(
            0,
            BT_ATT_OP_READ_REQ,
            Some(Arc::clone(&self.att)),
            Box::new(move |_attr: GattDbAttribute, err_code: i32, value: &[u8]| {
                if err_code != 0 {
                    Self::send_error_static(&att_clone, BT_ATT_OP_READ_REQ, handle, err_code as u8);
                } else {
                    // Truncate to MTU - 1 (for the opcode byte).
                    let max_len = (mtu as usize).saturating_sub(1);
                    let len = value.len().min(max_len);
                    Self::send_response_static(&att_clone, BT_ATT_OP_READ_RSP, &value[..len]);
                }
            }),
        );

        if !read_ok {
            self.send_error(BT_ATT_OP_READ_REQ, handle, BT_ATT_ERROR_UNLIKELY);
        }
    }

    // ------------------------------------------------------------------
    // Handler: Read Blob Request
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_READ_BLOB_REQ`.
    ///
    /// Reads an attribute's value starting at a given offset — used for
    /// long attribute reads.
    ///
    /// Mirrors `read_blob_cb` (gatt-server.c lines 703-778).
    fn handle_read_blob_req(&self, pdu: &[u8]) {
        // PDU: handle(2) + offset(2)
        if pdu.len() < 4 {
            self.send_error(BT_ATT_OP_READ_BLOB_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let handle = get_le16(pdu);
        let offset = get_le16(&pdu[2..]);

        if handle == 0 {
            self.send_error(BT_ATT_OP_READ_BLOB_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
            return;
        }

        let inner = self.inner.lock().unwrap();
        let attr = match inner.db.get_attribute(handle) {
            Some(a) => a,
            None => {
                drop(inner);
                self.send_error(BT_ATT_OP_READ_BLOB_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
                return;
            }
        };

        let att_guard = self.att.lock().unwrap();
        let perm_err = Self::check_permissions(&inner, &att_guard, &attr, BT_ATT_OP_READ_BLOB_REQ);
        drop(att_guard);
        drop(inner);

        if perm_err != 0 {
            self.send_error(BT_ATT_OP_READ_BLOB_REQ, handle, perm_err);
            return;
        }

        let att_clone = Arc::clone(&self.att);
        let mtu = self.get_current_mtu();
        let read_ok = attr.read(
            offset,
            BT_ATT_OP_READ_BLOB_REQ,
            Some(Arc::clone(&self.att)),
            Box::new(move |_attr: GattDbAttribute, err_code: i32, value: &[u8]| {
                if err_code != 0 {
                    Self::send_error_static(
                        &att_clone,
                        BT_ATT_OP_READ_BLOB_REQ,
                        handle,
                        err_code as u8,
                    );
                } else {
                    let max_len = (mtu as usize).saturating_sub(1);
                    let len = value.len().min(max_len);
                    Self::send_response_static(&att_clone, BT_ATT_OP_READ_BLOB_RSP, &value[..len]);
                }
            }),
        );

        if !read_ok {
            self.send_error(BT_ATT_OP_READ_BLOB_REQ, handle, BT_ATT_ERROR_UNLIKELY);
        }
    }

    // ------------------------------------------------------------------
    // Handler: Read Multiple Request
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_READ_MULT_REQ`.
    ///
    /// Reads multiple attributes and concatenates their values into a
    /// single response. All values are truncated to fit within the MTU.
    ///
    /// Mirrors `read_multiple_cb` for `BT_ATT_OP_READ_MULT_REQ`
    /// (gatt-server.c lines 780-880).
    fn handle_read_mult_req(&self, pdu: &[u8]) {
        // PDU: handle_1(2) + handle_2(2) + … — at least 2 handles
        if pdu.len() < 4 || pdu.len() % 2 != 0 {
            self.send_error(BT_ATT_OP_READ_MULT_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let num_handles = pdu.len() / 2;
        let mtu = self.get_current_mtu();
        let max_rsp_len = (mtu as usize).saturating_sub(1);
        let mut rsp = Vec::with_capacity(max_rsp_len);

        let inner = self.inner.lock().unwrap();
        let att_guard = self.att.lock().unwrap();

        for i in 0..num_handles {
            let handle = get_le16(&pdu[i * 2..]);

            if handle == 0 {
                drop(att_guard);
                drop(inner);
                self.send_error(BT_ATT_OP_READ_MULT_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
                return;
            }

            let attr = match inner.db.get_attribute(handle) {
                Some(a) => a,
                None => {
                    drop(att_guard);
                    drop(inner);
                    self.send_error(BT_ATT_OP_READ_MULT_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
                    return;
                }
            };

            let perm_err =
                Self::check_permissions(&inner, &att_guard, &attr, BT_ATT_OP_READ_MULT_REQ);
            if perm_err != 0 {
                drop(att_guard);
                drop(inner);
                self.send_error(BT_ATT_OP_READ_MULT_REQ, handle, perm_err);
                return;
            }

            let value = attr.get_value();
            let remaining = max_rsp_len.saturating_sub(rsp.len());
            if remaining == 0 {
                break;
            }
            let copy_len = value.len().min(remaining);
            rsp.extend_from_slice(&value[..copy_len]);
        }

        drop(att_guard);
        drop(inner);

        self.send_response(BT_ATT_OP_READ_MULT_RSP, &rsp);
    }

    // ------------------------------------------------------------------
    // Handler: Read Multiple Variable Length Request
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_READ_MULT_VL_REQ`.
    ///
    /// Variable-length multi-read (EATT). Each value in the response is
    /// preceded by a 2-byte length field.
    ///
    /// Mirrors `read_multiple_cb` for `BT_ATT_OP_READ_MULT_VL_REQ`
    /// (gatt-server.c lines 882-982).
    fn handle_read_mult_vl_req(&self, pdu: &[u8]) {
        if pdu.len() < 4 || pdu.len() % 2 != 0 {
            self.send_error(BT_ATT_OP_READ_MULT_VL_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let num_handles = pdu.len() / 2;
        let mtu = self.get_current_mtu();
        let max_rsp_len = (mtu as usize).saturating_sub(1);
        let mut rsp = Vec::with_capacity(max_rsp_len);

        let inner = self.inner.lock().unwrap();
        let att_guard = self.att.lock().unwrap();

        for i in 0..num_handles {
            let handle = get_le16(&pdu[i * 2..]);

            if handle == 0 {
                drop(att_guard);
                drop(inner);
                self.send_error(BT_ATT_OP_READ_MULT_VL_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
                return;
            }

            let attr = match inner.db.get_attribute(handle) {
                Some(a) => a,
                None => {
                    drop(att_guard);
                    drop(inner);
                    self.send_error(
                        BT_ATT_OP_READ_MULT_VL_REQ,
                        handle,
                        BT_ATT_ERROR_INVALID_HANDLE,
                    );
                    return;
                }
            };

            let perm_err =
                Self::check_permissions(&inner, &att_guard, &attr, BT_ATT_OP_READ_MULT_VL_REQ);
            if perm_err != 0 {
                drop(att_guard);
                drop(inner);
                self.send_error(BT_ATT_OP_READ_MULT_VL_REQ, handle, perm_err);
                return;
            }

            let value = attr.get_value();

            // Need at least 2 bytes for the length field.
            let remaining = max_rsp_len.saturating_sub(rsp.len());
            if remaining < 2 {
                break;
            }

            let max_val_len = remaining - 2;
            let copy_len = value.len().min(max_val_len);

            let mut len_buf = [0u8; 2];
            put_le16(copy_len as u16, &mut len_buf);
            rsp.extend_from_slice(&len_buf);
            rsp.extend_from_slice(&value[..copy_len]);
        }

        drop(att_guard);
        drop(inner);

        self.send_response(BT_ATT_OP_READ_MULT_VL_RSP, &rsp);
    }

    // ------------------------------------------------------------------
    // Handler: Prepare Write Request
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_PREP_WRITE_REQ`.
    ///
    /// Queues a write for later execution via Execute Write. Validates
    /// handle, checks permissions, and enforces the queue length limit.
    ///
    /// Mirrors `prep_write_cb` (gatt-server.c lines 984-1098).
    fn handle_prep_write_req(&self, pdu: &[u8]) {
        // PDU: handle(2) + offset(2) + value(variable)
        if pdu.len() < 4 {
            self.send_error(BT_ATT_OP_PREP_WRITE_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let handle = get_le16(pdu);
        let offset = get_le16(&pdu[2..]);
        let value = &pdu[4..];

        if handle == 0 {
            self.send_error(BT_ATT_OP_PREP_WRITE_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
            return;
        }

        let err = Self::check_length(offset, value.len() as u16);
        if err != 0 {
            self.send_error(BT_ATT_OP_PREP_WRITE_REQ, handle, err);
            return;
        }

        let mut inner = self.inner.lock().unwrap();

        // Check queue length limit.
        if inner.prep_queue.len() >= inner.max_prep_queue_len {
            drop(inner);
            self.send_error(BT_ATT_OP_PREP_WRITE_REQ, handle, BT_ATT_ERROR_PREPARE_QUEUE_FULL);
            return;
        }

        let attr = match inner.db.get_attribute(handle) {
            Some(a) => a,
            None => {
                drop(inner);
                self.send_error(BT_ATT_OP_PREP_WRITE_REQ, handle, BT_ATT_ERROR_INVALID_HANDLE);
                return;
            }
        };

        let att_guard = self.att.lock().unwrap();
        let perm_err = Self::check_permissions(&inner, &att_guard, &attr, BT_ATT_OP_PREP_WRITE_REQ);
        drop(att_guard);

        if perm_err != 0 {
            drop(inner);
            self.send_error(BT_ATT_OP_PREP_WRITE_REQ, handle, perm_err);
            return;
        }

        // Try to merge with the last queued write to the same handle at an
        // adjacent offset (contiguous write aggregation from C
        // `store_prep_data`).
        let merged = if let Some(last) = inner.prep_queue.last_mut() {
            if last.handle == handle
                && (last.offset as u32 + last.value.len() as u32) == offset as u32
            {
                last.value.extend_from_slice(value);
                true
            } else {
                false
            }
        } else {
            false
        };

        if !merged {
            // Check ext_prop for reliable write support. Look at the
            // characteristic declaration (handle - 1) for ext properties.
            let reliable_supported = Self::check_reliable_write_support(&inner.db, handle);

            inner.prep_queue.push(PrepWriteData {
                handle,
                offset,
                value: value.to_vec(),
                reliable_supported,
            });
        }

        drop(inner);

        // Respond by echoing back the handle, offset, and value.
        let mut rsp = Vec::with_capacity(4 + value.len());
        let mut hdr = [0u8; 4];
        put_le16(handle, &mut hdr[0..2]);
        put_le16(offset, &mut hdr[2..4]);
        rsp.extend_from_slice(&hdr);
        rsp.extend_from_slice(value);

        self.send_response(BT_ATT_OP_PREP_WRITE_RSP, &rsp);
    }

    /// Check whether the characteristic at `handle - 1` supports reliable
    /// writes (ext prop bit set).
    fn check_reliable_write_support(db: &GattDb, handle: u16) -> bool {
        if handle == 0 {
            return false;
        }
        if let Some(attr) = db.get_attribute(handle.wrapping_sub(1)) {
            if let Some(char_data) = attr.get_char_data() {
                return (char_data.ext_prop & (BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE as u16)) != 0;
            }
        }
        false
    }

    // ------------------------------------------------------------------
    // Handler: Execute Write Request
    // ------------------------------------------------------------------

    /// Handle `BT_ATT_OP_EXEC_WRITE_REQ`.
    ///
    /// If the flags byte is 0x01, all queued writes are applied.
    /// If 0x00, all queued writes are cancelled.
    ///
    /// For reliable writes (queue len > 1), the ext_prop check is enforced:
    /// if any queued attribute lacks `RELIABLE_WRITE`, the entire execute is
    /// rejected.
    ///
    /// Mirrors `exec_write_cb` (gatt-server.c lines 1100-1214).
    fn handle_exec_write_req(&self, pdu: &[u8]) {
        // PDU: flags(1)
        if pdu.is_empty() {
            self.send_error(BT_ATT_OP_EXEC_WRITE_REQ, 0, BT_ATT_ERROR_INVALID_PDU);
            return;
        }

        let flags = pdu[0];

        let mut inner = self.inner.lock().unwrap();
        let queue = std::mem::take(&mut inner.prep_queue);
        drop(inner);

        // Cancel: discard the queue.
        if flags == 0x00 {
            debug!("Execute write: cancelled {} queued entries", queue.len());
            self.send_response(BT_ATT_OP_EXEC_WRITE_RSP, &[]);
            return;
        }

        // Execute: apply all queued writes.
        if queue.is_empty() {
            self.send_response(BT_ATT_OP_EXEC_WRITE_RSP, &[]);
            return;
        }

        // Reliable write check: if more than one entry, all must support
        // reliable writes.
        if queue.len() > 1 {
            for entry in &queue {
                if !entry.reliable_supported {
                    self.send_error(
                        BT_ATT_OP_EXEC_WRITE_REQ,
                        entry.handle,
                        BT_ATT_ERROR_REQUEST_NOT_SUPPORTED,
                    );
                    return;
                }
            }
        }

        // Apply each queued write.
        let total = queue.len();
        let att_for_writes = Arc::clone(&self.att);

        // We process writes sequentially. Each write that has a completion
        // callback will trigger the next write (or the final response).
        // For simplicity, we process them all synchronously via the db write
        // call which will invoke the callback inline if it completes
        // synchronously.

        let inner = self.inner.lock().unwrap();
        for (idx, entry) in queue.iter().enumerate() {
            let is_last = idx == total - 1;
            let attr = match inner.db.get_attribute(entry.handle) {
                Some(a) => a,
                None => {
                    drop(inner);
                    self.send_error(
                        BT_ATT_OP_EXEC_WRITE_REQ,
                        entry.handle,
                        BT_ATT_ERROR_INVALID_HANDLE,
                    );
                    return;
                }
            };

            if is_last {
                // Last write: completion callback sends the response.
                let att_clone = Arc::clone(&att_for_writes);
                let handle = entry.handle;
                let write_ok = attr.write(
                    entry.offset,
                    &entry.value,
                    BT_ATT_OP_EXEC_WRITE_REQ,
                    Some(Arc::clone(&self.att)),
                    Some(Box::new(move |_attr, err_code| {
                        if err_code != 0 {
                            Self::send_error_static(
                                &att_clone,
                                BT_ATT_OP_EXEC_WRITE_REQ,
                                handle,
                                err_code as u8,
                            );
                        } else {
                            Self::send_response_static(&att_clone, BT_ATT_OP_EXEC_WRITE_RSP, &[]);
                        }
                    })),
                );
                if !write_ok {
                    drop(inner);
                    self.send_error(BT_ATT_OP_EXEC_WRITE_REQ, entry.handle, BT_ATT_ERROR_UNLIKELY);
                    return;
                }
            } else {
                // Intermediate writes: no response callback, but we still
                // need to fail on error.
                let att_clone = Arc::clone(&att_for_writes);
                let handle = entry.handle;
                let write_ok = attr.write(
                    entry.offset,
                    &entry.value,
                    BT_ATT_OP_EXEC_WRITE_REQ,
                    Some(Arc::clone(&self.att)),
                    Some(Box::new(move |_attr, err_code| {
                        if err_code != 0 {
                            Self::send_error_static(
                                &att_clone,
                                BT_ATT_OP_EXEC_WRITE_REQ,
                                handle,
                                err_code as u8,
                            );
                        }
                    })),
                );
                if !write_ok {
                    drop(inner);
                    self.send_error(BT_ATT_OP_EXEC_WRITE_REQ, entry.handle, BT_ATT_ERROR_UNLIKELY);
                    return;
                }
            }
        }

        drop(inner);
    }

    // ------------------------------------------------------------------
    // Private helpers: PDU send utilities
    // ------------------------------------------------------------------

    /// Send an ATT error response for the given request opcode and handle.
    fn send_error(&self, request_opcode: u8, handle: u16, ecode: u8) {
        Self::send_error_static(&self.att, request_opcode, handle, ecode);
    }

    /// Static variant of [`send_error`] that does not require `&self`.
    /// Used from within database completion callbacks that capture an
    /// `Arc<Mutex<BtAtt>>` rather than a server reference.
    fn send_error_static(att: &Arc<Mutex<BtAtt>>, request_opcode: u8, handle: u16, ecode: u8) {
        // Error response PDU: request_opcode(1) + handle(2) + error_code(1)
        let mut pdu = [0u8; 4];
        pdu[0] = request_opcode;
        put_le16(handle, &mut pdu[1..3]);
        pdu[3] = ecode;

        let mut att_guard = att.lock().unwrap();
        // BT_ATT_OP_ERROR_RSP = 0x01 from types.rs
        let _ = att_guard.send(0x01, &pdu, None);
    }

    /// Send a response PDU.
    fn send_response(&self, response_opcode: u8, rsp_body: &[u8]) {
        Self::send_response_static(&self.att, response_opcode, rsp_body);
    }

    /// Static variant of [`send_response`] for use from callbacks.
    fn send_response_static(att: &Arc<Mutex<BtAtt>>, response_opcode: u8, rsp_body: &[u8]) {
        let mut att_guard = att.lock().unwrap();
        let _ = att_guard.send(response_opcode, rsp_body, None);
    }

    /// Get the current effective MTU from the inner state.
    fn get_current_mtu(&self) -> u16 {
        let att = self.att.lock().unwrap();
        att.get_mtu()
    }
}

// ---------------------------------------------------------------------------
// Drop — cleanup
// ---------------------------------------------------------------------------

impl Drop for BtGattServer {
    /// Unregister all ATT handlers and cancel any pending NFY_MULT timer.
    fn drop(&mut self) {
        let mut inner = self.inner.lock().unwrap();

        // Cancel NFY_MULT timer.
        if let Some(timer) = inner.nfy_mult_timer.take() {
            timer.abort();
        }

        // Flush any remaining buffered notifications.
        if let Some(buf) = inner.nfy_mult.as_mut() {
            if !buf.pdu.is_empty() {
                let flush_pdu = std::mem::take(&mut buf.pdu);
                drop(inner);
                Self::flush_nfy_mult_pdu(&self.att, &flush_pdu);
                let mut inner = self.inner.lock().unwrap();
                // Unregister all ATT handlers.
                let ids = std::mem::take(&mut inner.handler_ids);
                drop(inner);
                let mut att = self.att.lock().unwrap();
                for id in ids {
                    att.unregister(id);
                }
                debug!("GATT server dropped, handlers unregistered");
                return;
            }
        }

        // Unregister all ATT handlers.
        let ids = std::mem::take(&mut inner.handler_ids);
        drop(inner);
        let mut att = self.att.lock().unwrap();
        for id in ids {
            att.unregister(id);
        }
        debug!("GATT server dropped, handlers unregistered");
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_length_within_bounds() {
        assert_eq!(BtGattServer::check_length(0, 512), 0);
        assert_eq!(BtGattServer::check_length(256, 256), 0);
        assert_eq!(BtGattServer::check_length(0, 0), 0);
        assert_eq!(BtGattServer::check_length(511, 1), 0);
    }

    #[test]
    fn test_check_length_exceeds_max() {
        assert_eq!(BtGattServer::check_length(1, 512), BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN,);
        assert_eq!(BtGattServer::check_length(256, 257), BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN,);
    }

    #[test]
    fn test_nfy_mult_append_entry() {
        let mut buf = NfyMultBuf { pdu: Vec::new(), capacity: 100 };
        BtGattServer::append_nfy_entry(&mut buf, 0x0042, &[0xAA, 0xBB]);
        assert_eq!(buf.pdu.len(), 6); // 2 handle + 2 length + 2 value
        assert_eq!(get_le16(&buf.pdu[0..2]), 0x0042);
        assert_eq!(get_le16(&buf.pdu[2..4]), 2);
        assert_eq!(&buf.pdu[4..6], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_MAX_PREP_QUEUE_LEN, 30);
        assert_eq!(NFY_MULT_TIMEOUT, Duration::from_millis(10));
        assert_eq!(GATT_PRIM_SVC_UUID, 0x2800);
        assert_eq!(GATT_SND_SVC_UUID, 0x2801);
    }

    #[test]
    fn test_prep_write_data_layout() {
        let pwd = PrepWriteData {
            handle: 0x0010,
            offset: 0x0020,
            value: vec![1, 2, 3],
            reliable_supported: true,
        };
        assert_eq!(pwd.handle, 0x0010);
        assert_eq!(pwd.offset, 0x0020);
        assert_eq!(pwd.value.len(), 3);
        assert!(pwd.reliable_supported);
    }
}
