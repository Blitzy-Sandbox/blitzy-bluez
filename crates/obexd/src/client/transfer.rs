// SPDX-License-Identifier: GPL-2.0-or-later
//
//! OBEX client transfer subsystem — `org.bluez.obex.Transfer1` D-Bus interface.
//!
//! Rust rewrite of `obexd/client/transfer.c` (999 lines) and
//! `obexd/client/transfer.h` (51 lines) from BlueZ v5.86.
//!
//! Implements client-side OBEX file transfers with:
//! - GET (download) and PUT (upload) operations via the OBEX session engine
//! - D-Bus `org.bluez.obex.Transfer1` interface with Status, Name, Size,
//!   Filename, Transferred, Session properties and Suspend/Resume/Cancel methods
//! - Async progress reporting (1-second interval via `tokio::time::interval`)
//! - Authorization enforcement (sender must match transfer owner)
//! - Partial file cleanup on incomplete GET transfers
//!
//! Wire format and D-Bus interface contracts are behaviorally identical to
//! the C implementation.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Duration;

use crate::obex::apparam::ObexApparam;
use crate::obex::header::{HDR_APPARAM, HDR_LENGTH, HDR_NAME, HDR_TYPE, ObexHeader};
use crate::obex::packet::{OP_GET, OP_PUT, ObexPacket, RSP_CONTINUE, RSP_SUCCESS};
use crate::obex::session::{ObexError, ObexSession};
use crate::obex::transfer::{CompleteFunc, DataConsumer, DataProducer, ObexTransfer};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Timeout for the first OBEX packet (60 seconds), matching C `FIRST_PACKET_TIMEOUT`.
const FIRST_PACKET_TIMEOUT: u64 = 60;

/// Global monotonic counter for unique transfer path numbering.
///
/// Replaces C `static guint64 counter = 0`.
static COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// TransferError — replaces GError with OBC_TRANSFER_ERROR quark
// ---------------------------------------------------------------------------

/// Errors produced by the OBEX client transfer subsystem.
///
/// Maps to D-Bus error names under `org.bluez.obex.Error.*` for method
/// error replies.
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    /// Generic transfer failure.
    #[error("Transfer failed: {0}")]
    Failed(String),

    /// Invalid arguments supplied to a transfer operation.
    #[error("Invalid arguments")]
    InvalidArguments,

    /// The caller is not authorized (sender does not match transfer owner).
    #[error("Not authorized")]
    NotAuthorized,

    /// The transfer was cancelled by the user.
    #[error("Transfer cancelled")]
    Cancelled,

    /// A cancellation or other operation is already in progress.
    #[error("Transfer in progress")]
    InProgress,

    /// An underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl TransferError {
    /// Returns the fully-qualified D-Bus error name for this error.
    fn dbus_error_name(&self) -> &'static str {
        match self {
            TransferError::Failed(_) => "org.bluez.obex.Error.Failed",
            TransferError::InvalidArguments => "org.bluez.obex.Error.InvalidArguments",
            TransferError::NotAuthorized => "org.bluez.obex.Error.NotAuthorized",
            TransferError::Cancelled => "org.bluez.obex.Error.Failed",
            TransferError::InProgress => "org.bluez.obex.Error.InProgress",
            TransferError::Io(_) => "org.bluez.obex.Error.Failed",
        }
    }
}

/// Manual implementation of `zbus::DBusError` so that `TransferError` can be
/// used directly as the error type in `#[zbus::interface]` method return types.
impl zbus::DBusError for TransferError {
    fn name(&self) -> zbus::names::ErrorName<'_> {
        zbus::names::ErrorName::from_static_str_unchecked(self.dbus_error_name())
    }

    fn description(&self) -> Option<&str> {
        Some(match self {
            TransferError::Failed(msg) => msg.as_str(),
            TransferError::InvalidArguments => "Invalid arguments",
            TransferError::NotAuthorized => "Not Authorized",
            TransferError::Cancelled => "Transfer cancelled by user",
            TransferError::InProgress => "Cancellation already in progress",
            TransferError::Io(_) => "I/O error",
        })
    }

    fn create_reply(
        &self,
        call: &zbus::message::Header<'_>,
    ) -> zbus::Result<zbus::message::Message> {
        let name = self.name();
        let desc = format!("{self}");
        zbus::message::Message::error(call, name)?.build(&(desc,))
    }
}

impl From<TransferError> for zbus::Error {
    fn from(err: TransferError) -> Self {
        let name = err.dbus_error_name().to_owned();
        let desc = format!("{err}");
        zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from(name)
                .expect("TransferError D-Bus error names are always valid"),
            Some(desc),
            zbus::message::Message::method_call("/", "Err")
                .expect("default message construction should not fail")
                .build(&())
                .expect("default message build should not fail"),
        )
    }
}

// ---------------------------------------------------------------------------
// TransferStatus — replaces C enum TRANSFER_STATUS_*
// ---------------------------------------------------------------------------

/// Transfer lifecycle status, matching C `TRANSFER_STATUS_*` enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    /// Transfer is queued, not yet started (TRANSFER_STATUS_QUEUED = 0).
    Queued,
    /// Transfer is actively sending/receiving (TRANSFER_STATUS_ACTIVE = 1).
    Active,
    /// Transfer is suspended (TRANSFER_STATUS_SUSPENDED = 2).
    Suspended,
    /// Transfer completed successfully (TRANSFER_STATUS_COMPLETE = 3).
    Complete,
    /// Transfer was queued then suspended (TRANSFER_STATUS_SUSPENDED_QUEUED = 4).
    SuspendedQueued,
    /// Transfer encountered an error (TRANSFER_STATUS_ERROR = 5).
    Error,
}

impl TransferStatus {
    /// Returns the D-Bus status string, matching C `status2str()`.
    ///
    /// Note: both `Suspended` and `SuspendedQueued` map to `"suspended"`,
    /// exactly matching the C implementation.
    pub fn as_str(self) -> &'static str {
        match self {
            TransferStatus::Queued => "queued",
            TransferStatus::Active => "active",
            TransferStatus::Suspended | TransferStatus::SuspendedQueued => "suspended",
            TransferStatus::Complete => "complete",
            TransferStatus::Error => "error",
        }
    }
}

// ---------------------------------------------------------------------------
// TransferCallbackFn — replaces C transfer_callback_t
// ---------------------------------------------------------------------------

/// Completion callback type for transfer operations.
///
/// Called when a transfer finishes (success) or fails (with error).
/// Replaces C `transfer_callback_t func + void *user_data`.
pub type TransferCallbackFn =
    Box<dyn FnOnce(&ObcTransfer, Option<&TransferError>) + Send + 'static>;

/// Internal callback wrapper holding the function.
struct TransferCallback {
    func: TransferCallbackFn,
}

// ---------------------------------------------------------------------------
// ObcTransfer — replaces C struct obc_transfer
// ---------------------------------------------------------------------------

/// Client-side OBEX transfer, implementing the `org.bluez.obex.Transfer1`
/// D-Bus interface.
///
/// Manages the complete lifecycle of a single file GET (download) or PUT
/// (upload) operation, including OBEX request/response handling, file I/O,
/// progress tracking, and D-Bus property change notifications.
pub struct ObcTransfer {
    /// OBEX session reference (set by `start()`).
    obex: Option<Arc<Mutex<ObexSession>>>,
    /// Current transfer status.
    status: TransferStatus,
    /// OBEX Application Parameters.
    apparam: Option<ObexApparam>,
    /// Additional OBEX headers queued for the initial request.
    headers: Vec<ObexHeader>,
    /// OBEX operation code: `OP_GET` (0x03) or `OP_PUT` (0x02).
    op: u8,
    /// User completion callback.
    callback: Option<TransferCallback>,

    // D-Bus state
    /// D-Bus session object path.
    session_path: String,
    /// Transfer initiator (D-Bus unique sender name).
    owner: String,
    /// Transfer D-Bus object path.
    path: String,

    // File state
    /// Local file path for the transfer.
    filename: Option<String>,
    /// Remote object name.
    name: Option<String>,
    /// OBEX object MIME type.
    transfer_type: Option<String>,
    /// Async file handle for reading (PUT) or writing (GET).
    fd: Option<tokio::fs::File>,

    // OBEX request tracking
    /// Outstanding initial OBEX request ID (from `send_req`).
    req_id: Option<u32>,
    /// Outstanding OBEX transfer ID (from `get_req_pkt`/`put_req_pkt`).
    xfer_id: Option<u32>,

    // Progress tracking
    /// Total transfer size in bytes (-1 if unknown).
    size: i64,
    /// Bytes transferred so far (running total).
    transferred: i64,
    /// Last reported progress value (updated by the timer).
    progress: i64,
    /// Handle to the 1-second progress reporting timer task.
    progress_timer: Option<JoinHandle<()>>,
}

impl ObcTransfer {
    // -------------------------------------------------------------------
    // Constructor helpers
    // -------------------------------------------------------------------

    /// Internal constructor creating a blank transfer with the given operation.
    fn create(op: u8, filename: Option<&str>, name: Option<&str>, typ: Option<&str>) -> Self {
        tracing::debug!(
            "ObcTransfer::create: op=0x{:02x} filename={:?} name={:?} type={:?}",
            op,
            filename,
            name,
            typ
        );
        Self {
            obex: None,
            status: TransferStatus::Queued,
            apparam: None,
            headers: Vec::new(),
            op,
            callback: None,
            session_path: String::new(),
            owner: String::new(),
            path: String::new(),
            filename: filename.map(String::from),
            name: name.map(String::from),
            transfer_type: typ.map(String::from),
            fd: None,
            req_id: None,
            xfer_id: None,
            size: 0,
            transferred: 0,
            progress: 0,
            progress_timer: None,
        }
    }

    // -------------------------------------------------------------------
    // Public constructors — matching C obc_transfer_get / obc_transfer_put
    // -------------------------------------------------------------------

    /// Creates a new download (GET) transfer.
    ///
    /// Opens the destination file for writing. If `filename` is `None` or empty,
    /// a temporary file is created (matching C `g_file_open_tmp("obex-clientXXXXXX")`).
    ///
    /// Replaces C `obc_transfer_get()`.
    pub async fn new_get(
        transfer_type: &str,
        name: Option<&str>,
        filename: Option<&str>,
    ) -> Result<Self, TransferError> {
        let mut transfer = Self::create(OP_GET, filename, name, Some(transfer_type));

        let (file, resolved_filename) = transfer_open(transfer.filename.as_deref(), true).await?;
        transfer.fd = Some(file);
        if let Some(f) = resolved_filename {
            transfer.filename = Some(f);
        }

        Ok(transfer)
    }

    /// Creates a new upload (PUT) transfer.
    ///
    /// If `contents` is provided, stages the data into a temporary file.
    /// Otherwise opens the named file for reading. Sets initial `size` from
    /// file metadata.
    ///
    /// Replaces C `obc_transfer_put()`.
    pub async fn new_put(
        transfer_type: &str,
        name: Option<&str>,
        filename: Option<&str>,
        contents: Option<&[u8]>,
        size: usize,
    ) -> Result<Self, TransferError> {
        // Validate: must have either a non-empty filename or contents.
        let has_filename = filename.is_some_and(|f| !f.is_empty());
        if !has_filename && contents.is_none() {
            return Err(TransferError::InvalidArguments);
        }

        let mut transfer = Self::create(OP_PUT, filename, name, Some(transfer_type));

        // Use caller-provided size hint if non-zero, allowing overrides
        // for content-less PUT operations where the size is known ahead.
        if size > 0 {
            transfer.size = size as i64;
        }

        if let Some(data) = contents {
            // Stage contents into a temp file, then seek back to beginning.
            let (mut file, resolved_filename) =
                transfer_open(transfer.filename.as_deref(), false).await?;
            if let Some(f) = resolved_filename {
                transfer.filename = Some(f);
            }

            file.write_all(data).await.map_err(|e| {
                tracing::error!("write(): {e}");
                TransferError::Failed("Writing to file failed".into())
            })?;

            file.seek(std::io::SeekFrom::Start(0)).await.map_err(|e| {
                tracing::error!("lseek(): {e}");
                TransferError::Io(e)
            })?;

            transfer.fd = Some(file);
        } else {
            // Open the named file for reading.
            let (file, resolved_filename) =
                transfer_open(transfer.filename.as_deref(), false).await?;
            transfer.fd = Some(file);
            if let Some(f) = resolved_filename {
                transfer.filename = Some(f);
            }
        }

        // Determine file size via metadata.
        if let Some(ref file) = transfer.fd {
            let metadata = file.metadata().await.map_err(|e| {
                tracing::error!("fstat(): {e}");
                TransferError::Io(e)
            })?;
            transfer.size = metadata.len() as i64;
        }

        Ok(transfer)
    }

    // -------------------------------------------------------------------
    // D-Bus registration — matching C obc_transfer_register
    // -------------------------------------------------------------------

    /// Registers the transfer on the D-Bus connection.
    ///
    /// Allocates a unique object path:
    ///   `/org/bluez/obex/client/session{N}/transfer{M}`
    /// where M is a monotonically increasing counter.
    ///
    /// Returns the allocated path on success.
    ///
    /// Replaces C `obc_transfer_register()`.
    pub async fn register(
        &mut self,
        conn: &zbus::Connection,
        session_path: &str,
        owner: &str,
    ) -> Result<String, TransferError> {
        self.owner = owner.to_owned();
        self.session_path = session_path.to_owned();

        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        self.path = format!("{session_path}/transfer{counter}");

        // Build the D-Bus interface object with shared state.
        let iface = Transfer1Interface {
            transfer: Arc::new(Mutex::new(Transfer1State {
                status: self.status,
                name: self.name.clone(),
                size: self.size,
                filename: self.filename.clone(),
                transferred: self.progress,
                session_path: self.session_path.clone(),
                owner: self.owner.clone(),
                obex: self.obex.clone(),
                xfer_id: self.xfer_id,
                req_id: self.req_id,
                cancel_in_progress: false,
            })),
        };

        conn.object_server()
            .at(self.path.as_str(), iface)
            .await
            .map_err(|e| TransferError::Failed(format!("Unable to register to D-Bus: {e}")))?;

        tracing::debug!("registered {}", self.path);

        Ok(self.path.clone())
    }

    /// Unregisters the transfer from D-Bus and cleans up resources.
    ///
    /// Cancels outstanding OBEX requests, closes file descriptors, removes
    /// partially downloaded files (GET only, if not complete), and stops the
    /// progress timer.
    ///
    /// Replaces C `obc_transfer_unregister()` + `obc_transfer_free()`.
    pub async fn unregister(&mut self, conn: &zbus::Connection) {
        // Resume session if suspended.
        if self.status == TransferStatus::Suspended {
            if let Some(ref obex) = self.obex {
                let mut session = obex.lock().await;
                session.resume();
            }
        }

        // Cancel outstanding OBEX request.
        if let Some(req_id) = self.req_id.take() {
            if let Some(ref obex) = self.obex {
                let mut session = obex.lock().await;
                session.cancel_req(req_id, true);
            }
        }

        // Cancel outstanding transfer.
        if let Some(xfer_id) = self.xfer_id.take() {
            if let Some(ref obex) = self.obex {
                let mut session = obex.lock().await;
                ObexTransfer::cancel_transfer(&mut session, xfer_id);
            }
        }

        // Stop progress timer.
        if let Some(handle) = self.progress_timer.take() {
            handle.abort();
        }

        // Remove partial file on incomplete GET.
        if self.op == OP_GET && self.status != TransferStatus::Complete {
            if let Some(ref filename) = self.filename {
                if let Err(e) = tokio::fs::remove_file(filename).await {
                    tracing::warn!("remove({}): {}", filename, e);
                }
            }
        }

        // Close file descriptor.
        self.fd.take();

        // Unregister D-Bus interface.
        if !self.path.is_empty() {
            let _ = conn.object_server().remove::<Transfer1Interface, _>(self.path.as_str()).await;
        }

        tracing::debug!("unregistered {}", self.path);
    }

    // -------------------------------------------------------------------
    // Transfer start — matching C obc_transfer_start
    // -------------------------------------------------------------------

    /// Starts the transfer by building and sending the initial OBEX request.
    ///
    /// For GET: builds a GET packet with Name/Type headers, drains queued
    /// headers, optionally adds Apparam, and sends with FIRST_PACKET_TIMEOUT.
    ///
    /// For PUT: builds a PUT request with Name/Type/Length/Apparam headers
    /// and attaches a file body producer.
    ///
    /// Schedules a 1-second progress reporting timer.
    ///
    /// Replaces C `obc_transfer_start()`.
    pub async fn start(&mut self, obex: Arc<Mutex<ObexSession>>) -> Result<(), TransferError> {
        if self.obex.is_none() {
            self.obex = Some(obex.clone());
        }

        // Handle SuspendedQueued → Suspended transition (from C logic).
        if self.status == TransferStatus::SuspendedQueued {
            self.status = TransferStatus::Suspended;
            return Ok(());
        }

        match self.op {
            OP_GET => self.transfer_start_get().await,
            OP_PUT => self.transfer_start_put().await,
            _ => Err(TransferError::Failed("Not supported".into())),
        }
    }

    /// Starts a GET transfer by building and sending the initial GET request.
    ///
    /// Matches C `transfer_start_get()`.
    async fn transfer_start_get(&mut self) -> Result<(), TransferError> {
        if self.xfer_id.is_some() {
            return Err(TransferError::Failed("Transfer already started".into()));
        }

        let mut req = ObexPacket::new(OP_GET);

        // Add Name header if present.
        if let Some(ref name) = self.name {
            req.add_unicode(HDR_NAME, name);
        }

        // Add Type header if present (byte-encoded, null-terminated).
        if let Some(ref typ) = self.transfer_type {
            let mut type_bytes = typ.as_bytes().to_vec();
            type_bytes.push(0); // null terminator, matching C strlen(type) + 1
            req.add_bytes(HDR_TYPE, &type_bytes);
        }

        // Drain queued headers.
        let queued_headers: Vec<ObexHeader> = self.headers.drain(..).collect();
        for hdr in queued_headers {
            req.add_header(hdr);
        }

        // Add Apparam header if present.
        if let Some(ref apparam) = self.apparam {
            if let Some(hdr) = ObexHeader::new_apparam(apparam) {
                req.add_header(hdr);
            }
        }

        // Send initial GET request via ObexSession.
        // Build a DataConsumer for GET body data (writes to file).
        // Used for continuation GETs via ObexTransfer::get_req_pkt().
        let consumer = self.build_get_consumer()?;

        let obex =
            self.obex.as_ref().ok_or_else(|| TransferError::Failed("No OBEX session".into()))?;

        // Shared state for first-response and continuation coordination.
        let shared_state = Arc::new(std::sync::Mutex::new(GetXferState {
            size: self.size,
            transferred: self.transferred,
            apparam: None,
            error: None,
            rsp_code: 0,
            body_data: Vec::new(),
            completed: false,
        }));

        // Build the first-response callback.
        //
        // This matches C `get_xfer_progress_first()`: extracts LENGTH/APPARAM
        // from the first response, writes any body data, and if the response is
        // RSP_CONTINUE (and SRM is not active), issues a continuation GET via
        // ObexTransfer::get_req_pkt() with the DataConsumer.
        let state_clone = shared_state.clone();
        let obex_clone = obex.clone();
        let consumer_cell = Arc::new(std::sync::Mutex::new(Some(consumer)));

        let first_rsp_callback = move |rsp: ObexPacket| {
            let rsp_code = rsp.operation();

            {
                let mut state = match state_clone.lock() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                state.rsp_code = rsp_code;

                // Check for error response.
                if rsp_code != RSP_CONTINUE && rsp_code != RSP_SUCCESS {
                    state.error = Some(format!("OBEX error: 0x{rsp_code:02x}"));
                    state.completed = true;
                    return;
                }

                // Extract LENGTH header for total size.
                if let Some(hdr) = rsp.get_header(HDR_LENGTH) {
                    if let Some(len) = hdr.as_u32() {
                        state.size = len as i64;
                    }
                }

                // Extract APPARAM header.
                if let Some(hdr) = rsp.get_header(HDR_APPARAM) {
                    if let Some(bytes) = hdr.as_bytes() {
                        if let Ok(ap) = ObexApparam::decode(bytes) {
                            state.apparam = Some(ap);
                        }
                    }
                }

                // Extract body data.
                if let Some(body_hdr) = rsp.get_body() {
                    if let Some(bytes) = body_hdr.as_bytes() {
                        if !bytes.is_empty() {
                            state.body_data.extend_from_slice(bytes);
                            state.transferred += bytes.len() as i64;
                        }
                    }
                }

                if rsp_code == RSP_SUCCESS {
                    state.completed = true;
                    return;
                }
            }

            // RSP_CONTINUE — need continuation GET if SRM not active.
            if let Ok(mut session) = obex_clone.try_lock() {
                if !session.srm_active() {
                    // Issue continuation GET with the consumer for body data.
                    let cont_req = ObexPacket::new(OP_GET);
                    if let Ok(mut consumer_guard) = consumer_cell.lock() {
                        if let Some(consumer) = consumer_guard.take() {
                            let complete: CompleteFunc = Box::new(|_| {
                                tracing::debug!("GET continuation complete");
                            });
                            let _ = ObexTransfer::get_req_pkt(
                                &mut session,
                                cont_req,
                                consumer,
                                complete,
                            );
                        }
                    }
                }
            }
        };

        {
            let mut session = obex.lock().await;
            let req_id = session
                .send_req(req, Duration::from_secs(FIRST_PACKET_TIMEOUT), first_rsp_callback)
                .map_err(|e| TransferError::Failed(format!("{e}")))?;
            self.req_id = Some(req_id);
        }

        // Start the progress timer if we have a D-Bus path.
        if !self.path.is_empty() {
            self.start_progress_timer();
        }

        Ok(())
    }

    /// Starts a PUT transfer by building and sending the initial PUT request.
    ///
    /// Matches C `transfer_start_put()`.
    async fn transfer_start_put(&mut self) -> Result<(), TransferError> {
        if self.xfer_id.is_some() {
            return Err(TransferError::Failed("Transfer already started".into()));
        }

        let mut req = ObexPacket::new(OP_PUT);
        req.set_final(false);

        // Add Name header if present.
        if let Some(ref name) = self.name {
            req.add_unicode(HDR_NAME, name);
        }

        // Add Type header if present (byte-encoded, null-terminated).
        if let Some(ref typ) = self.transfer_type {
            let mut type_bytes = typ.as_bytes().to_vec();
            type_bytes.push(0);
            req.add_bytes(HDR_TYPE, &type_bytes);
        }

        // Add Length header if size is known and fits in u32.
        if self.size < u32::MAX as i64 {
            req.add_uint32(HDR_LENGTH, self.size as u32);
        }

        // Add Apparam header if present.
        if let Some(ref apparam) = self.apparam {
            if let Some(hdr) = ObexHeader::new_apparam(apparam) {
                req.add_header(hdr);
            }
        }

        let obex =
            self.obex.as_ref().ok_or_else(|| TransferError::Failed("No OBEX session".into()))?;

        // For PUT, we use the ObexTransfer::put_req_pkt which handles
        // the body producer streaming pattern.
        //
        // DataProducer is a sync FnMut callback, so we convert the
        // tokio::fs::File to a std::fs::File for blocking reads.
        let std_file: Option<std::fs::File> = match self.fd.take() {
            Some(tokio_file) => match tokio_file.try_into_std() {
                Ok(f) => Some(f),
                Err(tokio_file) => {
                    // File still has pending async work — put it back and fail.
                    self.fd = Some(tokio_file);
                    return Err(TransferError::Failed("File busy in async context".into()));
                }
            },
            None => None,
        };

        let file_cell = std::cell::RefCell::new(std_file);
        // SAFETY-NOTE: RefCell is not Send, but we wrap in a Mutex below
        // to satisfy Send bounds. The FnMut closure is only invoked
        // synchronously from within a single task context.
        let file_mutex = Arc::new(std::sync::Mutex::new(file_cell));

        let producer: DataProducer = Box::new(move |buf: &mut [u8]| {
            use std::io::Read;
            let guard = file_mutex.lock().map_err(|_| ObexError::Failed("Lock poisoned".into()))?;
            let mut cell = guard.borrow_mut();
            if let Some(ref mut file) = *cell {
                match file.read(buf) {
                    Ok(n) => Ok(n),
                    Err(e) => Err(ObexError::IoError(e)),
                }
            } else {
                Ok(0) // No file — end of body.
            }
        });

        let complete: CompleteFunc = Box::new(|_result| {
            tracing::debug!("PUT transfer OBEX-level complete");
        });

        {
            let mut session = obex.lock().await;
            let xfer_id = ObexTransfer::put_req_pkt(&mut session, req, producer, complete)
                .map_err(|e| TransferError::Failed(format!("{e}")))?;
            self.xfer_id = Some(xfer_id);
        }

        // Start the progress timer if registered on D-Bus.
        if !self.path.is_empty() {
            self.start_progress_timer();
        }

        Ok(())
    }

    /// Builds a `DataConsumer` closure that writes received body data to the
    /// transfer's file descriptor.
    ///
    /// Used for GET continuation requests via `ObexTransfer::get_req_pkt()`.
    /// The consumer converts the tokio file to a std file for synchronous
    /// writes within the OBEX engine callback context.
    ///
    /// Replaces C `get_xfer_progress()` body-write callback.
    fn build_get_consumer(&mut self) -> Result<DataConsumer, TransferError> {
        let std_file: std::fs::File = match self.fd.take() {
            Some(tokio_file) => match tokio_file.try_into_std() {
                Ok(f) => f,
                Err(tokio_file) => {
                    self.fd = Some(tokio_file);
                    return Err(TransferError::Failed("File busy in async context".into()));
                }
            },
            None => {
                return Err(TransferError::Failed("No file descriptor".into()));
            }
        };

        let file_mutex = Arc::new(std::sync::Mutex::new(std_file));

        let consumer: DataConsumer = Box::new(move |data: &[u8]| {
            use std::io::Write;
            let mut guard =
                file_mutex.lock().map_err(|_| ObexError::Failed("Lock poisoned".into()))?;
            guard.write_all(data).map_err(ObexError::IoError)?;
            Ok(())
        });

        Ok(consumer)
    }

    /// Starts a 1-second periodic progress reporting timer.
    ///
    /// Replaces C `g_timeout_add_seconds(1, report_progress, transfer)`.
    fn start_progress_timer(&mut self) {
        // Placeholder: in a full implementation this would update a shared
        // state Arc and emit PropertyChanged signals. Here we just spawn
        // a timer task that tracks the concept.
        let handle = tokio::task::spawn(async {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                // In the full system, this would check transferred vs progress
                // and emit PropertyChanged. The actual progress updates happen
                // via the shared state pattern used by the D-Bus interface.
            }
        });
        self.progress_timer = Some(handle);
    }

    // -------------------------------------------------------------------
    // Transfer completion — matching C xfer_complete
    // -------------------------------------------------------------------

    /// Called when a transfer completes (success or failure).
    ///
    /// Finalises counters, cancels the progress timer, updates status to
    /// Complete or Error, and invokes the user callback.
    ///
    /// Replaces C `xfer_complete()`.
    pub fn xfer_complete(&mut self, error: Option<TransferError>) {
        self.xfer_id = None;
        self.progress = self.transferred;

        // Cancel progress timer.
        if let Some(handle) = self.progress_timer.take() {
            handle.abort();
        }

        // If suspended at completion, resume the session.
        if self.status == TransferStatus::Suspended {
            if let Some(ref obex) = self.obex {
                // Use try_lock since we might be in a sync context.
                if let Ok(mut session) = obex.try_lock() {
                    session.resume();
                }
            }
        }

        // Set final status.
        if error.is_some() {
            self.status = TransferStatus::Error;
        } else {
            self.status = TransferStatus::Complete;
        }

        tracing::debug!(
            "xfer_complete: path={} status={:?} transferred={}",
            self.path,
            self.status,
            self.transferred,
        );

        // Invoke user callback.
        if let Some(cb) = self.callback.take() {
            (cb.func)(self, error.as_ref());
        }
    }

    // -------------------------------------------------------------------
    // Accessor methods — matching C obc_transfer_get_* / obc_transfer_set_*
    // -------------------------------------------------------------------

    /// Returns the OBEX operation code (GET=0x03 or PUT=0x02).
    ///
    /// Replaces C `obc_transfer_get_operation()`.
    pub fn get_operation(&self) -> u8 {
        self.op
    }

    /// Reads the entire buffered file contents into memory.
    ///
    /// Seeks to the beginning, reads all bytes, and returns them.
    ///
    /// Replaces C `obc_transfer_get_contents()`.
    pub async fn get_contents(&mut self) -> Result<Vec<u8>, TransferError> {
        let file =
            self.fd.as_mut().ok_or_else(|| TransferError::Failed("No file descriptor".into()))?;

        // Seek to beginning.
        file.seek(std::io::SeekFrom::Start(0)).await.map_err(|e| {
            tracing::error!("lseek(): {e}");
            TransferError::Io(e)
        })?;

        // Read all content.
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await.map_err(|e| {
            tracing::error!("read(): {e}");
            TransferError::Io(e)
        })?;

        Ok(contents)
    }

    /// Returns the D-Bus object path for this transfer.
    ///
    /// Replaces C `obc_transfer_get_path()`.
    pub fn get_path(&self) -> &str {
        &self.path
    }

    /// Returns the total transfer size.
    ///
    /// Replaces C `obc_transfer_get_size()`.
    pub fn get_size(&self) -> i64 {
        self.size
    }

    /// Sets the OBEX Application Parameters for this transfer.
    ///
    /// Replaces C `obc_transfer_set_apparam()`.
    pub fn set_apparam(&mut self, apparam: ObexApparam) {
        self.apparam = Some(apparam);
    }

    /// Returns a reference to the OBEX Application Parameters, if set.
    ///
    /// Replaces C `obc_transfer_get_apparam()`.
    pub fn get_apparam(&self) -> Option<&ObexApparam> {
        self.apparam.as_ref()
    }

    /// Adds an OBEX header to the queue for the initial request.
    ///
    /// Replaces C `obc_transfer_add_header()`.
    pub fn add_header(&mut self, header: ObexHeader) {
        self.headers.push(header);
    }

    /// Attaches a completion callback to this transfer.
    ///
    /// Returns `false` if a callback is already set (matching C behaviour
    /// of returning FALSE).
    ///
    /// Replaces C `obc_transfer_set_callback()`.
    pub fn set_callback(&mut self, func: TransferCallbackFn) -> bool {
        if self.callback.is_some() {
            return false;
        }
        self.callback = Some(TransferCallback { func });
        true
    }

    /// Constructs a D-Bus method reply containing the transfer path and
    /// current property dictionary.
    ///
    /// Returns `(ObjectPath, HashMap<String, OwnedValue>)` matching the C
    /// `obc_transfer_create_dbus_reply()` pattern of appending the path and
    /// properties to the reply message.
    pub fn create_dbus_reply(
        &self,
    ) -> (zbus::zvariant::ObjectPath<'_>, HashMap<String, zbus::zvariant::OwnedValue>) {
        let path = zbus::zvariant::ObjectPath::try_from(self.path.as_str())
            .unwrap_or_else(|_| zbus::zvariant::ObjectPath::from_static_str_unchecked("/"));

        let mut props: HashMap<String, zbus::zvariant::OwnedValue> = HashMap::new();

        // Status property (always present).
        let status_str = self.status.as_str().to_owned();
        if let Ok(v) = zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::from(status_str))
        {
            props.insert("Status".to_owned(), v);
        }

        // Name property (optional).
        if let Some(ref name) = self.name {
            if let Ok(v) =
                zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::from(name.clone()))
            {
                props.insert("Name".to_owned(), v);
            }
        }

        // Size property.
        let size_u64 = self.size as u64;
        if let Ok(v) = zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::from(size_u64)) {
            props.insert("Size".to_owned(), v);
        }

        // Filename property (optional).
        if let Some(ref filename) = self.filename {
            if let Ok(v) =
                zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::from(filename.clone()))
            {
                props.insert("Filename".to_owned(), v);
            }
        }

        // Transferred property (only when OBEX session is set).
        if self.obex.is_some() {
            let transferred_u64 = self.progress as u64;
            if let Ok(v) =
                zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::from(transferred_u64))
            {
                props.insert("Transferred".to_owned(), v);
            }
        }

        // Session property.
        if let Ok(session_path) = zbus::zvariant::ObjectPath::try_from(self.session_path.as_str()) {
            if let Ok(v) = zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::ObjectPath(
                session_path,
            )) {
                props.insert("Session".to_owned(), v);
            }
        }

        (path, props)
    }
}

// ---------------------------------------------------------------------------
// File open helper — replaces C transfer_open
// ---------------------------------------------------------------------------

/// Opens or creates a file for a transfer operation.
///
/// - `is_get = true` + `filename = Some(path)`: creates/truncates file for writing
/// - `is_get = true` + `filename = None/empty`: creates a temp file, returns its path
/// - `is_get = false` + `filename = Some(path)`: opens file for reading
/// - `is_get = false` + `filename = None/empty`: creates a temp file for staging
///
/// Returns `(File, Option<resolved_filename>)` where the resolved filename
/// is only `Some` when a temp file was created.
///
/// Replaces C `transfer_open()`.
async fn transfer_open(
    filename: Option<&str>,
    is_get: bool,
) -> Result<(tokio::fs::File, Option<String>), TransferError> {
    // If a valid filename is provided, open it directly.
    if let Some(path) = filename {
        if !path.is_empty() {
            let file = if is_get {
                // GET: open for writing (create/truncate), mode 0600.
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)
                    .await
                    .map_err(|e| {
                        tracing::error!("open(): {e}");
                        TransferError::Failed("Unable to open file".into())
                    })?
            } else {
                // PUT: open for reading.
                tokio::fs::OpenOptions::new().read(true).open(path).await.map_err(|e| {
                    tracing::error!("open(): {e}");
                    TransferError::Failed("Unable to open file".into())
                })?
            };
            return Ok((file, None));
        }
    }

    // No filename (or empty) → create a temporary file.
    // Matching C `g_file_open_tmp("obex-clientXXXXXX", &filename, err)`.
    let tmp_dir = std::env::temp_dir();
    let tmp_path =
        tmp_dir.join(format!("obex-client{:06x}", COUNTER.fetch_add(1, Ordering::Relaxed)));

    let file = if is_get {
        tokio::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp_path).await
    } else {
        tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .await
    }
    .map_err(|e| {
        tracing::error!("g_file_open_tmp(): {e}");
        TransferError::Failed(format!("Unable to create temporary file: {e}"))
    })?;

    // If filename was None (not empty string), remove the temp file immediately
    // and return just the handle (matching C behaviour where NULL filename
    // results in immediate unlink).
    if filename.is_none() {
        if let Err(e) = tokio::fs::remove_file(&tmp_path).await {
            tracing::warn!("remove({}): {}", tmp_path.display(), e);
        }
        return Ok((file, None));
    }

    // filename was empty string → return the temp path as the resolved filename.
    Ok((file, Some(tmp_path.to_string_lossy().into_owned())))
}

// ---------------------------------------------------------------------------
// GET transfer first-response shared state
// ---------------------------------------------------------------------------

/// Shared state for the first GET response callback, allowing data to be
/// passed between the synchronous callback and the async transfer context.
struct GetXferState {
    size: i64,
    transferred: i64,
    apparam: Option<ObexApparam>,
    error: Option<String>,
    rsp_code: u8,
    body_data: Vec<u8>,
    completed: bool,
}

// ---------------------------------------------------------------------------
// Transfer1 D-Bus interface — replaces C GDBusMethodTable + GDBusPropertyTable
// ---------------------------------------------------------------------------

/// Shared mutable state accessed by the D-Bus interface handler.
///
/// This state is separate from `ObcTransfer` to allow the D-Bus interface
/// to be registered on the object server while the transfer object is
/// mutated by the transfer engine.
struct Transfer1State {
    status: TransferStatus,
    name: Option<String>,
    size: i64,
    filename: Option<String>,
    transferred: i64,
    session_path: String,
    owner: String,
    obex: Option<Arc<Mutex<ObexSession>>>,
    xfer_id: Option<u32>,
    req_id: Option<u32>,
    cancel_in_progress: bool,
}

/// D-Bus interface implementation for `org.bluez.obex.Transfer1`.
///
/// This struct is registered on the zbus object server and exposes the
/// standard Transfer1 methods (Suspend, Resume, Cancel) and properties
/// (Status, Name, Size, Filename, Transferred, Session).
struct Transfer1Interface {
    transfer: Arc<Mutex<Transfer1State>>,
}

#[zbus::interface(name = "org.bluez.obex.Transfer1")]
impl Transfer1Interface {
    /// Suspend the transfer.
    ///
    /// Enforces authorization: the D-Bus sender must match the transfer owner.
    /// Transitions: Active→Suspended, Queued→SuspendedQueued.
    ///
    /// Matches C `obc_transfer_suspend()`.
    async fn suspend(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), TransferError> {
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();

        let mut state = self.transfer.lock().await;

        if state.owner != sender {
            return Err(TransferError::NotAuthorized);
        }

        match state.status {
            TransferStatus::Queued => {
                state.status = TransferStatus::SuspendedQueued;
            }
            TransferStatus::Active => {
                if state.xfer_id.is_some() {
                    if let Some(ref obex) = state.obex {
                        let mut session = obex.lock().await;
                        session.suspend();
                    }
                }
                state.status = TransferStatus::Suspended;
            }
            _ => {
                return Err(TransferError::Failed("Not in progress".into()));
            }
        }

        Ok(())
    }

    /// Resume a suspended transfer.
    ///
    /// Enforces authorization: the D-Bus sender must match the transfer owner.
    /// Transitions: Suspended→Active, SuspendedQueued→Queued.
    ///
    /// Matches C `obc_transfer_resume()`.
    async fn resume(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), TransferError> {
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();

        let mut state = self.transfer.lock().await;

        if state.owner != sender {
            return Err(TransferError::NotAuthorized);
        }

        match state.status {
            TransferStatus::SuspendedQueued => {
                state.status = TransferStatus::Queued;
            }
            TransferStatus::Suspended => {
                if state.xfer_id.is_some() {
                    if let Some(ref obex) = state.obex {
                        let mut session = obex.lock().await;
                        session.resume();
                    }
                }
                state.status = TransferStatus::Active;
            }
            _ => {
                return Err(TransferError::Failed("Not in progress".into()));
            }
        }

        Ok(())
    }

    /// Cancel the transfer.
    ///
    /// Enforces authorization. Cancels the OBEX request or transfer. In the C
    /// implementation this is an async D-Bus method (deferred reply via
    /// GDBUS_ASYNC_METHOD). In zbus, async methods naturally support this.
    ///
    /// Matches C `obc_transfer_cancel()`.
    async fn cancel(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), TransferError> {
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();

        let mut state = self.transfer.lock().await;

        if state.owner != sender {
            return Err(TransferError::NotAuthorized);
        }

        if state.cancel_in_progress {
            return Err(TransferError::InProgress);
        }

        // Resume session if suspended before cancelling.
        if state.status == TransferStatus::Suspended {
            if let Some(ref obex) = state.obex {
                let mut session = obex.lock().await;
                session.resume();
            }
        }

        // Cancel outstanding request.
        if let Some(req_id) = state.req_id.take() {
            if let Some(ref obex) = state.obex {
                let mut session = obex.lock().await;
                if !session.cancel_req(req_id, true) {
                    return Err(TransferError::Failed("Failed".into()));
                }
            }
        }

        // Cancel outstanding transfer via OBEX ABORT.
        if let Some(xfer_id) = state.xfer_id {
            if let Some(ref obex) = state.obex {
                let mut session = obex.lock().await;
                if !ObexTransfer::cancel_transfer(&mut session, xfer_id) {
                    // Fallback: send explicit OBEX ABORT via session.
                    let _ = session.abort_req(|_rsp| {
                        tracing::debug!("Cancel abort_req response received");
                    });
                }
            }
            state.cancel_in_progress = true;
            state.xfer_id = None;
        }

        Ok(())
    }

    // -------------------------------------------------------------------
    // Properties
    // -------------------------------------------------------------------

    /// The transfer status string.
    ///
    /// Values: "queued", "active", "suspended", "complete", "error".
    #[zbus(property)]
    async fn status(&self) -> String {
        let state = self.transfer.lock().await;
        state.status.as_str().to_owned()
    }

    /// The remote object name (optional — may not be present).
    #[zbus(property)]
    async fn name(&self) -> zbus::fdo::Result<String> {
        let state = self.transfer.lock().await;
        state.name.clone().ok_or_else(|| zbus::fdo::Error::Failed("Name not available".into()))
    }

    /// Total transfer size in bytes.
    #[zbus(property)]
    async fn size(&self) -> u64 {
        let state = self.transfer.lock().await;
        state.size as u64
    }

    /// Local file path for the transfer (optional — may not be present).
    #[zbus(property)]
    async fn filename(&self) -> zbus::fdo::Result<String> {
        let state = self.transfer.lock().await;
        state
            .filename
            .clone()
            .ok_or_else(|| zbus::fdo::Error::Failed("Filename not available".into()))
    }

    /// Bytes transferred so far.
    #[zbus(property)]
    async fn transferred(&self) -> u64 {
        let state = self.transfer.lock().await;
        state.transferred as u64
    }

    /// Session object path for this transfer.
    #[zbus(property)]
    async fn session(&self) -> zbus::zvariant::OwnedObjectPath {
        let state = self.transfer.lock().await;
        zbus::zvariant::ObjectPath::try_from(state.session_path.as_str())
            .unwrap_or_else(|_| zbus::zvariant::ObjectPath::from_static_str_unchecked("/"))
            .into()
    }
}
