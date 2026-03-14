// SPDX-License-Identifier: GPL-2.0-or-later
//
//! OBEX transfer lifecycle management.
//!
//! Implements streaming PUT and GET operations for both client-side and
//! server-side OBEX flows.  Manages body data producers/consumers, handles
//! CONTINUE/SUCCESS response sequencing, SRM (Single Response Mode)
//! negotiation, transfer abort, and completion callbacks.
//!
//! ## Architecture
//!
//! Transfers are tracked in a module-level registry (`TRANSFERS`).  Each
//! transfer holds its mutable state behind `Arc<Mutex<TransferInner>>` so that
//! response callbacks (which only receive the packet, not the session) can
//! update transfer state and enqueue follow-up actions.
//!
//! **Server-side** request handlers receive `(&mut ObexSession, &ObexPacket)`
//! and can directly send responses.
//!
//! **Client-side** response callbacks receive only `ObexPacket`.  Follow-up
//! packets are queued in `TransferInner::pending_sends` and must be drained
//! by calling [`ObexTransfer::process_pending`] after
//! [`ObexSession::incoming_data`] returns.
//!
//! This is a Rust rewrite of `gobex/gobex-transfer.c` (662 lines).

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use std::time::Duration;

use super::header::{HDR_BODY_END, ObexHeader};
use super::packet::{
    OP_ABORT, OP_GET, OP_PUT, ObexPacket, PACKET_FINAL, PacketError, RSP_CONTINUE, RSP_FORBIDDEN,
    RSP_SUCCESS,
};
use super::session::{ObexError, ObexSession, obex_strerror};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Timeout for the initial transfer request (60 seconds).
///
/// Matches C `FIRST_PACKET_TIMEOUT` in `gobex-transfer.c`.
const FIRST_PACKET_TIMEOUT: u64 = 60;

/// Default timeout for follow-up requests (10 seconds).
///
/// Matches the session-level `DEFAULT_TIMEOUT` used for continuation
/// packets in the C codebase.
const DEFAULT_TIMEOUT: u64 = 10;

// ---------------------------------------------------------------------------
// Public callback type aliases
// ---------------------------------------------------------------------------

/// Body data producer: fills buffer with body bytes, returns byte count.
///
/// - `Ok(n)` where `n > 0` → body data was produced.
/// - `Ok(0)` → end of body (no more data to produce).
///
/// Replaces C `GObexDataProducer`.
pub type DataProducer = Box<dyn FnMut(&mut [u8]) -> Result<usize, ObexError> + Send>;

/// Body data consumer: receives body data bytes from the remote peer.
///
/// Replaces C `GObexDataConsumer`.
pub type DataConsumer = Box<dyn FnMut(&[u8]) -> Result<(), ObexError> + Send>;

/// Transfer completion callback: invoked when a transfer completes (success
/// or failure).
///
/// Replaces C `GObexFunc` used as the completion callback in transfer
/// operations.
pub type CompleteFunc = Box<dyn FnOnce(Result<(), ObexError>) + Send>;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// A follow-up packet queued for sending during [`ObexTransfer::process_pending`].
///
/// Client-side response callbacks cannot access `ObexSession` directly
/// (the callback signature is `FnMut(ObexPacket)`), so they enqueue pending
/// sends here instead.
struct PendingSend {
    /// The next OBEX packet to transmit.
    pkt: ObexPacket,
    /// Timeout for the send operation.
    timeout: Duration,
}

/// Internal mutable state for a single transfer, held behind
/// `Arc<Mutex<TransferInner>>`.
struct TransferInner {
    /// Monotonically increasing transfer identifier (starts at 1).
    id: u32,
    /// Transfer opcode: [`OP_PUT`] or [`OP_GET`].
    opcode: u8,
    /// ID of the currently pending request in the session (client-side).
    req_id: Option<u32>,
    /// Handler registration ID for incoming PUT requests (server-side).
    put_handler_id: Option<u32>,
    /// Handler registration ID for incoming GET requests (server-side).
    get_handler_id: Option<u32>,
    /// Handler registration ID for incoming ABORT requests (server-side).
    abort_handler_id: Option<u32>,
    /// Body data producer callback (PUT client / GET server).
    data_producer: Option<DataProducer>,
    /// Body data consumer callback (GET client / PUT server).
    data_consumer: Option<DataConsumer>,
    /// Transfer completion callback (invoked once on success or failure).
    complete_func: Option<CompleteFunc>,
    /// Queue of follow-up packets to send (drained by `process_pending`).
    pending_sends: Vec<PendingSend>,
    /// Completion result set by the response callback.
    complete_result: Option<Result<(), ObexError>>,
    /// Whether this transfer has reached a terminal state.
    completed: bool,
}

// ---------------------------------------------------------------------------
// Global transfer registry — replaces C `static GSList *transfers`
// ---------------------------------------------------------------------------

/// Monotonically increasing transfer ID counter (starts at 1).
///
/// Matches C `static guint next_id = 1`.
static NEXT_TRANSFER_ID: AtomicU32 = AtomicU32::new(1);

/// Global registry of active transfers.
///
/// Lock ordering: this lock must **never** be held when acquiring any
/// `TransferInner` lock (to prevent ABBA deadlocks).  Instead, clone the
/// `Arc` under the registry lock, release the registry lock, then lock the
/// individual transfer.
static TRANSFERS: Mutex<Vec<Arc<Mutex<TransferInner>>>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------------------
// Private helpers — transfer lifecycle
// ---------------------------------------------------------------------------

/// Allocates a new transfer with the given opcode, inserts it into the
/// global registry, and returns its shared state handle.
fn transfer_new(opcode: u8) -> Arc<Mutex<TransferInner>> {
    let id = NEXT_TRANSFER_ID.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(
        target: "obex::transfer",
        "transfer_new: id={id} opcode=0x{opcode:02x}"
    );

    let inner = Arc::new(Mutex::new(TransferInner {
        id,
        opcode,
        req_id: None,
        put_handler_id: None,
        get_handler_id: None,
        abort_handler_id: None,
        data_producer: None,
        data_consumer: None,
        complete_func: None,
        pending_sends: Vec::new(),
        complete_result: None,
        completed: false,
    }));

    TRANSFERS.lock().expect("TRANSFERS lock poisoned").push(inner.clone());
    inner
}

/// Removes a transfer from the global registry by ID.
fn transfer_remove(id: u32) {
    let mut registry = TRANSFERS.lock().expect("TRANSFERS lock poisoned");
    registry.retain(|arc| arc.lock().map(|inner| inner.id != id).unwrap_or(true));
    tracing::debug!(target: "obex::transfer", "transfer_remove: id={id}");
}

/// Finds a transfer in the global registry by ID, returning a cloned
/// `Arc` handle (so the caller can release the registry lock before
/// locking the individual transfer).
fn transfer_find(id: u32) -> Option<Arc<Mutex<TransferInner>>> {
    let registry = TRANSFERS.lock().expect("TRANSFERS lock poisoned");
    registry.iter().find(|arc| arc.lock().map(|inner| inner.id == id).unwrap_or(false)).cloned()
}

// ---------------------------------------------------------------------------
// Private helpers — body producer wrappers
// ---------------------------------------------------------------------------

/// Creates a body producer closure suitable for [`ObexPacket::set_body_producer`]
/// that delegates to the transfer's [`DataProducer`].
///
/// The closure locks the transfer state, invokes the `data_producer`, and
/// converts any [`ObexError`] into [`PacketError`].
fn make_body_producer(
    state: Arc<Mutex<TransferInner>>,
) -> Box<dyn FnMut(&mut [u8]) -> Result<usize, PacketError> + Send> {
    Box::new(move |buf: &mut [u8]| {
        let mut inner = state.lock().expect("TransferInner lock poisoned");
        if let Some(ref mut producer) = inner.data_producer {
            producer(buf).map_err(|e| PacketError::ParseError(e.to_string()))
        } else {
            // No producer set — signal end-of-body.
            Ok(0)
        }
    })
}

/// Creates a body producer that additionally sets a shared `AtomicBool` flag
/// when the underlying producer returns `Ok(0)` (end-of-body).
///
/// This allows the caller to detect producer exhaustion after
/// [`ObexSession::send_rsp`] returns (since the packet is consumed during
/// encoding).
fn make_body_producer_with_done(
    state: Arc<Mutex<TransferInner>>,
    done: Arc<AtomicBool>,
) -> Box<dyn FnMut(&mut [u8]) -> Result<usize, PacketError> + Send> {
    Box::new(move |buf: &mut [u8]| {
        let mut inner = state.lock().expect("TransferInner lock poisoned");
        if let Some(ref mut producer) = inner.data_producer {
            match producer(buf) {
                Ok(0) => {
                    done.store(true, Ordering::SeqCst);
                    Ok(0)
                }
                Ok(n) => Ok(n),
                Err(e) => Err(PacketError::ParseError(e.to_string())),
            }
        } else {
            done.store(true, Ordering::SeqCst);
            Ok(0)
        }
    })
}

// ---------------------------------------------------------------------------
// Private helpers — client response handling
// ---------------------------------------------------------------------------

/// Creates the response callback closure for client-side PUT/GET transfers.
///
/// The closure processes the response packet and queues follow-up actions in
/// `TransferInner::pending_sends` / `TransferInner::complete_result` for
/// later processing by [`ObexTransfer::process_pending`].
fn make_client_rsp_callback(state: Arc<Mutex<TransferInner>>) -> Box<dyn FnMut(ObexPacket) + Send> {
    Box::new(move |rsp_pkt: ObexPacket| {
        let rsp_code = rsp_pkt.opcode();
        let (id, opcode) = {
            let inner = state.lock().expect("TransferInner lock poisoned");
            (inner.id, inner.opcode)
        };

        tracing::debug!(
            target: "obex::transfer",
            "transfer {id}: client response 0x{rsp_code:02x}"
        );

        if opcode == OP_PUT {
            handle_put_response(&state, rsp_code, id);
        } else {
            handle_get_response(&state, &rsp_pkt, rsp_code, id);
        }
    })
}

/// Processes a client-side PUT response.
///
/// - `RSP_CONTINUE` → queues the next body chunk for sending.
/// - `RSP_SUCCESS` → marks the transfer complete (success).
/// - Any other code → marks the transfer complete (protocol error).
fn handle_put_response(state: &Arc<Mutex<TransferInner>>, rsp_code: u8, id: u32) {
    let mut inner = state.lock().expect("TransferInner lock poisoned");

    if rsp_code == RSP_CONTINUE {
        // Create the next PUT packet with body producer.
        let mut next_pkt = ObexPacket::new(OP_PUT | PACKET_FINAL);
        // Release the inner lock before creating the body producer (which
        // captures a clone of the Arc).
        drop(inner);
        next_pkt.set_body_producer(make_body_producer(state.clone()));

        let mut inner = state.lock().expect("TransferInner lock poisoned");
        inner
            .pending_sends
            .push(PendingSend { pkt: next_pkt, timeout: Duration::from_secs(DEFAULT_TIMEOUT) });
        tracing::debug!(
            target: "obex::transfer",
            "transfer {id}: PUT continue, queued next chunk"
        );
    } else if rsp_code == RSP_SUCCESS {
        inner.complete_result = Some(Ok(()));
        inner.completed = true;
        tracing::debug!(
            target: "obex::transfer",
            "transfer {id}: PUT complete (success)"
        );
    } else {
        let msg = obex_strerror(rsp_code).to_string();
        inner.complete_result =
            Some(Err(ObexError::ProtocolError { code: rsp_code, message: msg }));
        inner.completed = true;
        tracing::debug!(
            target: "obex::transfer",
            "transfer {id}: PUT error 0x{rsp_code:02x}"
        );
    }
}

/// Processes a client-side GET response.
///
/// - `RSP_CONTINUE` → consumes the body data and queues the next GET request.
/// - `RSP_SUCCESS` → consumes the final body data and completes the transfer.
/// - Any other code → marks the transfer complete (protocol error).
fn handle_get_response(
    state: &Arc<Mutex<TransferInner>>,
    rsp_pkt: &ObexPacket,
    rsp_code: u8,
    id: u32,
) {
    let mut inner = state.lock().expect("TransferInner lock poisoned");

    if rsp_code == RSP_CONTINUE || rsp_code == RSP_SUCCESS {
        // Consume body data from the response.
        if let Some(body_hdr) = rsp_pkt.get_body() {
            if let Some(body_data) = body_hdr.as_bytes() {
                if let Some(ref mut consumer) = inner.data_consumer {
                    if let Err(e) = consumer(body_data) {
                        tracing::debug!(
                            target: "obex::transfer",
                            "transfer {id}: GET consumer error"
                        );
                        inner.complete_result = Some(Err(e));
                        inner.completed = true;
                        return;
                    }
                }
            }
        }

        if rsp_code == RSP_CONTINUE {
            // Queue the next GET request (empty packet — just requesting
            // the next chunk).
            let next_pkt = ObexPacket::new(OP_GET | PACKET_FINAL);
            inner
                .pending_sends
                .push(PendingSend { pkt: next_pkt, timeout: Duration::from_secs(DEFAULT_TIMEOUT) });
            tracing::debug!(
                target: "obex::transfer",
                "transfer {id}: GET continue, queued next request"
            );
        } else {
            // RSP_SUCCESS — transfer complete.
            inner.complete_result = Some(Ok(()));
            inner.completed = true;
            tracing::debug!(
                target: "obex::transfer",
                "transfer {id}: GET complete (success)"
            );
        }
    } else {
        let msg = obex_strerror(rsp_code).to_string();
        inner.complete_result =
            Some(Err(ObexError::ProtocolError { code: rsp_code, message: msg }));
        inner.completed = true;
        tracing::debug!(
            target: "obex::transfer",
            "transfer {id}: GET error 0x{rsp_code:02x}"
        );
    }
}

// ---------------------------------------------------------------------------
// Private helpers — server-side request handlers
// ---------------------------------------------------------------------------

/// Extracts body data from a packet, feeds it to the consumer, and returns
/// the appropriate response code.
///
/// - `RSP_CONTINUE` if the packet has a non-final BODY header.
/// - `RSP_SUCCESS` if the packet is final (END_OF_BODY or no body + final).
/// - `RSP_FORBIDDEN` if the consumer rejects the data.
///
/// Matches C `put_get_bytes` in `gobex-transfer.c`.
fn put_get_bytes(inner: &mut TransferInner, pkt: &ObexPacket) -> u8 {
    let body_hdr = match pkt.get_body() {
        Some(hdr) => hdr,
        None => {
            // No body — if the packet is final, it signals end of transfer.
            if pkt.is_final() {
                return RSP_SUCCESS;
            }
            return RSP_CONTINUE;
        }
    };

    // Determine finality from the body header ID, NOT the packet FINAL bit.
    // HDR_BODY (0x48) = more data coming; HDR_BODY_END (0x49) = last chunk.
    // This matches the C implementation in transfer_put_req which checks
    // for G_OBEX_HDR_BODY vs G_OBEX_HDR_BODY_END.
    let is_final_body = body_hdr.id() == HDR_BODY_END;

    if let Some(data) = body_hdr.as_bytes() {
        if let Some(ref mut consumer) = inner.data_consumer {
            if consumer(data).is_err() {
                return RSP_FORBIDDEN;
            }
        }
    }

    if is_final_body { RSP_SUCCESS } else { RSP_CONTINUE }
}

/// Handler for incoming PUT requests on the server side.
///
/// Consumes body data from each received PUT packet and sends
/// `RSP_CONTINUE` or `RSP_SUCCESS` responses.  When the final body chunk
/// is received the transfer is completed.
///
/// Matches C `transfer_put_req`.
fn server_put_handler(
    state: &Arc<Mutex<TransferInner>>,
    session: &mut ObexSession,
    pkt: &ObexPacket,
) {
    let (id, rsp_code) = {
        let mut inner = state.lock().expect("TransferInner lock poisoned");
        let id = inner.id;
        let code = put_get_bytes(&mut inner, pkt);
        (id, code)
    };

    tracing::debug!(
        target: "obex::transfer",
        "server PUT handler: transfer {id}, rsp=0x{rsp_code:02x}"
    );

    if rsp_code == RSP_SUCCESS {
        // Final body received — send SUCCESS and complete.
        let rsp = ObexPacket::new_response(RSP_SUCCESS);
        let _ = session.send_rsp(OP_PUT, rsp);
        complete_server_transfer(state, session, Ok(()));
    } else if rsp_code == RSP_CONTINUE {
        // More data expected.  Send CONTINUE unless SRM is active (the
        // remote side keeps sending without acknowledgement in SRM).
        if !session.srm_active() {
            let rsp = ObexPacket::new_response(RSP_CONTINUE);
            let _ = session.send_rsp(OP_PUT, rsp);
        }
    } else {
        // Consumer error (RSP_FORBIDDEN).
        let rsp = ObexPacket::new_response(rsp_code);
        let _ = session.send_rsp(OP_PUT, rsp);
        complete_server_transfer(
            state,
            session,
            Err(ObexError::Failed("consumer rejected body data".into())),
        );
    }
}

/// Handler for incoming GET requests on the server side.
///
/// Sends response packets filled by the body producer.  When the producer
/// is exhausted (`Ok(0)`), the packet encoder automatically switches from
/// `RSP_CONTINUE` to `RSP_SUCCESS` and the transfer completes.
///
/// For SRM, the handler loops sending responses until the producer signals
/// end-of-body — there is no need to wait for further GET requests.
///
/// Matches C `transfer_get_req`.
fn server_get_handler(
    state: &Arc<Mutex<TransferInner>>,
    session: &mut ObexSession,
    _pkt: &ObexPacket,
) {
    let id = {
        let inner = state.lock().expect("TransferInner lock poisoned");
        inner.id
    };

    tracing::debug!(
        target: "obex::transfer",
        "server GET handler: transfer {id}"
    );

    loop {
        let done = Arc::new(AtomicBool::new(false));

        // Create response with body producer.
        let mut rsp_pkt = ObexPacket::new_response(RSP_CONTINUE);
        rsp_pkt.set_body_producer(make_body_producer_with_done(state.clone(), done.clone()));

        let _ = session.send_rsp(OP_GET, rsp_pkt);

        if done.load(Ordering::SeqCst) {
            // Producer exhausted — the packet encoder switched the opcode
            // to RSP_SUCCESS.  Transfer is complete.
            complete_server_transfer(state, session, Ok(()));
            return;
        }

        // If SRM is NOT active, return and wait for the next incoming GET.
        if !session.srm_active() {
            return;
        }
        // SRM is active — loop to send the next chunk immediately.
    }
}

/// Handler for incoming ABORT requests on the server side.
///
/// Acknowledges the ABORT with `RSP_SUCCESS` and completes the transfer
/// with [`ObexError::Cancelled`].
///
/// Matches C `transfer_abort_req`.
fn server_abort_handler(
    state: &Arc<Mutex<TransferInner>>,
    session: &mut ObexSession,
    _pkt: &ObexPacket,
) {
    let id = {
        let inner = state.lock().expect("TransferInner lock poisoned");
        inner.id
    };

    tracing::debug!(
        target: "obex::transfer",
        "server ABORT handler: transfer {id}"
    );

    // Acknowledge the ABORT.
    let rsp = ObexPacket::new_response(RSP_SUCCESS);
    // Use session.send() directly — fire-and-forget ABORT ACK needs no
    // opcode-specific handler cleanup that send_rsp might do.
    let _ = session.send(rsp);

    complete_server_transfer(state, session, Err(ObexError::Cancelled));
}

/// Completes a server-side transfer: unregisters request handlers, invokes
/// the completion callback, and removes the transfer from the global
/// registry.
fn complete_server_transfer(
    state: &Arc<Mutex<TransferInner>>,
    session: &mut ObexSession,
    result: Result<(), ObexError>,
) {
    let (id, put_hid, get_hid, abort_hid, complete_func) = {
        let mut inner = state.lock().expect("TransferInner lock poisoned");
        inner.completed = true;
        (
            inner.id,
            inner.put_handler_id.take(),
            inner.get_handler_id.take(),
            inner.abort_handler_id.take(),
            inner.complete_func.take(),
        )
    };

    // Unregister request handlers.
    if let Some(hid) = put_hid {
        session.remove_request_handler(hid);
    }
    if let Some(hid) = get_hid {
        session.remove_request_handler(hid);
    }
    if let Some(hid) = abort_hid {
        session.remove_request_handler(hid);
    }

    // On error, drop the transmit queue to prevent stale packets from
    // being sent.
    if result.is_err() {
        session.drop_tx_queue();
    }

    // Invoke the completion callback.
    if let Some(func) = complete_func {
        func(result);
    }

    transfer_remove(id);
    tracing::debug!(
        target: "obex::transfer",
        "transfer {id}: server transfer completed and removed"
    );
}

// ---------------------------------------------------------------------------
// ObexTransfer — public API
// ---------------------------------------------------------------------------

/// OBEX transfer lifecycle manager.
///
/// Provides associated functions for initiating PUT and GET transfers on both
/// the client side and server side, as well as cancellation and pending-action
/// processing.
///
/// Each function that creates a transfer returns a `u32` transfer ID that can
/// be passed to [`cancel_transfer`](Self::cancel_transfer) to abort the
/// operation.
///
/// Replaces the C transfer API in `gobex-transfer.c`:
/// - `g_obex_put_req()` / `g_obex_put_req_pkt()`
/// - `g_obex_get_req()` / `g_obex_get_req_pkt()`
/// - `g_obex_put_rsp()`
/// - `g_obex_get_rsp()` / `g_obex_get_rsp_pkt()`
/// - `g_obex_cancel_transfer()`
pub struct ObexTransfer;

impl ObexTransfer {
    // -------------------------------------------------------------------
    // Client PUT — g_obex_put_req / g_obex_put_req_pkt
    // -------------------------------------------------------------------

    /// Initiates a client-side PUT request with headers and a body producer.
    ///
    /// Creates a PUT packet containing the given headers, attaches the body
    /// producer, and sends the initial request with a 60-second timeout.
    /// Subsequent body chunks are sent automatically when
    /// [`process_pending`](Self::process_pending) is called after each
    /// `RSP_CONTINUE` response.
    ///
    /// Returns the transfer ID on success.
    ///
    /// Matches C `g_obex_put_req()`.
    pub fn put_req(
        session: &mut ObexSession,
        headers: Vec<ObexHeader>,
        producer: DataProducer,
        complete: CompleteFunc,
    ) -> Result<u32, ObexError> {
        let mut pkt = ObexPacket::new(OP_PUT | PACKET_FINAL);
        for hdr in headers {
            pkt.add_header(hdr);
        }
        Self::put_req_pkt(session, pkt, producer, complete)
    }

    /// Initiates a client-side PUT request with a pre-built packet and body
    /// producer.
    ///
    /// The packet should already contain any required headers (Name, Type,
    /// Length, etc.).  A body producer is attached and the first request is
    /// sent with `FIRST_PACKET_TIMEOUT` (60 s).
    ///
    /// Returns the transfer ID on success.
    ///
    /// Matches C `g_obex_put_req_pkt()`.
    pub fn put_req_pkt(
        session: &mut ObexSession,
        mut pkt: ObexPacket,
        producer: DataProducer,
        complete: CompleteFunc,
    ) -> Result<u32, ObexError> {
        let state = transfer_new(OP_PUT);
        let id = {
            let mut inner = state.lock().expect("TransferInner lock poisoned");
            inner.data_producer = Some(producer);
            inner.complete_func = Some(complete);
            inner.id
        };

        // Attach body producer to the initial packet.
        pkt.set_body_producer(make_body_producer(state.clone()));

        // Send the initial request with a 60-second timeout.
        let rsp_cb = make_client_rsp_callback(state.clone());
        let req_id = session.send_req(pkt, Duration::from_secs(FIRST_PACKET_TIMEOUT), rsp_cb)?;

        state.lock().expect("TransferInner lock poisoned").req_id = Some(req_id);

        tracing::debug!(
            target: "obex::transfer",
            "put_req_pkt: transfer {id} started, req_id={req_id}"
        );
        Ok(id)
    }

    // -------------------------------------------------------------------
    // Client GET — g_obex_get_req / g_obex_get_req_pkt
    // -------------------------------------------------------------------

    /// Initiates a client-side GET request with headers and a body consumer.
    ///
    /// Creates a GET packet containing the given headers and sends it.
    /// Incoming body data is fed to the `consumer` callback.  Follow-up GET
    /// requests are queued automatically and sent by
    /// [`process_pending`](Self::process_pending).
    ///
    /// Returns the transfer ID on success.
    ///
    /// Matches C `g_obex_get_req()`.
    pub fn get_req(
        session: &mut ObexSession,
        headers: Vec<ObexHeader>,
        consumer: DataConsumer,
        complete: CompleteFunc,
    ) -> Result<u32, ObexError> {
        let mut pkt = ObexPacket::new(OP_GET | PACKET_FINAL);
        for hdr in headers {
            pkt.add_header(hdr);
        }
        Self::get_req_pkt(session, pkt, consumer, complete)
    }

    /// Initiates a client-side GET request with a pre-built packet and body
    /// consumer.
    ///
    /// Returns the transfer ID on success.
    ///
    /// Matches C `g_obex_get_req_pkt()`.
    pub fn get_req_pkt(
        session: &mut ObexSession,
        pkt: ObexPacket,
        consumer: DataConsumer,
        complete: CompleteFunc,
    ) -> Result<u32, ObexError> {
        let state = transfer_new(OP_GET);
        let id = {
            let mut inner = state.lock().expect("TransferInner lock poisoned");
            inner.data_consumer = Some(consumer);
            inner.complete_func = Some(complete);
            inner.id
        };

        // Send initial GET request with 60-second timeout.
        let rsp_cb = make_client_rsp_callback(state.clone());
        let req_id = session.send_req(pkt, Duration::from_secs(FIRST_PACKET_TIMEOUT), rsp_cb)?;

        state.lock().expect("TransferInner lock poisoned").req_id = Some(req_id);

        tracing::debug!(
            target: "obex::transfer",
            "get_req_pkt: transfer {id} started, req_id={req_id}"
        );
        Ok(id)
    }

    // -------------------------------------------------------------------
    // Server PUT — g_obex_put_rsp
    // -------------------------------------------------------------------

    /// Sets up a server-side PUT response handler.
    ///
    /// Registers handlers for incoming PUT and ABORT requests on the session.
    /// Each incoming PUT packet's body data is fed to the `consumer`.  When
    /// the final body chunk is received, the `complete` callback is invoked
    /// with `Ok(())`.  An incoming ABORT completes the transfer with
    /// [`ObexError::Cancelled`].
    ///
    /// An initial `RSP_CONTINUE` is sent to signal readiness to receive data.
    ///
    /// Returns the transfer ID on success.
    ///
    /// Matches C `g_obex_put_rsp()`.
    pub fn put_rsp(
        session: &mut ObexSession,
        consumer: DataConsumer,
        complete: CompleteFunc,
    ) -> Result<u32, ObexError> {
        let state = transfer_new(OP_PUT);
        let id = {
            let mut inner = state.lock().expect("TransferInner lock poisoned");
            inner.data_consumer = Some(consumer);
            inner.complete_func = Some(complete);
            inner.id
        };

        // Register handler for incoming PUT requests.
        let state_put = state.clone();
        let put_handler_id =
            session.add_request_handler(OP_PUT, move |sess: &mut ObexSession, pkt: &ObexPacket| {
                server_put_handler(&state_put, sess, pkt);
            });

        // Register handler for incoming ABORT requests.
        let state_abort = state.clone();
        let abort_handler_id = session.add_request_handler(
            OP_ABORT,
            move |sess: &mut ObexSession, pkt: &ObexPacket| {
                server_abort_handler(&state_abort, sess, pkt);
            },
        );

        {
            let mut inner = state.lock().expect("TransferInner lock poisoned");
            inner.put_handler_id = Some(put_handler_id);
            inner.abort_handler_id = Some(abort_handler_id);
        }

        // Send initial RSP_CONTINUE to signal readiness.
        let rsp = ObexPacket::new_response(RSP_CONTINUE);
        session.send_rsp(OP_PUT, rsp)?;

        tracing::debug!(
            target: "obex::transfer",
            "put_rsp: transfer {id} ready for incoming PUT data"
        );
        Ok(id)
    }

    // -------------------------------------------------------------------
    // Server GET — g_obex_get_rsp / g_obex_get_rsp_pkt
    // -------------------------------------------------------------------

    /// Sets up a server-side GET response with headers and a body producer.
    ///
    /// Creates a `RSP_CONTINUE` response packet with the given headers,
    /// attaches the body producer, and delegates to
    /// [`get_rsp_pkt`](Self::get_rsp_pkt).
    ///
    /// Returns the transfer ID on success.
    ///
    /// Matches C `g_obex_get_rsp()`.
    pub fn get_rsp(
        session: &mut ObexSession,
        producer: DataProducer,
        complete: CompleteFunc,
        headers: Vec<ObexHeader>,
    ) -> Result<u32, ObexError> {
        let mut pkt = ObexPacket::new_response(RSP_CONTINUE);
        for hdr in headers {
            pkt.add_header(hdr);
        }
        Self::get_rsp_pkt(session, pkt, producer, complete)
    }

    /// Sets up a server-side GET response with a pre-built response packet
    /// and body producer.
    ///
    /// Sends the first response packet with body data produced by the
    /// `producer`.  Registers handlers for subsequent GET requests (which
    /// trigger further response packets) and ABORT requests.
    ///
    /// Returns the transfer ID on success.
    ///
    /// Matches C `g_obex_get_rsp_pkt()`.
    pub fn get_rsp_pkt(
        session: &mut ObexSession,
        mut pkt: ObexPacket,
        producer: DataProducer,
        complete: CompleteFunc,
    ) -> Result<u32, ObexError> {
        let state = transfer_new(OP_GET);
        let id = {
            let mut inner = state.lock().expect("TransferInner lock poisoned");
            inner.data_producer = Some(producer);
            inner.complete_func = Some(complete);
            inner.id
        };

        // Attach body producer to the first response packet.
        let done = Arc::new(AtomicBool::new(false));
        pkt.set_body_producer(make_body_producer_with_done(state.clone(), done.clone()));

        // Register handler for subsequent GET requests.
        let state_get = state.clone();
        let get_handler_id =
            session.add_request_handler(OP_GET, move |sess: &mut ObexSession, pkt: &ObexPacket| {
                server_get_handler(&state_get, sess, pkt);
            });

        // Register handler for ABORT requests.
        let state_abort = state.clone();
        let abort_handler_id = session.add_request_handler(
            OP_ABORT,
            move |sess: &mut ObexSession, pkt: &ObexPacket| {
                server_abort_handler(&state_abort, sess, pkt);
            },
        );

        {
            let mut inner = state.lock().expect("TransferInner lock poisoned");
            inner.get_handler_id = Some(get_handler_id);
            inner.abort_handler_id = Some(abort_handler_id);
        }

        // Send the first response.
        session.send_rsp(OP_GET, pkt)?;

        // Check if the body producer was already exhausted during encoding.
        if done.load(Ordering::SeqCst) {
            tracing::debug!(
                target: "obex::transfer",
                "get_rsp_pkt: transfer {id} completed on first response"
            );
            complete_server_transfer(&state, session, Ok(()));
        } else {
            tracing::debug!(
                target: "obex::transfer",
                "get_rsp_pkt: transfer {id} first response sent, awaiting GET"
            );
        }

        Ok(id)
    }

    // -------------------------------------------------------------------
    // Cancellation — g_obex_cancel_transfer
    // -------------------------------------------------------------------

    /// Cancels an active transfer by ID.
    ///
    /// **Client-side transfers:** If the request is still queued,
    /// [`ObexSession::cancel_req`] removes it.  If the request has already
    /// been sent, an ABORT request is transmitted.
    ///
    /// **Server-side transfers:** Request handlers are unregistered and an
    /// ABORT is sent.
    ///
    /// In both cases the completion callback is invoked with
    /// [`ObexError::Cancelled`] and the transfer is removed from the
    /// registry.
    ///
    /// Returns `true` if the transfer was found and cancelled, `false` if no
    /// transfer with the given ID exists.
    ///
    /// Matches C `g_obex_cancel_transfer()`.
    pub fn cancel_transfer(session: &mut ObexSession, transfer_id: u32) -> bool {
        let state = match transfer_find(transfer_id) {
            Some(s) => s,
            None => return false,
        };

        let req_id = {
            let inner = state.lock().expect("TransferInner lock poisoned");
            inner.req_id
        };

        tracing::debug!(
            target: "obex::transfer",
            "cancel_transfer: id={transfer_id}"
        );

        // Attempt to cancel any pending request or send ABORT.
        if let Some(rid) = req_id {
            // Client-side: try to remove the request from the queue.
            if !session.cancel_req(rid, true) {
                // The request was already sent — send ABORT to the remote.
                let _ = session.abort_req(|_rsp| {
                    tracing::debug!(
                        target: "obex::transfer",
                        "cancel ABORT response received"
                    );
                });
            }
        } else {
            // Server-side (no pending request ID) — send ABORT.
            let _ = session.abort_req(|_rsp| {
                tracing::debug!(
                    target: "obex::transfer",
                    "cancel ABORT response received"
                );
            });
        }

        // Clean up: unregister handlers, call complete(Cancelled), remove.
        free_transfer(&state, session);
        true
    }

    // -------------------------------------------------------------------
    // Pending action processing
    // -------------------------------------------------------------------

    /// Drains pending follow-up actions for **all** active client-side
    /// transfers.
    ///
    /// This must be called after [`ObexSession::incoming_data`] returns so
    /// that response-callback-queued packets (continuation PUTs, follow-up
    /// GETs) are actually sent, and completion callbacks are invoked.
    ///
    /// Server-side transfers handle their I/O directly inside request
    /// handlers — this function only processes their completion results if
    /// any are pending.
    pub fn process_pending(session: &mut ObexSession) {
        // Snapshot the current set of active transfers (cloning Arcs).
        let transfers: Vec<Arc<Mutex<TransferInner>>> =
            { TRANSFERS.lock().expect("TRANSFERS lock poisoned").clone() };

        let mut to_remove: Vec<u32> = Vec::new();

        for state in &transfers {
            let (id, pending_sends, complete_result) = {
                let mut inner = state.lock().expect("TransferInner lock poisoned");
                (inner.id, std::mem::take(&mut inner.pending_sends), inner.complete_result.take())
            };

            // --- Process queued sends ---
            for send in pending_sends {
                let rsp_cb = make_client_rsp_callback(state.clone());
                match session.send_req(send.pkt, send.timeout, rsp_cb) {
                    Ok(req_id) => {
                        state.lock().expect("TransferInner lock poisoned").req_id = Some(req_id);
                    }
                    Err(e) => {
                        tracing::error!(
                            target: "obex::transfer",
                            "transfer {id}: follow-up send failed: {e}"
                        );
                        // Invoke the completion callback with the error.
                        let complete_func = {
                            let mut inner = state.lock().expect("TransferInner lock poisoned");
                            inner.completed = true;
                            inner.complete_func.take()
                        };
                        if let Some(func) = complete_func {
                            func(Err(e));
                        }
                        to_remove.push(id);
                        break; // Skip remaining sends for this transfer.
                    }
                }
            }

            // --- Process completion ---
            if let Some(result) = complete_result {
                let complete_func = {
                    let mut inner = state.lock().expect("TransferInner lock poisoned");
                    inner.complete_func.take()
                };
                if let Some(func) = complete_func {
                    if result.is_err() {
                        session.drop_tx_queue();
                    }
                    func(result);
                }
                to_remove.push(id);
            }
        }

        // Remove completed transfers from the global registry.
        if !to_remove.is_empty() {
            let mut registry = TRANSFERS.lock().expect("TRANSFERS lock poisoned");
            registry.retain(|arc| {
                let tid = arc.lock().map(|inner| inner.id).unwrap_or(0);
                !to_remove.contains(&tid)
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Private helper — transfer cleanup (used by cancel_transfer)
// ---------------------------------------------------------------------------

/// Cleans up a cancelled transfer: unregisters request handlers, cancels any
/// pending request, invokes the completion callback with
/// [`ObexError::Cancelled`], and removes the transfer from the global
/// registry.
///
/// Matches the combined effect of C `transfer_free` + completion with
/// `G_IO_ERROR_CANCELLED`.
fn free_transfer(state: &Arc<Mutex<TransferInner>>, session: &mut ObexSession) {
    let (id, req_id, put_hid, get_hid, abort_hid, complete_func) = {
        let mut inner = state.lock().expect("TransferInner lock poisoned");
        inner.completed = true;
        (
            inner.id,
            inner.req_id.take(),
            inner.put_handler_id.take(),
            inner.get_handler_id.take(),
            inner.abort_handler_id.take(),
            inner.complete_func.take(),
        )
    };

    // Cancel the pending request (with remove=false so it's just marked).
    if let Some(rid) = req_id {
        session.cancel_req(rid, false);
    }

    // Unregister server-side request handlers.
    if let Some(hid) = put_hid {
        session.remove_request_handler(hid);
    }
    if let Some(hid) = get_hid {
        session.remove_request_handler(hid);
    }
    if let Some(hid) = abort_hid {
        session.remove_request_handler(hid);
    }

    // Drop pending transmit packets.
    session.drop_tx_queue();

    // Invoke the completion callback with Cancelled.
    if let Some(func) = complete_func {
        func(Err(ObexError::Cancelled));
    }

    transfer_remove(id);
    tracing::debug!(
        target: "obex::transfer",
        "free_transfer: transfer {id} cleaned up"
    );
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the `FIRST_PACKET_TIMEOUT` constant matches the C value.
    #[test]
    fn first_packet_timeout_matches_c() {
        assert_eq!(FIRST_PACKET_TIMEOUT, 60);
    }

    /// Verify that transfer IDs are monotonically increasing starting from 1.
    #[test]
    fn transfer_ids_monotonic() {
        // Reset is not possible with atomics, so we just check that new
        // transfers get incrementing IDs.
        let state1 = transfer_new(OP_PUT);
        let state2 = transfer_new(OP_GET);

        let id1 = state1.lock().unwrap().id;
        let id2 = state2.lock().unwrap().id;
        assert!(id2 > id1, "transfer IDs should be monotonically increasing");

        // Clean up.
        transfer_remove(id1);
        transfer_remove(id2);
    }

    /// Verify that `transfer_find` locates existing transfers and returns
    /// `None` for missing IDs.
    #[test]
    fn transfer_find_and_remove() {
        let state = transfer_new(OP_PUT);
        let id = state.lock().unwrap().id;

        assert!(transfer_find(id).is_some());
        transfer_remove(id);
        assert!(transfer_find(id).is_none());
    }

    /// Verify that `put_get_bytes` returns the correct response code based
    /// on packet finality and body data.
    #[test]
    fn put_get_bytes_response_codes() {
        use super::super::header::{HDR_BODY, HDR_BODY_END};

        // Packet with BODY header (non-final) → RSP_CONTINUE.
        let mut pkt = ObexPacket::new(OP_PUT);
        pkt.set_final(false);
        pkt.add_header(ObexHeader::new_bytes(HDR_BODY, b"hello"));
        let mut inner = TransferInner {
            id: 0,
            opcode: OP_PUT,
            req_id: None,
            put_handler_id: None,
            get_handler_id: None,
            abort_handler_id: None,
            data_producer: None,
            data_consumer: Some(Box::new(|_data: &[u8]| Ok(()))),
            complete_func: None,
            pending_sends: Vec::new(),
            complete_result: None,
            completed: false,
        };
        assert_eq!(put_get_bytes(&mut inner, &pkt), RSP_CONTINUE);

        // Packet with BODY_END header (final) → RSP_SUCCESS.
        let mut pkt_final = ObexPacket::new(OP_PUT | PACKET_FINAL);
        pkt_final.add_header(ObexHeader::new_bytes(HDR_BODY_END, b"world"));
        assert_eq!(put_get_bytes(&mut inner, &pkt_final), RSP_SUCCESS);

        // Packet with BODY header + consumer error → RSP_FORBIDDEN.
        inner.data_consumer =
            Some(Box::new(|_data: &[u8]| Err(ObexError::Failed("rejected".into()))));
        let mut pkt_err = ObexPacket::new(OP_PUT);
        pkt_err.set_final(false);
        pkt_err.add_header(ObexHeader::new_bytes(HDR_BODY, b"error"));
        assert_eq!(put_get_bytes(&mut inner, &pkt_err), RSP_FORBIDDEN);
    }

    /// Verify DataProducer / DataConsumer / CompleteFunc type aliases compile.
    #[test]
    fn callback_types_compile() {
        let _producer: DataProducer = Box::new(|buf: &mut [u8]| {
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = 0x42;
            Ok(1)
        });

        let _consumer: DataConsumer = Box::new(|_data: &[u8]| Ok(()));

        let _complete: CompleteFunc = Box::new(|result: Result<(), ObexError>| {
            let _ = result;
        });
    }

    /// Verify `handle_put_response` for RSP_CONTINUE queues a pending send.
    #[test]
    fn handle_put_response_continue() {
        let state = Arc::new(Mutex::new(TransferInner {
            id: 99,
            opcode: OP_PUT,
            req_id: Some(1),
            put_handler_id: None,
            get_handler_id: None,
            abort_handler_id: None,
            data_producer: Some(Box::new(|buf: &mut [u8]| {
                if buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = 0xAA;
                Ok(1)
            })),
            data_consumer: None,
            complete_func: None,
            pending_sends: Vec::new(),
            complete_result: None,
            completed: false,
        }));

        handle_put_response(&state, RSP_CONTINUE, 99);

        let inner = state.lock().unwrap();
        assert_eq!(inner.pending_sends.len(), 1);
        assert!(!inner.completed);
    }

    /// Verify `handle_put_response` for RSP_SUCCESS sets completion.
    #[test]
    fn handle_put_response_success() {
        let state = Arc::new(Mutex::new(TransferInner {
            id: 100,
            opcode: OP_PUT,
            req_id: Some(2),
            put_handler_id: None,
            get_handler_id: None,
            abort_handler_id: None,
            data_producer: None,
            data_consumer: None,
            complete_func: None,
            pending_sends: Vec::new(),
            complete_result: None,
            completed: false,
        }));

        handle_put_response(&state, RSP_SUCCESS, 100);

        let inner = state.lock().unwrap();
        assert!(inner.completed);
        assert!(inner.complete_result.as_ref().unwrap().is_ok());
    }

    /// Verify `handle_put_response` for error code sets protocol error.
    #[test]
    fn handle_put_response_error() {
        let state = Arc::new(Mutex::new(TransferInner {
            id: 101,
            opcode: OP_PUT,
            req_id: Some(3),
            put_handler_id: None,
            get_handler_id: None,
            abort_handler_id: None,
            data_producer: None,
            data_consumer: None,
            complete_func: None,
            pending_sends: Vec::new(),
            complete_result: None,
            completed: false,
        }));

        handle_put_response(&state, RSP_FORBIDDEN, 101);

        let inner = state.lock().unwrap();
        assert!(inner.completed);
        assert!(inner.complete_result.as_ref().unwrap().is_err());
    }

    /// Verify `handle_get_response` for RSP_CONTINUE consumes body and
    /// queues follow-up.
    #[test]
    fn handle_get_response_continue() {
        use std::sync::atomic::AtomicUsize;

        let consumed = Arc::new(AtomicUsize::new(0));
        let consumed_clone = consumed.clone();

        let state = Arc::new(Mutex::new(TransferInner {
            id: 200,
            opcode: OP_GET,
            req_id: Some(10),
            put_handler_id: None,
            get_handler_id: None,
            abort_handler_id: None,
            data_producer: None,
            data_consumer: Some(Box::new(move |data: &[u8]| {
                consumed_clone.fetch_add(data.len(), Ordering::Relaxed);
                Ok(())
            })),
            complete_func: None,
            pending_sends: Vec::new(),
            complete_result: None,
            completed: false,
        }));

        // Build a response packet with body data.
        let mut rsp_pkt = ObexPacket::new_response(RSP_CONTINUE);
        rsp_pkt.add_header(ObexHeader::new_bytes(super::super::header::HDR_BODY, b"test data"));

        handle_get_response(&state, &rsp_pkt, RSP_CONTINUE, 200);

        let inner = state.lock().unwrap();
        assert_eq!(inner.pending_sends.len(), 1, "should queue follow-up GET");
        assert!(!inner.completed);
        assert_eq!(consumed.load(Ordering::Relaxed), 9); // "test data" = 9 bytes
    }

    /// Verify `handle_get_response` for RSP_SUCCESS consumes body and
    /// completes.
    #[test]
    fn handle_get_response_success() {
        let state = Arc::new(Mutex::new(TransferInner {
            id: 201,
            opcode: OP_GET,
            req_id: Some(11),
            put_handler_id: None,
            get_handler_id: None,
            abort_handler_id: None,
            data_producer: None,
            data_consumer: Some(Box::new(|_data: &[u8]| Ok(()))),
            complete_func: None,
            pending_sends: Vec::new(),
            complete_result: None,
            completed: false,
        }));

        let mut rsp_pkt = ObexPacket::new_response(RSP_SUCCESS);
        rsp_pkt.add_header(ObexHeader::new_bytes(super::super::header::HDR_BODY_END, b"final"));

        handle_get_response(&state, &rsp_pkt, RSP_SUCCESS, 201);

        let inner = state.lock().unwrap();
        assert!(inner.completed);
        assert!(inner.complete_result.as_ref().unwrap().is_ok());
    }
}
