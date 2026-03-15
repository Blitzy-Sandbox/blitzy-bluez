// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2014 Intel Corporation. All rights reserved.
//
// BNEP (Bluetooth Network Encapsulation Protocol) socket tester.
// Rust rewrite of tools/bnep-tester.c.
//
// This binary validates basic BNEP socket operations against a virtual HCI
// emulator.  The single registered test — "Basic BNEP Socket - Success" —
// creates a raw `PF_BLUETOOTH` / `BTPROTO_BNEP` socket, verifies the kernel
// accepted it, and then closes it.

use std::any::Any;
use std::sync::Arc;

use tokio::sync::Mutex;

use bluez_emulator::hciemu::{EmulatorType, HciEmulator};
use bluez_shared::mgmt::client::MgmtSocket;
use bluez_shared::sys::bluetooth::{BTPROTO_BNEP, PF_BLUETOOTH, btohl, btohs};
use bluez_shared::sys::bnep::{BNEP_MTU, BNEP_PSM};
use bluez_shared::sys::hci::{OCF_WRITE_SCAN_ENABLE, OGF_HOST_CTL, cmd_opcode_pack};
use bluez_shared::sys::mgmt::{
    MGMT_EV_INDEX_ADDED, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE, MGMT_OP_READ_INDEX_LIST,
    MGMT_OP_READ_INFO, MGMT_OP_SET_POWERED, MGMT_STATUS_SUCCESS, mgmt_rp_read_info,
};
use bluez_shared::tester::{
    tester_add_full, tester_get_data, tester_init, tester_post_teardown_complete,
    tester_pre_setup_complete, tester_pre_setup_failed, tester_print, tester_run,
    tester_setup_complete, tester_setup_failed, tester_test_failed, tester_test_passed,
    tester_use_debug, tester_warn,
};

// ---------------------------------------------------------------------------
// Test data structure
// ---------------------------------------------------------------------------

/// Per-test state shared among lifecycle callbacks via `tester_get_data()`.
///
/// Replaces the C `struct test_data` from bnep-tester.c lines 34–42.
/// Wrapped in `tokio::sync::Mutex` so that async tasks spawned from
/// synchronous callbacks can safely access and mutate the fields.
struct TestData {
    /// MGMT protocol socket for controller management operations.
    mgmt: Option<MgmtSocket>,
    /// Controller index assigned by the kernel on INDEX_ADDED.
    mgmt_index: u16,
    /// Virtual HCI controller emulator instance.
    hciemu: Option<HciEmulator>,
    /// Emulator type (BR/EDR-only for BNEP tests).
    hciemu_type: EmulatorType,
    /// Handle to a background I/O task, if any (replaces C `io_id`).
    io_handle: Option<tokio::task::JoinHandle<()>>,
    /// ACL connection handle (reserved for future BNEP connection tests).
    _conn_handle: u16,
}

impl Default for TestData {
    fn default() -> Self {
        Self {
            mgmt: None,
            mgmt_index: 0,
            hciemu: None,
            hciemu_type: EmulatorType::BrEdr,
            io_handle: None,
            _conn_handle: 0,
        }
    }
}

/// Type alias for the shared test data accessed across lifecycle callbacks.
type SharedTestData = Mutex<TestData>;

// ---------------------------------------------------------------------------
// MGMT response parsing helpers
// ---------------------------------------------------------------------------

/// Parse a raw MGMT READ_INFO response buffer into a `mgmt_rp_read_info`
/// reference.
///
/// Returns `None` if the buffer is shorter than the expected wire-format size.
#[allow(unsafe_code)]
fn parse_read_info_rp(data: &[u8]) -> Option<&mgmt_rp_read_info> {
    if data.len() < std::mem::size_of::<mgmt_rp_read_info>() {
        return None;
    }
    // SAFETY: `mgmt_rp_read_info` is `#[repr(C, packed)]` and matches the
    // kernel MGMT wire format exactly.  We verified that `data` is long
    // enough.  The returned reference borrows from `data` with the correct
    // lifetime.
    Some(unsafe { &*(data.as_ptr() as *const mgmt_rp_read_info) })
}

// ---------------------------------------------------------------------------
// Pre-setup: create MGMT socket, emulator, validate controller info
// ---------------------------------------------------------------------------

/// Pre-setup callback: creates the MGMT socket, reads the controller index
/// list, subscribes to index events, creates the HCI emulator, waits for
/// INDEX_ADDED, sends READ_INFO, and validates the emulator address.
///
/// Replaces the C callback chain: `test_pre_setup` → `read_index_list_callback`
/// → `index_added_callback` → `read_info_callback` (bnep-tester.c lines 69–189).
fn test_pre_setup(_data: &dyn Any) {
    tokio::spawn(async {
        let td = match tester_get_data::<SharedTestData>() {
            Some(td) => td,
            None => {
                tester_pre_setup_failed();
                return;
            }
        };

        // ---- Step 1: create MGMT socket ----
        let mgmt = match MgmtSocket::new_default() {
            Ok(m) => m,
            Err(e) => {
                tester_warn(&format!("Failed to setup management interface: {e}"));
                tester_pre_setup_failed();
                return;
            }
        };

        // ---- Step 2: send READ_INDEX_LIST ----
        let resp = match mgmt.send_command(MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, &[]).await {
            Ok(r) => r,
            Err(e) => {
                tester_warn(&format!("READ_INDEX_LIST failed: {e}"));
                tester_pre_setup_failed();
                return;
            }
        };

        tester_print("Read Index List callback");
        tester_print(&format!("  Status: 0x{:02x}", resp.status));

        if resp.status != MGMT_STATUS_SUCCESS {
            tester_pre_setup_failed();
            return;
        }

        // ---- Step 3: subscribe to INDEX_ADDED / INDEX_REMOVED ----
        let (_added_id, mut added_rx) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;
        let (_removed_id, _removed_rx) =
            mgmt.subscribe(MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE).await;

        // ---- Step 4: create HCI emulator ----
        let emu_type = td.lock().await.hciemu_type;
        let mut hciemu = match HciEmulator::new(emu_type) {
            Ok(e) => e,
            Err(e) => {
                tester_warn(&format!("Failed to setup HCI emulation: {e}"));
                tester_pre_setup_failed();
                return;
            }
        };

        if tester_use_debug() {
            hciemu.set_debug(|msg| {
                tracing::info!("hciemu: {}", msg);
            });
        }

        tester_print("New hciemu instance created");

        // ---- Step 5: wait for INDEX_ADDED event ----
        let ev = match added_rx.recv().await {
            Some(ev) => ev,
            None => {
                tester_warn("INDEX_ADDED channel closed unexpectedly");
                tester_pre_setup_failed();
                return;
            }
        };

        let mgmt_index = ev.index;
        tester_print("Index Added callback");
        tester_print(&format!("  Index: 0x{:04x}", mgmt_index));

        // ---- Step 6: send READ_INFO for the new controller ----
        let info_resp = match mgmt.send_command(MGMT_OP_READ_INFO, mgmt_index, &[]).await {
            Ok(r) => r,
            Err(e) => {
                tester_warn(&format!("READ_INFO failed: {e}"));
                tester_pre_setup_failed();
                return;
            }
        };

        tester_print("Read Info callback");
        tester_print(&format!("  Status: 0x{:02x}", info_resp.status));

        if info_resp.status != MGMT_STATUS_SUCCESS {
            tester_pre_setup_failed();
            return;
        }

        // ---- Step 7: parse and validate controller info ----
        let rp = match parse_read_info_rp(&info_resp.data) {
            Some(rp) => rp,
            None => {
                tester_warn("READ_INFO response too short");
                tester_pre_setup_failed();
                return;
            }
        };

        let addr = rp.bdaddr.ba2str();
        let manufacturer = btohs(rp.manufacturer);
        let supported_settings = btohl(rp.supported_settings);
        let current_settings = btohl(rp.current_settings);

        tester_print(&format!("  Address: {addr}"));
        tester_print(&format!("  Version: 0x{:02x}", rp.version));
        tester_print(&format!("  Manufacturer: 0x{:04x}", manufacturer));
        tester_print(&format!("  Supported settings: 0x{:08x}", supported_settings));
        tester_print(&format!("  Current settings: 0x{:08x}", current_settings));
        tester_print(&format!(
            "  Class: 0x{:02x}{:02x}{:02x}",
            rp.dev_class[2], rp.dev_class[1], rp.dev_class[0]
        ));

        let name_end = rp.name.iter().position(|&b| b == 0).unwrap_or(rp.name.len());
        let name = String::from_utf8_lossy(&rp.name[..name_end]);
        tester_print(&format!("  Name: {name}"));

        let short_end = rp.short_name.iter().position(|&b| b == 0).unwrap_or(rp.short_name.len());
        let short_name = String::from_utf8_lossy(&rp.short_name[..short_end]);
        tester_print(&format!("  Short name: {short_name}"));

        // Validate: emulator address must match the MGMT-reported address.
        let emu_addr = hciemu.get_address();
        if emu_addr != addr {
            tester_warn(&format!("Address mismatch: emulator={emu_addr}, mgmt={addr}"));
            tester_pre_setup_failed();
            return;
        }

        // ---- Step 8: store state for subsequent lifecycle phases ----
        {
            let mut d = td.lock().await;
            d.mgmt = Some(mgmt);
            d.mgmt_index = mgmt_index;
            d.hciemu = Some(hciemu);
        }

        tester_pre_setup_complete();
    });
}

// ---------------------------------------------------------------------------
// Setup: power on controller and make client connectable
// ---------------------------------------------------------------------------

/// Setup callback: sends MGMT SET_POWERED to turn on the controller, then
/// configures the emulated client host to enable scan (make it connectable).
///
/// Replaces the C callback chain: `setup_powered_client` →
/// `setup_powered_client_callback` → `client_connectable_complete`
/// (bnep-tester.c lines 211–258).
fn setup_powered_client(_data: &dyn Any) {
    tokio::spawn(async {
        let td = match tester_get_data::<SharedTestData>() {
            Some(td) => td,
            None => {
                tester_setup_failed();
                return;
            }
        };

        tester_print("Powering on controller");

        let d = td.lock().await;

        // Send SET_POWERED command.
        let mgmt = match d.mgmt.as_ref() {
            Some(m) => m,
            None => {
                tester_warn("No MGMT socket available for SET_POWERED");
                tester_setup_failed();
                return;
            }
        };

        let resp = match mgmt.send_command(MGMT_OP_SET_POWERED, d.mgmt_index, &[0x01]).await {
            Ok(r) => r,
            Err(e) => {
                tester_warn(&format!("SET_POWERED failed: {e}"));
                tester_setup_failed();
                return;
            }
        };

        if resp.status != MGMT_STATUS_SUCCESS {
            tester_setup_failed();
            return;
        }

        tester_print("Controller powered on");

        // Configure the emulated client host: set the command-complete
        // callback, then issue WRITE_SCAN_ENABLE to make it connectable.
        let hciemu = match d.hciemu.as_ref() {
            Some(e) => e,
            None => {
                tester_warn("No HCI emulator available for setup");
                tester_setup_failed();
                return;
            }
        };

        let write_scan_opcode = cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE);

        if let Some(mut bthost) = hciemu.client_get_host() {
            bthost.set_cmd_complete_cb(move |opcode, status, _param| {
                if opcode != write_scan_opcode {
                    return;
                }
                tester_print(&format!("Client set connectable status 0x{:02x}", status));
                if status != 0 {
                    tester_setup_failed();
                } else {
                    tester_setup_complete();
                }
            });
            bthost.write_scan_enable(0x03);
        } else {
            tester_warn("Failed to get client bthost");
            tester_setup_failed();
        }
    });
}

// ---------------------------------------------------------------------------
// Test function: basic BNEP socket creation
// ---------------------------------------------------------------------------

/// Test callback: creates a raw `PF_BLUETOOTH` / `BTPROTO_BNEP` socket to
/// verify that the kernel BNEP module is available, then closes it.
///
/// Replaces C `test_basic` (bnep-tester.c lines 260–275).
#[allow(unsafe_code)]
fn test_basic(_data: &dyn Any) {
    // Log BNEP protocol constants for verification.
    tester_print(&format!("BNEP PSM: 0x{:04x}, MTU: {}", BNEP_PSM, BNEP_MTU));

    // SAFETY: Creating a PF_BLUETOOTH / SOCK_RAW / BTPROTO_BNEP socket via
    // libc.  This is a standard syscall that returns a file descriptor (≥ 0)
    // on success or -1 on error with errno set.  No invariants are violated.
    let sk = unsafe { libc::socket(PF_BLUETOOTH, libc::SOCK_RAW, BTPROTO_BNEP) };
    if sk < 0 {
        let err = nix::errno::Errno::last();
        tester_warn(&format!("Can't create socket: {err} ({})", err as i32));
        tester_test_failed();
        return;
    }

    // SAFETY: Closing the valid file descriptor obtained from socket() above.
    // After this call `sk` is no longer valid and must not be reused.
    unsafe {
        libc::close(sk);
    }

    tester_test_passed();
}

// ---------------------------------------------------------------------------
// Post-teardown: clean up emulator and management socket
// ---------------------------------------------------------------------------

/// Post-teardown callback: cancels any pending I/O task, drops the HCI
/// emulator (which triggers kernel INDEX_REMOVED), unsubscribes from
/// management events, and drops the MGMT socket.
///
/// Replaces the C callback chain: `test_post_teardown` +
/// `index_removed_callback` (bnep-tester.c lines 123–202).
fn test_post_teardown(_data: &dyn Any) {
    tokio::spawn(async {
        let td = match tester_get_data::<SharedTestData>() {
            Some(td) => td,
            None => {
                tester_post_teardown_complete();
                return;
            }
        };

        let mut d = td.lock().await;

        // Cancel any pending I/O task.
        if let Some(handle) = d.io_handle.take() {
            handle.abort();
        }

        // Drop emulator — triggers INDEX_REMOVED on the management socket.
        d.hciemu = None;

        tester_print("Index Removed callback");
        tester_print(&format!("  Index: 0x{:04x}", d.mgmt_index));

        // Unsubscribe management events and drop the socket.
        if let Some(ref mgmt) = d.mgmt {
            mgmt.unsubscribe_index(d.mgmt_index).await;
        }
        d.mgmt = None;

        tester_post_teardown_complete();
    });
}

// ---------------------------------------------------------------------------
// Test registration helper
// ---------------------------------------------------------------------------

/// Register a BNEP test case with the tester framework.
///
/// Replaces the C `test_bnep` macro (bnep-tester.c lines 277–289).  Each
/// test creates a fresh `TestData` with `EmulatorType::BrEdr` and wires up
/// the standard pre-setup, setup, test, and post-teardown callbacks.
fn register_bnep_test(name: &str, setup: fn(&dyn Any), test_fn: fn(&dyn Any)) {
    let test_data =
        Mutex::new(TestData { hciemu_type: EmulatorType::BrEdr, ..TestData::default() });

    tester_add_full::<SharedTestData, ()>(
        name,
        Some(test_data),
        Some(Arc::new(test_pre_setup)),
        Some(Arc::new(setup)),
        Some(Arc::new(test_fn)),
        None,
        Some(Arc::new(test_post_teardown)),
        2,
        None,
    );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// BNEP tester entry point.
///
/// Initialises the tracing subscriber for library-level log output, sets up
/// the test framework, registers the "Basic BNEP Socket - Success" test case,
/// and runs the test suite.
///
/// Replaces C `main` (bnep-tester.c lines 291–299).
fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    tester_init(&args);

    register_bnep_test("Basic BNEP Socket - Success", setup_powered_client, test_basic);

    std::process::exit(tester_run());
}
