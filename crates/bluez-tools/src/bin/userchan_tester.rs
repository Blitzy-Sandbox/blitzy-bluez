// SPDX-License-Identifier: GPL-2.0-or-later
//! HCI User Channel integration tester.
//!
//! Complete Rust rewrite of BlueZ `tools/userchan-tester.c` (390 lines).
//! Validates opening and closing HCI user channel sockets and tests
//! interaction between user channel access and the management interface.
//!
//! # Test Cases
//!
//! 1. **User channel open – Success** — Opens an HCI user channel on an
//!    unpowered controller and verifies the bind succeeds.
//! 2. **User channel open – Failed** — Attempts to open a user channel on
//!    a powered controller and verifies the bind fails (EBUSY).
//! 3. **User channel open – Power Toggle Success** — Powers on then off
//!    the controller, then opens a user channel and verifies success.
//! 4. **User channel close – Success** — Opens a user channel, closes it,
//!    then reads controller info to verify the controller is unpowered.
//!
//! Each test uses the shared tester harness from `bluez_shared::tester`
//! and the HCI emulator from `bluez_emulator::hciemu`.

#![deny(warnings)]

use std::any::Any;
use std::sync::{Arc, Mutex};

use bluez_emulator::hciemu::{EmulatorType, HciEmulator};
use bluez_shared::hci::transport::HciTransport;
use bluez_shared::mgmt::client::MgmtSocket;
use bluez_shared::sys::bluetooth::{btohl, btohs};
use bluez_shared::sys::mgmt::{
    MGMT_EV_INDEX_ADDED, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE, MGMT_OP_READ_INDEX_LIST,
    MGMT_OP_READ_INFO, MGMT_OP_SET_POWERED, MGMT_STATUS_SUCCESS, MgmtSettings, mgmt_rp_read_info,
};
use bluez_shared::tester::{
    TestCallback, tester_add_full, tester_init, tester_post_teardown_complete,
    tester_pre_setup_complete, tester_pre_setup_failed, tester_print, tester_run,
    tester_setup_complete, tester_setup_failed, tester_test_failed, tester_test_passed,
    tester_use_debug, tester_warn,
};

// ===========================================================================
// Per-test mutable state
// ===========================================================================

/// Per-test shared mutable state.
///
/// Replaces the C `struct test_data` allocated per test case. Wrapped in
/// `Arc<Mutex<…>>` so that callbacks can share it safely.
struct TestState {
    /// MGMT protocol client socket (shared via Arc since MgmtSocket is !Clone).
    mgmt: Option<Arc<MgmtSocket>>,
    /// HCI controller index discovered via INDEX_ADDED event.
    mgmt_index: u16,
    /// HCI emulator instance.
    hciemu: Option<HciEmulator>,
    /// Emulator type for this test (always BrEdr).
    hciemu_type: EmulatorType,
    /// Optional per-test data (e.g. initial power state for toggle tests).
    test_data_val: Option<bool>,
    /// Subscription ID for MGMT_EV_INDEX_REMOVED (set by test_open_success).
    remove_id: u32,
    /// HCI transport handle opened on user channel.
    hci: Option<Arc<HciTransport>>,
    /// Current controller settings from READ_INFO.
    current_settings: u32,
    /// Subscription ID for INDEX_ADDED event.
    index_added_sub_id: u32,
}

/// Thread-safe handle to per-test state.
type SharedState = Arc<Mutex<TestState>>;

impl TestState {
    /// Create a new `TestState` with defaults.
    fn new(hciemu_type: EmulatorType, test_data_val: Option<bool>) -> Self {
        Self {
            mgmt: None,
            mgmt_index: MGMT_INDEX_NONE,
            hciemu: None,
            hciemu_type,
            test_data_val,
            remove_id: 0,
            hci: None,
            current_settings: 0,
            index_added_sub_id: 0,
        }
    }
}

// ===========================================================================
// Helper: parse mgmt_rp_read_info from response bytes
// ===========================================================================

/// Minimum byte size of `mgmt_rp_read_info`.
const READ_INFO_SIZE: usize = std::mem::size_of::<mgmt_rp_read_info>();

/// Parse a `mgmt_rp_read_info` from a byte slice.
///
/// The struct is `#[repr(C, packed)]` with `zerocopy::FromBytes`, so we
/// copy byte-by-byte into a local buffer and reconstruct via
/// `read_unaligned` to avoid unaligned field access.
fn parse_read_info(data: &[u8]) -> Option<mgmt_rp_read_info> {
    if data.len() < READ_INFO_SIZE {
        return None;
    }
    let mut buf = [0u8; READ_INFO_SIZE];
    buf.copy_from_slice(&data[..READ_INFO_SIZE]);

    // SAFETY: mgmt_rp_read_info is Copy, repr(C,packed), and derives
    // FromBytes — every bit pattern is valid. read_unaligned handles
    // the packed layout correctly.
    #[allow(unsafe_code)]
    let rp: mgmt_rp_read_info =
        unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<mgmt_rp_read_info>()) };
    Some(rp)
}

// ===========================================================================
// Callbacks and lifecycle functions
// ===========================================================================

/// Read Info callback used during pre-setup.
///
/// Parses the MGMT READ_INFO response, prints controller information,
/// verifies the BD_ADDR matches the emulator, and stores `current_settings`.
///
/// Equivalent to C `read_info_callback`.
fn read_info_callback(state: &SharedState, status: u8, data: &[u8]) {
    tester_print("Read Info callback");
    tester_print(&format!("  Status: 0x{status:02x}"));

    if status != MGMT_STATUS_SUCCESS || data.is_empty() {
        tester_pre_setup_failed();
        return;
    }

    let rp = match parse_read_info(data) {
        Some(rp) => rp,
        None => {
            tester_pre_setup_failed();
            return;
        }
    };

    let addr_str = rp.bdaddr.ba2str();
    let manufacturer = btohs(rp.manufacturer);
    let supported_settings = btohl(rp.supported_settings);
    let current_settings = btohl(rp.current_settings);

    tester_print(&format!("  Address: {addr_str}"));
    tester_print(&format!("  Version: 0x{:02x}", rp.version));
    tester_print(&format!("  Manufacturer: 0x{manufacturer:04x}"));
    tester_print(&format!("  Supported settings: 0x{supported_settings:08x}"));
    tester_print(&format!("  Current settings: 0x{current_settings:08x}"));
    tester_print(&format!(
        "  Class: 0x{:02x}{:02x}{:02x}",
        rp.dev_class[2], rp.dev_class[1], rp.dev_class[0]
    ));

    // Extract NUL-terminated name strings.
    let name = rp
        .name
        .iter()
        .position(|&b| b == 0)
        .map(|pos| String::from_utf8_lossy(&rp.name[..pos]).into_owned())
        .unwrap_or_default();
    let short_name = rp
        .short_name
        .iter()
        .position(|&b| b == 0)
        .map(|pos| String::from_utf8_lossy(&rp.short_name[..pos]).into_owned())
        .unwrap_or_default();

    tester_print(&format!("  Name: {name}"));
    tester_print(&format!("  Short name: {short_name}"));

    // Store current_settings and verify emulator address match.
    let emu_addr = {
        let mut st = state.lock().unwrap();
        st.current_settings = current_settings;
        st.hciemu.as_ref().map(|e| e.get_address()).unwrap_or_default()
    };

    if emu_addr != addr_str {
        tester_pre_setup_failed();
        return;
    }

    tester_pre_setup_complete();
}

/// Index Added callback — discovers the new controller index and issues
/// READ_INFO.
///
/// Equivalent to C `index_added_callback`.
fn index_added_callback(state: &SharedState, index: u16) {
    tester_print("Index Added callback");
    tester_print(&format!("  Index: 0x{index:04x}"));

    // Acquire lock, check and update mgmt_index, extract the mgmt Arc.
    let (mgmt, mgmt_index) = {
        let mut st = state.lock().unwrap();
        if st.mgmt_index != MGMT_INDEX_NONE {
            return;
        }
        st.mgmt_index = index;
        let mgmt = st.mgmt.as_ref().map(Arc::clone);
        let idx = st.mgmt_index;
        (mgmt, idx)
    };

    let mgmt = match mgmt {
        Some(m) => m,
        None => return,
    };

    let state2 = Arc::clone(state);
    tokio::spawn(async move {
        match mgmt.send_command(MGMT_OP_READ_INFO, mgmt_index, &[]).await {
            Ok(resp) => read_info_callback(&state2, resp.status, &resp.data),
            Err(e) => {
                tester_warn(&format!("READ_INFO failed: {e}"));
                tester_pre_setup_failed();
            }
        }
    });
}

/// Index Removed callback — handles controller removal during test and
/// teardown phases.
///
/// Equivalent to C `index_removed_callback`.
fn index_removed_callback(state: &SharedState, index: u16) {
    tester_print("Index Removed callback");
    tester_print(&format!("  Index: 0x{index:04x}"));

    // Extract what we need from the lock before any async work.
    let (matched, has_remove_id, remove_id, mgmt, mgmt_index) = {
        let mut st = state.lock().unwrap();
        if index != st.mgmt_index {
            return;
        }
        let rid = st.remove_id;
        let has_rid = rid != 0;
        if has_rid {
            st.remove_id = 0;
        }
        let mgmt = st.mgmt.as_ref().map(Arc::clone);
        let idx = st.mgmt_index;
        (true, has_rid, rid, mgmt, idx)
    };

    if !matched {
        return;
    }

    // If remove_id is set, this removal was expected by the test
    // (test_open_success registered it). Unsubscribe and pass.
    if has_remove_id {
        if let Some(mgmt) = mgmt {
            let state2 = Arc::clone(state);
            tokio::spawn(async move {
                mgmt.unsubscribe(remove_id).await;
                // Drop the HCI handle — equivalent to bt_hci_unref.
                {
                    let mut st2 = state2.lock().unwrap();
                    st2.hci = None;
                }
                tester_test_passed();
            });
        }
        return;
    }

    // Normal teardown: unsubscribe all events for this index, drop mgmt.
    {
        let mut st = state.lock().unwrap();
        st.mgmt = None;
    }

    if let Some(mgmt) = mgmt {
        tokio::spawn(async move {
            mgmt.unsubscribe_index(mgmt_index).await;
            tester_post_teardown_complete();
        });
    } else {
        tester_post_teardown_complete();
    }
}

/// Read Index List callback — registers INDEX_ADDED event and creates
/// the HCI emulator.
///
/// Equivalent to C `read_index_list_callback`.
fn read_index_list_callback(state: &SharedState, status: u8, _data: &[u8]) {
    tester_print("Read Index List callback");
    tester_print(&format!("  Status: 0x{status:02x}"));

    if status != MGMT_STATUS_SUCCESS {
        tester_pre_setup_failed();
        return;
    }

    // Extract mgmt Arc and emulator type while holding the lock briefly.
    let (mgmt, emu_type) = {
        let st = state.lock().unwrap();
        let mgmt = st.mgmt.as_ref().map(Arc::clone);
        let emu_type = st.hciemu_type;
        (mgmt, emu_type)
    };

    let mgmt = match mgmt {
        Some(m) => m,
        None => {
            tester_pre_setup_failed();
            return;
        }
    };

    let state_added = Arc::clone(state);

    tokio::spawn(async move {
        // Subscribe to INDEX_ADDED events.
        let (sub_id, mut rx) = mgmt.subscribe(MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE).await;

        // Store subscription ID.
        {
            let mut st = state_added.lock().unwrap();
            st.index_added_sub_id = sub_id;
        }

        // Spawn listener for INDEX_ADDED events.
        let state_listener = Arc::clone(&state_added);
        tokio::spawn(async move {
            while let Some(evt) = rx.recv().await {
                index_added_callback(&state_listener, evt.index);
            }
        });

        // Create the HCI emulator.
        match HciEmulator::new(emu_type) {
            Ok(emu) => {
                {
                    let mut st = state_added.lock().unwrap();
                    st.hciemu = Some(emu);
                }
                tester_print("New hciemu instance created");
            }
            Err(e) => {
                tester_warn(&format!("Failed to setup HCI emulation: {e}"));
                tester_pre_setup_failed();
            }
        }
    });
}

// ===========================================================================
// Pre-setup / Post-teardown
// ===========================================================================

/// Test pre-setup: creates MGMT socket and sends READ_INDEX_LIST.
///
/// Equivalent to C `test_pre_setup`.
fn test_pre_setup(state: &SharedState) {
    let mgmt = match MgmtSocket::new_default() {
        Ok(m) => Arc::new(m),
        Err(e) => {
            tester_warn(&format!("Failed to setup management interface: {e}"));
            tester_pre_setup_failed();
            return;
        }
    };

    if tester_use_debug() {
        tracing::debug!("MGMT debug enabled for userchan-tester");
    }

    {
        let mut st = state.lock().unwrap();
        st.mgmt = Some(Arc::clone(&mgmt));
    }

    let state2 = Arc::clone(state);
    tokio::spawn(async move {
        match mgmt.send_command(MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, &[]).await {
            Ok(resp) => read_index_list_callback(&state2, resp.status, &resp.data),
            Err(e) => {
                tester_warn(&format!("READ_INDEX_LIST failed: {e}"));
                tester_pre_setup_failed();
            }
        }
    });
}

/// Test post-teardown: registers INDEX_REMOVED and drops the emulator.
///
/// Equivalent to C `test_post_teardown`.
fn test_post_teardown(state: &SharedState) {
    // Extract mgmt and index; drop emulator to trigger INDEX_REMOVED.
    let (mgmt, mgmt_index) = {
        let mut st = state.lock().unwrap();
        let mgmt = st.mgmt.as_ref().map(Arc::clone);
        let idx = st.mgmt_index;
        // Drop emulator to trigger kernel INDEX_REMOVED event.
        st.hciemu = None;
        (mgmt, idx)
    };

    let mgmt = match mgmt {
        Some(m) => m,
        None => {
            tester_post_teardown_complete();
            return;
        }
    };

    let state2 = Arc::clone(state);
    tokio::spawn(async move {
        let (_, mut rx) = mgmt.subscribe(MGMT_EV_INDEX_REMOVED, mgmt_index).await;

        let state3 = Arc::clone(&state2);
        tokio::spawn(async move {
            while let Some(evt) = rx.recv().await {
                index_removed_callback(&state3, evt.index);
            }
        });
    });
}

// ===========================================================================
// Setup functions
// ===========================================================================

/// Setup: power on the controller.
///
/// Equivalent to C `setup_powered`.
fn setup_powered(state: &SharedState) {
    let (mgmt, mgmt_index) = {
        let st = state.lock().unwrap();
        let mgmt = st.mgmt.as_ref().map(Arc::clone);
        let idx = st.mgmt_index;
        (mgmt, idx)
    };

    let mgmt = match mgmt {
        Some(m) => m,
        None => {
            tester_setup_failed();
            return;
        }
    };

    tester_print("Powering on controller");

    tokio::spawn(async move {
        let param: [u8; 1] = [0x01]; // power = on
        match mgmt.send_command(MGMT_OP_SET_POWERED, mgmt_index, &param).await {
            Ok(resp) => {
                if resp.status != MGMT_STATUS_SUCCESS {
                    tester_setup_failed();
                    return;
                }
                tester_print("Controller powered on");
                tester_setup_complete();
            }
            Err(e) => {
                tester_warn(&format!("SET_POWERED failed: {e}"));
                tester_setup_failed();
            }
        }
    });
}

/// Setup: toggle power on then off.
///
/// First powers on the controller, then powers it back off.
/// The initial power state comes from `test_data_val` (true = start powered on).
///
/// Equivalent to C `toggle_powered`.
fn toggle_powered(state: &SharedState) {
    let (mgmt, mgmt_index, power) = {
        let st = state.lock().unwrap();
        let mgmt = st.mgmt.as_ref().map(Arc::clone);
        let idx = st.mgmt_index;
        let power = st.test_data_val.unwrap_or(true);
        (mgmt, idx, power)
    };

    let mgmt = match mgmt {
        Some(m) => m,
        None => {
            tester_setup_failed();
            return;
        }
    };

    toggle_powered_step(mgmt, mgmt_index, power);
}

/// Recursive step for the toggle power sequence.
fn toggle_powered_step(mgmt: Arc<MgmtSocket>, mgmt_index: u16, power: bool) {
    let param: [u8; 1] = [u8::from(power)];

    tester_print(&format!("Powering {} controller", if power { "on" } else { "off" }));

    let mgmt2 = Arc::clone(&mgmt);
    tokio::spawn(async move {
        match mgmt2.send_command(MGMT_OP_SET_POWERED, mgmt_index, &param).await {
            Ok(resp) => {
                if resp.status != MGMT_STATUS_SUCCESS {
                    tester_setup_failed();
                    return;
                }
                tester_print(&format!("Controller powered {}", if power { "on" } else { "off" }));

                if power {
                    // Power was turned on; now turn it off.
                    toggle_powered_step(mgmt2, mgmt_index, false);
                } else {
                    // Power is now off; setup complete.
                    tester_setup_complete();
                }
            }
            Err(e) => {
                tester_warn(&format!("SET_POWERED toggle failed: {e}"));
                tester_setup_failed();
            }
        }
    });
}

/// Setup: open a user channel (for the close test).
///
/// Verifies the controller is unpowered, then opens an HCI user channel.
///
/// Equivalent to C `setup_channel_open`.
fn setup_channel_open(state: &SharedState) {
    let mut st = state.lock().unwrap();

    // Verify controller is not powered.
    let settings = MgmtSettings::from_bits_truncate(st.current_settings);
    if settings.contains(MgmtSettings::POWERED) {
        tester_print("Controller is powered");
        tester_setup_failed();
        return;
    }

    let mgmt_index = st.mgmt_index;

    // Open user channel.
    match HciTransport::new_user_channel(mgmt_index) {
        Ok(hci) => {
            st.hci = Some(hci);
            drop(st);
            tester_print("User Channel Opened");
            tester_setup_complete();
        }
        Err(e) => {
            tester_print(&format!("Failed to open user channel: {e}"));
            st.remove_id = 0;
            drop(st);
            tester_setup_failed();
        }
    }
}

// ===========================================================================
// Test functions
// ===========================================================================

/// Test: open user channel – Success.
///
/// Registers an INDEX_REMOVED subscription, opens a user channel, and
/// expects it to succeed. When the user channel is opened, the kernel
/// sends INDEX_REMOVED and the test passes in the removal callback.
///
/// Equivalent to C `test_open_success`.
fn test_open_success(state: &SharedState) {
    // Extract mgmt and index from state.
    let (mgmt, mgmt_index) = {
        let st = state.lock().unwrap();
        let mgmt = st.mgmt.as_ref().map(Arc::clone);
        let idx = st.mgmt_index;
        (mgmt, idx)
    };

    let mgmt = match mgmt {
        Some(m) => m,
        None => {
            tester_test_failed();
            return;
        }
    };

    let state2 = Arc::clone(state);
    tokio::spawn(async move {
        // Subscribe to INDEX_REMOVED for this index.
        let (sub_id, mut rx) = mgmt.subscribe(MGMT_EV_INDEX_REMOVED, mgmt_index).await;

        {
            let mut st = state2.lock().unwrap();
            st.remove_id = sub_id;
        }

        // Spawn listener for the INDEX_REMOVED event.
        let state3 = Arc::clone(&state2);
        tokio::spawn(async move {
            while let Some(evt) = rx.recv().await {
                index_removed_callback(&state3, evt.index);
            }
        });

        // Open user channel. On success the kernel takes over and
        // sends INDEX_REMOVED, which triggers test_passed in the callback.
        match HciTransport::new_user_channel(mgmt_index) {
            Ok(hci) => {
                // Success — drop the handle immediately (like C code does
                // bt_hci_unref(hci) right after confirming non-NULL).
                // The INDEX_REMOVED callback will signal test_passed.
                drop(hci);
            }
            Err(_) => {
                // Failed to open user channel — clean up and fail.
                let remove_id = {
                    let mut st = state2.lock().unwrap();
                    let rid = st.remove_id;
                    st.remove_id = 0;
                    rid
                };
                mgmt.unsubscribe(remove_id).await;
                tester_test_failed();
            }
        }
    });
}

/// Test: open user channel – Failed.
///
/// Attempts to open a user channel on a powered controller and expects
/// the operation to fail (EBUSY).
///
/// Equivalent to C `test_open_failed`.
fn test_open_failed(state: &SharedState) {
    let mgmt_index = {
        let st = state.lock().unwrap();
        st.mgmt_index
    };

    match HciTransport::new_user_channel(mgmt_index) {
        Err(_) => {
            // Expected failure — test passes.
            tester_test_passed();
        }
        Ok(hci) => {
            // Unexpectedly succeeded — drop handle and fail.
            drop(hci);
            tester_test_failed();
        }
    }
}

/// Read Info callback used by the close test to verify the controller is
/// unpowered after the user channel is released.
///
/// Equivalent to C `close_read_info_callback`.
fn close_read_info_callback(status: u8, data: &[u8]) {
    tester_print("Read Info callback");
    tester_print(&format!("  Status: 0x{status:02x}"));

    if status != MGMT_STATUS_SUCCESS || data.is_empty() {
        tester_test_failed();
        return;
    }

    let rp = match parse_read_info(data) {
        Some(rp) => rp,
        None => {
            tester_test_failed();
            return;
        }
    };

    let current_settings = btohl(rp.current_settings);
    let settings = MgmtSettings::from_bits_truncate(current_settings);
    if settings.contains(MgmtSettings::POWERED) {
        tester_print("Controller is powered");
        tester_test_failed();
        return;
    }

    tester_test_passed();
}

/// Test: close user channel – Success.
///
/// Closes the previously opened HCI handle and reads controller info to
/// verify the controller is no longer powered.
///
/// Equivalent to C `test_close_success`.
fn test_close_success(state: &SharedState) {
    tester_print("Close User Channel");

    // Drop HCI handle and extract mgmt + index.
    let (mgmt, mgmt_index) = {
        let mut st = state.lock().unwrap();
        // Drop the HCI transport handle — equivalent to bt_hci_unref.
        st.hci = None;
        let mgmt = st.mgmt.as_ref().map(Arc::clone);
        let idx = st.mgmt_index;
        (mgmt, idx)
    };

    let mgmt = match mgmt {
        Some(m) => m,
        None => {
            tester_test_failed();
            return;
        }
    };

    // Check if power is off by reading controller info.
    tokio::spawn(async move {
        match mgmt.send_command(MGMT_OP_READ_INFO, mgmt_index, &[]).await {
            Ok(resp) => close_read_info_callback(resp.status, &resp.data),
            Err(e) => {
                tester_warn(&format!("READ_INFO failed: {e}"));
                tester_test_failed();
            }
        }
    });
}

// ===========================================================================
// Test registration and main entry point
// ===========================================================================

/// Helper to build a `SharedState` and register a test with the harness.
///
/// Equivalent to the C `test_user` macro. Creates a `TestState` with
/// `EmulatorType::BrEdr` and `MGMT_INDEX_NONE`, builds callback closures,
/// and registers via `tester_add_full`.
fn register_test(
    name: &str,
    test_data_val: Option<bool>,
    setup_func: Option<fn(&SharedState)>,
    test_func: fn(&SharedState),
) {
    let state: SharedState =
        Arc::new(Mutex::new(TestState::new(EmulatorType::BrEdr, test_data_val)));

    // Pre-setup callback.
    let pre_state = Arc::clone(&state);
    let pre_setup: TestCallback = Arc::new(move |_: &dyn Any| {
        test_pre_setup(&pre_state);
    });

    // Post-teardown callback.
    let post_state = Arc::clone(&state);
    let post_teardown: TestCallback = Arc::new(move |_: &dyn Any| {
        test_post_teardown(&post_state);
    });

    // Optional setup callback.
    let wrapped_setup: Option<TestCallback> = setup_func.map(|f| {
        let s = Arc::clone(&state);
        let cb: TestCallback = Arc::new(move |_: &dyn Any| {
            f(&s);
        });
        cb
    });

    // Test callback.
    let test_state = Arc::clone(&state);
    let wrapped_test: TestCallback = Arc::new(move |_: &dyn Any| {
        test_func(&test_state);
    });

    // Register with user_data containing the shared state, so
    // tester_get_data can retrieve it if needed.
    tester_add_full::<(), SharedState>(
        name,
        None,
        Some(pre_setup),
        wrapped_setup,
        Some(wrapped_test),
        None, // no teardown (separate from post_teardown)
        Some(post_teardown),
        2, // 2-second timeout (matching C code)
        Some(Arc::clone(&state)),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    tester_init(&args);

    // Test 1: "User channel open - Success"
    // No setup; test_open_success verifies user channel can be opened.
    register_test("User channel open - Success", None, None, test_open_success);

    // Test 2: "User channel open - Failed"
    // setup_powered powers on the controller; test_open_failed expects EBUSY.
    register_test("User channel open - Failed", None, Some(setup_powered), test_open_failed);

    // Test 3: "User channel open - Power Toggle Success"
    // toggle_powered powers on then off; test_open_success verifies open.
    register_test(
        "User channel open - Power Toggle Success",
        Some(true),
        Some(toggle_powered),
        test_open_success,
    );

    // Test 4: "User channel close - Success"
    // setup_channel_open opens user channel; test_close_success closes and
    // verifies the controller is unpowered.
    register_test(
        "User channel close - Success",
        None,
        Some(setup_channel_open),
        test_close_success,
    );

    std::process::exit(tester_run());
}
