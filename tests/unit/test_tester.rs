// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_tester.rs — Rust port of unit/test-tester.c
//
// Comprehensive unit tests for `bluez_shared::tester`, verifying the test
// harness framework itself: initialisation, test registration, full lifecycle
// execution (pre-setup → setup → run → teardown → post-teardown), pass/fail
// signaling, timeout enforcement, I/O simulation via socketpairs, debug/quiet
// mode propagation, and the `iov_data!` convenience macro.
//
// Every test function maps directly to a test case in the original C file
// (`unit/test-tester.c`) or covers additional harness API surface required
// by the Rust rewrite.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bluez_shared::iov_data;
use bluez_shared::tester::{
    TestCallback, TestCase, TesterContext, TesterIo, TesterResult, TesterStage, tester_add,
    tester_add_full, tester_init, tester_io_send, tester_post_teardown_complete,
    tester_pre_setup_complete, tester_run, tester_setup_complete, tester_setup_io,
    tester_shutdown_io, tester_teardown_complete, tester_test_failed, tester_test_passed,
    tester_use_debug, tester_use_quiet,
};

// ============================================================================
// Enum and type accessibility tests
// ============================================================================

/// Verify `TesterResult` enum variants are accessible and correctly
/// distinguished.  Each result value must compare equal to itself and
/// unequal to every other variant.
#[test]
fn test_result_enum_variants() {
    // Identity — each variant equals itself.
    assert_eq!(TesterResult::NotRun, TesterResult::NotRun);
    assert_eq!(TesterResult::Passed, TesterResult::Passed);
    assert_eq!(TesterResult::Failed, TesterResult::Failed);
    assert_eq!(TesterResult::TimedOut, TesterResult::TimedOut);
    assert_eq!(TesterResult::Aborted, TesterResult::Aborted);
    assert_eq!(TesterResult::Skipped, TesterResult::Skipped);

    // Distinctness — key pairs that must be distinguishable.
    assert_ne!(TesterResult::Passed, TesterResult::Failed);
    assert_ne!(TesterResult::NotRun, TesterResult::Passed);
    assert_ne!(TesterResult::TimedOut, TesterResult::Aborted);
    assert_ne!(TesterResult::Skipped, TesterResult::Failed);
}

/// Verify `TesterStage` enum variants are accessible and correctly
/// distinguished.  The lifecycle ordering is validated in lifecycle tests;
/// here we just confirm variant identity.
#[test]
fn test_stage_enum_variants() {
    assert_eq!(TesterStage::PreSetup, TesterStage::PreSetup);
    assert_eq!(TesterStage::Setup, TesterStage::Setup);
    assert_eq!(TesterStage::Run, TesterStage::Run);
    assert_eq!(TesterStage::Teardown, TesterStage::Teardown);
    assert_eq!(TesterStage::PostTeardown, TesterStage::PostTeardown);

    assert_ne!(TesterStage::PreSetup, TesterStage::Run);
    assert_ne!(TesterStage::Setup, TesterStage::Teardown);
    assert_ne!(TesterStage::Run, TesterStage::PostTeardown);
}

/// Verify core struct types (`TesterContext`, `TestCase`, `TesterIo`) are
/// accessible as public types and have non-zero size.
#[test]
fn test_type_accessibility() {
    let ctx_size = std::mem::size_of::<TesterContext>();
    let tc_size = std::mem::size_of::<TestCase>();
    let tio_size = std::mem::size_of::<TesterIo>();

    assert!(ctx_size > 0, "TesterContext should be a non-zero-sized type");
    assert!(tc_size > 0, "TestCase should be a non-zero-sized type");
    assert!(tio_size > 0, "TesterIo should be a non-zero-sized type");
}

// ============================================================================
// iov_data! macro tests
// ============================================================================

/// Verify the `iov_data!` macro produces correct byte slices for various
/// argument counts.  This macro replaces the C `IOV_DATA(...)` macro.
#[test]
fn test_iov_data_macro() {
    // Single byte.
    let single: &[u8] = iov_data!(0x01);
    assert_eq!(single, &[0x01u8]);

    // Two bytes — matches the iov[] table from C test-tester.c.
    let pair: &[u8] = iov_data!(0x01, 0x02);
    assert_eq!(pair, &[0x01u8, 0x02u8]);

    // Empty invocation.
    let empty: &[u8] = iov_data!();
    assert!(empty.is_empty());

    // Four bytes with diverse values.
    let four: &[u8] = iov_data!(0xFF, 0x00, 0xAB, 0xCD);
    assert_eq!(four, &[0xFFu8, 0x00, 0xAB, 0xCD]);

    // Trailing comma is accepted.
    let trailing: &[u8] = iov_data!(0x42,);
    assert_eq!(trailing, &[0x42u8]);
}

// ============================================================================
// Initialisation tests
// ============================================================================

/// Test `tester_init` with no flags — default state has both quiet and
/// debug disabled.
#[test]
fn test_tester_init() {
    tester_init(&["test-tester".to_string()]);
    assert!(!tester_use_quiet(), "quiet should be false by default");
    assert!(!tester_use_debug(), "debug should be false by default");
}

/// Test `tester_init` with `--quiet` flag.
#[test]
fn test_tester_init_quiet() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);
    assert!(tester_use_quiet(), "quiet should be true after --quiet");
    assert!(!tester_use_debug(), "debug should remain false");
}

/// Test `tester_init` with `--debug` flag.
#[test]
fn test_tester_init_debug() {
    tester_init(&["test-tester".to_string(), "--debug".to_string()]);
    assert!(tester_use_debug(), "debug should be true after --debug");
    assert!(!tester_use_quiet(), "quiet should remain false");
}

/// Test `tester_init` with short flags (`-q`, `-d`).
#[test]
fn test_tester_init_short_flags() {
    tester_init(&["test-tester".to_string(), "-q".to_string(), "-d".to_string()]);
    assert!(tester_use_quiet(), "quiet should be true after -q");
    assert!(tester_use_debug(), "debug should be true after -d");
}

// ============================================================================
// Registration tests
// ============================================================================

/// Test `tester_add` registers a test case and `tester_run` executes it.
///
/// Ported from C: `tester_add("/tester/basic", ...)`.
#[test]
fn test_tester_add() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let test_fn: TestCallback = Arc::new(|_data| {
        tester_test_passed();
    });

    tester_add::<()>("/tester/add_test", None, None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0, "single passing test should yield exit code 0");
}

/// Test `tester_add` with multiple test cases — all should pass.
#[test]
fn test_tester_add_multiple() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    for i in 0..5 {
        let name = format!("/tester/multi_{i}");
        let test_fn: TestCallback = Arc::new(|_data| {
            tester_test_passed();
        });
        tester_add::<()>(&name, None, None, Some(test_fn), None);
    }

    let exit_code = tester_run();
    assert_eq!(exit_code, 0, "all five passing tests should yield exit code 0");
}

// ============================================================================
// Basic run tests (converted from C test_basic)
// ============================================================================

/// Direct conversion of C `test_basic` — a test that simply calls
/// `tester_test_passed()`.
///
/// C original (test-tester.c line 27–30):
/// ```c
/// static void test_basic(const void *data) { tester_test_passed(); }
/// ```
#[test]
fn test_tester_run_basic() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let test_fn: TestCallback = Arc::new(|_data| {
        tester_test_passed();
    });

    tester_add::<()>("/tester/basic", None, None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0, "basic passing test should yield exit code 0");
}

/// Test a failing test — calls `tester_test_failed()`.
#[test]
fn test_tester_run_fail() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let test_fn: TestCallback = Arc::new(|_data| {
        tester_test_failed();
    });

    tester_add::<()>("/tester/fail", None, None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 1, "failing test should yield exit code 1");
}

// ============================================================================
// Setup and teardown lifecycle tests
// ============================================================================

/// Test that setup and teardown callbacks are invoked in the correct
/// order around the test function.
///
/// Lifecycle ordering: setup(+1) → run(+10) → teardown(+100).
/// After execution, the counter should read 111.
#[test]
fn test_tester_setup_teardown() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let counter = Arc::new(AtomicU32::new(0));

    let setup_fn: TestCallback = {
        let c = Arc::clone(&counter);
        Arc::new(move |_data| {
            c.fetch_add(1, Ordering::SeqCst);
            tester_setup_complete();
        })
    };

    let test_fn: TestCallback = {
        let c = Arc::clone(&counter);
        Arc::new(move |_data| {
            let val = c.load(Ordering::SeqCst);
            assert_eq!(val, 1, "setup should have been called before test");
            c.fetch_add(10, Ordering::SeqCst);
            tester_test_passed();
        })
    };

    let teardown_fn: TestCallback = {
        let c = Arc::clone(&counter);
        Arc::new(move |_data| {
            let val = c.load(Ordering::SeqCst);
            assert_eq!(val, 11, "test should have been called before teardown");
            c.fetch_add(100, Ordering::SeqCst);
            tester_teardown_complete();
        })
    };

    tester_add::<()>(
        "/tester/setup_teardown",
        None,
        Some(setup_fn),
        Some(test_fn),
        Some(teardown_fn),
    );

    let exit_code = tester_run();
    assert_eq!(exit_code, 0);

    let final_val = counter.load(Ordering::SeqCst);
    assert_eq!(
        final_val, 111,
        "all lifecycle callbacks should have been called: setup(1) + test(10) + teardown(100)"
    );
}

// ============================================================================
// Full lifecycle with pre-setup and post-teardown
// ============================================================================

/// Test the complete five-phase lifecycle:
///   pre-setup(+1) → setup(+10) → run(+100) → teardown(+1000) → post-teardown(+10000).
///
/// Uses `tester_add_full` to register all five callbacks.
/// After execution, the counter should read 11111.
#[test]
fn test_tester_pre_post() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let counter = Arc::new(AtomicU32::new(0));

    let pre_setup_fn: TestCallback = {
        let c = Arc::clone(&counter);
        Arc::new(move |_data| {
            c.fetch_add(1, Ordering::SeqCst);
            tester_pre_setup_complete();
        })
    };

    let setup_fn: TestCallback = {
        let c = Arc::clone(&counter);
        Arc::new(move |_data| {
            c.fetch_add(10, Ordering::SeqCst);
            tester_setup_complete();
        })
    };

    let test_fn: TestCallback = {
        let c = Arc::clone(&counter);
        Arc::new(move |_data| {
            c.fetch_add(100, Ordering::SeqCst);
            tester_test_passed();
        })
    };

    let teardown_fn: TestCallback = {
        let c = Arc::clone(&counter);
        Arc::new(move |_data| {
            c.fetch_add(1000, Ordering::SeqCst);
            tester_teardown_complete();
        })
    };

    let post_teardown_fn: TestCallback = {
        let c = Arc::clone(&counter);
        Arc::new(move |_data| {
            c.fetch_add(10000, Ordering::SeqCst);
            tester_post_teardown_complete();
        })
    };

    tester_add_full::<(), ()>(
        "/tester/pre_post",
        None,
        Some(pre_setup_fn),
        Some(setup_fn),
        Some(test_fn),
        Some(teardown_fn),
        Some(post_teardown_fn),
        30,
        None,
    );

    let exit_code = tester_run();
    assert_eq!(exit_code, 0);

    let final_val = counter.load(Ordering::SeqCst);
    assert_eq!(
        final_val, 11111,
        "all 5 lifecycle callbacks should have run: \
         pre_setup(1) + setup(10) + test(100) + teardown(1000) + post_teardown(10000)"
    );
}

/// Verify lifecycle ordering: each stage runs strictly after the previous one.
/// Uses sequential stage numbers (1 → 2 → 3 → 4 → 5) instead of powers of ten.
#[test]
fn test_tester_add_full_lifecycle_ordering() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let stages = Arc::new(AtomicU32::new(0));

    let pre_setup_fn: TestCallback = {
        let s = Arc::clone(&stages);
        Arc::new(move |_data| {
            let prev = s.load(Ordering::SeqCst);
            assert_eq!(prev, 0, "pre-setup should be the first stage");
            s.store(1, Ordering::SeqCst);
            tester_pre_setup_complete();
        })
    };

    let setup_fn: TestCallback = {
        let s = Arc::clone(&stages);
        Arc::new(move |_data| {
            let prev = s.load(Ordering::SeqCst);
            assert_eq!(prev, 1, "setup should follow pre-setup");
            s.store(2, Ordering::SeqCst);
            tester_setup_complete();
        })
    };

    let test_fn: TestCallback = {
        let s = Arc::clone(&stages);
        Arc::new(move |_data| {
            let prev = s.load(Ordering::SeqCst);
            assert_eq!(prev, 2, "run should follow setup");
            s.store(3, Ordering::SeqCst);
            tester_test_passed();
        })
    };

    let teardown_fn: TestCallback = {
        let s = Arc::clone(&stages);
        Arc::new(move |_data| {
            let prev = s.load(Ordering::SeqCst);
            assert_eq!(prev, 3, "teardown should follow run");
            s.store(4, Ordering::SeqCst);
            tester_teardown_complete();
        })
    };

    let post_teardown_fn: TestCallback = {
        let s = Arc::clone(&stages);
        Arc::new(move |_data| {
            let prev = s.load(Ordering::SeqCst);
            assert_eq!(prev, 4, "post-teardown should follow teardown");
            s.store(5, Ordering::SeqCst);
            tester_post_teardown_complete();
        })
    };

    tester_add_full::<(), ()>(
        "/tester/full_lifecycle",
        None,
        Some(pre_setup_fn),
        Some(setup_fn),
        Some(test_fn),
        Some(teardown_fn),
        Some(post_teardown_fn),
        30,
        None,
    );

    let exit_code = tester_run();
    assert_eq!(exit_code, 0);

    let final_stage = stages.load(Ordering::SeqCst);
    assert_eq!(final_stage, 5, "all 5 lifecycle stages should have executed in order");
}

// ============================================================================
// Timeout test
// ============================================================================

/// Test that a test which never signals completion times out.
///
/// Uses `tester_add_full` with a 1-second timeout.  The test callback
/// returns without calling `tester_test_passed()` or `tester_test_failed()`,
/// so the framework should detect the timeout and report failure.
///
/// Wrapped in `tokio::time::timeout` as an outer safety net to prevent
/// the test itself from hanging if the framework fails to enforce the
/// deadline.
#[tokio::test]
async fn test_tester_timeout() {
    // Run in spawn_blocking since tester_run creates its own tokio runtime.
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(|| {
            tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

            // This test function returns without signaling — should timeout.
            let test_fn: TestCallback = Arc::new(|_data| {
                // Intentionally empty: no tester_test_passed/failed call.
                // The framework should detect timeout after 1 second.
            });

            tester_add_full::<(), ()>(
                "/tester/timeout",
                None,
                None,
                None,
                Some(test_fn),
                None,
                None,
                1, // 1-second timeout
                None,
            );

            tester_run()
        }),
    )
    .await;

    let exit_code = result
        .expect("tester_run should complete within 30 seconds")
        .expect("spawn_blocking should succeed");
    assert_eq!(exit_code, 1, "timed-out test should yield exit code 1");
}

// ============================================================================
// Debug mode test
// ============================================================================

/// Test that the `--debug` flag propagates correctly and remains active
/// inside test callbacks.
#[test]
fn test_tester_debug() {
    tester_init(&["test-tester".to_string(), "--debug".to_string(), "--quiet".to_string()]);

    assert!(tester_use_debug(), "debug mode should be active");

    let test_fn: TestCallback = Arc::new(|_data| {
        // Inside the test callback, debug should still be active.
        assert!(tester_use_debug(), "debug should be active inside callback");
        tester_test_passed();
    });

    tester_add::<()>("/tester/debug", None, None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0);
}

// ============================================================================
// Monitor test
// ============================================================================

/// Test that the `--monitor` flag is accepted and the framework runs
/// without error.  Actual HCI logging output cannot be verified in a
/// unit test, but we confirm the flag does not cause panics.
#[test]
fn test_tester_monitor() {
    tester_init(&["test-tester".to_string(), "--monitor".to_string(), "--quiet".to_string()]);

    let test_fn: TestCallback = Arc::new(|_data| {
        tester_test_passed();
    });

    tester_add::<()>("/tester/monitor", None, None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0);
}

// ============================================================================
// I/O simulation tests (converted from C test_setup_io and test_io_send)
// ============================================================================

/// Test `tester_setup_io` creates a valid socketpair and `tester_io_send`
/// successfully sends data without panicking.
///
/// Converted from C `test_setup_io` (test-tester.c lines 57–69):
/// ```c
/// io = tester_setup_io(iov, ARRAY_SIZE(iov));
/// g_assert(io);
/// io_set_read_handler(io, test_io_recv, (void *)&iov[1], NULL);
/// len = io_send(io, (void *)&iov[0], 1);
/// g_assert_cmpint(len, ==, iov[0].iov_len);
/// ```
///
/// In the Rust version, `tester_setup_io` returns a raw fd instead of an
/// `io` object.  We verify the fd is valid and that the harness-side send
/// operation (`tester_io_send`) completes without error.
#[test]
fn test_setup_io() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let test_fn: TestCallback = Arc::new(|_data| {
        // Replicate the C iov[] table: IOV_DATA(0x01), IOV_DATA(0x01, 0x02).
        let data1: &[u8] = iov_data!(0x01);
        let data2: &[u8] = iov_data!(0x01, 0x02);

        let test_fd = tester_setup_io(&[data1, data2]);
        assert!(test_fd >= 0, "tester_setup_io should return a valid fd");

        // Send the first scripted entry from the harness endpoint to the
        // test endpoint.  In the C original, this was `io_send(io, &iov[0], 1)`.
        tester_io_send();

        // The I/O operations succeeded without panic — signal test passed.
        tester_test_passed();
    });

    tester_add::<()>("/tester/setup_io", None, None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0, "setup_io test should pass");
}

/// Test `tester_io_send` sends the next scripted entry from the harness
/// endpoint to the test endpoint.
///
/// Converted from C `test_io_send` (test-tester.c lines 71–81):
/// ```c
/// io = tester_setup_io(iov, ARRAY_SIZE(iov));
/// g_assert(io);
/// io_set_read_handler(io, test_io_recv, (void *)&iov[0], NULL);
/// tester_io_send();
/// ```
#[test]
fn test_io_send() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let test_fn: TestCallback = Arc::new(|_data| {
        let data1: &[u8] = iov_data!(0x01);
        let data2: &[u8] = iov_data!(0x01, 0x02);

        let test_fd = tester_setup_io(&[data1, data2]);
        assert!(test_fd >= 0, "tester_setup_io should return a valid fd");

        // `tester_io_send` sends the next scripted entry from harness side.
        tester_io_send();

        // Signal test passed — send completed without panic.
        tester_test_passed();
    });

    tester_add::<()>("/tester/io_send", None, None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0, "io_send test should pass");
}

/// Test `tester_shutdown_io` cleans up the I/O layer without panicking.
#[test]
fn test_shutdown_io() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let test_fn: TestCallback = Arc::new(|_data| {
        let data: &[u8] = iov_data!(0xAA, 0xBB);
        let _test_fd = tester_setup_io(&[data]);

        // Explicitly shut down I/O before test completes.
        tester_shutdown_io();

        tester_test_passed();
    });

    tester_add::<()>("/tester/shutdown_io", None, None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0, "shutdown_io test should pass");
}

/// Test I/O setup followed by multiple sends.
#[test]
fn test_io_send_multiple() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let test_fn: TestCallback = Arc::new(|_data| {
        let data1: &[u8] = iov_data!(0x01);
        let data2: &[u8] = iov_data!(0x02, 0x03);
        let data3: &[u8] = iov_data!(0x04, 0x05, 0x06);

        let test_fd = tester_setup_io(&[data1, data2, data3]);
        assert!(test_fd >= 0);

        // Send all three scripted entries sequentially.
        tester_io_send(); // sends data1
        tester_io_send(); // sends data2
        tester_io_send(); // sends data3

        tester_test_passed();
    });

    tester_add::<()>("/tester/io_send_multi", None, None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0);
}

// ============================================================================
// Test data propagation
// ============================================================================

/// Verify that test data registered with `tester_add` is accessible in
/// callbacks via the `&dyn Any` parameter.
#[test]
fn test_tester_data_propagation() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let test_fn: TestCallback = Arc::new(|data| {
        let val = data.downcast_ref::<u32>().expect("test data should be u32");
        assert_eq!(*val, 42, "test data should be 42");
        tester_test_passed();
    });

    tester_add("/tester/data", Some(42u32), None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0);
}

// ============================================================================
// Mixed pass/fail results
// ============================================================================

/// Verify that a mix of passing and failing tests produces exit code 1.
#[test]
fn test_tester_mixed_results() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let pass_fn: TestCallback = Arc::new(|_data| {
        tester_test_passed();
    });

    let fail_fn: TestCallback = Arc::new(|_data| {
        tester_test_failed();
    });

    tester_add::<()>("/tester/pass1", None, None, Some(Arc::clone(&pass_fn)), None);
    tester_add::<()>("/tester/fail1", None, None, Some(Arc::clone(&fail_fn)), None);
    tester_add::<()>("/tester/pass2", None, None, Some(pass_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 1, "mixed results should yield exit code 1");
}

// ============================================================================
// Empty test suite
// ============================================================================

/// Verify that running with no registered tests yields exit code 0.
#[test]
fn test_tester_empty_suite() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);
    let exit_code = tester_run();
    assert_eq!(exit_code, 0, "empty suite should yield exit code 0");
}

// ============================================================================
// No-op callback tests (None callbacks auto-complete)
// ============================================================================

/// Test that omitting setup/teardown callbacks causes them to auto-complete.
/// The framework should automatically signal completion for missing callbacks.
#[test]
fn test_tester_no_setup_no_teardown() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    let test_fn: TestCallback = Arc::new(|_data| {
        tester_test_passed();
    });

    // No setup_func, no teardown_func — framework auto-completes both.
    tester_add::<()>("/tester/no_callbacks", None, None, Some(test_fn), None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0);
}

/// Test that omitting the test_func causes auto-pass (framework sends
/// TestPassed when no test function is provided).
#[test]
fn test_tester_no_test_func() {
    tester_init(&["test-tester".to_string(), "--quiet".to_string()]);

    // No test_func — framework auto-signals TestPassed.
    tester_add::<()>("/tester/no_test_fn", None::<()>, None, None, None);

    let exit_code = tester_run();
    assert_eq!(exit_code, 0, "no test function should auto-pass");
}
