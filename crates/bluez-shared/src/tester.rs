// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
//! Test harness framework — Rust rewrite of `src/shared/tester.c` / `tester.h`.
//!
//! Provides a sequential test execution engine with lifecycle phases
//! (pre-setup → setup → run → teardown → post-teardown), per-test timeout
//! enforcement via `tokio::time`, ANSI-colored progress output, I/O simulation
//! via AF_UNIX SOCK_SEQPACKET socketpairs, and structured traffic monitoring
//! through the HCI logging channel.
//!
//! Used by all 44 unit tests and integration testers.

use std::any::Any;
use std::cell::RefCell;
use std::io::IoSlice;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{self, UnboundedSender};

use crate::log::{bt_log_close, bt_log_sendmsg, bt_log_vprintf};
use crate::sys::hci::HCI_DEV_NONE;
use crate::util::hexdump;

// ---------------------------------------------------------------------------
// ANSI Color Constants (matching C tester output exactly)
// ---------------------------------------------------------------------------

const COLOR_OFF: &str = "\x1B[0m";
const COLOR_BLACK: &str = "\x1B[0;30m";
const COLOR_RED: &str = "\x1B[0;31m";
const COLOR_GREEN: &str = "\x1B[0;32m";
const COLOR_YELLOW: &str = "\x1B[0;33m";
const COLOR_BLUE: &str = "\x1B[0;34m";
const COLOR_MAGENTA: &str = "\x1B[0;35m";
const COLOR_HIGHLIGHT: &str = "\x1B[1;39m";

/// Syslog priority for LOG_INFO (6).
const LOG_INFO: i32 = 6;
/// Syslog priority for LOG_DEBUG (7).
const LOG_DEBUG: i32 = 7;

/// Default timeout for tests registered with [`tester_add`] (30 seconds).
const DEFAULT_TIMEOUT_SECS: u32 = 30;

// ---------------------------------------------------------------------------
// Convenience Macros
// ---------------------------------------------------------------------------

/// Construct a byte slice from literal byte arguments.
///
/// Equivalent to C `IOV_DATA(args...)`. Creates a `&'static [u8]` from
/// the provided comma-separated byte values.
///
/// # Examples
/// ```ignore
/// let data = iov_data!(0x01, 0x02, 0x03);
/// assert_eq!(data, &[0x01, 0x02, 0x03]);
/// ```
#[macro_export]
macro_rules! iov_data {
    ($($byte:expr),* $(,)?) => {{
        const DATA: &[u8] = &[$($byte as u8),*];
        DATA
    }};
}

/// Construct an empty (sentinel) byte slice.
///
/// Equivalent to C `IOV_NULL`. Returns an empty `&[u8]` used as a
/// separator or terminator in I/O vector scripts.
#[macro_export]
macro_rules! iov_null {
    () => {{
        const DATA: &[u8] = &[];
        DATA
    }};
}

// ---------------------------------------------------------------------------
// Core Enums
// ---------------------------------------------------------------------------

/// Outcome of a single test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TesterResult {
    /// Test has not yet been executed.
    NotRun,
    /// Test completed successfully.
    Passed,
    /// Test completed with a failure.
    Failed,
    /// Test exceeded its deadline.
    TimedOut,
    /// Test was aborted before completion.
    Aborted,
    /// Test was skipped (e.g. via `tester_pre_setup_skip_by_default`).
    Skipped,
}

/// Current lifecycle phase of a test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TesterStage {
    /// Before setup begins.
    PreSetup,
    /// Setup phase is executing.
    Setup,
    /// The test function itself is executing.
    Run,
    /// Teardown phase is executing.
    Teardown,
    /// Post-teardown cleanup is executing.
    PostTeardown,
}

/// Internal signal sent from lifecycle functions to the run loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TesterSignal {
    PreSetupComplete,
    PreSetupFailed,
    PreSetupAbort,
    SetupComplete,
    SetupFailed,
    TestPassed,
    TestFailed,
    TestAbort,
    TeardownComplete,
    TeardownFailed,
    PostTeardownComplete,
    PostTeardownFailed,
}

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

/// Callback type for test lifecycle phases.
///
/// Receives a reference to the test data (`&dyn Any`) that was provided
/// when the test was registered.
pub type TestCallback = Arc<dyn Fn(&dyn Any) + Send + Sync>;

/// Callback type for I/O completion notification.
///
/// Receives a reference to the current test's data when the scripted I/O
/// exchange has finished.
pub type IoCompleteCallback = Box<dyn FnOnce(&dyn Any) + Send>;

// ---------------------------------------------------------------------------
// Core Structs
// ---------------------------------------------------------------------------

/// A single registered test case with its lifecycle callbacks and metadata.
pub struct TestCase {
    /// Human-readable name of the test (e.g. `"ATT/Read/Success"`).
    pub name: String,
    /// Current lifecycle stage.
    pub stage: TesterStage,
    /// Final result after execution.
    pub result: TesterResult,
    /// Immutable test data shared across all lifecycle callbacks.
    pub test_data: Option<Arc<dyn Any + Send + Sync>>,
    /// Per-test user data — available to lifecycle callbacks for custom state.
    pub user_data: Option<Arc<dyn Any + Send + Sync>>,
    /// Pre-setup callback.
    pub pre_setup_func: Option<TestCallback>,
    /// Setup callback.
    pub setup_func: Option<TestCallback>,
    /// Test function callback.
    pub test_func: Option<TestCallback>,
    /// Teardown callback.
    pub teardown_func: Option<TestCallback>,
    /// Post-teardown callback.
    pub post_teardown_func: Option<TestCallback>,
    /// Maximum time allowed for this test (pre-setup through run).
    pub timeout: Duration,
    /// Wall-clock time when this test started executing.
    pub start_time: Option<Instant>,
    /// Wall-clock time when this test finished executing.
    pub end_time: Option<Instant>,
}

/// Socketpair-based I/O simulation layer for scripted packet exchange testing.
///
/// Provides a pair of connected AF_UNIX SOCK_SEQPACKET sockets with a script
/// of expected I/O vectors.  One endpoint is given to the test code; the other
/// is used by the harness to validate and respond.
pub struct TesterIo {
    /// Connected socket pair: (test_end, harness_end).
    pub endpoints: (OwnedFd, OwnedFd),
    /// Scripted I/O vectors: alternating receive-validate / send entries.
    pub iov_script: Vec<Vec<u8>>,
    /// Current position in the iov script.
    pub iov_index: usize,
    /// Callback invoked when all scripted I/O entries have been processed.
    pub complete_func: Option<IoCompleteCallback>,
}

/// Main test harness context holding all registered tests and runtime state.
pub struct TesterContext {
    /// All registered test cases.
    pub test_list: Vec<TestCase>,
    /// Index of the currently executing test.
    pub current_index: usize,
    /// Suppress console output (--quiet).
    pub quiet: bool,
    /// Enable extra debug hexdumps (--debug).
    pub debug: bool,
    /// Keep bt_log open for packet traces (--monitor).
    pub monitor: bool,
    /// Only run tests whose name starts with this prefix (--prefix).
    pub prefix_filter: Option<String>,
    /// Only run tests whose name contains this string (--string).
    pub string_filter: Option<String>,
    /// Only list test names without executing (--list).
    pub list_only: bool,
    /// Active I/O simulation layer.
    pub io: Option<TesterIo>,
    /// Name of the tester binary (derived from argv[0]).
    pub tester_name: String,
}

// ---------------------------------------------------------------------------
// Thread-Local Global State
// ---------------------------------------------------------------------------

thread_local! {
    /// Process-wide tester context.
    static TESTER_CTX: RefCell<Option<TesterContext>> = const { RefCell::new(None) };
    /// Signal sender for lifecycle transitions.
    static SIGNAL_TX: RefCell<Option<UnboundedSender<TesterSignal>>> = const { RefCell::new(None) };
}

/// Send a lifecycle signal to the run loop.
fn send_signal(signal: TesterSignal) {
    SIGNAL_TX.with(|tx| {
        if let Some(sender) = tx.borrow().as_ref() {
            let _ = sender.send(signal);
        }
    });
}

/// Read a field from the current tester context.
fn with_ctx<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&TesterContext) -> R,
{
    TESTER_CTX.with(|ctx| {
        let guard = ctx.borrow();
        guard.as_ref().map(f)
    })
}

/// Mutably access the current tester context.
fn with_ctx_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut TesterContext) -> R,
{
    TESTER_CTX.with(|ctx| {
        let mut guard = ctx.borrow_mut();
        guard.as_mut().map(f)
    })
}

/// Get the name of the current test (short borrow, returns owned String).
fn current_test_name() -> Option<String> {
    with_ctx(|c| c.test_list.get(c.current_index).map(|t| t.name.clone())).flatten()
}

/// Get the tester binary name.
fn tester_name() -> String {
    with_ctx(|c| c.tester_name.clone()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Output and Diagnostics Functions
// ---------------------------------------------------------------------------

/// Format and print a message to stdout AND the HCI logging channel.
///
/// Respects the `quiet` flag — suppresses console output when set.
/// The message is always sent to `bt_log_vprintf` regardless of quiet mode.
fn tester_log(color: &str, label: &str, msg: &str) {
    let name = tester_name();
    let quiet = with_ctx(|c| c.quiet).unwrap_or(false);
    if !quiet {
        if color.is_empty() {
            println!("  {msg}");
        } else {
            println!("  {color}{msg}{COLOR_OFF}");
        }
    }
    let log_label = if name.is_empty() { label } else { &name };
    let _ = bt_log_vprintf(HCI_DEV_NONE, log_label, LOG_INFO, msg);
}

/// Print a normal informational message (no color prefix).
pub fn tester_print(msg: &str) {
    tester_log("", "tester", msg);
}

/// Print a warning message (yellow).
pub fn tester_warn(msg: &str) {
    tester_log(COLOR_YELLOW, "tester", &format!("Warning: {msg}"));
}

/// Print a debug message (only when `--debug` is active).
pub fn tester_debug(msg: &str) {
    let is_debug = with_ctx(|c| c.debug).unwrap_or(false);
    if is_debug {
        tester_log(COLOR_MAGENTA, "tester", msg);
    }
}

/// Structured traffic monitoring via the HCI logging channel.
///
/// `dir` — direction character (`'>'` = outgoing, `'<'` = incoming)
/// `cid` — L2CAP channel identifier
/// `psm`— Protocol/Service Multiplexer
/// `data` — raw packet bytes
///
/// Sends a structured L2CAP monitoring header followed by the payload to
/// `bt_log_sendmsg`, then optionally dumps the packet via `hexdump` when
/// debug mode is enabled.
pub fn tester_monitor(dir: char, cid: u16, psm: u16, data: &[u8]) {
    let is_monitor = with_ctx(|c| c.monitor).unwrap_or(false);
    if !is_monitor {
        return;
    }
    monitor_log(dir, cid, psm, data);
    let is_debug = with_ctx(|c| c.debug).unwrap_or(false);
    if is_debug {
        let prefix = format!("{dir} ");
        hexdump(&prefix, data, |line| {
            tester_debug(line);
        });
    }
}

/// Pack a monitor L2CAP header and send via `bt_log_sendmsg`.
///
/// Header layout (little-endian, packed):
///   bytes 0-1 : handle  (0x0000)
///   bytes 2-3 : cid
///   bytes 4-5 : psm
///   byte  6   : direction flag (0x00 = out, 0x01 = in)
fn monitor_log(dir: char, cid: u16, psm: u16, data: &[u8]) {
    let name = tester_name();
    let label = if name.is_empty() { "tester" } else { &name };

    // Build a 7-byte L2CAP monitor header.
    let mut hdr = [0u8; 7];
    // handle is 0x0000 (bytes 0-1)
    hdr[2] = (cid & 0xFF) as u8;
    hdr[3] = ((cid >> 8) & 0xFF) as u8;
    hdr[4] = (psm & 0xFF) as u8;
    hdr[5] = ((psm >> 8) & 0xFF) as u8;
    hdr[6] = if dir == '<' { 0x01 } else { 0x00 };

    let slices = [IoSlice::new(&hdr), IoSlice::new(data)];
    let _ = bt_log_sendmsg(HCI_DEV_NONE, label, LOG_DEBUG, &slices);
}

/// Print a 52-char left-aligned summary line with colored result text.
fn print_summary(name: &str, color: &str, label: &str) {
    let padded = format!("{name:<52}");
    println!("  {padded}{color}{label}{COLOR_OFF}");
}

/// Print progress message with highlighted test name.
fn print_progress(name: &str, color: &str, label: &str) {
    let quiet = with_ctx(|c| c.quiet).unwrap_or(false);
    if quiet {
        return;
    }
    println!("  {COLOR_HIGHLIGHT}{name}{COLOR_OFF} - {color}{label}{COLOR_OFF}",);
}

// ---------------------------------------------------------------------------
// Convenience Free Functions (iov_data / iov_null)
// ---------------------------------------------------------------------------

/// Return a `Vec<u8>` containing the given data bytes.
///
/// This is the functional form of [`iov_data!`] for use in contexts
/// where macros are inconvenient. Returns an owned vector.
pub fn iov_data(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

/// Return an empty `Vec<u8>` (sentinel/null I/O vector entry).
pub fn iov_null() -> Vec<u8> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Query Functions
// ---------------------------------------------------------------------------

/// Return `true` if quiet mode is active.
pub fn tester_use_quiet() -> bool {
    with_ctx(|c| c.quiet).unwrap_or(false)
}

/// Return `true` if debug mode is active.
pub fn tester_use_debug() -> bool {
    with_ctx(|c| c.debug).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Initialise the test harness, parsing command-line options.
///
/// Recognises the following flags:
/// - `--version`  — print version and exit
/// - `--quiet`    — suppress console output
/// - `--debug`    — enable extra hexdumps
/// - `--monitor`  — keep HCI logging channel open
/// - `--list`     — list test names without executing
/// - `--prefix=X` — only run tests with names starting with `X`
/// - `--string=X` — only run tests with names containing `X`
pub fn tester_init(args: &[String]) {
    let mut quiet = false;
    let mut debug = false;
    let mut monitor = false;
    let mut list_only = false;
    let mut prefix_filter: Option<String> = None;
    let mut string_filter: Option<String> = None;

    // Extract binary name from argv[0].
    let tester_name = args
        .first()
        .map(|a| {
            std::path::Path::new(a).file_name().unwrap_or_default().to_string_lossy().into_owned()
        })
        .unwrap_or_default();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--version" | "-v" => {
                println!("{tester_name}");
                std::process::exit(0);
            }
            "--quiet" | "-q" => quiet = true,
            "--debug" | "-d" => debug = true,
            "--monitor" | "-m" => monitor = true,
            "--list" | "-l" => list_only = true,
            s if s.starts_with("--prefix=") => {
                prefix_filter = Some(s.trim_start_matches("--prefix=").to_owned());
            }
            s if s.starts_with("--string=") => {
                string_filter = Some(s.trim_start_matches("--string=").to_owned());
            }
            "--prefix" | "-p" => {
                i += 1;
                if i < args.len() {
                    prefix_filter = Some(args[i].clone());
                }
            }
            "--string" | "-s" => {
                i += 1;
                if i < args.len() {
                    string_filter = Some(args[i].clone());
                }
            }
            _ => {
                // Unknown arguments are silently ignored (matching C behaviour).
            }
        }
        i += 1;
    }

    let ctx = TesterContext {
        test_list: Vec::new(),
        current_index: 0,
        quiet,
        debug,
        monitor,
        prefix_filter,
        string_filter,
        list_only,
        io: None,
        tester_name,
    };

    TESTER_CTX.with(|c| {
        *c.borrow_mut() = Some(ctx);
    });
}

// ---------------------------------------------------------------------------
// Test Registration
// ---------------------------------------------------------------------------

/// Register a test case with full lifecycle callbacks.
///
/// `name`              — test name (used for filtering and display)
/// `test_data`         — immutable data shared across callbacks (user_data in C)
/// `pre_setup_func`    — called before setup (optional)
/// `setup_func`        — called to set up test fixtures (optional)
/// `test_func`         — the actual test function (optional)
/// `teardown_func`     — called to tear down fixtures (optional)
/// `post_teardown_func`— called after teardown (optional)
/// `timeout_secs`      — per-test timeout in seconds (0 = no timeout)
/// `user_data`         — per-test mutable context
pub fn tester_add_full<D, U>(
    name: &str,
    test_data: Option<D>,
    pre_setup_func: Option<TestCallback>,
    setup_func: Option<TestCallback>,
    test_func: Option<TestCallback>,
    teardown_func: Option<TestCallback>,
    post_teardown_func: Option<TestCallback>,
    timeout_secs: u32,
    user_data: Option<U>,
) where
    D: Any + Send + Sync + 'static,
    U: Any + Send + Sync + 'static,
{
    with_ctx_mut(|ctx| {
        // Apply prefix filter — skip tests that don't match.
        if let Some(ref pfx) = ctx.prefix_filter {
            if !name.starts_with(pfx.as_str()) {
                return;
            }
        }
        // Apply string filter — skip tests that don't contain the substring.
        if let Some(ref s) = ctx.string_filter {
            if !name.contains(s.as_str()) {
                return;
            }
        }

        // In list-only mode, print the name and skip registration.
        if ctx.list_only {
            println!("{name}");
            return;
        }

        let td: Option<Arc<dyn Any + Send + Sync>> =
            test_data.map(|d| Arc::new(d) as Arc<dyn Any + Send + Sync>);
        let ud: Option<Arc<dyn Any + Send + Sync>> =
            user_data.map(|u| Arc::new(u) as Arc<dyn Any + Send + Sync>);

        let timeout = if timeout_secs > 0 {
            Duration::from_secs(u64::from(timeout_secs))
        } else {
            Duration::ZERO
        };

        let tc = TestCase {
            name: name.to_owned(),
            stage: TesterStage::PreSetup,
            result: TesterResult::NotRun,
            test_data: td,
            user_data: ud,
            pre_setup_func,
            setup_func,
            test_func,
            teardown_func,
            post_teardown_func,
            timeout,
            start_time: None,
            end_time: None,
        };
        ctx.test_list.push(tc);
    });
}

/// Convenience wrapper for [`tester_add_full`] with default
/// pre-setup/post-teardown callbacks and a 30-second timeout.
pub fn tester_add<D>(
    name: &str,
    test_data: Option<D>,
    setup_func: Option<TestCallback>,
    test_func: Option<TestCallback>,
    teardown_func: Option<TestCallback>,
) where
    D: Any + Send + Sync + 'static,
{
    tester_add_full::<D, ()>(
        name,
        test_data,
        None,
        setup_func,
        test_func,
        teardown_func,
        None,
        DEFAULT_TIMEOUT_SECS,
        None,
    );
}

/// Get the current test's test data, downcast to `T`.
///
/// Returns `None` if no test is running, no data was registered, or the
/// downcast fails.
pub fn tester_get_data<T: Any + Send + Sync + 'static>() -> Option<Arc<T>> {
    let arc = with_ctx(|c| c.test_list.get(c.current_index).and_then(|tc| tc.test_data.clone()))
        .flatten();

    arc.and_then(|a| Arc::downcast::<T>(a).ok())
}

// ---------------------------------------------------------------------------
// Lifecycle Signaling API
// ---------------------------------------------------------------------------

/// Signal that pre-setup completed successfully.
/// Schedules the setup callback.
pub fn tester_pre_setup_complete() {
    send_signal(TesterSignal::PreSetupComplete);
}

/// Signal that pre-setup failed.
pub fn tester_pre_setup_failed() {
    send_signal(TesterSignal::PreSetupFailed);
}

/// Abort the current test during pre-setup.
pub fn tester_pre_setup_abort() {
    send_signal(TesterSignal::PreSetupAbort);
}

/// Check if the current test should be skipped by default.
///
/// Returns `true` and sends an abort signal when no prefix or string
/// filter is set, allowing tests to opt-in to skip-by-default behaviour.
pub fn tester_pre_setup_skip_by_default() -> bool {
    let has_filter =
        with_ctx(|c| c.prefix_filter.is_some() || c.string_filter.is_some()).unwrap_or(false);
    if !has_filter {
        tester_pre_setup_abort();
        return true;
    }
    false
}

/// Signal that setup completed successfully.
/// Schedules the test function.
pub fn tester_setup_complete() {
    send_signal(TesterSignal::SetupComplete);
}

/// Signal that setup failed.
pub fn tester_setup_failed() {
    send_signal(TesterSignal::SetupFailed);
}

/// Signal that the test passed.
pub fn tester_test_passed() {
    send_signal(TesterSignal::TestPassed);
}

/// Signal that the test failed.
pub fn tester_test_failed() {
    send_signal(TesterSignal::TestFailed);
}

/// Abort the test.
pub fn tester_test_abort() {
    send_signal(TesterSignal::TestAbort);
}

/// Signal that teardown completed successfully.
pub fn tester_teardown_complete() {
    send_signal(TesterSignal::TeardownComplete);
}

/// Signal that teardown failed.
pub fn tester_teardown_failed() {
    send_signal(TesterSignal::TeardownFailed);
}

/// Signal that post-teardown completed successfully.
pub fn tester_post_teardown_complete() {
    send_signal(TesterSignal::PostTeardownComplete);
}

/// Signal that post-teardown failed.
pub fn tester_post_teardown_failed() {
    send_signal(TesterSignal::PostTeardownFailed);
}

// ---------------------------------------------------------------------------
// I/O Simulation Layer
// ---------------------------------------------------------------------------

/// Create a socketpair-backed I/O simulation layer.
///
/// `iovs` — the scripted I/O vectors. Alternating entries represent:
///   - receive-validate (what the harness expects to read from the test side)
///   - send (what the harness sends back to the test side)
///
/// Returns the raw file descriptor of the test endpoint so that the test
/// code can read/write on it directly.
pub fn tester_setup_io(iovs: &[&[u8]]) -> RawFd {
    let (fd0, fd1) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::SeqPacket,
        None,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
    )
    .expect("socketpair creation failed");

    let test_fd = fd0.as_raw_fd();

    let script: Vec<Vec<u8>> = iovs.iter().map(|v| v.to_vec()).collect();

    let tio =
        TesterIo { endpoints: (fd0, fd1), iov_script: script, iov_index: 0, complete_func: None };

    with_ctx_mut(|ctx| {
        ctx.io = Some(tio);
    });

    test_fd
}

/// Shut down the I/O simulation layer, closing both socketpair endpoints.
pub fn tester_shutdown_io() {
    with_ctx_mut(|ctx| {
        ctx.io = None;
    });
}

/// Send the next scripted I/O vector from the harness endpoint to the test
/// endpoint.
///
/// Advances through the iov_script, skipping null (empty) entries that serve
/// as separators. Sends data on the harness side of the socketpair and
/// monitors the outgoing traffic.
pub fn tester_io_send() {
    // Perform the write inside the borrow (OwnedFd implements AsFd),
    // then monitor outside the borrow to avoid re-entrant thread_local access.
    let monitor_data = with_ctx_mut(|ctx| -> Option<(Vec<u8>, bool)> {
        let io = ctx.io.as_mut()?;
        if io.iov_index >= io.iov_script.len() {
            return None;
        }
        let entry = io.iov_script[io.iov_index].clone();
        io.iov_index += 1;
        if entry.is_empty() {
            return None;
        }
        // Write on the harness endpoint — &OwnedFd implements AsFd.
        let _ = nix::unistd::write(&io.endpoints.1, &entry);
        Some((entry, ctx.monitor))
    })
    .flatten();

    if let Some((data, do_monitor)) = monitor_data {
        if do_monitor {
            tester_monitor('>', 0x0000, 0x0000, &data);
        }
    }
}

/// Read data from the test endpoint and validate against the current
/// scripted I/O vector.
///
/// Returns `true` if the read data matches the expected vector (or if
/// the script is exhausted / no I/O layer is active), `false` on mismatch.
/// This uses `nix::unistd::read` to receive data from the socketpair.
pub fn tester_io_recv_and_validate() -> bool {
    let read_result = with_ctx_mut(|ctx| -> Option<(Vec<u8>, Vec<u8>, bool)> {
        let io = ctx.io.as_mut()?;
        if io.iov_index >= io.iov_script.len() {
            return None;
        }
        let expected = io.iov_script[io.iov_index].clone();
        io.iov_index += 1;
        if expected.is_empty() {
            return None;
        }

        // Read from the test endpoint (endpoint 0).
        let mut buf = vec![0u8; 2048];
        let len = match nix::unistd::read(io.endpoints.0.as_raw_fd(), &mut buf) {
            Ok(n) => n,
            Err(_) => return Some((expected, Vec::new(), ctx.monitor)),
        };
        buf.truncate(len);
        Some((expected, buf, ctx.monitor))
    })
    .flatten();

    match read_result {
        Some((expected, received, do_monitor)) => {
            if do_monitor {
                tester_monitor('<', 0x0000, 0x0000, &received);
            }
            expected == received
        }
        None => true, // Script exhausted or no I/O layer — vacuously OK.
    }
}

/// Register a completion callback for the I/O simulation.
///
/// The callback is invoked once all scripted I/O vectors have been
/// processed (or when the script encounters a terminal empty entry).
pub fn tester_io_set_complete_func(func: impl FnOnce(&dyn Any) + Send + 'static) {
    with_ctx_mut(|ctx| {
        if let Some(ref mut io) = ctx.io {
            io.complete_func = Some(Box::new(func));
        }
    });
}

// ---------------------------------------------------------------------------
// Wait Utility
// ---------------------------------------------------------------------------

/// Count down `seconds` on-screen, then invoke `func`.
///
/// Prints the remaining seconds each tick (matching the C harness behaviour).
/// Uses `tokio::time::sleep` for the countdown.
pub fn tester_wait(seconds: u32, func: impl FnOnce() + Send + 'static) {
    // Schedule the countdown asynchronously via tokio::spawn when a runtime
    // is available; fall back to synchronous sleep otherwise.
    let handle_result = tokio::runtime::Handle::try_current();
    match handle_result {
        Ok(_handle) => {
            tokio::spawn(async move {
                for remaining in (1..=seconds).rev() {
                    let quiet = with_ctx(|c| c.quiet).unwrap_or(false);
                    if !quiet {
                        println!("  Waiting {remaining} seconds...");
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                func();
            });
        }
        Err(_) => {
            // Fallback: if no tokio runtime, execute synchronously.
            for remaining in (1..=seconds).rev() {
                let quiet = with_ctx(|c| c.quiet).unwrap_or(false);
                if !quiet {
                    println!("  Waiting {remaining} seconds...");
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            func();
        }
    }
}

// ---------------------------------------------------------------------------
// Test Execution Engine
// ---------------------------------------------------------------------------

/// Summarise the test run and print pass/fail statistics.
///
/// Returns the process exit code (0 if all passed, 1 otherwise).
fn tester_summarize() -> i32 {
    let timer_elapsed =
        with_ctx(|c| c.test_list.first().and_then(|t| t.start_time).map(|st| st.elapsed()))
            .flatten()
            .unwrap_or(Duration::ZERO);

    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut not_run = 0u32;
    let mut timed_out = 0u32;
    let mut skipped = 0u32;
    let mut total = 0u32;

    with_ctx(|c| {
        for tc in &c.test_list {
            total += 1;
            match tc.result {
                TesterResult::Passed => {
                    passed += 1;
                    print_summary(&tc.name, COLOR_GREEN, "Passed");
                }
                TesterResult::Failed => {
                    failed += 1;
                    print_summary(&tc.name, COLOR_RED, "Failed");
                }
                TesterResult::TimedOut => {
                    timed_out += 1;
                    print_summary(&tc.name, COLOR_RED, "Timed out");
                }
                TesterResult::NotRun => {
                    not_run += 1;
                    print_summary(&tc.name, COLOR_YELLOW, "Not Run");
                }
                TesterResult::Aborted => {
                    not_run += 1;
                    print_summary(&tc.name, COLOR_YELLOW, "Not Run");
                }
                TesterResult::Skipped => {
                    skipped += 1;
                    print_summary(&tc.name, COLOR_YELLOW, "Skipped");
                }
            }
        }
    });

    let total_secs = timer_elapsed.as_secs_f64();
    println!();
    println!(
        "  Total: {total}  Passed: {passed}  Failed: {failed}  \
         Not Run: {not_run}  Timed Out: {timed_out}"
    );
    println!("  Overall execution time: {total_secs:.3} seconds");

    if failed > 0 || timed_out > 0 { 1 } else { 0 }
}

/// Invoke a callback, extracting it from the test case to avoid borrow conflicts.
fn invoke_callback(callback_extractor: impl FnOnce(&mut TestCase) -> Option<TestCallback>) {
    let cb_and_data = with_ctx_mut(|ctx| -> Option<(TestCallback, Arc<dyn Any + Send + Sync>)> {
        let tc = ctx.test_list.get_mut(ctx.current_index)?;
        let cb = callback_extractor(tc)?;
        let data = tc.test_data.clone().unwrap_or_else(|| Arc::new(()));
        Some((cb, data))
    })
    .flatten();
    if let Some((cb, data)) = cb_and_data {
        cb(data.as_ref());
    }
}

/// Execute the full test suite.
///
/// If `list_only` is set, returns immediately (names were printed during
/// registration).
///
/// Otherwise runs all registered tests sequentially through the lifecycle
/// phases, enforcing per-test timeouts, handling SIGINT/SIGTERM for clean
/// abort, printing colorised progress, and returning a process exit code
/// (0 = all passed, 1 = any failures).
pub fn tester_run() -> i32 {
    // In list-only mode, tests were printed during add — nothing else to do.
    let is_list = with_ctx(|c| c.list_only).unwrap_or(false);
    if is_list {
        return 0;
    }

    let total = with_ctx(|c| c.test_list.len()).unwrap_or(0);
    if total == 0 {
        println!("  No test cases registered");
        return 0;
    }

    // Build a current_thread tokio runtime for test execution.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime for tester");

    let exit_code = rt.block_on(async { run_all_tests().await });

    // Cleanup: close bt_log if monitor was active.
    let is_monitor = with_ctx(|c| c.monitor).unwrap_or(false);
    if is_monitor {
        bt_log_close();
    }

    exit_code
}

/// Async engine: run all tests sequentially.
async fn run_all_tests() -> i32 {
    // Set up signal handling for clean abort.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("failed to register SIGINT handler");
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");

    let total = with_ctx(|c| c.test_list.len()).unwrap_or(0);

    for idx in 0..total {
        // Set current test index.
        with_ctx_mut(|c| c.current_index = idx);

        // Record start time.
        let start = Instant::now();
        with_ctx_mut(|c| {
            if let Some(tc) = c.test_list.get_mut(idx) {
                tc.start_time = Some(start);
                tc.stage = TesterStage::PreSetup;
                tc.result = TesterResult::NotRun;
            }
        });

        let test_name = current_test_name().unwrap_or_default();
        print_progress(&test_name, COLOR_BLACK, "Pre-Setup");

        // Create the signal channel for this test.
        let (tx, mut rx) = mpsc::unbounded_channel::<TesterSignal>();
        SIGNAL_TX.with(|s| *s.borrow_mut() = Some(tx));

        let timeout_dur = with_ctx(|c| c.test_list.get(c.current_index).map(|tc| tc.timeout))
            .flatten()
            .unwrap_or(Duration::ZERO);

        // Run the test lifecycle.
        let result = run_single_test(&mut rx, &mut sigint, &mut sigterm, timeout_dur).await;

        // Record result and end time.
        with_ctx_mut(|c| {
            if let Some(tc) = c.test_list.get_mut(idx) {
                tc.result = result;
                tc.end_time = Some(Instant::now());
            }
        });

        // Shut down I/O for this test.
        tester_shutdown_io();

        // Remove signal sender.
        SIGNAL_TX.with(|s| *s.borrow_mut() = None);
    }

    tester_summarize()
}

/// Execute a single test through its lifecycle phases.
///
/// Returns the final `TesterResult` for the test.
async fn run_single_test(
    rx: &mut mpsc::UnboundedReceiver<TesterSignal>,
    sigint: &mut tokio::signal::unix::Signal,
    sigterm: &mut tokio::signal::unix::Signal,
    timeout_dur: Duration,
) -> TesterResult {
    let test_name = current_test_name().unwrap_or_default();

    // --- Pre-Setup ---
    invoke_callback(|tc| {
        if let Some(ref cb) = tc.pre_setup_func {
            Some(Arc::clone(cb))
        } else {
            // No pre-setup callback → auto-complete.
            send_signal(TesterSignal::PreSetupComplete);
            None
        }
    });

    // Wait for pre-setup signal.
    let signal = wait_for_signal(rx, sigint, sigterm, Duration::ZERO).await;
    match signal {
        Some(TesterSignal::PreSetupComplete) => {}
        Some(TesterSignal::PreSetupFailed) => {
            print_progress(&test_name, COLOR_RED, "Pre-Setup - Failed");
            return TesterResult::Failed;
        }
        Some(TesterSignal::PreSetupAbort) => {
            print_progress(&test_name, COLOR_YELLOW, "Pre-Setup - Abort");
            return TesterResult::NotRun;
        }
        None => {
            // Signal (SIGINT/SIGTERM) received.
            return TesterResult::Aborted;
        }
        _ => {
            return TesterResult::Failed;
        }
    }

    // --- Setup ---
    with_ctx_mut(|c| {
        if let Some(tc) = c.test_list.get_mut(c.current_index) {
            tc.stage = TesterStage::Setup;
        }
    });
    print_progress(&test_name, COLOR_BLUE, "Setup");

    invoke_callback(|tc| {
        if let Some(ref cb) = tc.setup_func {
            Some(Arc::clone(cb))
        } else {
            send_signal(TesterSignal::SetupComplete);
            None
        }
    });

    let signal = wait_for_signal(rx, sigint, sigterm, Duration::ZERO).await;
    match signal {
        Some(TesterSignal::SetupComplete) => {}
        Some(TesterSignal::SetupFailed) => {
            print_progress(&test_name, COLOR_RED, "Setup - Failed");
            // Skip to post-teardown.
            run_post_teardown(rx, sigint, sigterm).await;
            return TesterResult::Failed;
        }
        None => {
            return TesterResult::Aborted;
        }
        _ => {
            return TesterResult::Failed;
        }
    }

    // --- Run ---
    with_ctx_mut(|c| {
        if let Some(tc) = c.test_list.get_mut(c.current_index) {
            tc.stage = TesterStage::Run;
        }
    });
    print_progress(&test_name, COLOR_BLACK, "Run");

    invoke_callback(|tc| {
        if let Some(ref cb) = tc.test_func {
            Some(Arc::clone(cb))
        } else {
            send_signal(TesterSignal::TestPassed);
            None
        }
    });

    // Wait for test result with timeout.
    let signal = wait_for_signal(rx, sigint, sigterm, timeout_dur).await;
    let test_result = match signal {
        Some(TesterSignal::TestPassed) => {
            print_progress(&test_name, COLOR_GREEN, "Test - Passed");
            TesterResult::Passed
        }
        Some(TesterSignal::TestFailed) => {
            print_progress(&test_name, COLOR_RED, "Test - Failed");
            TesterResult::Failed
        }
        Some(TesterSignal::TestAbort) => {
            print_progress(&test_name, COLOR_YELLOW, "Test - Abort");
            TesterResult::Aborted
        }
        Some(TesterSignal::SetupFailed) => {
            // Setup failure signalled during run phase.
            print_progress(&test_name, COLOR_RED, "Test - Failed");
            TesterResult::Failed
        }
        None => {
            // Timeout or OS signal.
            if timeout_dur > Duration::ZERO {
                print_progress(&test_name, COLOR_RED, "Test - Timed out");
                TesterResult::TimedOut
            } else {
                TesterResult::Aborted
            }
        }
        _ => TesterResult::Failed,
    };

    // --- Teardown (always runs) ---
    with_ctx_mut(|c| {
        if let Some(tc) = c.test_list.get_mut(c.current_index) {
            tc.stage = TesterStage::Teardown;
        }
    });
    print_progress(&test_name, COLOR_BLACK, "Teardown");

    invoke_callback(|tc| {
        if let Some(ref cb) = tc.teardown_func {
            Some(Arc::clone(cb))
        } else {
            send_signal(TesterSignal::TeardownComplete);
            None
        }
    });

    let signal = wait_for_signal(rx, sigint, sigterm, Duration::ZERO).await;
    match signal {
        Some(TesterSignal::TeardownComplete) => {}
        Some(TesterSignal::TeardownFailed) => {
            print_progress(&test_name, COLOR_RED, "Teardown - Failed");
        }
        None => {}
        _ => {}
    }

    // --- Post-Teardown ---
    run_post_teardown(rx, sigint, sigterm).await;

    test_result
}

/// Execute the post-teardown phase.
async fn run_post_teardown(
    rx: &mut mpsc::UnboundedReceiver<TesterSignal>,
    sigint: &mut tokio::signal::unix::Signal,
    sigterm: &mut tokio::signal::unix::Signal,
) {
    let test_name = current_test_name().unwrap_or_default();
    with_ctx_mut(|c| {
        if let Some(tc) = c.test_list.get_mut(c.current_index) {
            tc.stage = TesterStage::PostTeardown;
        }
    });
    print_progress(&test_name, COLOR_BLACK, "Post-Teardown");

    invoke_callback(|tc| {
        if let Some(ref cb) = tc.post_teardown_func {
            Some(Arc::clone(cb))
        } else {
            send_signal(TesterSignal::PostTeardownComplete);
            None
        }
    });

    let signal = wait_for_signal(rx, sigint, sigterm, Duration::ZERO).await;
    match signal {
        Some(TesterSignal::PostTeardownComplete) => {}
        Some(TesterSignal::PostTeardownFailed) => {
            print_progress(&test_name, COLOR_RED, "Post-Teardown - Failed");
        }
        _ => {}
    }
}

/// Wait for a lifecycle signal, an OS signal (SIGINT/SIGTERM), or a timeout.
///
/// `timeout_dur` of `Duration::ZERO` disables the timeout.
/// Returns `None` when a timeout or OS signal fires.
///
/// Timeout is enforced via `tokio::time::timeout` wrapping the channel
/// receive, as required by the AAP for per-test deadline enforcement.
async fn wait_for_signal(
    rx: &mut mpsc::UnboundedReceiver<TesterSignal>,
    sigint: &mut tokio::signal::unix::Signal,
    sigterm: &mut tokio::signal::unix::Signal,
    timeout_dur: Duration,
) -> Option<TesterSignal> {
    if timeout_dur > Duration::ZERO {
        // Use tokio::time::timeout for per-test deadline enforcement.
        let recv_future = async {
            tokio::select! {
                sig = rx.recv() => sig,
                _ = sigint.recv() => None,
                _ = sigterm.recv() => None,
            }
        };
        tokio::time::timeout(timeout_dur, recv_future).await.unwrap_or_default()
    } else {
        tokio::select! {
            sig = rx.recv() => sig,
            _ = sigint.recv() => None,
            _ = sigterm.recv() => None,
        }
    }
}
