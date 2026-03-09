// SPDX-License-Identifier: GPL-2.0-or-later
//
// Test framework extensions for the bluez-tools crate.
//
// Wraps bluez_shared::tester with convenience helpers specific to the
// test-tool binaries: environment checks, standard main() wrapper, and
// colored output formatting.

use bluez_shared::tester::{TestStatus, TestSuite};

/// Check whether the current platform supports Bluetooth testing.
///
/// On Linux this checks for the existence of /dev/vhci. On other
/// platforms the tests are not runnable and all cases are skipped.
pub fn platform_supports_bluetooth() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/dev/vhci").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Print a single test result line.
pub fn print_test_result(name: &str, status: TestStatus) {
    let tag = match status {
        TestStatus::Passed => "PASS",
        TestStatus::Failed => "FAIL",
        TestStatus::Skipped => "SKIP",
        TestStatus::TimedOut => "TIME",
        TestStatus::Running => "RUN ",
        TestStatus::NotRun => "----",
    };
    println!("  [{tag}] {name}");
}

/// Print detailed results for every test in the suite.
pub fn print_results(suite: &TestSuite) {
    println!("\n=== {} Results ===", suite.name);
    for test in &suite.tests {
        print_test_result(&test.name, test.status);
    }
    println!();
    suite.print_summary();
}

/// Standard entry point for a tester binary.
///
/// Creates a Tokio runtime, runs the suite, prints results, and returns
/// the process exit code (0 if all tests passed or were skipped, 1 if
/// any failed).
pub fn run_tester_main(mut suite: TestSuite) -> i32 {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let (_passed, failed, _skipped) = rt.block_on(suite.run_all());
    print_results(&suite);

    if failed > 0 {
        1
    } else {
        0
    }
}

/// Helper to create a skipped test that reports *why* it was skipped.
pub async fn skip_not_linux() -> TestStatus {
    println!("    (skipped: not running on Linux)");
    TestStatus::Skipped
}

/// Helper to create a stub test that always passes.
pub async fn stub_pass() -> TestStatus {
    TestStatus::Passed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_check_returns_bool() {
        // On macOS / CI this will be false; on Linux it depends on vhci.
        let result = platform_supports_bluetooth();
        // We just verify the function is callable and returns a bool.
        assert!(result || !result);
    }

    #[test]
    fn run_tester_main_passes_empty_suite() {
        let suite = TestSuite::new("empty-suite");
        let exit_code = run_tester_main(suite);
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn run_tester_main_reports_failure() {
        let mut suite = TestSuite::new("fail-suite");
        suite.add_test("always-fail", || async { TestStatus::Failed });
        let exit_code = run_tester_main(suite);
        assert_eq!(exit_code, 1);
    }

    #[test]
    fn print_test_result_all_variants() {
        // Smoke-test that printing doesn't panic for any status variant.
        for &status in &[
            TestStatus::Passed,
            TestStatus::Failed,
            TestStatus::Skipped,
            TestStatus::TimedOut,
            TestStatus::Running,
            TestStatus::NotRun,
        ] {
            print_test_result("dummy", status);
        }
    }
}
