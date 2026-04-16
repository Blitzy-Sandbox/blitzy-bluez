// SPDX-License-Identifier: GPL-2.0-or-later
//
// Test framework replacing src/shared/tester.c
//
// Provides a structured test runner for Bluetooth protocol tests.
// Used by mgmt-tester, l2cap-tester, etc.

use std::future::Future;
use std::pin::Pin;

/// Test case status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    /// Test has not been run.
    NotRun,
    /// Test is currently running.
    Running,
    /// Test passed.
    Passed,
    /// Test failed.
    Failed,
    /// Test timed out.
    TimedOut,
    /// Test was skipped.
    Skipped,
}

impl std::fmt::Display for TestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRun => write!(f, "Not Run"),
            Self::Running => write!(f, "Running"),
            Self::Passed => write!(f, "Passed"),
            Self::Failed => write!(f, "Failed"),
            Self::TimedOut => write!(f, "Timed Out"),
            Self::Skipped => write!(f, "Skipped"),
        }
    }
}

/// A single test case.
pub struct TestCase {
    /// Test name.
    pub name: String,
    /// Test function.
    test_fn: Box<dyn Fn() -> Pin<Box<dyn Future<Output = TestStatus> + Send>> + Send + Sync>,
    /// Test result.
    pub status: TestStatus,
}

impl TestCase {
    /// Create a new test case.
    pub fn new<F, Fut>(name: &str, f: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = TestStatus> + Send + 'static,
    {
        Self {
            name: name.to_string(),
            test_fn: Box::new(move || Box::pin(f())),
            status: TestStatus::NotRun,
        }
    }

    /// Run the test case.
    pub async fn run(&mut self) {
        self.status = TestStatus::Running;
        self.status = (self.test_fn)().await;
    }
}

/// Test suite containing multiple test cases.
pub struct TestSuite {
    /// Suite name.
    pub name: String,
    /// Test cases.
    pub tests: Vec<TestCase>,
    /// Default timeout per test in seconds.
    pub timeout_secs: u64,
}

impl TestSuite {
    /// Create a new test suite.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            tests: Vec::new(),
            timeout_secs: 30,
        }
    }

    /// Add a test case.
    pub fn add_test<F, Fut>(&mut self, name: &str, f: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = TestStatus> + Send + 'static,
    {
        self.tests.push(TestCase::new(name, f));
    }

    /// Run all tests and return (passed, failed, skipped) counts.
    pub async fn run_all(&mut self) -> (usize, usize, usize) {
        let mut passed = 0;
        let mut failed = 0;
        let mut skipped = 0;

        for test in &mut self.tests {
            let timeout = tokio::time::Duration::from_secs(self.timeout_secs);
            match tokio::time::timeout(timeout, test.run()).await {
                Ok(()) => {}
                Err(_) => {
                    test.status = TestStatus::TimedOut;
                }
            }

            match test.status {
                TestStatus::Passed => passed += 1,
                TestStatus::Skipped => skipped += 1,
                _ => failed += 1,
            }
        }

        (passed, failed, skipped)
    }

    /// Print a summary of test results.
    pub fn print_summary(&self) {
        let total = self.tests.len();
        let passed = self.tests.iter().filter(|t| t.status == TestStatus::Passed).count();
        let failed = self
            .tests
            .iter()
            .filter(|t| matches!(t.status, TestStatus::Failed | TestStatus::TimedOut))
            .count();
        let skipped = self.tests.iter().filter(|t| t.status == TestStatus::Skipped).count();

        tracing::info!(
            "{}: Total: {} Passed: {} Failed: {} Skipped: {}",
            self.name,
            total,
            passed,
            failed,
            skipped
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_status_display() {
        assert_eq!(format!("{}", TestStatus::Passed), "Passed");
        assert_eq!(format!("{}", TestStatus::Failed), "Failed");
    }

    #[test]
    fn test_suite_run() {
        rt().block_on(async {
            let mut suite = TestSuite::new("test-suite");
            suite.add_test("pass", || async { TestStatus::Passed });
            suite.add_test("fail", || async { TestStatus::Failed });
            suite.add_test("skip", || async { TestStatus::Skipped });

            let (passed, failed, skipped) = suite.run_all().await;
            assert_eq!(passed, 1);
            assert_eq!(failed, 1);
            assert_eq!(skipped, 1);
        });
    }

    #[test]
    fn test_empty_suite() {
        rt().block_on(async {
            let mut suite = TestSuite::new("empty");
            let (p, f, s) = suite.run_all().await;
            assert_eq!((p, f, s), (0, 0, 0));
        });
    }

    // ---------------------------------------------------------------
    // Tests ported from unit/test-tester.c
    // ---------------------------------------------------------------

    /// test_basic from test-tester.c: a trivial test that just passes.
    #[test]
    fn test_c_tester_basic() {
        rt().block_on(async {
            let mut suite = TestSuite::new("tester-basic");
            suite.add_test("basic", || async { TestStatus::Passed });

            let (passed, failed, skipped) = suite.run_all().await;
            assert_eq!(passed, 1);
            assert_eq!(failed, 0);
            assert_eq!(skipped, 0);
        });
    }

    /// Ported from test-tester.c test_setup_io / test_io_send:
    /// Verify the test framework can run multiple tests with IO-like behavior.
    #[test]
    fn test_c_tester_multiple_io_tests() {
        rt().block_on(async {
            let mut suite = TestSuite::new("tester-io");

            // Simulate setup_io test: send data and verify received
            suite.add_test("setup_io", || async {
                let data = vec![0x01u8, 0x02];
                // Verify the data is what we expect (simulating IO round-trip)
                if data == vec![0x01, 0x02] {
                    TestStatus::Passed
                } else {
                    TestStatus::Failed
                }
            });

            // Simulate io_send test
            suite.add_test("io_send", || async {
                let send_data = vec![0x01u8];
                if !send_data.is_empty() {
                    TestStatus::Passed
                } else {
                    TestStatus::Failed
                }
            });

            let (passed, failed, _) = suite.run_all().await;
            assert_eq!(passed, 2);
            assert_eq!(failed, 0);
        });
    }

    /// Test that the suite correctly reports test names and statuses.
    #[test]
    fn test_c_tester_status_tracking() {
        rt().block_on(async {
            let mut suite = TestSuite::new("status-track");
            suite.add_test("will_pass", || async { TestStatus::Passed });
            suite.add_test("will_fail", || async { TestStatus::Failed });
            suite.add_test("will_skip", || async { TestStatus::Skipped });

            suite.run_all().await;

            assert_eq!(suite.tests[0].name, "will_pass");
            assert_eq!(suite.tests[0].status, TestStatus::Passed);
            assert_eq!(suite.tests[1].name, "will_fail");
            assert_eq!(suite.tests[1].status, TestStatus::Failed);
            assert_eq!(suite.tests[2].name, "will_skip");
            assert_eq!(suite.tests[2].status, TestStatus::Skipped);
        });
    }
}
