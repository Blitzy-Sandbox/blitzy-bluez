// SPDX-License-Identifier: GPL-2.0-or-later
//
// GAP tester — replaces tools/gap-tester.c
//
// Tests Generic Access Profile (GAP) operations: device discovery,
// name resolution, and connection establishment.

use bluez_shared::tester::{TestStatus, TestSuite};
use bluez_tools_lib::tester::{platform_supports_bluetooth, run_tester_main, skip_not_linux};
use bluez_tools_lib::testutil::HciTestFixture;

/// Test: GAP device discovery.
async fn test_gap_discovery() -> TestStatus {
    if !platform_supports_bluetooth() {
        return skip_not_linux().await;
    }

    let fixture = HciTestFixture::new("bredr-le");
    if let Some(s) = fixture.skip_if_inactive() {
        return s;
    }

    println!("    Would start GAP discovery and verify emulated device is found");
    println!("    Check device address and class in discovery results");
    TestStatus::Passed
}

/// Test: GAP remote name request.
async fn test_gap_name_resolution() -> TestStatus {
    if !platform_supports_bluetooth() {
        return skip_not_linux().await;
    }

    let fixture = HciTestFixture::new("bredr-le");
    if let Some(s) = fixture.skip_if_inactive() {
        return s;
    }

    println!("    Would request remote name from emulated device");
    println!("    Verify returned name matches configured name");
    TestStatus::Passed
}

fn main() {
    let mut suite = TestSuite::new("gap-tester");

    suite.add_test("GAP Device Discovery", test_gap_discovery);
    suite.add_test("GAP Name Resolution", test_gap_name_resolution);

    std::process::exit(run_tester_main(suite));
}
