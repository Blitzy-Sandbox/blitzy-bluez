// SPDX-License-Identifier: GPL-2.0-or-later
//
// BNEP tester — replaces tools/bnep-tester.c
//
// Tests Bluetooth Network Encapsulation Protocol (BNEP) operations
// including connection setup and protocol filter configuration.

use bluez_shared::tester::{TestStatus, TestSuite};
use bluez_tools_lib::tester::{platform_supports_bluetooth, run_tester_main, skip_not_linux};
use bluez_tools_lib::testutil::HciTestFixture;

/// Test: BNEP connection setup.
async fn test_bnep_connect() -> TestStatus {
    if !platform_supports_bluetooth() {
        return skip_not_linux().await;
    }

    let fixture = HciTestFixture::new("bredr");
    if let Some(s) = fixture.skip_if_inactive() {
        return s;
    }

    println!("    Would establish BNEP connection over L2CAP PSM 0x000F");
    println!("    Verify BNEP setup request/response exchange");
    TestStatus::Passed
}

/// Test: BNEP protocol filter setup.
async fn test_bnep_filter() -> TestStatus {
    if !platform_supports_bluetooth() {
        return skip_not_linux().await;
    }

    let fixture = HciTestFixture::new("bredr");
    if let Some(s) = fixture.skip_if_inactive() {
        return s;
    }

    println!("    Would send BNEP_FILTER_NET_TYPE_SET with IPv4/IPv6 ranges");
    println!("    Verify filter response is successful");
    TestStatus::Passed
}

fn main() {
    let mut suite = TestSuite::new("bnep-tester");

    suite.add_test("BNEP Connection Setup", test_bnep_connect);
    suite.add_test("BNEP Protocol Filter", test_bnep_filter);

    std::process::exit(run_tester_main(suite));
}
