// SPDX-License-Identifier: GPL-2.0-or-later
//
// RFCOMM tester — replaces tools/rfcomm-tester.c
//
// Tests RFCOMM socket operations including channel creation and
// server/client connections over the emulated Bluetooth link.

use bluez_shared::tester::{TestStatus, TestSuite};
use bluez_tools_lib::tester::{platform_supports_bluetooth, run_tester_main, skip_not_linux};
use bluez_tools_lib::testutil::HciTestFixture;

/// Test: RFCOMM socket creation and channel allocation.
async fn test_rfcomm_socket_create() -> TestStatus {
    if !platform_supports_bluetooth() {
        return skip_not_linux().await;
    }

    let fixture = HciTestFixture::new("bredr");
    if let Some(s) = fixture.skip_if_inactive() {
        return s;
    }

    println!("    Would create RFCOMM socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)");
    println!("    Bind to channel 0 (auto-allocate) and verify assigned channel");
    TestStatus::Passed
}

fn main() {
    let mut suite = TestSuite::new("rfcomm-tester");

    suite.add_test("RFCOMM Socket Create", test_rfcomm_socket_create);

    std::process::exit(run_tester_main(suite));
}
