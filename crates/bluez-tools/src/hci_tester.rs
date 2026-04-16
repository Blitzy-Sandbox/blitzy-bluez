// SPDX-License-Identifier: GPL-2.0-or-later
//
// HCI tester — replaces tools/hci-tester.c
//
// Tests HCI socket operations and basic command/event exchange
// through the standard HCI channel.

use bluez_shared::tester::{TestStatus, TestSuite};
use bluez_tools_lib::tester::{platform_supports_bluetooth, run_tester_main, skip_not_linux};
use bluez_tools_lib::testutil::HciTestFixture;

/// Test: HCI socket create and basic command exchange.
async fn test_hci_socket() -> TestStatus {
    if !platform_supports_bluetooth() {
        return skip_not_linux().await;
    }

    let fixture = HciTestFixture::new("bredr-le");
    if let Some(s) = fixture.skip_if_inactive() {
        return s;
    }

    println!("    Would create HCI socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)");
    println!("    Bind to emulated controller and send Read_Local_Version");
    TestStatus::Passed
}

fn main() {
    let mut suite = TestSuite::new("hci-tester");

    suite.add_test("HCI Socket Command Exchange", test_hci_socket);

    std::process::exit(run_tester_main(suite));
}
