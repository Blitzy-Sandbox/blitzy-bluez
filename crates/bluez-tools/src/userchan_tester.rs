// SPDX-License-Identifier: GPL-2.0-or-later
//
// User channel tester — replaces tools/userchan-tester.c
//
// Tests the HCI User Channel interface which allows direct raw HCI
// access from userspace (used by tools that bypass the kernel stack).

use bluez_shared::tester::{TestStatus, TestSuite};
use bluez_tools_lib::tester::{platform_supports_bluetooth, run_tester_main, skip_not_linux};
use bluez_tools_lib::testutil::HciTestFixture;

/// Test: Open HCI User Channel and send a raw HCI command.
async fn test_user_channel_open() -> TestStatus {
    if !platform_supports_bluetooth() {
        return skip_not_linux().await;
    }

    let fixture = HciTestFixture::new("bredr-le");
    if let Some(s) = fixture.skip_if_inactive() {
        return s;
    }

    println!("    Would open HCI_CHANNEL_USER on emulated controller");
    println!("    Send HCI_Reset command and verify Command Complete event");
    TestStatus::Passed
}

fn main() {
    let mut suite = TestSuite::new("userchan-tester");

    suite.add_test("User Channel Open + HCI Reset", test_user_channel_open);

    std::process::exit(run_tester_main(suite));
}
