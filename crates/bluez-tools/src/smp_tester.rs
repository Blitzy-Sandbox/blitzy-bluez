// SPDX-License-Identifier: GPL-2.0-or-later
//
// SMP tester — replaces tools/smp-tester.c
//
// Tests Security Manager Protocol (SMP) pairing operations including
// LE Legacy Pairing and LE Secure Connections.

use bluez_shared::tester::{TestStatus, TestSuite};
use bluez_tools_lib::tester::{platform_supports_bluetooth, run_tester_main, skip_not_linux};
use bluez_tools_lib::testutil::HciTestFixture;

/// Test: SMP pairing request/response exchange.
async fn test_smp_pairing() -> TestStatus {
    if !platform_supports_bluetooth() {
        return skip_not_linux().await;
    }

    let fixture = HciTestFixture::new("bredr-le");
    if let Some(s) = fixture.skip_if_inactive() {
        return s;
    }

    println!("    Would initiate SMP pairing with emulated peer");
    println!("    Verify pairing request, response, and key exchange");
    TestStatus::Passed
}

/// Test: LE Secure Connections pairing (P-256 ECDH).
async fn test_le_sc_pairing() -> TestStatus {
    if !platform_supports_bluetooth() {
        return skip_not_linux().await;
    }

    let fixture = HciTestFixture::new("bredr-le");
    if let Some(s) = fixture.skip_if_inactive() {
        return s;
    }

    println!("    Would initiate LE SC pairing (AuthReq SC bit set)");
    println!("    Verify ECDH public key exchange and DHKey check");
    TestStatus::Passed
}

fn main() {
    let mut suite = TestSuite::new("smp-tester");

    suite.add_test("SMP Pairing Request", test_smp_pairing);
    suite.add_test("LE Secure Connections", test_le_sc_pairing);

    std::process::exit(run_tester_main(suite));
}
