// SPDX-License-Identifier: GPL-2.0-or-later
//
// Common test utilities shared across tester binaries.
//
// Provides fixture helpers, HCI emulator setup/teardown wrappers, and
// common assertions used by Bluetooth protocol tests.

use bluez_shared::tester::TestStatus;

/// Fixture for a test that requires an HCI emulator.
///
/// On non-Linux platforms the emulator is not available, so the fixture
/// returns `None` and the test should be skipped.
pub struct HciTestFixture {
    /// Emulator type requested (stored for diagnostics).
    pub emu_type: &'static str,
    /// Whether the fixture was actually set up (Linux-only).
    pub active: bool,
}

impl HciTestFixture {
    /// Attempt to create an HCI test fixture.
    ///
    /// On non-Linux platforms this always returns an inactive fixture.
    pub fn new(emu_type: &'static str) -> Self {
        let active = cfg!(target_os = "linux") && std::path::Path::new("/dev/vhci").exists();

        if !active {
            println!(
                "    HCI emulator not available (emu_type={emu_type}), will skip"
            );
        }

        Self { emu_type, active }
    }

    /// Convenience: return Skipped status when the fixture is inactive.
    pub fn skip_if_inactive(&self) -> Option<TestStatus> {
        if self.active {
            None
        } else {
            Some(TestStatus::Skipped)
        }
    }
}

impl Drop for HciTestFixture {
    fn drop(&mut self) {
        if self.active {
            println!("    Tearing down HCI fixture (emu_type={})", self.emu_type);
        }
    }
}

/// Assert that a management response status is success (0x00).
pub fn assert_mgmt_success(status: u8) -> TestStatus {
    if status == 0x00 {
        TestStatus::Passed
    } else {
        println!("    MGMT response status 0x{status:02x}, expected 0x00");
        TestStatus::Failed
    }
}

/// Assert a value matches expected, returning Passed/Failed.
pub fn assert_eq_or_fail<T: PartialEq + std::fmt::Debug>(actual: &T, expected: &T) -> TestStatus {
    if actual == expected {
        TestStatus::Passed
    } else {
        println!("    Expected {expected:?}, got {actual:?}");
        TestStatus::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_inactive_on_non_linux() {
        let fixture = HciTestFixture::new("bredr-le");
        // On macOS CI the fixture should not be active.
        if !cfg!(target_os = "linux") {
            assert!(!fixture.active);
            assert_eq!(fixture.skip_if_inactive(), Some(TestStatus::Skipped));
        }
    }

    #[test]
    fn assert_mgmt_success_works() {
        assert_eq!(assert_mgmt_success(0x00), TestStatus::Passed);
        assert_eq!(assert_mgmt_success(0x03), TestStatus::Failed);
    }
}
