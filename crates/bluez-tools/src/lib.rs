// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ Tools — multi-binary crate containing Bluetooth test tools.
//
// Replaces tools/*-tester.c and related utilities from the C codebase.
// Each binary creates a TestSuite, registers test cases, and runs them
// through the shared tester framework (bluez_shared::tester).

pub mod tester;
pub mod testutil;
