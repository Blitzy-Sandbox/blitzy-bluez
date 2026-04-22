// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2011-2014  Intel Corporation
// Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>

//! Hardware database lookup module for btmon.
//!
//! Provides optional systemd-hwdb lookups for vendor/model/company strings
//! associated with USB/PCI modalias identifiers and Bluetooth OUI prefixes.
//!
//! When the `udev` Cargo feature is enabled, this module queries the
//! systemd hardware database via command-line tools (`systemd-hwdb` or
//! `udevadm`). When the feature is disabled, stub implementations
//! return `None`, matching the original C implementation's `HAVE_UDEV`
//! conditional compilation.

// ─── Feature-gated implementation (udev enabled) ────────────────────────────

/// Queries the systemd hardware database for vendor and model information
/// associated with the given modalias string.
///
/// The modalias identifies a specific hardware device (e.g. a USB or PCI
/// device identifier). The hardware database is queried for the human-readable
/// vendor and model names.
///
/// # Returns
///
/// * `Some((vendor, model))` — The hwdb query succeeded. `vendor` and `model`
///   are individually `None` if the corresponding property was not found in the
///   database.
/// * `None` — The hwdb query failed entirely (e.g. tools not installed or
///   database not accessible).
#[cfg(feature = "udev")]
pub fn hwdb_get_vendor_model(modalias: &str) -> Option<(Option<String>, Option<String>)> {
    let output = run_hwdb_query(modalias)?;

    let vendor = extract_property(&output, "ID_VENDOR_FROM_DATABASE");
    let model = extract_property(&output, "ID_MODEL_FROM_DATABASE");

    Some((vendor, model))
}

/// Queries the systemd hardware database for the company name associated
/// with the OUI (Organizationally Unique Identifier) of a Bluetooth device
/// address.
///
/// The `bdaddr` parameter is a 6-byte Bluetooth address in BlueZ
/// little-endian byte order: byte `[0]` is the least significant octet
/// and byte `[5]` is the most significant. The OUI is the vendor-assigned
/// portion formed from bytes `[5]`, `[4]`, `[3]`.
///
/// The hwdb is queried with a modalias of the form `"OUI:XXYYZZ"` where
/// XX, YY, ZZ are uppercase hex representations of `bdaddr[5]`, `bdaddr[4]`,
/// `bdaddr[3]` respectively.
///
/// # Returns
///
/// * `Some(company)` — The OUI was found in the database.
/// * `None` — The lower three octets (`bdaddr[0..3]`) are all zero (guard
///   check matching original C behavior), the query failed, or the OUI was
///   not found.
#[cfg(feature = "udev")]
pub fn hwdb_get_company(bdaddr: &[u8; 6]) -> Option<String> {
    // Guard: skip lookup if lower octets (device-unique portion) are all zero.
    // This matches the C check: `if (!bdaddr[2] && !bdaddr[1] && !bdaddr[0])`
    if bdaddr[0] == 0 && bdaddr[1] == 0 && bdaddr[2] == 0 {
        return None;
    }

    // Format OUI modalias from the upper three octets in big-endian order.
    // C equivalent: sprintf(modalias, "OUI:%2.2X%2.2X%2.2X",
    //                       bdaddr[5], bdaddr[4], bdaddr[3]);
    let modalias = format!("OUI:{:02X}{:02X}{:02X}", bdaddr[5], bdaddr[4], bdaddr[3]);

    let output = run_hwdb_query(&modalias)?;
    extract_property(&output, "ID_OUI_FROM_DATABASE")
}

/// Executes a hardware database query via command-line tools.
///
/// Tries `systemd-hwdb query <modalias>` first, then falls back to
/// `udevadm hwdb --test=<modalias>`. This approach avoids any `unsafe`
/// FFI calls to libudev while providing identical query results.
///
/// Returns the raw stdout output as a `String`, or `None` if neither
/// tool is available or the query fails.
#[cfg(feature = "udev")]
fn run_hwdb_query(modalias: &str) -> Option<String> {
    use std::process::Command;

    // Attempt systemd-hwdb first (available on systemd >= 219).
    let output = Command::new("systemd-hwdb")
        .args(["query", modalias])
        .output()
        .or_else(|_| {
            // Fall back to udevadm hwdb --test=<modalias>.
            Command::new("udevadm").arg("hwdb").arg(format!("--test={modalias}")).output()
        })
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Extracts a property value from hwdb query output.
///
/// The output is expected to contain lines in `KEY=VALUE` format,
/// one property per line. Returns the value for the first line whose
/// key matches exactly, or `None` if no match is found.
#[cfg(feature = "udev")]
fn extract_property(output: &str, key: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k == key {
                return Some(v.to_owned());
            }
        }
    }
    None
}

// ─── Stub implementation (udev disabled) ────────────────────────────────────

/// Stub: always returns `None` when the `udev` feature is disabled.
///
/// This matches the C implementation's `#else` branch when `HAVE_UDEV`
/// is not defined.
#[cfg(not(feature = "udev"))]
pub fn hwdb_get_vendor_model(_modalias: &str) -> Option<(Option<String>, Option<String>)> {
    None
}

/// Stub: always returns `None` when the `udev` feature is disabled.
///
/// This matches the C implementation's `#else` branch when `HAVE_UDEV`
/// is not defined.
#[cfg(not(feature = "udev"))]
pub fn hwdb_get_company(_bdaddr: &[u8; 6]) -> Option<String> {
    None
}

// ─── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_model_stub_returns_none() {
        // Without the udev feature (default), should always return None.
        #[cfg(not(feature = "udev"))]
        {
            assert!(hwdb_get_vendor_model("usb:v1D6Bp0001").is_none());
            assert!(hwdb_get_vendor_model("").is_none());
            assert!(hwdb_get_vendor_model("pci:v00008086d00009A49").is_none());
        }
    }

    #[test]
    fn test_company_stub_returns_none() {
        // Without the udev feature (default), should always return None.
        #[cfg(not(feature = "udev"))]
        {
            let addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
            assert!(hwdb_get_company(&addr).is_none());
        }
    }

    #[test]
    fn test_company_zero_address_guard() {
        // When the lower 3 bytes are all zero, both feature-gated and stub
        // paths should return None.
        let zero_lower = [0x00, 0x00, 0x00, 0x04, 0x05, 0x06];
        assert!(hwdb_get_company(&zero_lower).is_none());
    }

    #[test]
    fn test_company_partial_zero_not_guarded() {
        // Only guard when ALL three lower bytes are zero.
        // When only some are zero, the function should not short-circuit.
        // (It will still return None without udev, but via the stub path.)
        let partial_zero_1 = [0x01, 0x00, 0x00, 0x04, 0x05, 0x06];
        let partial_zero_2 = [0x00, 0x01, 0x00, 0x04, 0x05, 0x06];
        let partial_zero_3 = [0x00, 0x00, 0x01, 0x04, 0x05, 0x06];

        // These should NOT trigger the guard — the result depends on
        // whether the udev feature is enabled and the database is available.
        // Without udev, stubs return None anyway, so this test just
        // verifies no panic occurs.
        let _ = hwdb_get_company(&partial_zero_1);
        let _ = hwdb_get_company(&partial_zero_2);
        let _ = hwdb_get_company(&partial_zero_3);
    }

    #[test]
    fn test_company_all_zeros_guard() {
        // Completely zero address should be guarded.
        let all_zero = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(hwdb_get_company(&all_zero).is_none());
    }

    #[cfg(feature = "udev")]
    #[test]
    fn test_extract_property_finds_key() {
        let output = "ID_VENDOR_FROM_DATABASE=Intel Corp.\n\
                       ID_MODEL_FROM_DATABASE=Wireless 8265\n";
        assert_eq!(
            extract_property(output, "ID_VENDOR_FROM_DATABASE"),
            Some("Intel Corp.".to_owned())
        );
        assert_eq!(
            extract_property(output, "ID_MODEL_FROM_DATABASE"),
            Some("Wireless 8265".to_owned())
        );
    }

    #[cfg(feature = "udev")]
    #[test]
    fn test_extract_property_not_found() {
        let output = "ID_VENDOR_FROM_DATABASE=Intel Corp.\n";
        assert_eq!(extract_property(output, "ID_NONEXISTENT"), None);
    }

    #[cfg(feature = "udev")]
    #[test]
    fn test_extract_property_empty_output() {
        assert_eq!(extract_property("", "ID_OUI_FROM_DATABASE"), None);
    }

    #[cfg(feature = "udev")]
    #[test]
    fn test_extract_property_malformed_lines() {
        let output = "no_equals_sign\n\
                       =no_key\n\
                       ID_OUI_FROM_DATABASE=Good Company\n\
                       another_bad_line";
        assert_eq!(
            extract_property(output, "ID_OUI_FROM_DATABASE"),
            Some("Good Company".to_owned())
        );
    }

    #[cfg(feature = "udev")]
    #[test]
    fn test_extract_property_value_with_equals() {
        // Values may legitimately contain '=' characters.
        let output = "ID_VENDOR_FROM_DATABASE=Foo = Bar Corp.\n";
        assert_eq!(
            extract_property(output, "ID_VENDOR_FROM_DATABASE"),
            Some("Foo = Bar Corp.".to_owned())
        );
    }

    #[cfg(feature = "udev")]
    #[test]
    fn test_extract_property_whitespace_handling() {
        // Lines may have leading/trailing whitespace depending on tool.
        // The entire line is trimmed, so trailing whitespace on the value
        // is also removed.
        let output = "  ID_VENDOR_FROM_DATABASE=Trimmed Corp.  \n";
        assert_eq!(
            extract_property(output, "ID_VENDOR_FROM_DATABASE"),
            Some("Trimmed Corp.".to_owned())
        );

        // Clean lines (no extra whitespace) work normally.
        let clean = "ID_VENDOR_FROM_DATABASE=Clean Corp.\n";
        assert_eq!(
            extract_property(clean, "ID_VENDOR_FROM_DATABASE"),
            Some("Clean Corp.".to_owned())
        );
    }
}
