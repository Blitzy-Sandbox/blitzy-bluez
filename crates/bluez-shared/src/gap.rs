// SPDX-License-Identifier: GPL-2.0-or-later
//
// GAP (Generic Access Profile) helpers replacing src/shared/gap.c
//
// Provides GAP-related constants and appearance category definitions.

/// GAP appearance categories.
/// See Bluetooth Assigned Numbers, Section 2.6.
pub const GAP_APPEARANCE_UNKNOWN: u16 = 0x0000;
pub const GAP_APPEARANCE_GENERIC_PHONE: u16 = 0x0040;
pub const GAP_APPEARANCE_GENERIC_COMPUTER: u16 = 0x0080;
pub const GAP_APPEARANCE_GENERIC_WATCH: u16 = 0x00C0;
pub const GAP_APPEARANCE_GENERIC_CLOCK: u16 = 0x0100;
pub const GAP_APPEARANCE_GENERIC_DISPLAY: u16 = 0x0140;
pub const GAP_APPEARANCE_GENERIC_REMOTE_CONTROL: u16 = 0x0180;
pub const GAP_APPEARANCE_GENERIC_EYE_GLASSES: u16 = 0x01C0;
pub const GAP_APPEARANCE_GENERIC_TAG: u16 = 0x0200;
pub const GAP_APPEARANCE_GENERIC_KEYRING: u16 = 0x0240;
pub const GAP_APPEARANCE_GENERIC_MEDIA_PLAYER: u16 = 0x0280;
pub const GAP_APPEARANCE_GENERIC_BARCODE_SCANNER: u16 = 0x02C0;
pub const GAP_APPEARANCE_GENERIC_THERMOMETER: u16 = 0x0300;
pub const GAP_APPEARANCE_GENERIC_HEART_RATE: u16 = 0x0340;
pub const GAP_APPEARANCE_GENERIC_BLOOD_PRESSURE: u16 = 0x0380;
pub const GAP_APPEARANCE_GENERIC_HID: u16 = 0x03C0;
pub const GAP_APPEARANCE_HID_KEYBOARD: u16 = 0x03C1;
pub const GAP_APPEARANCE_HID_MOUSE: u16 = 0x03C2;
pub const GAP_APPEARANCE_HID_JOYSTICK: u16 = 0x03C3;
pub const GAP_APPEARANCE_HID_GAMEPAD: u16 = 0x03C4;
pub const GAP_APPEARANCE_HID_DIGITIZER_TABLET: u16 = 0x03C5;
pub const GAP_APPEARANCE_HID_CARD_READER: u16 = 0x03C6;
pub const GAP_APPEARANCE_HID_DIGITAL_PEN: u16 = 0x03C7;
pub const GAP_APPEARANCE_HID_BARCODE_SCANNER: u16 = 0x03C8;
pub const GAP_APPEARANCE_GENERIC_GLUCOSE: u16 = 0x0400;
pub const GAP_APPEARANCE_GENERIC_RUNNING: u16 = 0x0440;
pub const GAP_APPEARANCE_GENERIC_CYCLING: u16 = 0x0480;
pub const GAP_APPEARANCE_GENERIC_PULSE_OXIMETER: u16 = 0x0C40;
pub const GAP_APPEARANCE_GENERIC_WEIGHT_SCALE: u16 = 0x0C80;
pub const GAP_APPEARANCE_GENERIC_OUTDOOR_SPORTS: u16 = 0x1440;
pub const GAP_APPEARANCE_GENERIC_AUDIO_SOURCE: u16 = 0x0880;
pub const GAP_APPEARANCE_GENERIC_AUDIO_SINK: u16 = 0x08C0;
pub const GAP_APPEARANCE_GENERIC_HEARING_AID: u16 = 0x0A40;

/// Get a human-readable string for a GAP appearance value.
pub fn appearance_to_str(appearance: u16) -> &'static str {
    // Extract category (upper 10 bits)
    match appearance & 0xFFC0 {
        0x0000 => "Unknown",
        0x0040 => "Phone",
        0x0080 => "Computer",
        0x00C0 => "Watch",
        0x0100 => "Clock",
        0x0140 => "Display",
        0x0180 => "Remote Control",
        0x01C0 => "Eye-glasses",
        0x0200 => "Tag",
        0x0240 => "Keyring",
        0x0280 => "Media Player",
        0x02C0 => "Barcode Scanner",
        0x0300 => "Thermometer",
        0x0340 => "Heart Rate",
        0x0380 => "Blood Pressure",
        0x03C0 => "Human Interface Device",
        0x0400 => "Glucose Meter",
        0x0440 => "Running Walking Sensor",
        0x0480 => "Cycling",
        0x0880 => "Audio Source",
        0x08C0 => "Audio Sink",
        0x0A40 => "Hearing Aid",
        0x0C40 => "Pulse Oximeter",
        0x0C80 => "Weight Scale",
        0x1440 => "Outdoor Sports Activity",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_appearance_values() {
        assert_eq!(GAP_APPEARANCE_UNKNOWN, 0);
        assert_eq!(GAP_APPEARANCE_HID_KEYBOARD, 0x03C1);
    }

    #[test]
    fn test_appearance_to_str() {
        assert_eq!(appearance_to_str(GAP_APPEARANCE_GENERIC_PHONE), "Phone");
        assert_eq!(
            appearance_to_str(GAP_APPEARANCE_HID_KEYBOARD),
            "Human Interface Device"
        );
        assert_eq!(appearance_to_str(0xFFFF), "Unknown");
    }
}
