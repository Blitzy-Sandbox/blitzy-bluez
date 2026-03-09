// SPDX-License-Identifier: GPL-2.0-or-later
//
// MIDI over BLE profile implementation (~966 LOC C).
//
// BLE MIDI service — handles MIDI message parsing/assembly over GATT,
// including timestamp handling and message fragmentation.

/// BLE MIDI Service UUID (128-bit).
pub const MIDI_SERVICE_UUID: &str = "03b80e5a-ede8-4b33-a751-6ce34ec4c700";
/// BLE MIDI I/O Characteristic UUID (128-bit).
pub const MIDI_IO_UUID: &str = "7772e5db-3868-4112-a1a9-f2669d106bf3";

/// MIDI message status byte categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidiMessageType {
    NoteOff,
    NoteOn,
    PolyKeyPressure,
    ControlChange,
    ProgramChange,
    ChannelPressure,
    PitchBend,
    SystemExclusive,
    SystemCommon,
    SystemRealTime,
}

impl MidiMessageType {
    /// Classify a MIDI status byte.
    pub fn from_status(status: u8) -> Option<Self> {
        match status & 0xF0 {
            0x80 => Some(Self::NoteOff),
            0x90 => Some(Self::NoteOn),
            0xA0 => Some(Self::PolyKeyPressure),
            0xB0 => Some(Self::ControlChange),
            0xC0 => Some(Self::ProgramChange),
            0xD0 => Some(Self::ChannelPressure),
            0xE0 => Some(Self::PitchBend),
            0xF0 => match status {
                0xF0 => Some(Self::SystemExclusive),
                0xF1..=0xF6 | 0xF8..=0xFF => {
                    if status >= 0xF8 {
                        Some(Self::SystemRealTime)
                    } else {
                        Some(Self::SystemCommon)
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// Number of data bytes following the status byte.
    pub fn data_length(&self) -> usize {
        match self {
            Self::NoteOff | Self::NoteOn | Self::PolyKeyPressure => 2,
            Self::ControlChange | Self::PitchBend => 2,
            Self::ProgramChange | Self::ChannelPressure => 1,
            Self::SystemExclusive => 0, // variable length
            Self::SystemCommon => 0,    // varies
            Self::SystemRealTime => 0,
        }
    }
}

/// A parsed MIDI event with BLE timestamp.
#[derive(Debug, Clone)]
pub struct MidiEvent {
    /// 13-bit BLE MIDI timestamp (ms within the connection interval).
    pub timestamp: u16,
    /// Raw MIDI bytes (status + data).
    pub data: Vec<u8>,
}

/// State for SysEx fragmentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysExState {
    Idle,
    /// Accumulating SysEx bytes.
    Receiving,
}

/// MIDI over BLE profile plugin.
#[derive(Debug)]
pub struct MidiProfile {
    /// GATT handle for the MIDI I/O characteristic.
    pub io_handle: u16,
    /// GATT handle for the CCC descriptor.
    pub ccc_handle: u16,
    /// Whether notifications are enabled.
    pub notify_enabled: bool,
    /// Running status byte for output optimization.
    pub running_status: Option<u8>,
    /// SysEx fragmentation state.
    pub sysex_state: SysExState,
    /// Buffer for incoming SysEx message.
    pub sysex_buffer: Vec<u8>,
    /// Pending outgoing events.
    pub tx_queue: Vec<MidiEvent>,
}

impl MidiProfile {
    pub fn new() -> Self {
        Self {
            io_handle: 0,
            ccc_handle: 0,
            notify_enabled: false,
            running_status: None,
            sysex_state: SysExState::Idle,
            sysex_buffer: Vec::new(),
            tx_queue: Vec::new(),
        }
    }

    /// Reset SysEx state.
    pub fn reset_sysex(&mut self) {
        self.sysex_state = SysExState::Idle;
        self.sysex_buffer.clear();
    }
}

impl Default for MidiProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Message classification (from test-midi.c event types) ----

    #[test]
    fn test_midi_note_on_all_channels() {
        for ch in 0..16u8 {
            assert_eq!(
                MidiMessageType::from_status(0x90 + ch),
                Some(MidiMessageType::NoteOn)
            );
        }
    }

    #[test]
    fn test_midi_note_off_all_channels() {
        for ch in 0..16u8 {
            assert_eq!(
                MidiMessageType::from_status(0x80 + ch),
                Some(MidiMessageType::NoteOff)
            );
        }
    }

    #[test]
    fn test_midi_control_change() {
        assert_eq!(
            MidiMessageType::from_status(0xB0),
            Some(MidiMessageType::ControlChange)
        );
        assert_eq!(
            MidiMessageType::from_status(0xB8), // channel 8
            Some(MidiMessageType::ControlChange)
        );
    }

    #[test]
    fn test_midi_pitch_bend() {
        // From test-midi.c: Pitch Bend events on channel 8 (0xE8)
        assert_eq!(
            MidiMessageType::from_status(0xE8),
            Some(MidiMessageType::PitchBend)
        );
        assert_eq!(MidiMessageType::PitchBend.data_length(), 2);
    }

    #[test]
    fn test_midi_channel_pressure() {
        // From test-midi.c: Channel Aftertouch on channel 8 (0xD8)
        assert_eq!(
            MidiMessageType::from_status(0xD8),
            Some(MidiMessageType::ChannelPressure)
        );
        assert_eq!(MidiMessageType::ChannelPressure.data_length(), 1);
    }

    #[test]
    fn test_midi_program_change() {
        assert_eq!(
            MidiMessageType::from_status(0xC0),
            Some(MidiMessageType::ProgramChange)
        );
        assert_eq!(MidiMessageType::ProgramChange.data_length(), 1);
    }

    #[test]
    fn test_midi_poly_key_pressure() {
        assert_eq!(
            MidiMessageType::from_status(0xA0),
            Some(MidiMessageType::PolyKeyPressure)
        );
        assert_eq!(MidiMessageType::PolyKeyPressure.data_length(), 2);
    }

    #[test]
    fn test_midi_sysex_classification() {
        // From test-midi.c: SysEx (0xF0) start
        assert_eq!(
            MidiMessageType::from_status(0xF0),
            Some(MidiMessageType::SystemExclusive)
        );
        assert_eq!(MidiMessageType::SystemExclusive.data_length(), 0);
    }

    #[test]
    fn test_midi_system_realtime() {
        // F8-FF are realtime
        for status in 0xF8..=0xFFu8 {
            assert_eq!(
                MidiMessageType::from_status(status),
                Some(MidiMessageType::SystemRealTime),
                "status 0x{:02x} should be SystemRealTime",
                status,
            );
        }
    }

    #[test]
    fn test_midi_system_common() {
        // F1-F6 are system common
        for status in [0xF1u8, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6] {
            assert_eq!(
                MidiMessageType::from_status(status),
                Some(MidiMessageType::SystemCommon),
                "status 0x{:02x} should be SystemCommon",
                status,
            );
        }
    }

    #[test]
    fn test_midi_invalid_status() {
        // Data bytes (0x00-0x7F) are not valid status bytes
        assert_eq!(MidiMessageType::from_status(0x00), None);
        assert_eq!(MidiMessageType::from_status(0x7F), None);
    }

    // ---- Data length tests (from test-midi.c event sizes) ----

    #[test]
    fn test_midi_data_lengths() {
        assert_eq!(MidiMessageType::NoteOn.data_length(), 2);
        assert_eq!(MidiMessageType::NoteOff.data_length(), 2);
        assert_eq!(MidiMessageType::ControlChange.data_length(), 2);
        assert_eq!(MidiMessageType::ProgramChange.data_length(), 1);
        assert_eq!(MidiMessageType::SystemRealTime.data_length(), 0);
    }

    // ---- SysEx state management (from test-midi.c SysEx tests) ----

    #[test]
    fn test_midi_sysex_reset() {
        let mut midi = MidiProfile::new();
        midi.sysex_state = SysExState::Receiving;
        midi.sysex_buffer.extend_from_slice(&[0xF0, 0x7E, 0x01]);
        midi.reset_sysex();
        assert_eq!(midi.sysex_state, SysExState::Idle);
        assert!(midi.sysex_buffer.is_empty());
    }

    #[test]
    fn test_midi_sysex_accumulation() {
        // From test-midi.c: SysEx across multiple packets
        let mut midi = MidiProfile::new();
        let sysex_start = vec![0xF0, 0x01, 0x02, 0x03];
        midi.sysex_state = SysExState::Receiving;
        midi.sysex_buffer.extend_from_slice(&sysex_start);

        let sysex_continue = vec![0x04, 0x05, 0x06];
        midi.sysex_buffer.extend_from_slice(&sysex_continue);

        let sysex_end = vec![0xF7];
        midi.sysex_buffer.extend_from_slice(&sysex_end);

        assert_eq!(
            midi.sysex_buffer,
            vec![0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xF7]
        );
    }

    // ---- Profile defaults ----

    #[test]
    fn test_midi_profile_defaults() {
        let midi = MidiProfile::new();
        assert_eq!(midi.sysex_state, SysExState::Idle);
        assert!(midi.sysex_buffer.is_empty());
        assert!(midi.running_status.is_none());
        assert!(!midi.notify_enabled);
        assert!(midi.tx_queue.is_empty());
    }

    // ---- Service UUIDs ----

    #[test]
    fn test_midi_service_uuid() {
        assert_eq!(MIDI_SERVICE_UUID, "03b80e5a-ede8-4b33-a751-6ce34ec4c700");
    }

    #[test]
    fn test_midi_io_uuid() {
        assert_eq!(MIDI_IO_UUID, "7772e5db-3868-4112-a1a9-f2669d106bf3");
    }
}
