// SPDX-License-Identifier: GPL-2.0-or-later
//
// Basic Audio Profile (BAP) definitions replacing src/shared/bap.c
//
// BAP manages Audio Stream Endpoints (ASEs) for LE Audio. This module
// provides the ASE state machine, codec configuration types, and QoS
// parameters. The full GATT-based client/server integration is deferred
// to the bluetoothd phase.

// ---- BAP UUIDs ----

pub const BAP_UUID: u16 = 0x184E;
pub const PACS_UUID: u16 = 0x1850;
pub const ASCS_UUID: u16 = 0x184E;
pub const PAC_SINK_UUID: u16 = 0x2BC9;
pub const PAC_SOURCE_UUID: u16 = 0x2BCB;
pub const PAC_SINK_LOC_UUID: u16 = 0x2BCA;
pub const PAC_SOURCE_LOC_UUID: u16 = 0x2BCC;
pub const PAC_CONTEXT_UUID: u16 = 0x2BCE;
pub const PAC_SUPPORTED_CONTEXT_UUID: u16 = 0x2BCF;
pub const ASE_SINK_UUID: u16 = 0x2BC4;
pub const ASE_SOURCE_UUID: u16 = 0x2BC5;
pub const ASE_CP_UUID: u16 = 0x2BC6;

// ---- ASE State Machine ----

/// ASE (Audio Stream Endpoint) states per BAP spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AseState {
    Idle = 0x00,
    CodecConfigured = 0x01,
    QosConfigured = 0x02,
    Enabling = 0x03,
    Streaming = 0x04,
    Disabling = 0x05,
    Releasing = 0x06,
}

impl AseState {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::Idle),
            0x01 => Some(Self::CodecConfigured),
            0x02 => Some(Self::QosConfigured),
            0x03 => Some(Self::Enabling),
            0x04 => Some(Self::Streaming),
            0x05 => Some(Self::Disabling),
            0x06 => Some(Self::Releasing),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::CodecConfigured => "codec-configured",
            Self::QosConfigured => "qos-configured",
            Self::Enabling => "enabling",
            Self::Streaming => "streaming",
            Self::Disabling => "disabling",
            Self::Releasing => "releasing",
        }
    }
}

// ---- ASE Control Point Opcodes ----

pub const ASE_CP_CONFIG_CODEC: u8 = 0x01;
pub const ASE_CP_CONFIG_QOS: u8 = 0x02;
pub const ASE_CP_ENABLE: u8 = 0x03;
pub const ASE_CP_RECEIVER_START_READY: u8 = 0x04;
pub const ASE_CP_DISABLE: u8 = 0x05;
pub const ASE_CP_RECEIVER_STOP_READY: u8 = 0x06;
pub const ASE_CP_UPDATE_METADATA: u8 = 0x07;
pub const ASE_CP_RELEASE: u8 = 0x08;

// ---- ASE Response Codes ----

pub const ASE_RSP_SUCCESS: u8 = 0x00;
pub const ASE_RSP_UNSUPPORTED_OPCODE: u8 = 0x01;
pub const ASE_RSP_INVALID_LENGTH: u8 = 0x02;
pub const ASE_RSP_INVALID_ASE_ID: u8 = 0x03;
pub const ASE_RSP_INVALID_STATE: u8 = 0x04;
pub const ASE_RSP_INVALID_DIRECTION: u8 = 0x05;
pub const ASE_RSP_UNSUPPORTED_AUDIO_CAP: u8 = 0x06;
pub const ASE_RSP_UNSUPPORTED_CONF: u8 = 0x07;
pub const ASE_RSP_REJECTED_CONF: u8 = 0x08;
pub const ASE_RSP_INVALID_CONF: u8 = 0x09;
pub const ASE_RSP_UNSUPPORTED_METADATA: u8 = 0x0A;
pub const ASE_RSP_REJECTED_METADATA: u8 = 0x0B;
pub const ASE_RSP_INVALID_METADATA: u8 = 0x0C;
pub const ASE_RSP_INSUFFICIENT_RESOURCES: u8 = 0x0D;
pub const ASE_RSP_UNSPECIFIED_ERROR: u8 = 0x0E;

// ---- Codec ID ----

/// Codec ID (5 bytes per BAP spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecId {
    /// Coding format (0x06 = LC3).
    pub format: u8,
    /// Company ID (0x0000 for standard codecs).
    pub company: u16,
    /// Vendor-specific codec ID.
    pub vendor: u16,
}

impl CodecId {
    /// LC3 codec (standard).
    pub const LC3: Self = Self {
        format: 0x06,
        company: 0x0000,
        vendor: 0x0000,
    };

    /// Parse from 5 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 {
            return None;
        }
        Some(Self {
            format: bytes[0],
            company: u16::from_le_bytes([bytes[1], bytes[2]]),
            vendor: u16::from_le_bytes([bytes[3], bytes[4]]),
        })
    }

    /// Serialize to 5 bytes.
    pub fn to_bytes(&self) -> [u8; 5] {
        let mut out = [0u8; 5];
        out[0] = self.format;
        out[1..3].copy_from_slice(&self.company.to_le_bytes());
        out[3..5].copy_from_slice(&self.vendor.to_le_bytes());
        out
    }
}

// ---- QoS Configuration ----

/// QoS configuration parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosConfig {
    /// CIG ID.
    pub cig_id: u8,
    /// CIS ID.
    pub cis_id: u8,
    /// SDU interval in microseconds.
    pub sdu_interval: u32,
    /// Framing (0=unframed, 1=framed).
    pub framing: u8,
    /// PHY (1=1M, 2=2M, 4=Coded).
    pub phy: u8,
    /// Maximum SDU size.
    pub max_sdu: u16,
    /// Retransmission number.
    pub retransmission: u8,
    /// Transport latency in milliseconds.
    pub latency: u16,
    /// Presentation delay in microseconds.
    pub presentation_delay: u32,
}

// ---- Audio Locations ----

pub const BAP_LOCATION_FRONT_LEFT: u32 = 0x00000001;
pub const BAP_LOCATION_FRONT_RIGHT: u32 = 0x00000002;
pub const BAP_LOCATION_FRONT_CENTER: u32 = 0x00000004;
pub const BAP_LOCATION_LOW_FREQUENCY: u32 = 0x00000008;
pub const BAP_LOCATION_BACK_LEFT: u32 = 0x00000010;
pub const BAP_LOCATION_BACK_RIGHT: u32 = 0x00000020;

// ---- Context Types ----

pub const BAP_CONTEXT_UNSPECIFIED: u16 = 0x0001;
pub const BAP_CONTEXT_CONVERSATIONAL: u16 = 0x0002;
pub const BAP_CONTEXT_MEDIA: u16 = 0x0004;
pub const BAP_CONTEXT_GAME: u16 = 0x0008;
pub const BAP_CONTEXT_INSTRUCTIONAL: u16 = 0x0010;
pub const BAP_CONTEXT_VOICE_ASSISTANTS: u16 = 0x0020;
pub const BAP_CONTEXT_LIVE: u16 = 0x0040;
pub const BAP_CONTEXT_SOUND_EFFECTS: u16 = 0x0080;
pub const BAP_CONTEXT_NOTIFICATIONS: u16 = 0x0100;
pub const BAP_CONTEXT_RINGTONE: u16 = 0x0200;
pub const BAP_CONTEXT_ALERTS: u16 = 0x0400;
pub const BAP_CONTEXT_EMERGENCY: u16 = 0x0800;

// ---- LC3 Codec-Specific Configuration LTV Types ----

pub const LC3_CONFIG_FREQ: u8 = 0x01;
pub const LC3_CONFIG_DURATION: u8 = 0x02;
pub const LC3_CONFIG_CHAN_ALLOC: u8 = 0x03;
pub const LC3_CONFIG_FRAME_LEN: u8 = 0x04;
pub const LC3_CONFIG_FRAMES_PER_SDU: u8 = 0x05;

// ---- LC3 Sampling Frequencies ----

pub const LC3_FREQ_8KHZ: u8 = 0x01;
pub const LC3_FREQ_11KHZ: u8 = 0x02;
pub const LC3_FREQ_16KHZ: u8 = 0x03;
pub const LC3_FREQ_22KHZ: u8 = 0x04;
pub const LC3_FREQ_24KHZ: u8 = 0x05;
pub const LC3_FREQ_32KHZ: u8 = 0x06;
pub const LC3_FREQ_44KHZ: u8 = 0x07;
pub const LC3_FREQ_48KHZ: u8 = 0x08;

// ---- LC3 Frame Durations ----

pub const LC3_DURATION_7_5MS: u8 = 0x00;
pub const LC3_DURATION_10MS: u8 = 0x01;

// ---- LC3 Frame Lengths for standard configurations ----

pub const LC3_FRAME_LEN_8_1: u16 = 26;
pub const LC3_FRAME_LEN_8_2: u16 = 30;
pub const LC3_FRAME_LEN_16_1: u16 = 30;
pub const LC3_FRAME_LEN_16_2: u16 = 40;
pub const LC3_FRAME_LEN_24_1: u16 = 45;
pub const LC3_FRAME_LEN_24_2: u16 = 60;
pub const LC3_FRAME_LEN_32_1: u16 = 60;
pub const LC3_FRAME_LEN_32_2: u16 = 80;
pub const LC3_FRAME_LEN_44_1: u16 = 97;
pub const LC3_FRAME_LEN_44_2: u16 = 130;
pub const LC3_FRAME_LEN_48_1: u16 = 75;
pub const LC3_FRAME_LEN_48_2: u16 = 100;
pub const LC3_FRAME_LEN_48_3: u16 = 90;
pub const LC3_FRAME_LEN_48_4: u16 = 120;
pub const LC3_FRAME_LEN_48_5: u16 = 117;
pub const LC3_FRAME_LEN_48_6: u16 = 155;

// ---- LC3 Codec Configuration (LTV encoding) ----

/// LC3 codec-specific configuration parsed from LTV format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lc3Config {
    /// Sampling frequency index.
    pub freq: u8,
    /// Frame duration index (0=7.5ms, 1=10ms).
    pub duration: u8,
    /// Audio channel allocation (bitmask). None if not present.
    pub chan_alloc: Option<u32>,
    /// Octets per codec frame.
    pub frame_len: u16,
    /// Codec frames per SDU. None if not present (defaults to 1).
    pub frames_per_sdu: Option<u8>,
}

impl Lc3Config {
    /// Build a standard LC3 configuration (no channel allocation).
    pub fn new(freq: u8, duration: u8, frame_len: u16) -> Self {
        Self {
            freq,
            duration,
            chan_alloc: None,
            frame_len,
            frames_per_sdu: None,
        }
    }

    /// Encode to LTV byte vector (as used in BAP Codec_Specific_Configuration).
    pub fn to_ltv(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Sampling Frequency
        out.extend_from_slice(&[0x02, LC3_CONFIG_FREQ, self.freq]);
        // Frame Duration
        out.extend_from_slice(&[0x02, LC3_CONFIG_DURATION, self.duration]);
        // Channel Allocation (optional)
        if let Some(alloc) = self.chan_alloc {
            out.push(0x05);
            out.push(LC3_CONFIG_CHAN_ALLOC);
            out.extend_from_slice(&alloc.to_le_bytes());
        }
        // Frame Length
        out.push(0x03);
        out.push(LC3_CONFIG_FRAME_LEN);
        out.extend_from_slice(&self.frame_len.to_le_bytes());
        // Frames Per SDU (optional)
        if let Some(count) = self.frames_per_sdu {
            out.extend_from_slice(&[0x02, LC3_CONFIG_FRAMES_PER_SDU, count]);
        }
        out
    }

    /// Parse from LTV bytes. Returns None on invalid data.
    pub fn from_ltv(data: &[u8]) -> Option<Self> {
        let mut freq = None;
        let mut duration = None;
        let mut chan_alloc = None;
        let mut frame_len = None;
        let mut frames_per_sdu = None;

        let mut pos = 0;
        while pos < data.len() {
            if pos + 1 > data.len() {
                return None;
            }
            let len = data[pos] as usize;
            if len == 0 || pos + 1 + len > data.len() {
                return None;
            }
            let typ = data[pos + 1];
            let val = &data[pos + 2..pos + 1 + len];
            match typ {
                LC3_CONFIG_FREQ if val.len() == 1 => freq = Some(val[0]),
                LC3_CONFIG_DURATION if val.len() == 1 => duration = Some(val[0]),
                LC3_CONFIG_CHAN_ALLOC if val.len() == 4 => {
                    chan_alloc = Some(u32::from_le_bytes([val[0], val[1], val[2], val[3]]));
                }
                LC3_CONFIG_FRAME_LEN if val.len() == 2 => {
                    frame_len = Some(u16::from_le_bytes([val[0], val[1]]));
                }
                LC3_CONFIG_FRAMES_PER_SDU if val.len() == 1 => {
                    frames_per_sdu = Some(val[0]);
                }
                _ => {} // skip unknown
            }
            pos += 1 + len;
        }

        Some(Self {
            freq: freq?,
            duration: duration?,
            chan_alloc,
            frame_len: frame_len?,
            frames_per_sdu,
        })
    }
}

/// Parse a single LTV entry from bytes at given offset.
/// Returns (type, value_bytes, next_offset) or None.
pub fn parse_ltv_entry(data: &[u8], offset: usize) -> Option<(u8, &[u8], usize)> {
    if offset >= data.len() {
        return None;
    }
    let len = data[offset] as usize;
    if len == 0 || offset + 1 + len > data.len() {
        return None;
    }
    let typ = data[offset + 1];
    let val = &data[offset + 2..offset + 1 + len];
    Some((typ, val, offset + 1 + len))
}

/// Validate that an ASE state transition is legal per BAP spec.
/// Returns true if transitioning from `old` to `new` is valid.
pub fn is_valid_ase_transition(old: AseState, new: AseState) -> bool {
    use AseState::*;
    matches!(
        (old, new),
        // From Idle
        (Idle, CodecConfigured) |
        // From CodecConfigured
        (CodecConfigured, Idle) |
        (CodecConfigured, CodecConfigured) |
        (CodecConfigured, QosConfigured) |
        (CodecConfigured, Releasing) |
        // From QosConfigured
        (QosConfigured, Idle) |
        (QosConfigured, CodecConfigured) |
        (QosConfigured, QosConfigured) |
        (QosConfigured, Enabling) |
        (QosConfigured, Releasing) |
        // From Enabling
        (Enabling, Streaming) |
        (Enabling, Disabling) |
        (Enabling, Releasing) |
        // From Streaming
        (Streaming, Disabling) |
        (Streaming, Releasing) |
        // From Disabling
        (Disabling, Idle) |
        (Disabling, QosConfigured) |
        (Disabling, Releasing) |
        // From Releasing
        (Releasing, Idle)
    )
}

// ---- Standard LC3 configurations (matching C lc3.h) ----

pub const LC3_CONFIG_8_1: Lc3Config = Lc3Config {
    freq: LC3_FREQ_8KHZ, duration: LC3_DURATION_7_5MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_8_1, frames_per_sdu: None,
};
pub const LC3_CONFIG_8_2: Lc3Config = Lc3Config {
    freq: LC3_FREQ_8KHZ, duration: LC3_DURATION_10MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_8_2, frames_per_sdu: None,
};
pub const LC3_CONFIG_16_1: Lc3Config = Lc3Config {
    freq: LC3_FREQ_16KHZ, duration: LC3_DURATION_7_5MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_16_1, frames_per_sdu: None,
};
pub const LC3_CONFIG_16_2: Lc3Config = Lc3Config {
    freq: LC3_FREQ_16KHZ, duration: LC3_DURATION_10MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_16_2, frames_per_sdu: None,
};
pub const LC3_CONFIG_24_1: Lc3Config = Lc3Config {
    freq: LC3_FREQ_24KHZ, duration: LC3_DURATION_7_5MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_24_1, frames_per_sdu: None,
};
pub const LC3_CONFIG_24_2: Lc3Config = Lc3Config {
    freq: LC3_FREQ_24KHZ, duration: LC3_DURATION_10MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_24_2, frames_per_sdu: None,
};
pub const LC3_CONFIG_32_1: Lc3Config = Lc3Config {
    freq: LC3_FREQ_32KHZ, duration: LC3_DURATION_7_5MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_32_1, frames_per_sdu: None,
};
pub const LC3_CONFIG_32_2: Lc3Config = Lc3Config {
    freq: LC3_FREQ_32KHZ, duration: LC3_DURATION_10MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_32_2, frames_per_sdu: None,
};
pub const LC3_CONFIG_44_1: Lc3Config = Lc3Config {
    freq: LC3_FREQ_44KHZ, duration: LC3_DURATION_7_5MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_44_1, frames_per_sdu: None,
};
pub const LC3_CONFIG_44_2: Lc3Config = Lc3Config {
    freq: LC3_FREQ_44KHZ, duration: LC3_DURATION_10MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_44_2, frames_per_sdu: None,
};
pub const LC3_CONFIG_48_1: Lc3Config = Lc3Config {
    freq: LC3_FREQ_48KHZ, duration: LC3_DURATION_7_5MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_48_1, frames_per_sdu: None,
};
pub const LC3_CONFIG_48_2: Lc3Config = Lc3Config {
    freq: LC3_FREQ_48KHZ, duration: LC3_DURATION_10MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_48_2, frames_per_sdu: None,
};
pub const LC3_CONFIG_48_3: Lc3Config = Lc3Config {
    freq: LC3_FREQ_48KHZ, duration: LC3_DURATION_7_5MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_48_3, frames_per_sdu: None,
};
pub const LC3_CONFIG_48_4: Lc3Config = Lc3Config {
    freq: LC3_FREQ_48KHZ, duration: LC3_DURATION_10MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_48_4, frames_per_sdu: None,
};
pub const LC3_CONFIG_48_5: Lc3Config = Lc3Config {
    freq: LC3_FREQ_48KHZ, duration: LC3_DURATION_7_5MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_48_5, frames_per_sdu: None,
};
pub const LC3_CONFIG_48_6: Lc3Config = Lc3Config {
    freq: LC3_FREQ_48KHZ, duration: LC3_DURATION_10MS,
    chan_alloc: None, frame_len: LC3_FRAME_LEN_48_6, frames_per_sdu: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ASE State Machine Tests (from test-bap.c state transition tests) ----

    #[test]
    fn test_ase_state_roundtrip() {
        for val in 0..=6u8 {
            let state = AseState::from_u8(val).unwrap();
            assert_eq!(state as u8, val);
        }
        assert!(AseState::from_u8(7).is_none());
    }

    #[test]
    fn test_ase_state_from_u8_invalid_values() {
        // Values 7..=255 must all be invalid (from test-bap.c state coverage)
        for val in 7..=255u8 {
            assert!(
                AseState::from_u8(val).is_none(),
                "AseState::from_u8({}) should be None",
                val
            );
        }
    }

    #[test]
    fn test_ase_state_str() {
        assert_eq!(AseState::Idle.as_str(), "idle");
        assert_eq!(AseState::CodecConfigured.as_str(), "codec-configured");
        assert_eq!(AseState::QosConfigured.as_str(), "qos-configured");
        assert_eq!(AseState::Enabling.as_str(), "enabling");
        assert_eq!(AseState::Streaming.as_str(), "streaming");
        assert_eq!(AseState::Disabling.as_str(), "disabling");
        assert_eq!(AseState::Releasing.as_str(), "releasing");
    }

    // ---- Valid ASE state transitions (from test-bap.c SCC/QOS/Enable tests) ----

    #[test]
    fn test_valid_transitions_from_idle() {
        assert!(is_valid_ase_transition(AseState::Idle, AseState::CodecConfigured));
        assert!(!is_valid_ase_transition(AseState::Idle, AseState::QosConfigured));
        assert!(!is_valid_ase_transition(AseState::Idle, AseState::Enabling));
        assert!(!is_valid_ase_transition(AseState::Idle, AseState::Streaming));
        assert!(!is_valid_ase_transition(AseState::Idle, AseState::Disabling));
        assert!(!is_valid_ase_transition(AseState::Idle, AseState::Releasing));
    }

    #[test]
    fn test_valid_transitions_from_codec_configured() {
        assert!(is_valid_ase_transition(AseState::CodecConfigured, AseState::Idle));
        assert!(is_valid_ase_transition(AseState::CodecConfigured, AseState::CodecConfigured));
        assert!(is_valid_ase_transition(AseState::CodecConfigured, AseState::QosConfigured));
        assert!(is_valid_ase_transition(AseState::CodecConfigured, AseState::Releasing));
        assert!(!is_valid_ase_transition(AseState::CodecConfigured, AseState::Enabling));
        assert!(!is_valid_ase_transition(AseState::CodecConfigured, AseState::Streaming));
        assert!(!is_valid_ase_transition(AseState::CodecConfigured, AseState::Disabling));
    }

    #[test]
    fn test_valid_transitions_from_qos_configured() {
        assert!(is_valid_ase_transition(AseState::QosConfigured, AseState::Idle));
        assert!(is_valid_ase_transition(AseState::QosConfigured, AseState::CodecConfigured));
        assert!(is_valid_ase_transition(AseState::QosConfigured, AseState::QosConfigured));
        assert!(is_valid_ase_transition(AseState::QosConfigured, AseState::Enabling));
        assert!(is_valid_ase_transition(AseState::QosConfigured, AseState::Releasing));
        assert!(!is_valid_ase_transition(AseState::QosConfigured, AseState::Streaming));
        assert!(!is_valid_ase_transition(AseState::QosConfigured, AseState::Disabling));
    }

    #[test]
    fn test_valid_transitions_from_enabling() {
        assert!(is_valid_ase_transition(AseState::Enabling, AseState::Streaming));
        assert!(is_valid_ase_transition(AseState::Enabling, AseState::Disabling));
        assert!(is_valid_ase_transition(AseState::Enabling, AseState::Releasing));
        assert!(!is_valid_ase_transition(AseState::Enabling, AseState::Idle));
        assert!(!is_valid_ase_transition(AseState::Enabling, AseState::CodecConfigured));
        assert!(!is_valid_ase_transition(AseState::Enabling, AseState::QosConfigured));
    }

    #[test]
    fn test_valid_transitions_from_streaming() {
        assert!(is_valid_ase_transition(AseState::Streaming, AseState::Disabling));
        assert!(is_valid_ase_transition(AseState::Streaming, AseState::Releasing));
        assert!(!is_valid_ase_transition(AseState::Streaming, AseState::Idle));
        assert!(!is_valid_ase_transition(AseState::Streaming, AseState::CodecConfigured));
        assert!(!is_valid_ase_transition(AseState::Streaming, AseState::QosConfigured));
        assert!(!is_valid_ase_transition(AseState::Streaming, AseState::Enabling));
    }

    #[test]
    fn test_valid_transitions_from_disabling() {
        assert!(is_valid_ase_transition(AseState::Disabling, AseState::Idle));
        assert!(is_valid_ase_transition(AseState::Disabling, AseState::QosConfigured));
        assert!(is_valid_ase_transition(AseState::Disabling, AseState::Releasing));
        assert!(!is_valid_ase_transition(AseState::Disabling, AseState::CodecConfigured));
        assert!(!is_valid_ase_transition(AseState::Disabling, AseState::Enabling));
        assert!(!is_valid_ase_transition(AseState::Disabling, AseState::Streaming));
    }

    #[test]
    fn test_valid_transitions_from_releasing() {
        assert!(is_valid_ase_transition(AseState::Releasing, AseState::Idle));
        assert!(!is_valid_ase_transition(AseState::Releasing, AseState::CodecConfigured));
        assert!(!is_valid_ase_transition(AseState::Releasing, AseState::QosConfigured));
        assert!(!is_valid_ase_transition(AseState::Releasing, AseState::Enabling));
        assert!(!is_valid_ase_transition(AseState::Releasing, AseState::Streaming));
        assert!(!is_valid_ase_transition(AseState::Releasing, AseState::Disabling));
    }

    // ---- Codec ID Tests ----

    #[test]
    fn test_codec_id_lc3() {
        let lc3 = CodecId::LC3;
        assert_eq!(lc3.format, 0x06);
        assert_eq!(lc3.company, 0x0000);
        assert_eq!(lc3.vendor, 0x0000);
        let bytes = lc3.to_bytes();
        assert_eq!(bytes, [0x06, 0x00, 0x00, 0x00, 0x00]);
        let parsed = CodecId::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, lc3);
    }

    #[test]
    fn test_codec_id_vendor_specific() {
        // From test-bap.c cfg_snk_vs / cfg_src_vs
        let vs = CodecId {
            format: 0xFF,
            company: 0x1234,
            vendor: 0x5678,
        };
        let bytes = vs.to_bytes();
        assert_eq!(bytes, [0xFF, 0x34, 0x12, 0x78, 0x56]);
        let parsed = CodecId::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, vs);
    }

    #[test]
    fn test_codec_id_from_bytes_too_short() {
        assert!(CodecId::from_bytes(&[]).is_none());
        assert!(CodecId::from_bytes(&[0x06]).is_none());
        assert!(CodecId::from_bytes(&[0x06, 0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_codec_id_from_bytes_extra_ignored() {
        let bytes = [0x06, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF];
        let parsed = CodecId::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, CodecId::LC3);
    }

    // ---- LC3 Codec Config LTV Encoding/Decoding Tests ----
    // These correspond to the SCC (Stream Codec Configuration) tests
    // from test-bap.c: BAP/UCL/SCC/BV-001-C through BV-032-C

    #[test]
    fn test_lc3_config_8_1_ltv() {
        // LC3 8_1: 8kHz, 7.5ms, 26 octets
        // Expected LTV: 02 01 01  02 02 00  03 04 1a 00
        let cfg = LC3_CONFIG_8_1;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x03, 0x04, 0x1a, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_8_2_ltv() {
        // LC3 8_2: 8kHz, 10ms, 30 octets
        let cfg = LC3_CONFIG_8_2;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x01, 0x02, 0x02, 0x01, 0x03, 0x04, 0x1e, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_16_1_ltv() {
        // LC3 16_1: 16kHz, 7.5ms, 30 octets
        let cfg = LC3_CONFIG_16_1;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x03, 0x02, 0x02, 0x00, 0x03, 0x04, 0x1e, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_16_2_ltv() {
        let cfg = LC3_CONFIG_16_2;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x03, 0x02, 0x02, 0x01, 0x03, 0x04, 0x28, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_24_1_ltv() {
        let cfg = LC3_CONFIG_24_1;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x05, 0x02, 0x02, 0x00, 0x03, 0x04, 0x2d, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_24_2_ltv() {
        let cfg = LC3_CONFIG_24_2;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x05, 0x02, 0x02, 0x01, 0x03, 0x04, 0x3c, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_32_1_ltv() {
        let cfg = LC3_CONFIG_32_1;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x06, 0x02, 0x02, 0x00, 0x03, 0x04, 0x3c, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_32_2_ltv() {
        let cfg = LC3_CONFIG_32_2;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x06, 0x02, 0x02, 0x01, 0x03, 0x04, 0x50, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_44_1_ltv() {
        let cfg = LC3_CONFIG_44_1;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x07, 0x02, 0x02, 0x00, 0x03, 0x04, 0x61, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_44_2_ltv() {
        let cfg = LC3_CONFIG_44_2;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x07, 0x02, 0x02, 0x01, 0x03, 0x04, 0x82, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_48_1_ltv() {
        let cfg = LC3_CONFIG_48_1;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x08, 0x02, 0x02, 0x00, 0x03, 0x04, 0x4b, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_48_2_ltv() {
        let cfg = LC3_CONFIG_48_2;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x08, 0x02, 0x02, 0x01, 0x03, 0x04, 0x64, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_48_3_ltv() {
        let cfg = LC3_CONFIG_48_3;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x08, 0x02, 0x02, 0x00, 0x03, 0x04, 0x5a, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_48_4_ltv() {
        let cfg = LC3_CONFIG_48_4;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x08, 0x02, 0x02, 0x01, 0x03, 0x04, 0x78, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_48_5_ltv() {
        let cfg = LC3_CONFIG_48_5;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x08, 0x02, 0x02, 0x00, 0x03, 0x04, 0x75, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_48_6_ltv() {
        let cfg = LC3_CONFIG_48_6;
        let ltv = cfg.to_ltv();
        assert_eq!(ltv, vec![0x02, 0x01, 0x08, 0x02, 0x02, 0x01, 0x03, 0x04, 0x9b, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    // ---- LTV with Channel Allocation ----

    #[test]
    fn test_lc3_config_with_channel_alloc_front_left() {
        let cfg = Lc3Config {
            freq: LC3_FREQ_48KHZ,
            duration: LC3_DURATION_10MS,
            chan_alloc: Some(BAP_LOCATION_FRONT_LEFT),
            frame_len: LC3_FRAME_LEN_48_2,
            frames_per_sdu: None,
        };
        let ltv = cfg.to_ltv();
        // freq LTV + duration LTV + chan_alloc LTV + frame_len LTV
        assert_eq!(ltv.len(), 3 + 3 + 6 + 4);
        // Channel alloc entry: 05 03 01 00 00 00
        assert_eq!(&ltv[6..12], &[0x05, 0x03, 0x01, 0x00, 0x00, 0x00]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn test_lc3_config_with_channel_alloc_stereo() {
        let alloc = BAP_LOCATION_FRONT_LEFT | BAP_LOCATION_FRONT_RIGHT;
        let cfg = Lc3Config {
            freq: LC3_FREQ_48KHZ,
            duration: LC3_DURATION_10MS,
            chan_alloc: Some(alloc),
            frame_len: LC3_FRAME_LEN_48_2,
            frames_per_sdu: None,
        };
        let ltv = cfg.to_ltv();
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed.chan_alloc, Some(0x03));
    }

    // ---- LTV with Frames Per SDU ----

    #[test]
    fn test_lc3_config_with_frames_per_sdu() {
        let cfg = Lc3Config {
            freq: LC3_FREQ_16KHZ,
            duration: LC3_DURATION_10MS,
            chan_alloc: None,
            frame_len: LC3_FRAME_LEN_16_2,
            frames_per_sdu: Some(2),
        };
        let ltv = cfg.to_ltv();
        // Should end with frames_per_sdu LTV: 02 05 02
        let tail = &ltv[ltv.len() - 3..];
        assert_eq!(tail, &[0x02, 0x05, 0x02]);
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed.frames_per_sdu, Some(2));
    }

    // ---- LTV parsing edge cases ----

    #[test]
    fn test_ltv_parse_empty() {
        assert!(Lc3Config::from_ltv(&[]).is_none());
    }

    #[test]
    fn test_ltv_parse_zero_length_entry() {
        // Length=0 is invalid LTV
        assert!(Lc3Config::from_ltv(&[0x00]).is_none());
    }

    #[test]
    fn test_ltv_parse_truncated() {
        // Valid start but truncated
        assert!(Lc3Config::from_ltv(&[0x02, 0x01]).is_none());
    }

    #[test]
    fn test_ltv_parse_missing_required_field() {
        // Only freq, missing duration and frame_len
        assert!(Lc3Config::from_ltv(&[0x02, 0x01, 0x08]).is_none());
    }

    #[test]
    fn test_ltv_parse_unknown_types_ignored() {
        // Valid config with unknown type 0xFF injected
        let mut ltv = LC3_CONFIG_48_1.to_ltv();
        ltv.extend_from_slice(&[0x02, 0xFF, 0x42]); // unknown type
        let parsed = Lc3Config::from_ltv(&ltv).unwrap();
        assert_eq!(parsed, LC3_CONFIG_48_1);
    }

    #[test]
    fn test_parse_ltv_entry_basic() {
        let data = [0x02, 0x01, 0x08, 0x02, 0x02, 0x01];
        let (typ, val, next) = parse_ltv_entry(&data, 0).unwrap();
        assert_eq!(typ, 0x01);
        assert_eq!(val, &[0x08]);
        assert_eq!(next, 3);

        let (typ2, val2, next2) = parse_ltv_entry(&data, next).unwrap();
        assert_eq!(typ2, 0x02);
        assert_eq!(val2, &[0x01]);
        assert_eq!(next2, 6);

        assert!(parse_ltv_entry(&data, next2).is_none());
    }

    // ---- QoS Config Tests ----

    #[test]
    fn test_qos_config_default() {
        let qos = QosConfig {
            cig_id: 0,
            cis_id: 0,
            sdu_interval: 10000,
            framing: 0,
            phy: 2,
            max_sdu: 100,
            retransmission: 2,
            latency: 10,
            presentation_delay: 40000,
        };
        assert_eq!(qos.sdu_interval, 10000);
        assert_eq!(qos.phy, 2); // 2M PHY
    }

    // ---- ASE CP Opcode Tests ----

    #[test]
    fn test_ase_cp_opcodes() {
        assert_eq!(ASE_CP_CONFIG_CODEC, 0x01);
        assert_eq!(ASE_CP_CONFIG_QOS, 0x02);
        assert_eq!(ASE_CP_ENABLE, 0x03);
        assert_eq!(ASE_CP_RECEIVER_START_READY, 0x04);
        assert_eq!(ASE_CP_DISABLE, 0x05);
        assert_eq!(ASE_CP_RECEIVER_STOP_READY, 0x06);
        assert_eq!(ASE_CP_UPDATE_METADATA, 0x07);
        assert_eq!(ASE_CP_RELEASE, 0x08);
    }

    // ---- ASE Response Code Tests ----

    #[test]
    fn test_ase_response_codes() {
        assert_eq!(ASE_RSP_SUCCESS, 0x00);
        assert_eq!(ASE_RSP_UNSUPPORTED_OPCODE, 0x01);
        assert_eq!(ASE_RSP_INVALID_LENGTH, 0x02);
        assert_eq!(ASE_RSP_INVALID_ASE_ID, 0x03);
        assert_eq!(ASE_RSP_INVALID_STATE, 0x04);
        assert_eq!(ASE_RSP_INVALID_DIRECTION, 0x05);
        assert_eq!(ASE_RSP_UNSUPPORTED_AUDIO_CAP, 0x06);
        assert_eq!(ASE_RSP_UNSUPPORTED_CONF, 0x07);
        assert_eq!(ASE_RSP_REJECTED_CONF, 0x08);
        assert_eq!(ASE_RSP_INVALID_CONF, 0x09);
        assert_eq!(ASE_RSP_UNSUPPORTED_METADATA, 0x0A);
        assert_eq!(ASE_RSP_REJECTED_METADATA, 0x0B);
        assert_eq!(ASE_RSP_INVALID_METADATA, 0x0C);
        assert_eq!(ASE_RSP_INSUFFICIENT_RESOURCES, 0x0D);
        assert_eq!(ASE_RSP_UNSPECIFIED_ERROR, 0x0E);
    }

    // ---- UUID Tests (from test-bap.c DISC tests) ----

    #[test]
    fn test_bap_service_uuids() {
        assert_eq!(BAP_UUID, 0x184E);
        assert_eq!(PACS_UUID, 0x1850);
        assert_eq!(ASE_SINK_UUID, 0x2BC4);
        assert_eq!(ASE_SOURCE_UUID, 0x2BC5);
        assert_eq!(ASE_CP_UUID, 0x2BC6);
    }

    #[test]
    fn test_pac_uuids() {
        assert_eq!(PAC_SINK_UUID, 0x2BC9);
        assert_eq!(PAC_SOURCE_UUID, 0x2BCB);
        assert_eq!(PAC_SINK_LOC_UUID, 0x2BCA);
        assert_eq!(PAC_SOURCE_LOC_UUID, 0x2BCC);
        assert_eq!(PAC_CONTEXT_UUID, 0x2BCE);
        assert_eq!(PAC_SUPPORTED_CONTEXT_UUID, 0x2BCF);
    }

    // ---- Audio Location Tests ----

    #[test]
    fn test_audio_locations_bitmask() {
        let stereo = BAP_LOCATION_FRONT_LEFT | BAP_LOCATION_FRONT_RIGHT;
        assert_eq!(stereo, 0x03);

        let surround = BAP_LOCATION_FRONT_LEFT
            | BAP_LOCATION_FRONT_RIGHT
            | BAP_LOCATION_FRONT_CENTER
            | BAP_LOCATION_LOW_FREQUENCY
            | BAP_LOCATION_BACK_LEFT
            | BAP_LOCATION_BACK_RIGHT;
        assert_eq!(surround, 0x3F);
    }

    // ---- Context Types Tests ----

    #[test]
    fn test_context_types() {
        assert_eq!(BAP_CONTEXT_UNSPECIFIED, 0x0001);
        assert_eq!(BAP_CONTEXT_CONVERSATIONAL, 0x0002);
        assert_eq!(BAP_CONTEXT_MEDIA, 0x0004);
        assert_eq!(BAP_CONTEXT_GAME, 0x0008);
        assert_eq!(BAP_CONTEXT_EMERGENCY, 0x0800);

        // All contexts bitmask (from test-bap.c lc3_qos.supported_context = 0x0fff)
        let all_contexts = BAP_CONTEXT_UNSPECIFIED
            | BAP_CONTEXT_CONVERSATIONAL
            | BAP_CONTEXT_MEDIA
            | BAP_CONTEXT_GAME
            | BAP_CONTEXT_INSTRUCTIONAL
            | BAP_CONTEXT_VOICE_ASSISTANTS
            | BAP_CONTEXT_LIVE
            | BAP_CONTEXT_SOUND_EFFECTS
            | BAP_CONTEXT_NOTIFICATIONS
            | BAP_CONTEXT_RINGTONE
            | BAP_CONTEXT_ALERTS
            | BAP_CONTEXT_EMERGENCY;
        assert_eq!(all_contexts, 0x0FFF);
    }

    // ---- LC3 Frequency / Duration constant tests ----

    #[test]
    fn test_lc3_freq_constants() {
        assert_eq!(LC3_FREQ_8KHZ, 0x01);
        assert_eq!(LC3_FREQ_11KHZ, 0x02);
        assert_eq!(LC3_FREQ_16KHZ, 0x03);
        assert_eq!(LC3_FREQ_22KHZ, 0x04);
        assert_eq!(LC3_FREQ_24KHZ, 0x05);
        assert_eq!(LC3_FREQ_32KHZ, 0x06);
        assert_eq!(LC3_FREQ_44KHZ, 0x07);
        assert_eq!(LC3_FREQ_48KHZ, 0x08);
    }

    #[test]
    fn test_lc3_duration_constants() {
        assert_eq!(LC3_DURATION_7_5MS, 0x00);
        assert_eq!(LC3_DURATION_10MS, 0x01);
    }

    // ---- Frame length constants (from lc3.h) ----

    #[test]
    fn test_lc3_frame_len_constants() {
        assert_eq!(LC3_FRAME_LEN_8_1, 26);
        assert_eq!(LC3_FRAME_LEN_8_2, 30);
        assert_eq!(LC3_FRAME_LEN_16_1, 30);
        assert_eq!(LC3_FRAME_LEN_16_2, 40);
        assert_eq!(LC3_FRAME_LEN_24_1, 45);
        assert_eq!(LC3_FRAME_LEN_24_2, 60);
        assert_eq!(LC3_FRAME_LEN_32_1, 60);
        assert_eq!(LC3_FRAME_LEN_32_2, 80);
        assert_eq!(LC3_FRAME_LEN_44_1, 97);
        assert_eq!(LC3_FRAME_LEN_44_2, 130);
        assert_eq!(LC3_FRAME_LEN_48_1, 75);
        assert_eq!(LC3_FRAME_LEN_48_2, 100);
        assert_eq!(LC3_FRAME_LEN_48_3, 90);
        assert_eq!(LC3_FRAME_LEN_48_4, 120);
        assert_eq!(LC3_FRAME_LEN_48_5, 117);
        assert_eq!(LC3_FRAME_LEN_48_6, 155);
    }

    // ---- All 16 standard configs roundtrip ----

    #[test]
    fn test_all_standard_configs_roundtrip() {
        let configs = [
            LC3_CONFIG_8_1, LC3_CONFIG_8_2,
            LC3_CONFIG_16_1, LC3_CONFIG_16_2,
            LC3_CONFIG_24_1, LC3_CONFIG_24_2,
            LC3_CONFIG_32_1, LC3_CONFIG_32_2,
            LC3_CONFIG_44_1, LC3_CONFIG_44_2,
            LC3_CONFIG_48_1, LC3_CONFIG_48_2,
            LC3_CONFIG_48_3, LC3_CONFIG_48_4,
            LC3_CONFIG_48_5, LC3_CONFIG_48_6,
        ];
        for cfg in &configs {
            let ltv = cfg.to_ltv();
            let parsed = Lc3Config::from_ltv(&ltv).unwrap();
            assert_eq!(&parsed, cfg, "Roundtrip failed for {:?}", cfg);
        }
    }
}
