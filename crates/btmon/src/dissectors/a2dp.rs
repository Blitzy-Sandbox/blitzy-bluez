// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// Copyright (C) 2015  Andrzej Kaczmarek <andrzej.kaczmarek@codecoup.pl>
// Copyright (C) 2018  Pali Rohár <pali.rohar@gmail.com>
//
// a2dp.rs — A2DP codec capability/configuration dissector.
//
// Complete Rust rewrite of monitor/a2dp.c (959 lines) + monitor/a2dp.h.
// Decodes A2DP media codec capabilities and configurations for SBC,
// MPEG-1,2 Audio, MPEG-2,4 AAC, ATRAC, aptX, aptX HD, LDAC,
// Opus (Google), FastStream, aptX Low Latency, and generic vendor codecs.

use super::l2cap::L2capFrame;
use crate::packet;
use crate::print_field;
use bluez_shared::sys::bluetooth::bt_compidtostr;

// ============================================================================
// Constants
// ============================================================================

/// Base indentation level for codec-specific fields.
const BASE_INDENT: usize = 4;

// Codec Types (from a2dp.c lines 32-37)
const A2DP_CODEC_SBC: u8 = 0x00;
const A2DP_CODEC_MPEG12: u8 = 0x01;
const A2DP_CODEC_MPEG24: u8 = 0x02;
const A2DP_CODEC_ATRAC: u8 = 0x04;
const A2DP_CODEC_VENDOR: u8 = 0xff;

// Vendor-Specific A2DP Codecs (from a2dp.c lines 40-51)
const APTX_VENDOR_ID: u32 = 0x0000_004f;
const APTX_CODEC_ID: u16 = 0x0001;
const FASTSTREAM_VENDOR_ID: u32 = 0x0000_000a;
const FASTSTREAM_CODEC_ID: u16 = 0x0001;
const APTX_LL_VENDOR_ID: u32 = 0x0000_000a;
const APTX_LL_CODEC_ID: u16 = 0x0002;
const APTX_HD_VENDOR_ID: u32 = 0x0000_00d7;
const APTX_HD_CODEC_ID: u16 = 0x0024;
const LDAC_VENDOR_ID: u32 = 0x0000_012d;
const LDAC_CODEC_ID: u16 = 0x00aa;
const OPUS_G_VENDOR_ID: u32 = 0x0000_00e0;
const OPUS_G_CODEC_ID: u16 = 0x0001;

// ============================================================================
// Bit Descriptor Table Infrastructure
// ============================================================================

/// Describes a single bit position and its human-readable label.
struct BitDesc {
    bit_num: u8,
    str_val: &'static str,
}

// SBC Tables (from a2dp.c lines 58-92)

static SBC_FREQUENCY_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 7, str_val: "16000" },
    BitDesc { bit_num: 6, str_val: "32000" },
    BitDesc { bit_num: 5, str_val: "44100" },
    BitDesc { bit_num: 4, str_val: "48000" },
];

static SBC_CHANNEL_MODE_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 3, str_val: "Mono" },
    BitDesc { bit_num: 2, str_val: "Dual Channel" },
    BitDesc { bit_num: 1, str_val: "Stereo" },
    BitDesc { bit_num: 0, str_val: "Joint Stereo" },
];

static SBC_BLOCKLEN_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 7, str_val: "4" },
    BitDesc { bit_num: 6, str_val: "8" },
    BitDesc { bit_num: 5, str_val: "12" },
    BitDesc { bit_num: 4, str_val: "16" },
];

static SBC_SUBBANDS_TABLE: &[BitDesc] =
    &[BitDesc { bit_num: 3, str_val: "4" }, BitDesc { bit_num: 2, str_val: "8" }];

static SBC_ALLOCATION_TABLE: &[BitDesc] =
    &[BitDesc { bit_num: 1, str_val: "SNR" }, BitDesc { bit_num: 0, str_val: "Loudness" }];

// MPEG-1,2 Audio Tables (from a2dp.c lines 94-136)

static MPEG12_LAYER_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 7, str_val: "Layer I (mp1)" },
    BitDesc { bit_num: 6, str_val: "Layer II (mp2)" },
    BitDesc { bit_num: 5, str_val: "Layer III (mp3)" },
];

static MPEG12_CHANNEL_MODE_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 3, str_val: "Mono" },
    BitDesc { bit_num: 2, str_val: "Dual Channel" },
    BitDesc { bit_num: 1, str_val: "Stereo" },
    BitDesc { bit_num: 0, str_val: "Joint Stereo" },
];

static MPEG12_FREQUENCY_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 5, str_val: "16000" },
    BitDesc { bit_num: 4, str_val: "22050" },
    BitDesc { bit_num: 3, str_val: "24000" },
    BitDesc { bit_num: 2, str_val: "32000" },
    BitDesc { bit_num: 1, str_val: "44100" },
    BitDesc { bit_num: 0, str_val: "48000" },
];

static MPEG12_BITRATE_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 14, str_val: "1110" },
    BitDesc { bit_num: 13, str_val: "1101" },
    BitDesc { bit_num: 12, str_val: "1100" },
    BitDesc { bit_num: 11, str_val: "1011" },
    BitDesc { bit_num: 10, str_val: "1010" },
    BitDesc { bit_num: 9, str_val: "1001" },
    BitDesc { bit_num: 8, str_val: "1000" },
    BitDesc { bit_num: 7, str_val: "0111" },
    BitDesc { bit_num: 6, str_val: "0110" },
    BitDesc { bit_num: 5, str_val: "0101" },
    BitDesc { bit_num: 4, str_val: "0100" },
    BitDesc { bit_num: 3, str_val: "0011" },
    BitDesc { bit_num: 2, str_val: "0010" },
    BitDesc { bit_num: 1, str_val: "0001" },
    BitDesc { bit_num: 0, str_val: "0000" },
];

// AAC Tables (from a2dp.c lines 138-170)

static AAC_OBJECT_TYPE_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 7, str_val: "MPEG-2 AAC LC" },
    BitDesc { bit_num: 6, str_val: "MPEG-4 AAC LC" },
    BitDesc { bit_num: 5, str_val: "MPEG-4 AAC LTP" },
    BitDesc { bit_num: 4, str_val: "MPEG-4 AAC scalable" },
    BitDesc { bit_num: 3, str_val: "RFA (b3)" },
    BitDesc { bit_num: 2, str_val: "RFA (b2)" },
    BitDesc { bit_num: 1, str_val: "RFA (b1)" },
    BitDesc { bit_num: 0, str_val: "RFA (b0)" },
];

static AAC_FREQUENCY_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 15, str_val: "8000" },
    BitDesc { bit_num: 14, str_val: "11025" },
    BitDesc { bit_num: 13, str_val: "12000" },
    BitDesc { bit_num: 12, str_val: "16000" },
    BitDesc { bit_num: 11, str_val: "22050" },
    BitDesc { bit_num: 10, str_val: "24000" },
    BitDesc { bit_num: 9, str_val: "32000" },
    BitDesc { bit_num: 8, str_val: "44100" },
    BitDesc { bit_num: 7, str_val: "48000" },
    BitDesc { bit_num: 6, str_val: "64000" },
    BitDesc { bit_num: 5, str_val: "88200" },
    BitDesc { bit_num: 4, str_val: "96000" },
];

static AAC_CHANNELS_TABLE: &[BitDesc] =
    &[BitDesc { bit_num: 3, str_val: "1" }, BitDesc { bit_num: 2, str_val: "2" }];

// aptX Tables (from a2dp.c lines 172-184)

static APTX_FREQUENCY_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 7, str_val: "16000" },
    BitDesc { bit_num: 6, str_val: "32000" },
    BitDesc { bit_num: 5, str_val: "44100" },
    BitDesc { bit_num: 4, str_val: "48000" },
];

static APTX_CHANNEL_MODE_TABLE: &[BitDesc] =
    &[BitDesc { bit_num: 0, str_val: "Mono" }, BitDesc { bit_num: 1, str_val: "Stereo" }];

// FastStream Tables (from a2dp.c lines 186-204)

static FASTSTREAM_DIRECTION_TABLE: &[BitDesc] =
    &[BitDesc { bit_num: 0, str_val: "Sink" }, BitDesc { bit_num: 1, str_val: "Source" }];

static FASTSTREAM_SINK_FREQUENCY_TABLE: &[BitDesc] = &[
    // In config buffer, 48kHz takes precedence over 44.1kHz
    BitDesc { bit_num: 0, str_val: "48000" },
    BitDesc { bit_num: 1, str_val: "44100" },
];

static FASTSTREAM_SOURCE_FREQUENCY_TABLE: &[BitDesc] = &[BitDesc { bit_num: 5, str_val: "16000" }];

// Opus (Google) Tables (from a2dp.c lines 206-222)

static OPUS_G_FREQUENCY_TABLE: &[BitDesc] = &[BitDesc { bit_num: 7, str_val: "48000" }];

static OPUS_G_DURATION_TABLE: &[BitDesc] =
    &[BitDesc { bit_num: 3, str_val: "10 ms" }, BitDesc { bit_num: 4, str_val: "20 ms" }];

static OPUS_G_CHANNELS_TABLE: &[BitDesc] = &[
    BitDesc { bit_num: 0, str_val: "Mono" },
    BitDesc { bit_num: 1, str_val: "Stereo" },
    BitDesc { bit_num: 2, str_val: "Dual Mono" },
];

// ============================================================================
// Vendor Codec Name Table
// ============================================================================

/// Vendor codec descriptor for name lookup.
struct VndCodec {
    vendor_id: u32,
    codec_id: u16,
    codec_name: &'static str,
}

static VNDCODECS: &[VndCodec] = &[
    VndCodec { vendor_id: APTX_VENDOR_ID, codec_id: APTX_CODEC_ID, codec_name: "aptX" },
    VndCodec {
        vendor_id: FASTSTREAM_VENDOR_ID,
        codec_id: FASTSTREAM_CODEC_ID,
        codec_name: "FastStream",
    },
    VndCodec {
        vendor_id: APTX_LL_VENDOR_ID,
        codec_id: APTX_LL_CODEC_ID,
        codec_name: "aptX Low Latency",
    },
    VndCodec { vendor_id: APTX_HD_VENDOR_ID, codec_id: APTX_HD_CODEC_ID, codec_name: "aptX HD" },
    VndCodec { vendor_id: LDAC_VENDOR_ID, codec_id: LDAC_CODEC_ID, codec_name: "LDAC" },
    VndCodec {
        vendor_id: OPUS_G_VENDOR_ID,
        codec_id: OPUS_G_CODEC_ID,
        codec_name: "Opus (Google)",
    },
];

// ============================================================================
// Helper Functions
// ============================================================================

/// Print each set bit from `value` as a named capability label.
/// Matches C `print_value_bits()` — each matching entry printed on its own
/// line at `indent + 2` beyond the print_field base indent.
fn print_value_bits(indent: usize, value: u32, table: &[BitDesc]) {
    for entry in table {
        if value & (1 << entry.bit_num) != 0 {
            print_field!("{:>width$}{}", ' ', entry.str_val, width = indent + 2);
        }
    }
}

/// Find the first matching bit in `value` from the table and return its label.
/// Used in configuration (cfg) mode where exactly one bit should be set.
/// Returns `"Unknown"` if no bits match, matching C `find_value_bit()`.
fn find_value_bit(value: u32, table: &[BitDesc]) -> &'static str {
    for entry in table {
        if value & (1 << entry.bit_num) != 0 {
            return entry.str_val;
        }
    }
    "Unknown"
}

/// Look up the human-readable name for a vendor-specific codec.
/// Returns `"Unknown"` for unrecognised vendor/codec ID pairs.
fn vndcodec2str(vendor_id: u32, codec_id: u16) -> &'static str {
    for vc in VNDCODECS {
        if vc.vendor_id == vendor_id && vc.codec_id == codec_id {
            return vc.codec_name;
        }
    }
    "Unknown"
}

/// Hexdump `losc` bytes from the frame's current position and advance past them.
fn hexdump_and_pull(frame: &mut L2capFrame, losc: u8) {
    let remaining = frame.remaining_data();
    let dump_len = std::cmp::min(losc as usize, remaining.len());
    packet::hexdump(&remaining[..dump_len]);
    frame.pull(losc as usize);
}

// ============================================================================
// SBC Codec Decoder (from a2dp.c lines 298-376)
// ============================================================================

/// Decode SBC capability bitfields (4 bytes).
fn codec_sbc_cap(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 4 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    print_field!("{:>width$}Frequency: 0x{:02x}", ' ', cap & 0xf0, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(cap & 0xf0), SBC_FREQUENCY_TABLE);

    print_field!("{:>width$}Channel Mode: 0x{:02x}", ' ', cap & 0x0f, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(cap & 0x0f), SBC_CHANNEL_MODE_TABLE);

    let cap = frame.get_u8().unwrap_or(0);

    print_field!("{:>width$}Block Length: 0x{:02x}", ' ', cap & 0xf0, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(cap & 0xf0), SBC_BLOCKLEN_TABLE);

    print_field!("{:>width$}Subbands: 0x{:02x}", ' ', cap & 0x0c, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(cap & 0x0c), SBC_SUBBANDS_TABLE);

    print_field!("{:>width$}Allocation Method: 0x{:02x}", ' ', cap & 0x03, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(cap & 0x03), SBC_ALLOCATION_TABLE);

    let cap = frame.get_u8().unwrap_or(0);
    print_field!("{:>width$}Minimum Bitpool: {}", ' ', cap, width = BASE_INDENT);

    let cap = frame.get_u8().unwrap_or(0);
    print_field!("{:>width$}Maximum Bitpool: {}", ' ', cap, width = BASE_INDENT);

    true
}

/// Decode SBC configuration (4 bytes) — prints selected value names.
fn codec_sbc_cfg(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 4 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    print_field!(
        "{:>width$}Frequency: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0xf0), SBC_FREQUENCY_TABLE),
        cap & 0xf0,
        width = BASE_INDENT
    );

    print_field!(
        "{:>width$}Channel Mode: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0x0f), SBC_CHANNEL_MODE_TABLE),
        cap & 0x0f,
        width = BASE_INDENT
    );

    let cap = frame.get_u8().unwrap_or(0);

    print_field!(
        "{:>width$}Block Length: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0xf0), SBC_BLOCKLEN_TABLE),
        cap & 0xf0,
        width = BASE_INDENT
    );

    print_field!(
        "{:>width$}Subbands: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0x0c), SBC_SUBBANDS_TABLE),
        cap & 0x0c,
        width = BASE_INDENT
    );

    print_field!(
        "{:>width$}Allocation Method: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0x03), SBC_ALLOCATION_TABLE),
        cap & 0x03,
        width = BASE_INDENT
    );

    let cap = frame.get_u8().unwrap_or(0);
    print_field!("{:>width$}Minimum Bitpool: {}", ' ', cap, width = BASE_INDENT);

    let cap = frame.get_u8().unwrap_or(0);
    print_field!("{:>width$}Maximum Bitpool: {}", ' ', cap, width = BASE_INDENT);

    true
}

// ============================================================================
// MPEG-1,2 Audio Codec Decoder (from a2dp.c lines 378-482)
// ============================================================================

/// Decode MPEG-1,2 Audio capability bitfields (4 bytes).
fn codec_mpeg12_cap(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 4 {
        return false;
    }

    let Some(cap) = frame.get_be16() else { return false };

    let layer = ((cap >> 8) & 0xe0) as u8;
    let crc = cap & 0x1000 != 0;
    let chan = ((cap >> 8) & 0x0f) as u8;
    let mpf = cap & 0x0040 != 0;
    let freq = (cap & 0x003f) as u8;

    let Some(cap) = frame.get_be16() else { return false };

    let vbr = cap & 0x8000 != 0;
    let bitrate = cap & 0x7fff;

    print_field!("{:>width$}Layer: 0x{:02x}", ' ', layer, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(layer), MPEG12_LAYER_TABLE);

    print_field!("{:>width$}CRC: {}", ' ', if crc { "Yes" } else { "No" }, width = BASE_INDENT);

    print_field!("{:>width$}Channel Mode: 0x{:02x}", ' ', chan, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(chan), MPEG12_CHANNEL_MODE_TABLE);

    print_field!(
        "{:>width$}Media Payload Format: {}",
        ' ',
        if mpf { "RFC-2250 RFC-3119" } else { "RFC-2250" },
        width = BASE_INDENT
    );

    print_field!("{:>width$}Frequency: 0x{:02x}", ' ', freq, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(freq), MPEG12_FREQUENCY_TABLE);

    // NOTE: C code intentionally passes `freq` (not `bitrate`) to print_value_bits.
    // We replicate this exactly for behavioral clone fidelity.
    if !vbr {
        print_field!("{:>width$}Bitrate Index: 0x{:04x}", ' ', bitrate, width = BASE_INDENT);
        print_value_bits(BASE_INDENT, u32::from(freq), MPEG12_BITRATE_TABLE);
    }

    print_field!("{:>width$}VBR: {}", ' ', if vbr { "Yes" } else { "No" }, width = BASE_INDENT);

    true
}

/// Decode MPEG-1,2 Audio configuration (4 bytes).
fn codec_mpeg12_cfg(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 4 {
        return false;
    }

    let Some(cap) = frame.get_be16() else { return false };

    let layer = ((cap >> 8) & 0xe0) as u8;
    let crc = cap & 0x1000 != 0;
    let chan = ((cap >> 8) & 0x0f) as u8;
    let mpf = cap & 0x0040 != 0;
    let freq = (cap & 0x003f) as u8;

    let Some(cap) = frame.get_be16() else { return false };

    let vbr = cap & 0x8000 != 0;
    let bitrate = cap & 0x7fff;

    print_field!(
        "{:>width$}Layer: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(layer), MPEG12_LAYER_TABLE),
        layer,
        width = BASE_INDENT
    );

    print_field!("{:>width$}CRC: {}", ' ', if crc { "Yes" } else { "No" }, width = BASE_INDENT);

    print_field!(
        "{:>width$}Channel Mode: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(chan), MPEG12_CHANNEL_MODE_TABLE),
        chan,
        width = BASE_INDENT
    );

    print_field!(
        "{:>width$}Media Payload Format: {}",
        ' ',
        if mpf { "RFC-2250 RFC-3119" } else { "RFC-2250" },
        width = BASE_INDENT
    );

    print_field!(
        "{:>width$}Frequency: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(freq), MPEG12_FREQUENCY_TABLE),
        freq,
        width = BASE_INDENT
    );

    // NOTE: C code intentionally passes `freq` (not `bitrate`) to find_value_bit.
    // We replicate this exactly for behavioral clone fidelity.
    if !vbr {
        print_field!(
            "{:>width$}Bitrate Index: {} (0x{:04x})",
            ' ',
            find_value_bit(u32::from(freq), MPEG12_BITRATE_TABLE),
            bitrate,
            width = BASE_INDENT
        );
    }

    print_field!("{:>width$}VBR: {}", ' ', if vbr { "Yes" } else { "No" }, width = BASE_INDENT);

    true
}

// ============================================================================
// MPEG-2,4 AAC Codec Decoder (from a2dp.c lines 484-574)
// ============================================================================

/// Decode AAC capability bitfields (6 bytes).
fn codec_aac_cap(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 6 {
        return false;
    }

    let Some(cap) = frame.get_be16() else { return false };

    let obj_type = (cap >> 8) as u8;
    let mut freq: u16 = cap << 8;

    let Some(cap) = frame.get_be16() else { return false };

    freq |= (cap >> 8) & 0xf0;
    let chan = ((cap >> 8) & 0x0c) as u8;
    let mut bitrate: u32 = (u32::from(cap) << 16) & 0x007f_0000;
    let vbr = cap & 0x0080 != 0;

    let Some(cap) = frame.get_be16() else { return false };

    bitrate |= u32::from(cap);

    print_field!("{:>width$}Object Type: 0x{:02x}", ' ', obj_type, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(obj_type), AAC_OBJECT_TYPE_TABLE);

    print_field!("{:>width$}Frequency: 0x{:02x}", ' ', freq, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(freq), AAC_FREQUENCY_TABLE);

    print_field!("{:>width$}Channels: 0x{:02x}", ' ', chan, width = BASE_INDENT);
    print_value_bits(BASE_INDENT, u32::from(chan), AAC_CHANNELS_TABLE);

    print_field!("{:>width$}Bitrate: {}bps", ' ', bitrate, width = BASE_INDENT);
    print_field!("{:>width$}VBR: {}", ' ', if vbr { "Yes" } else { "No" }, width = BASE_INDENT);

    true
}

/// Decode AAC configuration (6 bytes).
fn codec_aac_cfg(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 6 {
        return false;
    }

    let Some(cap) = frame.get_be16() else { return false };

    let obj_type = (cap >> 8) as u8;
    let mut freq: u16 = cap << 8;

    let Some(cap) = frame.get_be16() else { return false };

    freq |= (cap >> 8) & 0xf0;
    let chan = ((cap >> 8) & 0x0c) as u8;
    let mut bitrate: u32 = (u32::from(cap) << 16) & 0x007f_0000;
    let vbr = cap & 0x0080 != 0;

    let Some(cap) = frame.get_be16() else { return false };

    bitrate |= u32::from(cap);

    print_field!(
        "{:>width$}Object Type: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(obj_type), AAC_OBJECT_TYPE_TABLE),
        obj_type,
        width = BASE_INDENT
    );

    print_field!(
        "{:>width$}Frequency: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(freq), AAC_FREQUENCY_TABLE),
        freq,
        width = BASE_INDENT
    );

    print_field!(
        "{:>width$}Channels: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(chan), AAC_CHANNELS_TABLE),
        chan,
        width = BASE_INDENT
    );

    print_field!("{:>width$}Bitrate: {}bps", ' ', bitrate, width = BASE_INDENT);
    print_field!("{:>width$}VBR: {}", ' ', if vbr { "Yes" } else { "No" }, width = BASE_INDENT);

    true
}

// ============================================================================
// Vendor Codec Decoders (from a2dp.c lines 576-733)
// ============================================================================

/// Decode aptX capability (1 byte after vendor header).
fn codec_vendor_aptx_cap(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 1 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    print_field!("{:>width$}Frequency: 0x{:02x}", ' ', cap & 0xf0, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap & 0xf0), APTX_FREQUENCY_TABLE);

    print_field!("{:>width$}Channel Mode: 0x{:02x}", ' ', cap & 0x0f, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap & 0x0f), APTX_CHANNEL_MODE_TABLE);

    true
}

/// Decode aptX configuration (1 byte after vendor header).
fn codec_vendor_aptx_cfg(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 1 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    print_field!(
        "{:>width$}Frequency: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0xf0), APTX_FREQUENCY_TABLE),
        cap & 0xf0,
        width = BASE_INDENT + 2
    );

    print_field!(
        "{:>width$}Channel Mode: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0x0f), APTX_CHANNEL_MODE_TABLE),
        cap & 0x0f,
        width = BASE_INDENT + 2
    );

    true
}

/// Decode FastStream capability (2 bytes after vendor header).
fn codec_vendor_faststream_cap(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 2 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    print_field!("{:>width$}Direction: 0x{:02x}", ' ', cap, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap), FASTSTREAM_DIRECTION_TABLE);

    let cap = frame.get_u8().unwrap_or(0);

    print_field!("{:>width$}Sink Frequency: 0x{:02x}", ' ', cap & 0x0f, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap & 0x0f), FASTSTREAM_SINK_FREQUENCY_TABLE);

    print_field!("{:>width$}Source Frequency: 0x{:02x}", ' ', cap & 0xf0, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap & 0xf0), FASTSTREAM_SOURCE_FREQUENCY_TABLE);

    true
}

/// Decode FastStream configuration (2 bytes after vendor header).
fn codec_vendor_faststream_cfg(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 2 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    // FastStream codec is bi-directional
    print_field!("{:>width$}Direction: 0x{:02x}", ' ', cap, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap), FASTSTREAM_DIRECTION_TABLE);

    let cap = frame.get_u8().unwrap_or(0);

    print_field!(
        "{:>width$}Sink Frequency: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0x0f), FASTSTREAM_SINK_FREQUENCY_TABLE),
        cap & 0x0f,
        width = BASE_INDENT + 2
    );

    print_field!(
        "{:>width$}Source Frequency: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0xf0), FASTSTREAM_SOURCE_FREQUENCY_TABLE),
        cap & 0xf0,
        width = BASE_INDENT + 2
    );

    true
}

/// Decode aptX Low Latency capability (2 or 11 bytes after vendor header).
fn codec_vendor_aptx_ll_cap(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 2 && losc != 11 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    print_field!("{:>width$}Frequency: 0x{:02x}", ' ', cap & 0xf0, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap & 0xf0), APTX_FREQUENCY_TABLE);

    print_field!("{:>width$}Channel Mode: 0x{:02x}", ' ', cap & 0x0f, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap & 0x0f), APTX_CHANNEL_MODE_TABLE);

    let cap = frame.get_u8().unwrap_or(0);

    print_field!(
        "{:>width$}Bidirectional link: {}",
        ' ',
        if cap & 1 != 0 { "Yes" } else { "No" },
        width = BASE_INDENT
    );

    if (cap & 2 != 0) && losc == 11 {
        // Reserved byte
        let _ = frame.get_u8();

        let level = frame.get_le16().unwrap_or(0);
        print_field!(
            "{:>width$}Target codec buffer level: {} (0x{:02x})",
            ' ',
            level,
            level,
            width = BASE_INDENT + 2
        );

        let level = frame.get_le16().unwrap_or(0);
        print_field!(
            "{:>width$}Initial codec buffer level: {} (0x{:02x})",
            ' ',
            level,
            level,
            width = BASE_INDENT + 2
        );

        let cap = frame.get_u8().unwrap_or(0);
        let sra_rate = f64::from(cap) / 10000.0;
        print_field!(
            "{:>width$}SRA max rate: {} (0x{:02x})",
            ' ',
            sra_rate,
            cap,
            width = BASE_INDENT + 2
        );

        let cap = frame.get_u8().unwrap_or(0);
        print_field!(
            "{:>width$}SRA averaging time: {}s (0x{:02x})",
            ' ',
            cap,
            cap,
            width = BASE_INDENT + 2
        );

        let level = frame.get_le16().unwrap_or(0);
        print_field!(
            "{:>width$}Good working codec buffer level: {} (0x{:02x})",
            ' ',
            level,
            level,
            width = BASE_INDENT + 2
        );
    }

    true
}

/// Decode aptX Low Latency configuration (2 or 11 bytes after vendor header).
fn codec_vendor_aptx_ll_cfg(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 2 && losc != 11 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    print_field!(
        "{:>width$}Frequency: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0xf0), APTX_FREQUENCY_TABLE),
        cap & 0xf0,
        width = BASE_INDENT + 2
    );

    print_field!(
        "{:>width$}Channel Mode: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0x0f), APTX_CHANNEL_MODE_TABLE),
        cap & 0x0f,
        width = BASE_INDENT + 2
    );

    let cap = frame.get_u8().unwrap_or(0);

    print_field!(
        "{:>width$}Bidirectional link: {}",
        ' ',
        if cap & 1 != 0 { "Yes" } else { "No" },
        width = BASE_INDENT
    );

    if (cap & 2 != 0) && losc == 11 {
        // Reserved byte
        let _ = frame.get_u8();

        let level = frame.get_le16().unwrap_or(0);
        print_field!(
            "{:>width$}Target codec buffer level: {} (0x{:02x})",
            ' ',
            level,
            level,
            width = BASE_INDENT + 2
        );

        let level = frame.get_le16().unwrap_or(0);
        print_field!(
            "{:>width$}Initial codec buffer level: {} (0x{:02x})",
            ' ',
            level,
            level,
            width = BASE_INDENT + 2
        );

        let cap = frame.get_u8().unwrap_or(0);
        let sra_rate = f64::from(cap) / 10000.0;
        print_field!(
            "{:>width$}SRA max rate: {} (0x{:02x})",
            ' ',
            sra_rate,
            cap,
            width = BASE_INDENT + 2
        );

        let cap = frame.get_u8().unwrap_or(0);
        print_field!(
            "{:>width$}SRA averaging time: {}s (0x{:02x})",
            ' ',
            cap,
            cap,
            width = BASE_INDENT + 2
        );

        let level = frame.get_le16().unwrap_or(0);
        print_field!(
            "{:>width$}Good working codec buffer level: {} (0x{:02x})",
            ' ',
            level,
            level,
            width = BASE_INDENT + 2
        );
    }

    true
}

/// Decode aptX HD capability (5 bytes after vendor header: 1 freq/chan + 4 reserved).
fn codec_vendor_aptx_hd_cap(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 5 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    print_field!("{:>width$}Frequency: 0x{:02x}", ' ', cap & 0xf0, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap & 0xf0), APTX_FREQUENCY_TABLE);

    print_field!("{:>width$}Channel Mode: 0x{:02x}", ' ', cap & 0x0f, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap & 0x0f), APTX_CHANNEL_MODE_TABLE);

    // 4 reserved bytes
    let _ = frame.get_u8();
    let _ = frame.get_u8();
    let _ = frame.get_u8();
    let _ = frame.get_u8();

    true
}

/// Decode aptX HD configuration (5 bytes after vendor header: 1 freq/chan + 4 reserved).
fn codec_vendor_aptx_hd_cfg(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 5 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    print_field!(
        "{:>width$}Frequency: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0xf0), APTX_FREQUENCY_TABLE),
        cap & 0xf0,
        width = BASE_INDENT + 2
    );

    print_field!(
        "{:>width$}Channel Mode: {} (0x{:02x})",
        ' ',
        find_value_bit(u32::from(cap & 0x0f), APTX_CHANNEL_MODE_TABLE),
        cap & 0x0f,
        width = BASE_INDENT + 2
    );

    // 4 reserved bytes
    let _ = frame.get_u8();
    let _ = frame.get_u8();
    let _ = frame.get_u8();
    let _ = frame.get_u8();

    true
}

/// Decode LDAC capability or configuration (2 bytes after vendor header).
/// Both cap and cfg use the same decoder in the C original.
fn codec_vendor_ldac(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 2 {
        return false;
    }

    let cap = frame.get_le16().unwrap_or(0);

    print_field!("{:>width$}Unknown: 0x{:04x}", ' ', cap, width = BASE_INDENT + 2);

    true
}

/// Decode Opus (Google) capability or configuration (1 byte after vendor header).
/// Both cap and cfg use the same decoder in the C original.
fn codec_vendor_opus_g(losc: u8, frame: &mut L2capFrame) -> bool {
    if losc != 1 {
        return false;
    }

    let cap = frame.get_u8().unwrap_or(0);

    print_field!("{:>width$}Frequency: 0x{:02x}", ' ', cap & 0x80, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap), OPUS_G_FREQUENCY_TABLE);

    print_field!("{:>width$}Frame Duration: 0x{:02x}", ' ', cap & 0x18, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap), OPUS_G_DURATION_TABLE);

    print_field!("{:>width$}Channel Mode: 0x{:02x}", ' ', cap & 0x07, width = BASE_INDENT + 2);
    print_value_bits(BASE_INDENT + 2, u32::from(cap), OPUS_G_CHANNELS_TABLE);

    print_field!("{:>width$}Reserved: 0x{:02x}", ' ', cap & 0x60, width = BASE_INDENT + 2);

    true
}

// ============================================================================
// Vendor Codec Dispatch (from a2dp.c lines 736-923)
// ============================================================================

/// Decode vendor-specific codec capability.
/// Reads vendor ID (LE32) and codec ID (LE16), prints them, then dispatches
/// to the appropriate vendor codec decoder. Falls back to hexdump for
/// unrecognised vendor/codec pairs.
fn codec_vendor_cap(mut losc: u8, frame: &mut L2capFrame) -> bool {
    if losc < 6 {
        return false;
    }

    let vendor_id = frame.get_le32().unwrap_or(0);
    let codec_id = frame.get_le16().unwrap_or(0);

    losc -= 6;

    print_field!(
        "{:>width$}Vendor ID: {} (0x{:08x})",
        ' ',
        bt_compidtostr(vendor_id as i32),
        vendor_id,
        width = BASE_INDENT
    );

    print_field!(
        "{:>width$}Vendor Specific Codec ID: {} (0x{:04x})",
        ' ',
        vndcodec2str(vendor_id, codec_id),
        codec_id,
        width = BASE_INDENT
    );

    match (vendor_id, codec_id) {
        (APTX_VENDOR_ID, APTX_CODEC_ID) => return codec_vendor_aptx_cap(losc, frame),
        (FASTSTREAM_VENDOR_ID, FASTSTREAM_CODEC_ID) => {
            return codec_vendor_faststream_cap(losc, frame);
        }
        (APTX_LL_VENDOR_ID, APTX_LL_CODEC_ID) => return codec_vendor_aptx_ll_cap(losc, frame),
        (APTX_HD_VENDOR_ID, APTX_HD_CODEC_ID) => return codec_vendor_aptx_hd_cap(losc, frame),
        (LDAC_VENDOR_ID, LDAC_CODEC_ID) => return codec_vendor_ldac(losc, frame),
        (OPUS_G_VENDOR_ID, OPUS_G_CODEC_ID) => return codec_vendor_opus_g(losc, frame),
        _ => {}
    }

    // Unknown vendor codec — hexdump remaining bytes
    hexdump_and_pull(frame, losc);

    true
}

/// Decode vendor-specific codec configuration.
/// Same dispatch pattern as `codec_vendor_cap` but routes to `*_cfg` handlers.
fn codec_vendor_cfg(mut losc: u8, frame: &mut L2capFrame) -> bool {
    if losc < 6 {
        return false;
    }

    let vendor_id = frame.get_le32().unwrap_or(0);
    let codec_id = frame.get_le16().unwrap_or(0);

    losc -= 6;

    print_field!(
        "{:>width$}Vendor ID: {} (0x{:08x})",
        ' ',
        bt_compidtostr(vendor_id as i32),
        vendor_id,
        width = BASE_INDENT
    );

    print_field!(
        "{:>width$}Vendor Specific Codec ID: {} (0x{:04x})",
        ' ',
        vndcodec2str(vendor_id, codec_id),
        codec_id,
        width = BASE_INDENT
    );

    match (vendor_id, codec_id) {
        (APTX_VENDOR_ID, APTX_CODEC_ID) => return codec_vendor_aptx_cfg(losc, frame),
        (FASTSTREAM_VENDOR_ID, FASTSTREAM_CODEC_ID) => {
            return codec_vendor_faststream_cfg(losc, frame);
        }
        (APTX_LL_VENDOR_ID, APTX_LL_CODEC_ID) => return codec_vendor_aptx_ll_cfg(losc, frame),
        (APTX_HD_VENDOR_ID, APTX_HD_CODEC_ID) => return codec_vendor_aptx_hd_cfg(losc, frame),
        (LDAC_VENDOR_ID, LDAC_CODEC_ID) => return codec_vendor_ldac(losc, frame),
        (OPUS_G_VENDOR_ID, OPUS_G_CODEC_ID) => return codec_vendor_opus_g(losc, frame),
        _ => {}
    }

    // Unknown vendor codec — hexdump remaining bytes
    hexdump_and_pull(frame, losc);

    true
}

// ============================================================================
// Public API (from a2dp.h lines 11-13, a2dp.c lines 925-959)
// ============================================================================

/// Decode an A2DP media codec capability element.
///
/// Dispatches to the appropriate codec-specific decoder based on the `codec`
/// type identifier. Returns `true` on success, `false` on parse error.
///
/// # Arguments
/// * `codec` — A2DP codec type (SBC=0x00, MPEG12=0x01, MPEG24=0x02,
///   ATRAC=0x04, Vendor=0xFF)
/// * `losc`  — Length of Service Capability (codec-specific bytes)
/// * `frame` — Frame cursor positioned at the start of codec data
pub fn a2dp_codec_cap(codec: u8, losc: u8, frame: &mut L2capFrame) -> bool {
    match codec {
        A2DP_CODEC_SBC => codec_sbc_cap(losc, frame),
        A2DP_CODEC_MPEG12 => codec_mpeg12_cap(losc, frame),
        A2DP_CODEC_MPEG24 => codec_aac_cap(losc, frame),
        A2DP_CODEC_VENDOR => codec_vendor_cap(losc, frame),
        // ATRAC has no dedicated decoder — hexdump the raw payload
        A2DP_CODEC_ATRAC => {
            hexdump_and_pull(frame, losc);
            true
        }
        // All other unrecognised standard codec types
        _ => {
            hexdump_and_pull(frame, losc);
            true
        }
    }
}

/// Decode an A2DP media codec configuration element.
///
/// Dispatches to the appropriate codec-specific decoder based on the `codec`
/// type identifier. Returns `true` on success, `false` on parse error.
///
/// # Arguments
/// * `codec` — A2DP codec type (SBC=0x00, MPEG12=0x01, MPEG24=0x02,
///   ATRAC=0x04, Vendor=0xFF)
/// * `losc`  — Length of Service Capability (codec-specific bytes)
/// * `frame` — Frame cursor positioned at the start of codec data
pub fn a2dp_codec_cfg(codec: u8, losc: u8, frame: &mut L2capFrame) -> bool {
    match codec {
        A2DP_CODEC_SBC => codec_sbc_cfg(losc, frame),
        A2DP_CODEC_MPEG12 => codec_mpeg12_cfg(losc, frame),
        A2DP_CODEC_MPEG24 => codec_aac_cfg(losc, frame),
        A2DP_CODEC_VENDOR => codec_vendor_cfg(losc, frame),
        // ATRAC has no dedicated decoder — hexdump the raw payload
        A2DP_CODEC_ATRAC => {
            hexdump_and_pull(frame, losc);
            true
        }
        // All other unrecognised standard codec types
        _ => {
            hexdump_and_pull(frame, losc);
            true
        }
    }
}
