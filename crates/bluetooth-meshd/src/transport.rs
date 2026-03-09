// SPDX-License-Identifier: GPL-2.0-or-later
//
// Mesh transport layer — replaces transport portions of mesh/net.c
//
// Handles segmentation and reassembly of transport PDUs.

use std::collections::HashMap;

/// Maximum unsegmented access payload size.
pub const MAX_UNSEG_PAYLOAD: usize = 15;

/// Maximum segment payload size.
pub const MAX_SEG_PAYLOAD: usize = 12;

/// Maximum total segmented message payload (32 segments * 12 bytes).
pub const MAX_SEG_TOTAL: usize = 32 * MAX_SEG_PAYLOAD;

/// Maximum number of segments (0-indexed, so 32 segments = seg_count 31).
pub const MAX_SEG_COUNT: u8 = 31;

/// A lower transport PDU.
#[derive(Debug, Clone)]
pub struct TransportPdu {
    /// Segmented flag.
    pub seg: bool,
    /// Application key flag (true = app key, false = device key).
    pub akf: bool,
    /// Application key identifier (6-bit).
    pub aid: u8,
    /// Upper transport payload.
    pub payload: Vec<u8>,
}

/// A transport segment with full header info for network-layer framing.
#[derive(Debug, Clone)]
pub struct TransportSegment {
    /// Segment index (SegO).
    pub seg_index: u8,
    /// Total segment count minus 1 (SegN).
    pub seg_count: u8,
    /// SeqZero — lower 13 bits of the sequence number of the first segment.
    pub seq_zero: u16,
    /// Application key flag.
    pub akf: bool,
    /// Application key identifier (6-bit).
    pub aid: u8,
    /// Segment payload (up to 12 bytes).
    pub payload: Vec<u8>,
}

/// Segmentation state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentState {
    Idle,
    Sending,
    Receiving,
}

/// Tracks reassembly of an incoming segmented message.
#[derive(Debug)]
pub struct SegmentedMessage {
    /// Source address.
    pub src: u16,
    /// Sequence number of the first segment (SeqZero).
    pub seq_zero: u16,
    /// Total number of segments minus 1 (SegN).
    pub seg_count: u8,
    /// Received segments bitmap.
    pub received_mask: u32,
    /// Reassembly buffer.
    pub buffer: Vec<u8>,
    /// Actual length of valid data (last segment may be shorter).
    pub total_len: usize,
    /// Current state.
    pub state: SegmentState,
}

impl SegmentedMessage {
    /// Create a new reassembly context.
    pub fn new(src: u16, seq_zero: u16, seg_count: u8) -> Self {
        Self {
            src,
            seq_zero,
            seg_count,
            received_mask: 0,
            buffer: vec![0u8; (seg_count as usize + 1) * MAX_SEG_PAYLOAD],
            total_len: 0,
            state: SegmentState::Receiving,
        }
    }

    /// Process a received segment. Returns true if all segments have been received.
    pub fn receive_segment(&mut self, seg_index: u8, data: &[u8]) -> bool {
        if seg_index > self.seg_count {
            return false;
        }

        let offset = seg_index as usize * MAX_SEG_PAYLOAD;
        let end = (offset + data.len()).min(self.buffer.len());
        let copy_len = end - offset;
        self.buffer[offset..end].copy_from_slice(&data[..copy_len]);
        self.received_mask |= 1 << seg_index;

        // Track total length: if this is the last segment, the actual length is
        // seg_count * MAX_SEG_PAYLOAD + data.len() for the last chunk
        if seg_index == self.seg_count {
            self.total_len = offset + data.len();
        }

        self.is_complete()
    }

    /// Check if all segments have been received.
    pub fn is_complete(&self) -> bool {
        let expected = (1u32 << (self.seg_count as u32 + 1)) - 1;
        (self.received_mask & expected) == expected
    }

    /// Get the reassembled payload (only valid when complete).
    /// Returns the exact-length payload (not padded to segment boundaries).
    pub fn payload(&self) -> &[u8] {
        if self.total_len > 0 {
            &self.buffer[..self.total_len]
        } else {
            &self.buffer
        }
    }

    /// Build a block acknowledgment message.
    /// Returns the 32-bit bitmap of received segments.
    pub fn block_ack(&self) -> u32 {
        self.received_mask
    }

    /// Check which segments are still missing.
    pub fn missing_segments(&self) -> Vec<u8> {
        let expected = (1u32 << (self.seg_count as u32 + 1)) - 1;
        let missing_mask = expected & !self.received_mask;
        let mut missing = Vec::new();
        for i in 0..=self.seg_count {
            if missing_mask & (1 << i) != 0 {
                missing.push(i);
            }
        }
        missing
    }
}

/// Segment an access PDU into transport segments with full header information.
///
/// `pdu` — the upper transport PDU bytes to segment.
/// `seq` — the sequence number for SeqZero (lower 13 bits used).
/// `akf` — application key flag.
/// `aid` — application key identifier.
///
/// Returns a list of `TransportSegment`s. If the PDU fits in a single
/// unsegmented message, returns one segment with `seg_index=0` and `seg_count=0`.
pub fn segment_access_pdu(
    pdu: &[u8],
    seq: u32,
    akf: bool,
    aid: u8,
) -> Vec<TransportSegment> {
    let seq_zero = (seq & 0x1FFF) as u16;

    if pdu.len() <= MAX_UNSEG_PAYLOAD {
        return vec![TransportSegment {
            seg_index: 0,
            seg_count: 0,
            seq_zero,
            akf,
            aid,
            payload: pdu.to_vec(),
        }];
    }

    let chunks: Vec<&[u8]> = pdu.chunks(MAX_SEG_PAYLOAD).collect();
    let seg_count = (chunks.len() - 1) as u8;

    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| TransportSegment {
            seg_index: i as u8,
            seg_count,
            seq_zero,
            akf,
            aid,
            payload: chunk.to_vec(),
        })
        .collect()
}

/// Reassemble an access PDU from a set of transport segments.
///
/// Segments must all belong to the same message (same src, seq_zero).
/// Returns `None` if segments are incomplete or inconsistent.
pub fn reassemble_access_pdu(segments: &[TransportSegment]) -> Option<Vec<u8>> {
    if segments.is_empty() {
        return None;
    }

    // For unsegmented (seg_count == 0)
    if segments.len() == 1 && segments[0].seg_count == 0 {
        return Some(segments[0].payload.clone());
    }

    let seg_count = segments[0].seg_count;
    let seq_zero = segments[0].seq_zero;

    // Verify all segments agree on seg_count and seq_zero
    for seg in segments {
        if seg.seg_count != seg_count || seg.seq_zero != seq_zero {
            return None;
        }
    }

    // Check that we have all segments
    let expected_count = seg_count as usize + 1;
    if segments.len() != expected_count {
        return None;
    }

    // Sort by seg_index and concatenate
    let mut sorted: Vec<&TransportSegment> = segments.iter().collect();
    sorted.sort_by_key(|s| s.seg_index);

    // Verify indices are 0..seg_count with no gaps
    for (i, seg) in sorted.iter().enumerate() {
        if seg.seg_index != i as u8 {
            return None;
        }
    }

    let mut result = Vec::new();
    for seg in &sorted {
        result.extend_from_slice(&seg.payload);
    }
    Some(result)
}

/// Build a segment acknowledgment message (opcode 0x00 for control).
///
/// Format per Mesh Profile spec 3.5.2.3:
/// - OBO(1) || SeqZero(13) || RFU(2) || BlockAck(32) = 6 bytes total
pub fn build_segment_ack(obo: bool, seq_zero: u16, block_ack: u32) -> [u8; 6] {
    let mut ack = [0u8; 6];
    // Byte 0: OBO(1) | SeqZero[12:7]
    let obo_bit = if obo { 0x80u8 } else { 0x00 };
    ack[0] = obo_bit | ((seq_zero >> 6) as u8 & 0x7F);
    // Byte 1: SeqZero[6:0] | RFU(1)
    ack[1] = ((seq_zero & 0x3F) as u8) << 2;
    // Bytes 2..6: BlockAck (big-endian)
    ack[2] = (block_ack >> 24) as u8;
    ack[3] = (block_ack >> 16) as u8;
    ack[4] = (block_ack >> 8) as u8;
    ack[5] = block_ack as u8;
    ack
}

/// Segmentation/reassembly engine for the lower transport layer.
#[derive(Debug, Default)]
pub struct TransportLayer {
    /// Pending incoming segmented messages keyed by (src, seq_zero).
    pending_rx: HashMap<(u16, u16), SegmentedMessage>,
}

impl TransportLayer {
    pub fn new() -> Self {
        Self {
            pending_rx: HashMap::new(),
        }
    }

    /// Segment an outgoing upper transport PDU into lower transport segments.
    pub fn segment_pdu(payload: &[u8], akf: bool, aid: u8) -> Vec<TransportPdu> {
        if payload.len() <= MAX_UNSEG_PAYLOAD {
            return vec![TransportPdu {
                seg: false,
                akf,
                aid,
                payload: payload.to_vec(),
            }];
        }

        payload
            .chunks(MAX_SEG_PAYLOAD)
            .map(|chunk| TransportPdu {
                seg: true,
                akf,
                aid,
                payload: chunk.to_vec(),
            })
            .collect()
    }

    /// Process an incoming segment. Returns the complete reassembled payload when done.
    pub fn process_segment(
        &mut self,
        src: u16,
        seq_zero: u16,
        seg_index: u8,
        seg_count: u8,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let key = (src, seq_zero);
        let msg = self
            .pending_rx
            .entry(key)
            .or_insert_with(|| SegmentedMessage::new(src, seq_zero, seg_count));

        if msg.receive_segment(seg_index, data) {
            let payload = msg.payload().to_vec();
            self.pending_rx.remove(&key);
            Some(payload)
        } else {
            None
        }
    }

    /// Get a block acknowledgment bitmap for a pending message.
    pub fn get_block_ack(&self, src: u16, seq_zero: u16) -> Option<u32> {
        self.pending_rx.get(&(src, seq_zero)).map(|msg| msg.block_ack())
    }

    /// Check if there are any pending reassembly contexts.
    pub fn has_pending(&self) -> bool {
        !self.pending_rx.is_empty()
    }

    /// Remove a timed-out reassembly context.
    pub fn timeout_reassembly(&mut self, src: u16, seq_zero: u16) -> bool {
        self.pending_rx.remove(&(src, seq_zero)).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsegmented_pdu() {
        let payload = vec![0x01; 10];
        let segments = TransportLayer::segment_pdu(&payload, true, 0x05);
        assert_eq!(segments.len(), 1);
        assert!(!segments[0].seg);
        assert_eq!(segments[0].payload, payload);
    }

    #[test]
    fn test_segmented_reassembly() {
        let mut transport = TransportLayer::new();

        // 3 segments (seg_count = 2 means indices 0, 1, 2)
        let seg_count = 2;
        let data0 = vec![0xAA; MAX_SEG_PAYLOAD];
        let data1 = vec![0xBB; MAX_SEG_PAYLOAD];
        let data2 = vec![0xCC; 4];

        assert!(transport
            .process_segment(0x0001, 100, 0, seg_count, &data0)
            .is_none());
        assert!(transport
            .process_segment(0x0001, 100, 1, seg_count, &data1)
            .is_none());

        let result = transport
            .process_segment(0x0001, 100, 2, seg_count, &data2)
            .unwrap();

        // First 12 bytes should be 0xAA
        assert_eq!(&result[..MAX_SEG_PAYLOAD], &data0[..]);
        // Next 12 bytes should be 0xBB
        assert_eq!(
            &result[MAX_SEG_PAYLOAD..2 * MAX_SEG_PAYLOAD],
            &data1[..]
        );
        // Last 4 bytes should be 0xCC
        assert_eq!(&result[2 * MAX_SEG_PAYLOAD..], &data2[..]);
    }

    #[test]
    fn test_segment_and_reassemble() {
        // Create a payload that requires segmentation
        let original = vec![0x42u8; 30]; // 30 bytes > 15 (unseg limit), needs 3 segments of 12
        let segments = segment_access_pdu(&original, 0x1234, true, 0x0A);

        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].seg_count, 2);
        assert_eq!(segments[0].seg_index, 0);
        assert_eq!(segments[1].seg_index, 1);
        assert_eq!(segments[2].seg_index, 2);
        assert_eq!(segments[0].seq_zero, 0x1234 & 0x1FFF);

        // Reassemble
        let reassembled = reassemble_access_pdu(&segments).unwrap();
        assert_eq!(reassembled, original);
    }

    #[test]
    fn test_segment_single_unsegmented() {
        let original = vec![0x55u8; 10]; // fits in unsegmented
        let segments = segment_access_pdu(&original, 42, false, 0x00);

        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].seg_count, 0);
        assert_eq!(segments[0].seg_index, 0);

        let reassembled = reassemble_access_pdu(&segments).unwrap();
        assert_eq!(reassembled, original);
    }

    #[test]
    fn test_reassemble_incomplete_fails() {
        let original = vec![0x42u8; 30];
        let segments = segment_access_pdu(&original, 100, true, 0x05);

        // Only pass first 2 of 3 segments
        let partial = &segments[..2];
        assert!(reassemble_access_pdu(partial).is_none());
    }

    #[test]
    fn test_block_ack() {
        let mut msg = SegmentedMessage::new(0x0001, 100, 2);
        assert_eq!(msg.block_ack(), 0);
        assert_eq!(msg.missing_segments(), vec![0, 1, 2]);

        msg.receive_segment(0, &[0xAA; 12]);
        assert_eq!(msg.block_ack(), 0x01);
        assert_eq!(msg.missing_segments(), vec![1, 2]);

        msg.receive_segment(2, &[0xCC; 4]);
        assert_eq!(msg.block_ack(), 0x05);
        assert_eq!(msg.missing_segments(), vec![1]);
    }

    #[test]
    fn test_build_segment_ack() {
        let ack = build_segment_ack(false, 0x100, 0x07);
        // Verify it's 6 bytes
        assert_eq!(ack.len(), 6);
        // Block ack bytes should encode 0x00000007
        assert_eq!(ack[2], 0x00);
        assert_eq!(ack[3], 0x00);
        assert_eq!(ack[4], 0x00);
        assert_eq!(ack[5], 0x07);
    }

    #[test]
    fn test_transport_layer_timeout() {
        let mut transport = TransportLayer::new();
        transport.process_segment(0x0001, 100, 0, 2, &[0xAA; 12]);
        assert!(transport.has_pending());

        // Timeout the pending reassembly
        assert!(transport.timeout_reassembly(0x0001, 100));
        assert!(!transport.has_pending());

        // Double timeout returns false
        assert!(!transport.timeout_reassembly(0x0001, 100));
    }
}
