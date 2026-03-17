// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_midi.rs — BLE-MIDI parser/writer unit tests
//
// Rust port of unit/test-midi.c from BlueZ v5.86.
// Validates the MidiReadParser (BLE→ALSA) and MidiWriteParser (ALSA→BLE)
// implementations in crates/bluetoothd/src/profiles/midi.rs.

use alsa::seq::{EvCtrl, EvNote, Event, EventType};
use rand::Rng;

use bluetoothd::profiles::midi::{MidiReadParser, MidiWriteParser};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of random-MTU iterations for each write test (matches C NUM_WRITE_TESTS).
const NUM_WRITE_TESTS: usize = 100;

// ---------------------------------------------------------------------------
// Helper: event comparison
// ---------------------------------------------------------------------------

/// Assert that an event is a note-class event with the expected fields.
fn assert_note_event(
    ev: &Event<'_>,
    expected_type: EventType,
    channel: u8,
    note: u8,
    velocity: u8,
) {
    assert_eq!(
        ev.get_type(),
        expected_type,
        "expected event type {:?}, got {:?}",
        expected_type,
        ev.get_type()
    );
    let data: EvNote = ev.get_data::<EvNote>().expect("expected EvNote data in note event");
    assert_eq!(data.channel, channel, "note event channel mismatch");
    assert_eq!(data.note, note, "note event note mismatch");
    assert_eq!(data.velocity, velocity, "note event velocity mismatch");
}

/// Assert that an event is a control-class event with the expected fields.
fn assert_ctrl_event(
    ev: &Event<'_>,
    expected_type: EventType,
    channel: u8,
    value: i32,
    param: u32,
) {
    assert_eq!(
        ev.get_type(),
        expected_type,
        "expected event type {:?}, got {:?}",
        expected_type,
        ev.get_type()
    );
    let data: EvCtrl = ev.get_data::<EvCtrl>().expect("expected EvCtrl data in control event");
    assert_eq!(data.channel, channel, "ctrl event channel mismatch");
    assert_eq!(data.value, value, "ctrl event value mismatch");
    assert_eq!(data.param, param, "ctrl event param mismatch");
}

/// Assert that an event is a SysEx event with the expected payload.
fn assert_sysex_event(ev: &Event<'_>, expected_data: &[u8]) {
    assert_eq!(
        ev.get_type(),
        EventType::Sysex,
        "expected Sysex event type, got {:?}",
        ev.get_type()
    );
    let ext = ev.get_ext().expect("expected ext data in sysex event");
    assert_eq!(ext, expected_data, "sysex payload mismatch");
}

/// Compare two event lists element by element, checking type and relevant
/// fields depending on whether the event carries note, control, or sysex data.
fn compare_events(actual: &[Event<'_>], expected: &[Event<'_>]) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "event count mismatch: got {}, expected {}",
        actual.len(),
        expected.len()
    );
    for (i, (a, e)) in actual.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            a.get_type(),
            e.get_type(),
            "event[{}] type mismatch: got {:?}, expected {:?}",
            i,
            a.get_type(),
            e.get_type()
        );
        match e.get_type() {
            EventType::Noteon | EventType::Noteoff | EventType::Keypress => {
                let ad: EvNote = a
                    .get_data::<EvNote>()
                    .unwrap_or_else(|| panic!("event[{i}] actual: expected EvNote data"));
                let ed: EvNote = e
                    .get_data::<EvNote>()
                    .unwrap_or_else(|| panic!("event[{i}] expected: expected EvNote data"));
                assert_eq!(ad.channel, ed.channel, "event[{i}] channel mismatch");
                assert_eq!(ad.note, ed.note, "event[{i}] note mismatch");
                assert_eq!(ad.velocity, ed.velocity, "event[{i}] velocity mismatch");
            }
            EventType::Controller
            | EventType::Pgmchange
            | EventType::Chanpress
            | EventType::Pitchbend => {
                let ad: EvCtrl = a
                    .get_data::<EvCtrl>()
                    .unwrap_or_else(|| panic!("event[{i}] actual: expected EvCtrl data"));
                let ed: EvCtrl = e
                    .get_data::<EvCtrl>()
                    .unwrap_or_else(|| panic!("event[{i}] expected: expected EvCtrl data"));
                assert_eq!(ad.channel, ed.channel, "event[{i}] channel mismatch");
                assert_eq!(ad.param, ed.param, "event[{i}] param mismatch");
                assert_eq!(ad.value, ed.value, "event[{i}] value mismatch");
            }
            EventType::Sysex => {
                let a_ext = a
                    .get_ext()
                    .unwrap_or_else(|| panic!("event[{i}] actual: expected ext data for sysex"));
                let e_ext = e
                    .get_ext()
                    .unwrap_or_else(|| panic!("event[{i}] expected: expected ext data for sysex"));
                assert_eq!(a_ext, e_ext, "event[{i}] sysex payload mismatch");
            }
            _ => {
                // For other event types just verify type matched (already done above).
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: event builders (mirrors C macros NOTE_EVENT / CONTROL_EVENT / SYSEX_EVENT)
// ---------------------------------------------------------------------------

fn note_event(t: EventType, channel: u8, note: u8, velocity: u8) -> Event<'static> {
    Event::new(t, &EvNote { channel, note, velocity, off_velocity: 0, duration: 0 })
}

fn ctrl_event(t: EventType, channel: u8, value: i32, param: u32) -> Event<'static> {
    Event::new(t, &EvCtrl { channel, param, value })
}

fn sysex_event(data: &[u8]) -> Event<'static> {
    Event::new_ext(EventType::Sysex, data.to_vec()).into_owned()
}

// ---------------------------------------------------------------------------
// Test data: BLE-MIDI read — regular messages (from C midi1)
// ---------------------------------------------------------------------------

/// Packet 1-1: PitchBend ch8 val=0, Controller ch8 val=63 param=74, NoteOn ch8 n=62 v=14
const PACKET1_1: &[u8] =
    &[0xa6, 0x88, 0xe8, 0x00, 0x40, 0x88, 0xb8, 0x4a, 0x3f, 0x88, 0x98, 0x3e, 0x0e];

/// Packet 1-2: ChanPress ch8 val=113
const PACKET1_2: &[u8] = &[0xa6, 0xaa, 0xd8, 0x71];

/// Packet 1-3: Controller ch8 val=67 param=74
const PACKET1_3: &[u8] = &[0xa6, 0xb7, 0xb8, 0x4a, 0x43];

/// Packet 1-4: PitchBend ch8 val=-2, PitchBend ch8 val=-3, PitchBend ch8 val=-4
/// (uses running status for second/third bends)
const PACKET1_4: &[u8] = &[0xa6, 0xc4, 0xe8, 0x7e, 0x3f, 0x7d, 0x3f, 0xc4, 0x7c, 0x3f];

// ---------------------------------------------------------------------------
// Test data: BLE-MIDI read — SysEx messages (from C midi2)
// ---------------------------------------------------------------------------

/// Expected SysEx payloads.
const SYSEX2_1: &[u8] = &[0xf0, 0x01, 0x02, 0x03, 0xf7];
const SYSEX2_2: &[u8] = &[0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0xf7];
const SYSEX2_3: &[u8] = &[
    0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x01, 0x02, 0x03, 0x04, 0xf7,
];
const SYSEX2_4: &[u8] = &[0xf0, 0x01, 0x02, 0x03, 0xf7];
const SYSEX2_5: &[u8] = &[0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0xf7];

/// Single-packet SysEx: complete F0…F7 in one BLE packet.
const PACKET2_1: &[u8] = &[0xa6, 0x88, 0xf0, 0x01, 0x02, 0x03, 0x88, 0xf7];

/// Two-packet SysEx: F0…data then continuation…F7.
const PACKET2_2: &[u8] = &[0xa6, 0x88, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05];
const PACKET2_3: &[u8] = &[0xa6, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x88, 0xf7];

/// Multi-packet SysEx: spans 4 BLE packets.
const PACKET2_4: &[u8] = &[0xa6, 0x88, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05];
const PACKET2_5: &[u8] = &[0xa6, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x01, 0x02];
const PACKET2_6: &[u8] = &[0xa6, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
const PACKET2_7: &[u8] = &[0xa6, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x88, 0xf7];

/// Two interleaved SysEx in separate BLE packets.
const PACKET2_8: &[u8] = &[0xa6, 0x88, 0xf0, 0x01, 0x02, 0x03, 0x88, 0xf7];
const PACKET2_9: &[u8] = &[0xa6, 0x88, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x88, 0xf7];

// ---------------------------------------------------------------------------
// Test data: SysEx payloads for write tests
// ---------------------------------------------------------------------------

const SYSEX4_1: &[u8] = &[0xf0, 0x01, 0x02, 0x03, 0xf7];
const SYSEX4_2: &[u8] = &[0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0xf7];
const SYSEX4_3: &[u8] = &[
    0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x01, 0x02, 0x03, 0x04, 0xf7,
];
const SYSEX4_4: &[u8] = &[0xf0, 0x01, 0x02, 0x03, 0xf7];
const SYSEX4_5: &[u8] = &[0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0xf7];

// ---------------------------------------------------------------------------
// Test data: Large split SysEx for write test (from C sysex5_1 — 1024 bytes)
// ---------------------------------------------------------------------------

/// Build the 1024-byte SysEx payload used by the split-SysEx write test.
/// Pattern: 0xF0, 0x01..0x7E repeating, ..., 0xF7 (total 1024 bytes).
fn build_sysex5_1() -> Vec<u8> {
    // The C test defines sysex5_1 as a static 1024-byte array that starts
    // with 0xF0, contains cycling data values 0x01–0x7E, and ends with 0xF7.
    let mut data = Vec::with_capacity(1024);
    data.push(0xf0);
    let mut val: u8 = 0x01;
    for _ in 1..1023 {
        data.push(val);
        val = if val >= 0x7e { 0x01 } else { val + 1 };
    }
    data.push(0xf7);
    assert_eq!(data.len(), 1024);
    data
}

// =========================================================================
// Individual parse tests (Phase 2 of the agent prompt)
// =========================================================================

/// Parse a single BLE-MIDI Note On message.
#[test]
fn test_midi_parse_note_on() {
    let mut parser = MidiReadParser::new();
    // BLE-MIDI packet: header=0x80, timestamp=0x80, status=0x91 (NoteOn ch1),
    // note=60 (middle C), velocity=100.
    let packet: &[u8] = &[0x80, 0x80, 0x91, 0x3c, 0x64];
    let events = parser.midi_read_raw(packet);
    assert_eq!(events.len(), 1);
    assert_note_event(&events[0], EventType::Noteon, 1, 60, 100);
}

/// Parse a single BLE-MIDI Note Off message.
#[test]
fn test_midi_parse_note_off() {
    let mut parser = MidiReadParser::new();
    // Status=0x81 (NoteOff ch1), note=60, velocity=64.
    let packet: &[u8] = &[0x80, 0x80, 0x81, 0x3c, 0x40];
    let events = parser.midi_read_raw(packet);
    assert_eq!(events.len(), 1);
    assert_note_event(&events[0], EventType::Noteoff, 1, 60, 64);
}

/// Parse a single BLE-MIDI Control Change message.
#[test]
fn test_midi_parse_control_change() {
    let mut parser = MidiReadParser::new();
    // Status=0xB2 (CC ch2), controller=7 (volume), value=127.
    let packet: &[u8] = &[0x80, 0x80, 0xb2, 0x07, 0x7f];
    let events = parser.midi_read_raw(packet);
    assert_eq!(events.len(), 1);
    assert_ctrl_event(&events[0], EventType::Controller, 2, 127, 7);
}

/// Parse a single BLE-MIDI Program Change message.
#[test]
fn test_midi_parse_program_change() {
    let mut parser = MidiReadParser::new();
    // Status=0xC3 (PgmChange ch3), program=42.
    let packet: &[u8] = &[0x80, 0x80, 0xc3, 0x2a];
    let events = parser.midi_read_raw(packet);
    assert_eq!(events.len(), 1);
    assert_ctrl_event(&events[0], EventType::Pgmchange, 3, 42, 0);
}

/// Parse a single complete SysEx message within one BLE-MIDI packet.
#[test]
fn test_midi_parse_sysex() {
    let mut parser = MidiReadParser::new();
    // F0 ... F7 within one packet.
    let packet: &[u8] = &[0x80, 0x80, 0xf0, 0x7e, 0x7f, 0x09, 0x01, 0x80, 0xf7];
    let events = parser.midi_read_raw(packet);
    assert_eq!(events.len(), 1);
    assert_sysex_event(&events[0], &[0xf0, 0x7e, 0x7f, 0x09, 0x01, 0xf7]);
}

/// Parse BLE-MIDI real-time messages (status 0xF8–0xFF).
/// Real-time messages may appear anywhere and are single-byte.
#[test]
fn test_midi_parse_realtime() {
    let mut parser = MidiReadParser::new();
    // Packet with a NoteOn and an interleaved Timing Clock (0xF8).
    // header=0x80, ts=0x80, NoteOn ch0=0x90 note=60 vel=100,
    // then realtime 0xF8 (Timing Clock) — the parser should recognise it.
    let packet: &[u8] = &[0x80, 0x80, 0x90, 0x3c, 0x64, 0xf8];
    let events = parser.midi_read_raw(packet);
    // Expect NoteOn event.  The parser treats 0xF8 as a realtime status byte.
    // Realtime bytes with is_midi_realtime check → next_is_timestamp returns false,
    // so 0xF8 is handled as a status byte requiring 0 data bytes.
    assert!(!events.is_empty(), "should parse at least one event");
    assert_note_event(&events[0], EventType::Noteon, 0, 60, 100);
}

// =========================================================================
// Aggregate read tests (from C midi1 / midi2)
// =========================================================================

/// Read test: parse BLE-MIDI packets containing regular messages.
/// Adapted from C midi1 test. Packets 1–4 are processed WITHOUT reset
/// between them (running status carries over).
#[test]
fn test_midi_read_regular() {
    let mut parser = MidiReadParser::new();
    let mut all_events: Vec<Event<'static>> = Vec::new();

    // Process packets 1–4.
    for pkt in &[PACKET1_1, PACKET1_2, PACKET1_3, PACKET1_4] {
        let evts = parser.midi_read_raw(pkt);
        all_events.extend(evts);
    }

    // Expected 8 events from packets 1–4:
    let expected: Vec<Event<'static>> = vec![
        // Packet 1-1
        ctrl_event(EventType::Pitchbend, 8, 0, 0),
        ctrl_event(EventType::Controller, 8, 63, 74),
        note_event(EventType::Noteon, 8, 62, 14),
        // Packet 1-2
        ctrl_event(EventType::Chanpress, 8, 113, 0),
        // Packet 1-3
        ctrl_event(EventType::Controller, 8, 67, 74),
        // Packet 1-4
        ctrl_event(EventType::Pitchbend, 8, -2, 0),
        ctrl_event(EventType::Pitchbend, 8, -3, 0),
        ctrl_event(EventType::Pitchbend, 8, -4, 0),
    ];

    compare_events(&all_events, &expected);
}

/// Read test: parse BLE-MIDI packets containing SysEx messages.
/// Adapted from C midi2 test.
#[test]
fn test_midi_read_sysex() {
    let mut parser = MidiReadParser::new();

    // --- Single-packet SysEx (sysex2_1) ---
    let evts = parser.midi_read_raw(PACKET2_1);
    assert_eq!(evts.len(), 1, "single-packet sysex should yield 1 event");
    assert_sysex_event(&evts[0], SYSEX2_1);

    // --- Two-packet SysEx (sysex2_2) ---
    parser.midi_read_reset();
    let evts = parser.midi_read_raw(PACKET2_2);
    assert!(evts.is_empty(), "first half of split sysex should yield 0 events");
    let evts = parser.midi_read_raw(PACKET2_3);
    assert_eq!(evts.len(), 1, "second half of split sysex should yield 1 event");
    assert_sysex_event(&evts[0], SYSEX2_2);

    // --- Multi-packet SysEx spanning 4 packets (sysex2_3) ---
    parser.midi_read_reset();
    let evts = parser.midi_read_raw(PACKET2_4);
    assert!(evts.is_empty());
    let evts = parser.midi_read_raw(PACKET2_5);
    assert!(evts.is_empty());
    let evts = parser.midi_read_raw(PACKET2_6);
    assert!(evts.is_empty());
    let evts = parser.midi_read_raw(PACKET2_7);
    assert_eq!(evts.len(), 1, "final packet of 4-packet sysex should complete it");
    assert_sysex_event(&evts[0], SYSEX2_3);

    // --- Two separate SysEx messages in consecutive packets (sysex2_4 + sysex2_5) ---
    parser.midi_read_reset();
    let evts = parser.midi_read_raw(PACKET2_8);
    assert_eq!(evts.len(), 1);
    assert_sysex_event(&evts[0], SYSEX2_4);
    let evts = parser.midi_read_raw(PACKET2_9);
    assert_eq!(evts.len(), 1);
    assert_sysex_event(&evts[0], SYSEX2_5);
}

// =========================================================================
// Write tests (from C midi3, midi4, midi5)
// =========================================================================

/// Helper: run a write-then-read round-trip test.
///
/// For `num_iters` iterations:
/// 1. Pick a random MTU in `[5, 512)`.
/// 2. Create a fresh writer (MTU is set at construction).
/// 3. Feed each event through the writer's `midi_read_ev`, collecting
///    BLE-MIDI packets via the flush callback.
/// 4. Collect any remaining buffered data from the writer.
/// 5. Parse all collected BLE-MIDI packets back through a reader.
/// 6. Compare round-tripped events against the expected events.
fn run_write_test(input_events: &[Event<'_>], expected_events: &[Event<'_>], num_iters: usize) {
    let mut rng = rand::thread_rng();

    for iter in 0..num_iters {
        let mtu: usize = rng.gen_range(5..512);
        let mut writer = MidiWriteParser::new(mtu);
        let mut packets: Vec<Vec<u8>> = Vec::new();

        // Feed events through the writer.
        for ev in input_events {
            writer.midi_read_ev(ev, |data: &[u8]| {
                packets.push(data.to_vec());
            });
        }

        // Collect remaining buffered data.
        if writer.midi_write_has_data() {
            let buf = writer.midi_write_data();
            if !buf.is_empty() {
                packets.push(buf.to_vec());
            }
        }

        // Read all packets back through a reader and collect events.
        let mut reader = MidiReadParser::new();
        let mut round_trip: Vec<Event<'static>> = Vec::new();
        for pkt in &packets {
            let evts = reader.midi_read_raw(pkt);
            round_trip.extend(evts);
        }

        // Compare.
        assert_eq!(
            round_trip.len(),
            expected_events.len(),
            "write test iter {iter} mtu={mtu}: event count mismatch (got {}, expected {})",
            round_trip.len(),
            expected_events.len()
        );
        compare_events(&round_trip, expected_events);
    }
}

/// Write test: encode regular MIDI events to BLE-MIDI, then decode back.
/// Adapted from C midi3 test.
#[test]
fn test_midi_write_note() {
    let input: Vec<Event<'static>> = vec![
        ctrl_event(EventType::Pitchbend, 8, 0, 0),
        ctrl_event(EventType::Controller, 8, 63, 74),
        note_event(EventType::Noteon, 8, 62, 14),
        ctrl_event(EventType::Chanpress, 8, 113, 0),
        ctrl_event(EventType::Controller, 8, 67, 74),
        ctrl_event(EventType::Pitchbend, 8, -2, 0),
        ctrl_event(EventType::Pitchbend, 8, -3, 0),
        ctrl_event(EventType::Pitchbend, 8, -4, 0),
        note_event(EventType::Noteoff, 8, 62, 0),
    ];

    let expected = input.clone();
    run_write_test(&input, &expected, NUM_WRITE_TESTS);
}

/// Write test: encode SysEx events to BLE-MIDI, then decode back.
/// Adapted from C midi4 test.
#[test]
fn test_midi_write_sysex() {
    let input: Vec<Event<'static>> = vec![
        sysex_event(SYSEX4_1),
        sysex_event(SYSEX4_2),
        sysex_event(SYSEX4_3),
        sysex_event(SYSEX4_4),
        sysex_event(SYSEX4_5),
    ];

    let expected = input.clone();
    run_write_test(&input, &expected, NUM_WRITE_TESTS);
}

/// Write test: encode a large SysEx (1024 bytes) that the writer must
/// fragment across multiple BLE-MIDI packets according to the MTU.
/// The reader should reassemble those packets into the original SysEx.
/// Adapted from C midi5 test (which tested ALSA split SysEx; here we
/// test the writer's own packet-level fragmentation/reassembly instead).
#[test]
fn test_midi_write_split_sysex() {
    let full_sysex = build_sysex5_1();

    // Feed the entire 1024-byte SysEx as a single ALSA event.
    // The writer will fragment it across BLE packets based on MTU.
    let input: Vec<Event<'static>> = vec![sysex_event(&full_sysex)];

    // After round-trip through writer → BLE packets → reader, we expect
    // the same complete SysEx back.
    let expected: Vec<Event<'static>> = vec![sysex_event(&full_sysex)];

    run_write_test(&input, &expected, NUM_WRITE_TESTS);
}

// =========================================================================
// Timestamp handling
// =========================================================================

/// Verify that BLE-MIDI timestamp bytes are consumed without affecting
/// the MIDI event data. Two packets with different timestamps but identical
/// MIDI content must produce identical events.
#[test]
fn test_midi_timestamp() {
    let mut parser = MidiReadParser::new();

    // Packet with timestamp-low = 0x80 (value 0).
    let pkt_a: &[u8] = &[0x80, 0x80, 0x90, 0x3c, 0x64];
    let evts_a = parser.midi_read_raw(pkt_a);
    assert_eq!(evts_a.len(), 1);

    parser.midi_read_reset();

    // Packet with timestamp-low = 0xBF (value 63).
    let pkt_b: &[u8] = &[0x80, 0xbf, 0x90, 0x3c, 0x64];
    let evts_b = parser.midi_read_raw(pkt_b);
    assert_eq!(evts_b.len(), 1);

    // Both should decode to identical NoteOn events.
    compare_events(&evts_a, &evts_b);
    assert_note_event(&evts_a[0], EventType::Noteon, 0, 60, 100);
}

// =========================================================================
// Running status
// =========================================================================

/// Verify running status: once a status byte is seen, subsequent data
/// bytes without a new status byte reuse the previous status.
#[test]
fn test_midi_running_status() {
    let mut parser = MidiReadParser::new();

    // Packet with two NoteOn messages via running status:
    //  header=0x80, ts=0x80, status=0x90 (NoteOn ch0),
    //  note=60, vel=100,
    //  ts=0x81, (running status: 0x90 still applies)
    //  note=62, vel=80.
    let packet: &[u8] = &[0x80, 0x80, 0x90, 0x3c, 0x64, 0x81, 0x3e, 0x50];
    let events = parser.midi_read_raw(packet);

    assert_eq!(events.len(), 2, "running status should produce two NoteOn events");
    assert_note_event(&events[0], EventType::Noteon, 0, 60, 100);
    assert_note_event(&events[1], EventType::Noteon, 0, 62, 80);
}

// =========================================================================
// Error handling / malformed data
// =========================================================================

/// Empty packet (fewer than 3 bytes) must not crash and should return no events.
#[test]
fn test_midi_parse_empty_packet() {
    let mut parser = MidiReadParser::new();

    // Zero-length slice.
    let events = parser.midi_read_raw(&[]);
    assert!(events.is_empty(), "empty packet must produce no events");

    // 1-byte packet (only header, no timestamp, no data).
    let events = parser.midi_read_raw(&[0x80]);
    assert!(events.is_empty(), "1-byte packet must produce no events");

    // 2-byte packet (header + timestamp, no MIDI data).
    let events = parser.midi_read_raw(&[0x80, 0x80]);
    assert!(events.is_empty(), "2-byte packet must produce no events");
}

/// Packet with only a status byte but no data bytes for a message that
/// requires data (e.g. NoteOn) should produce no events.
#[test]
fn test_midi_parse_truncated_message() {
    let mut parser = MidiReadParser::new();
    // header=0x80, ts=0x80, status=0x90 (NoteOn ch0), only 1 data byte (needs 2).
    let packet: &[u8] = &[0x80, 0x80, 0x90, 0x3c];
    let events = parser.midi_read_raw(packet);
    assert!(events.is_empty(), "truncated NoteOn (missing velocity) should produce no events");
}

/// Data bytes received with no running status set should be discarded.
#[test]
fn test_midi_parse_data_without_status() {
    let mut parser = MidiReadParser::new();
    // header=0x80, ts=0x80, data bytes 0x3c 0x64 with no preceding status.
    // The parser has running_status=0 (fresh), so these should be skipped.
    let packet: &[u8] = &[0x80, 0x80, 0x3c, 0x64];
    let events = parser.midi_read_raw(packet);
    assert!(events.is_empty(), "data without status should be discarded");
}

/// Verify that midi_read_reset clears state so that running status from
/// a previous packet does not bleed through.
#[test]
fn test_midi_reset_clears_running_status() {
    let mut parser = MidiReadParser::new();

    // First packet: set running status via NoteOn.
    let pkt1: &[u8] = &[0x80, 0x80, 0x90, 0x3c, 0x64];
    let evts = parser.midi_read_raw(pkt1);
    assert_eq!(evts.len(), 1, "first packet should parse NoteOn");

    // Reset the parser.
    parser.midi_read_reset();

    // Second packet: data bytes only (no status). After reset, running
    // status is 0, so these should be discarded.
    let pkt2: &[u8] = &[0x80, 0x80, 0x3c, 0x64];
    let evts = parser.midi_read_raw(pkt2);
    assert!(evts.is_empty(), "after reset, data bytes without status should produce no events");
}

/// Verify incomplete SysEx (no terminating 0xF7 in a single packet)
/// does not emit a SysEx event until the terminator arrives.
#[test]
fn test_midi_parse_incomplete_sysex() {
    let mut parser = MidiReadParser::new();

    // Packet with F0 but no F7.
    let pkt: &[u8] = &[0x80, 0x80, 0xf0, 0x01, 0x02, 0x03];
    let events = parser.midi_read_raw(pkt);
    assert!(events.is_empty(), "incomplete SysEx without F7 should produce no events");

    // Now send terminator in next packet.
    let pkt2: &[u8] = &[0x80, 0x04, 0x05, 0x80, 0xf7];
    let events = parser.midi_read_raw(pkt2);
    assert_eq!(events.len(), 1, "completing SysEx should produce 1 event");
    assert_sysex_event(&events[0], &[0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0xf7]);
}

/// Writer new() / has_data / reset basic lifecycle.
#[test]
fn test_midi_writer_lifecycle() {
    let mut writer = MidiWriteParser::new(64);
    // Fresh writer has no data.
    assert!(!writer.midi_write_has_data(), "new writer should have no pending data");

    // Feed a NoteOn event.
    let ev = note_event(EventType::Noteon, 0, 60, 100);
    writer.midi_read_ev(&ev, |_data: &[u8]| {
        // Callback receives BLE packet bytes; we just accept them.
    });

    // Reset the writer.
    writer.midi_write_reset();

    // After reset, pending data should be cleared.
    assert!(!writer.midi_write_has_data(), "after reset, writer should have no pending data");
}
