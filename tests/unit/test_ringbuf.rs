//! Converted ring buffer unit tests from `unit/test-ringbuf.c`.
//!
//! Exercises the [`RingBuf`] circular byte buffer from
//! `bluez_shared::util::ringbuf`.  The original C test file contained three
//! test functions registered via `tester_add`:
//!
//! * **`test_power2`** — verified three independent next-power-of-2 algorithms
//!   (`nlpo2`, `align_power2`, brute-force shift) agreed for values 1..999 999.
//! * **`test_alloc`** — allocated buffers of sizes 2..9 999 and asserted
//!   `capacity == avail` for each fresh buffer.
//! * **`test_printf`** — exercised the full write → peek → drain cycle with a
//!   500-byte (capacity 512) buffer across 10 000 iterations.
//!
//! This Rust conversion faithfully reproduces all three tests and adds
//! additional cases for `is_empty`, wrap-around, full-buffer, drain edge
//! cases, peek offsets, and invalid construction to ensure complete API
//! coverage.

use bluez_shared::util::ringbuf::RingBuf;

// ---------------------------------------------------------------------------
// Converted C tests
// ---------------------------------------------------------------------------

/// Converted from C `test_power2`.
///
/// The original C test verified that three independent implementations of
/// "next largest power of 2" — `nlpo2` (bit-manipulation), `align_power2`
/// (`1 << fls(u-1)`), and a brute-force left-shift loop — all produced
/// identical results for every integer in 1..=999 999.
///
/// In Rust the standard library provides [`usize::next_power_of_two`] and
/// `RingBuf::new` uses it internally.  This test:
///
/// 1. Verifies three equivalent algorithms agree for 1..=999 999 (pure
///    arithmetic — no allocations).
/// 2. Spot-checks that `RingBuf::new(size).capacity()` matches the expected
///    rounded value for a representative sample of sizes.
#[test]
fn test_power2() {
    // --- Part 1: verify three power-of-2 algorithms agree (mirrors C test) ---
    for i in 1u32..=999_999 {
        let n = i as usize;

        // Method 1 — Rust standard library
        let val1 = n.next_power_of_two();

        // Method 2 — brute-force shift loop (same as C test)
        let mut val2: usize = 1;
        while val2 < n {
            val2 <<= 1;
        }

        // Method 3 — nlpo2 bit-manipulation (translated from C)
        let val3 = {
            let mut x = n.wrapping_sub(1);
            x |= x >> 1;
            x |= x >> 2;
            x |= x >> 4;
            x |= x >> 8;
            x |= x >> 16;
            x.wrapping_add(1)
        };

        assert_eq!(val1, val2, "power2 mismatch at {i}: std={val1}, brute={val2}");
        assert_eq!(val1, val3, "power2 mismatch at {i}: std={val1}, nlpo2={val3}");
    }

    // --- Part 2: verify RingBuf uses the same rounding ---
    let sample_sizes: &[usize] = &[
        2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 255, 256, 257,
        500, 511, 512, 513, 1000, 1023, 1024, 1025, 4096, 9999,
    ];
    for &size in sample_sizes {
        let expected = size.next_power_of_two();
        let rb = RingBuf::new(size).expect("RingBuf::new should succeed for valid size");
        assert_eq!(
            rb.capacity(),
            expected,
            "RingBuf capacity mismatch for requested size {size}: got {}, expected {expected}",
            rb.capacity(),
        );
    }
}

/// Converted from C `test_alloc`.
///
/// Allocates ring buffers with sizes 2 through 9 999 and asserts that
/// `capacity == avail` for each fresh (empty) buffer.
///
/// Original C:
/// ```c
/// for (i = 2; i < 10000; i++) {
///     struct ringbuf *rb = ringbuf_new(i);
///     g_assert(rb != NULL);
///     g_assert_cmpint(ringbuf_capacity(rb), ==, ringbuf_avail(rb));
///     ringbuf_free(rb);
/// }
/// ```
#[test]
fn test_alloc() {
    for i in 2..10_000 {
        let rb = RingBuf::new(i).expect("RingBuf::new should succeed");
        assert_eq!(
            rb.capacity(),
            rb.avail(),
            "fresh buffer: capacity ({}) != avail ({}) for requested size {i}",
            rb.capacity(),
            rb.avail(),
        );
    }
}

/// Converted from C `test_printf`.
///
/// Creates a 500-byte buffer (capacity rounds to 512).  Iterates 0..10 000;
/// for each `count = i % 512` (skipping 0), writes `count` 'x' characters
/// via `printf`, verifies `len` and `avail`, peeks to compare data, drains
/// fully, and verifies the buffer returns to empty state.
///
/// Because `drain` resets both cursors to 0 when the buffer becomes empty,
/// data never wraps across iterations and `peek` always returns a single
/// contiguous slice.
#[test]
fn test_printf() {
    let mut rb = RingBuf::new(500).expect("RingBuf::new(500) should succeed");
    assert_eq!(rb.capacity(), 512, "500 should round up to 512");

    for i in 0..10_000 {
        let count = i % rb.capacity();
        if count == 0 {
            continue;
        }

        // Build a string of `count` 'x' characters (mirrors g_strnfill)
        let s: String = "x".repeat(count);

        // Write via printf (atomic — all-or-nothing)
        let written =
            rb.printf(format_args!("{s}")).expect("printf should succeed when avail is sufficient");
        assert_eq!(written, count, "printf return value mismatch at i={i}");

        // Verify length and available space
        assert_eq!(rb.len(), count, "len mismatch after printf at i={i}");
        assert_eq!(rb.avail(), 512 - count, "avail mismatch after printf at i={i}",);

        // Peek and compare data — mirrors C's ringbuf_peek + strncmp
        let (first, second) = rb.peek(0);
        assert!(second.is_none(), "unexpected wrap in peek at i={i}");
        assert_eq!(first.len(), count, "peek length mismatch at i={i}");
        assert_eq!(first, s.as_bytes(), "peek data mismatch at i={i}");

        // Drain all data
        assert_eq!(rb.drain(count), count, "drain count mismatch at i={i}");

        // Verify empty state
        assert_eq!(rb.len(), 0, "len should be 0 after drain at i={i}");
        assert_eq!(rb.avail(), 512, "avail should be 512 after drain at i={i}");
    }
}

// ---------------------------------------------------------------------------
// Additional tests (beyond C source) for complete API coverage
// ---------------------------------------------------------------------------

/// Verify `RingBuf::new` rejects invalid sizes and accepts the minimum valid
/// size.
#[test]
fn test_ringbuf_new_invalid() {
    // Size 0 — below minimum
    assert!(RingBuf::new(0).is_none(), "RingBuf::new(0) should return None",);

    // Size 1 — still below minimum (< 2)
    assert!(RingBuf::new(1).is_none(), "RingBuf::new(1) should return None",);

    // Size 2 — minimum valid
    let rb = RingBuf::new(2);
    assert!(rb.is_some(), "RingBuf::new(2) should succeed");
    assert_eq!(rb.unwrap().capacity(), 2);
}

/// Basic create → write → peek → drain cycle verifying data integrity.
///
/// Exercises: `new`, `capacity`, `len`, `avail`, `is_empty`, `printf`,
/// `peek`, `drain`.
#[test]
fn test_ringbuf_basic() {
    let mut rb = RingBuf::new(64).expect("RingBuf::new(64) should succeed");

    // Initial state
    assert_eq!(rb.capacity(), 64);
    assert_eq!(rb.len(), 0);
    assert_eq!(rb.avail(), 64);
    assert!(rb.is_empty());

    // Write data
    let msg = "Hello, Bluetooth!";
    rb.printf(format_args!("{msg}")).expect("printf should succeed");
    assert_eq!(rb.len(), msg.len());
    assert_eq!(rb.avail(), 64 - msg.len());
    assert!(!rb.is_empty());

    // Peek to verify data integrity
    let (first, second) = rb.peek(0);
    assert_eq!(first, msg.as_bytes());
    assert!(second.is_none());

    // Drain and verify empty state
    let drained = rb.drain(msg.len());
    assert_eq!(drained, msg.len());
    assert!(rb.is_empty());
    assert_eq!(rb.len(), 0);
    assert_eq!(rb.avail(), 64);
}

/// Verify `is_empty` transitions across the buffer lifecycle.
///
/// Exercises: `new`, `is_empty`, `printf`, `len`, `avail`, `drain`,
/// `capacity`.
#[test]
fn test_ringbuf_empty() {
    let mut rb = RingBuf::new(16).expect("RingBuf::new(16) should succeed");

    // Fresh buffer is empty
    assert!(rb.is_empty(), "fresh buffer should be empty");
    assert_eq!(rb.len(), 0);
    assert_eq!(rb.avail(), rb.capacity());

    // After writing, not empty
    rb.printf(format_args!("hello")).expect("printf should succeed");
    assert!(!rb.is_empty(), "buffer should not be empty after write");
    assert_eq!(rb.len(), 5);

    // After partial drain, still not empty
    rb.drain(3);
    assert!(!rb.is_empty(), "buffer should not be empty after partial drain",);
    assert_eq!(rb.len(), 2);

    // After full drain, empty again
    rb.drain(2);
    assert!(rb.is_empty(), "buffer should be empty after draining all data",);
    assert_eq!(rb.len(), 0);
    assert_eq!(rb.avail(), rb.capacity());
}

/// Buffer full condition handling.
///
/// Exercises: `new`, `capacity`, `avail`, `printf`, `len`.
#[test]
fn test_ringbuf_full() {
    let mut rb = RingBuf::new(8).expect("RingBuf::new(8) should succeed");
    assert_eq!(rb.capacity(), 8);

    // Fill the buffer completely
    let data = "12345678";
    let written =
        rb.printf(format_args!("{data}")).expect("printf of exactly capacity bytes should succeed");
    assert_eq!(written, 8);
    assert_eq!(rb.len(), 8);
    assert_eq!(rb.avail(), 0);
    assert!(!rb.is_empty());

    // Attempting to write more should fail with BufferFull
    let result = rb.printf(format_args!("x"));
    assert!(result.is_err(), "printf should fail when buffer is full");
}

/// Capacity and available-space tracking across multiple operations.
///
/// Exercises: `new`, `capacity`, `avail`, `len`, `printf`, `drain`.
#[test]
fn test_ringbuf_capacity() {
    let mut rb = RingBuf::new(32).expect("RingBuf::new(32) should succeed");
    assert_eq!(rb.capacity(), 32);
    assert_eq!(rb.avail(), 32);
    assert_eq!(rb.len(), 0);

    // Write 10 bytes
    rb.printf(format_args!("0123456789")).expect("printf should succeed");
    assert_eq!(rb.capacity(), 32); // capacity never changes
    assert_eq!(rb.avail(), 22);
    assert_eq!(rb.len(), 10);

    // Drain 5
    rb.drain(5);
    assert_eq!(rb.capacity(), 32);
    assert_eq!(rb.avail(), 27);
    assert_eq!(rb.len(), 5);

    // Write 15 more
    rb.printf(format_args!("abcdefghijklmno")).expect("printf should succeed");
    assert_eq!(rb.capacity(), 32);
    assert_eq!(rb.avail(), 12);
    assert_eq!(rb.len(), 20);

    // Drain all
    rb.drain(20);
    assert_eq!(rb.capacity(), 32);
    assert_eq!(rb.avail(), 32);
    assert_eq!(rb.len(), 0);
}

/// Drain edge-case behavior: over-drain, drain-from-empty, partial drains.
///
/// Exercises: `new`, `printf`, `drain`, `len`, `avail`, `is_empty`.
#[test]
fn test_ringbuf_drain() {
    let mut rb = RingBuf::new(16).expect("RingBuf::new(16) should succeed");

    // Write some data
    rb.printf(format_args!("abcdefgh")).expect("printf should succeed");
    assert_eq!(rb.len(), 8);

    // Drain more than available — should only drain what exists
    let drained = rb.drain(100);
    assert_eq!(drained, 8, "drain should return actual bytes drained");
    assert!(rb.is_empty());
    assert_eq!(rb.len(), 0);
    assert_eq!(rb.avail(), 16);

    // Drain from empty buffer — should return 0
    let drained = rb.drain(10);
    assert_eq!(drained, 0, "drain from empty buffer should return 0");

    // Multiple partial drains
    rb.printf(format_args!("1234567890")).expect("printf should succeed");
    assert_eq!(rb.drain(3), 3);
    assert_eq!(rb.len(), 7);
    assert_eq!(rb.drain(3), 3);
    assert_eq!(rb.len(), 4);
    assert_eq!(rb.drain(4), 4);
    assert!(rb.is_empty());
}

/// Peek without consuming data; peek with various offsets.
///
/// Exercises: `new`, `printf`, `peek`, `len`, `drain`.
#[test]
fn test_ringbuf_peek() {
    let mut rb = RingBuf::new(16).expect("RingBuf::new(16) should succeed");

    // Peek on empty buffer
    let (first, second) = rb.peek(0);
    assert!(first.is_empty(), "peek on empty buffer should return empty slice");
    assert!(second.is_none());

    // Write and peek
    rb.printf(format_args!("hello")).expect("printf should succeed");
    let (first, second) = rb.peek(0);
    assert_eq!(first, b"hello");
    assert!(second.is_none());

    // Peek does not consume — len unchanged
    assert_eq!(rb.len(), 5);

    // Peek with offset
    let (first, second) = rb.peek(2);
    assert_eq!(first, b"llo");
    assert!(second.is_none());

    // Peek with offset beyond data
    let (first, second) = rb.peek(10);
    assert!(first.is_empty());
    assert!(second.is_none());

    // Peek at exact end of data
    let (first, second) = rb.peek(5);
    assert!(first.is_empty());
    assert!(second.is_none());

    // Drain partially and verify peek returns remaining data
    rb.drain(3);
    let (first, second) = rb.peek(0);
    assert_eq!(first, b"lo");
    assert!(second.is_none());
}

/// Write/read across the buffer wrap boundary, producing a two-slice peek.
///
/// Exercises: `new`, `capacity`, `printf`, `drain`, `peek`, `len`, `avail`,
/// `is_empty`.
///
/// Scenario with an 8-byte buffer:
/// 1. Write `"abcdef"` (6 bytes) → positions `[0..6]`
/// 2. Drain 4 → `read_pos=4`, data `"ef"` at `[4..6]`
/// 3. Write `"ghij"` → wraps: `"gh"` at `[6..8]`, `"ij"` at `[0..2]`
/// 4. Peek → first=`"efgh"`, second=`"ij"`
#[test]
fn test_ringbuf_wrap() {
    let mut rb = RingBuf::new(8).expect("RingBuf::new(8) should succeed");
    assert_eq!(rb.capacity(), 8);

    // Step 1: write 6 bytes — fills positions 0..6
    rb.printf(format_args!("abcdef")).expect("printf should succeed");
    assert_eq!(rb.len(), 6);

    // Step 2: partial drain 4 — read_pos advances; data = "ef" at [4..6]
    rb.drain(4);
    assert_eq!(rb.len(), 2);
    assert_eq!(rb.avail(), 6);

    // Step 3: write 4 more bytes — wraps around the boundary
    //   "gh" fills [6..8], "ij" fills [0..2]
    rb.printf(format_args!("ghij")).expect("printf should succeed with wrap-around");
    assert_eq!(rb.len(), 6);
    assert_eq!(rb.avail(), 2);

    // Step 4: peek should return wrapped data as two slices
    let (first, second) = rb.peek(0);
    assert_eq!(first, b"efgh", "first peek slice should span from read_pos to end");
    assert!(second.is_some(), "peek should return a second slice for wrapped data",);
    assert_eq!(second.unwrap(), b"ij", "second peek slice should be the wrapped portion",);

    // Verify total data length via combined slices
    let total_len = first.len() + second.map_or(0, |s| s.len());
    assert_eq!(total_len, 6);

    // Drain all — buffer becomes empty
    rb.drain(6);
    assert!(rb.is_empty());
}

/// Multiple printf writes accumulate data correctly before draining.
///
/// Exercises: `new`, `printf`, `len`, `avail`, `peek`, `drain`, `is_empty`.
#[test]
fn test_ringbuf_multiple_writes() {
    let mut rb = RingBuf::new(32).expect("RingBuf::new(32) should succeed");

    // Three successive writes
    rb.printf(format_args!("AAA")).expect("first printf should succeed");
    rb.printf(format_args!("BBB")).expect("second printf should succeed");
    rb.printf(format_args!("CCC")).expect("third printf should succeed");

    assert_eq!(rb.len(), 9);
    assert_eq!(rb.avail(), 32 - 9);

    // Peek should show concatenated data
    let (first, second) = rb.peek(0);
    assert_eq!(first, b"AAABBBCCC");
    assert!(second.is_none());

    // Drain all at once
    rb.drain(9);
    assert!(rb.is_empty());
}

/// Repeated fill-and-drain cycles do not corrupt the buffer.
///
/// Exercises: `new`, `printf`, `drain`, `len`, `avail`, `peek`, `capacity`.
#[test]
fn test_ringbuf_repeated_cycles() {
    let mut rb = RingBuf::new(8).expect("RingBuf::new(8) should succeed");

    for cycle in 0..100 {
        // Fill buffer to capacity
        let data = "ABCDEFGH";
        rb.printf(format_args!("{data}")).expect("printf should succeed at start of cycle");
        assert_eq!(rb.len(), 8, "len mismatch at cycle {cycle}");
        assert_eq!(rb.avail(), 0, "avail mismatch at cycle {cycle}");

        // Verify data
        let (first, second) = rb.peek(0);
        let mut combined = first.to_vec();
        if let Some(s) = second {
            combined.extend_from_slice(s);
        }
        assert_eq!(combined, data.as_bytes(), "data mismatch at cycle {cycle}");

        // Drain completely — cursors reset
        rb.drain(8);
        assert_eq!(rb.len(), 0, "len not 0 after drain at cycle {cycle}");
        assert_eq!(rb.avail(), rb.capacity(), "avail != capacity after drain at cycle {cycle}",);
    }
}
