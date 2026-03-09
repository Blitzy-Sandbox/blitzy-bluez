// SPDX-License-Identifier: GPL-2.0-or-later
//
// Ring buffer replacing src/shared/ringbuf.c
//
// Fixed-size circular byte buffer used by HFP and other protocol transports
// for buffering read/write data.

use std::cmp;

/// A fixed-size circular byte buffer.
///
/// Replaces C's `struct ringbuf`. Provides O(1) push/pull operations
/// with automatic wraparound.
pub struct RingBuf {
    data: Vec<u8>,
    read_pos: usize,
    write_pos: usize,
    size: usize,
}

impl RingBuf {
    /// Create a new ring buffer with the given capacity.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
            read_pos: 0,
            write_pos: 0,
            size,
        }
    }

    /// Number of bytes available to read.
    pub fn len(&self) -> usize {
        if self.write_pos >= self.read_pos {
            self.write_pos - self.read_pos
        } else {
            self.size - self.read_pos + self.write_pos
        }
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.read_pos == self.write_pos
    }

    /// Number of bytes of free space.
    pub fn avail(&self) -> usize {
        // Reserve 1 byte to distinguish full from empty
        self.size - 1 - self.len()
    }

    /// Total capacity.
    pub fn capacity(&self) -> usize {
        self.size - 1
    }

    /// Write bytes into the buffer. Returns the number of bytes written.
    pub fn write(&mut self, src: &[u8]) -> usize {
        let avail = self.avail();
        let to_write = cmp::min(src.len(), avail);

        if to_write == 0 {
            return 0;
        }

        let first_chunk = cmp::min(to_write, self.size - self.write_pos);
        self.data[self.write_pos..self.write_pos + first_chunk]
            .copy_from_slice(&src[..first_chunk]);

        if to_write > first_chunk {
            let second_chunk = to_write - first_chunk;
            self.data[..second_chunk].copy_from_slice(&src[first_chunk..to_write]);
        }

        self.write_pos = (self.write_pos + to_write) % self.size;
        to_write
    }

    /// Read bytes from the buffer. Returns the number of bytes read.
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let available = self.len();
        let to_read = cmp::min(dst.len(), available);

        if to_read == 0 {
            return 0;
        }

        let first_chunk = cmp::min(to_read, self.size - self.read_pos);
        dst[..first_chunk]
            .copy_from_slice(&self.data[self.read_pos..self.read_pos + first_chunk]);

        if to_read > first_chunk {
            let second_chunk = to_read - first_chunk;
            dst[first_chunk..to_read].copy_from_slice(&self.data[..second_chunk]);
        }

        self.read_pos = (self.read_pos + to_read) % self.size;
        to_read
    }

    /// Peek at bytes without consuming them.
    pub fn peek(&self, dst: &mut [u8]) -> usize {
        let available = self.len();
        let to_read = cmp::min(dst.len(), available);

        if to_read == 0 {
            return 0;
        }

        let first_chunk = cmp::min(to_read, self.size - self.read_pos);
        dst[..first_chunk]
            .copy_from_slice(&self.data[self.read_pos..self.read_pos + first_chunk]);

        if to_read > first_chunk {
            let second_chunk = to_read - first_chunk;
            dst[first_chunk..to_read].copy_from_slice(&self.data[..second_chunk]);
        }

        to_read
    }

    /// Skip (consume) up to `count` bytes without copying. Returns bytes skipped.
    pub fn drain(&mut self, count: usize) -> usize {
        let available = self.len();
        let to_drain = cmp::min(count, available);
        self.read_pos = (self.read_pos + to_drain) % self.size;
        to_drain
    }

    /// Reset the buffer to empty state.
    pub fn reset(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_ringbuf() {
        let rb = RingBuf::new(64);
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
        assert_eq!(rb.capacity(), 63);
        assert_eq!(rb.avail(), 63);
    }

    #[test]
    fn test_write_and_read() {
        let mut rb = RingBuf::new(16);
        let data = b"hello";
        assert_eq!(rb.write(data), 5);
        assert_eq!(rb.len(), 5);

        let mut buf = [0u8; 16];
        assert_eq!(rb.read(&mut buf), 5);
        assert_eq!(&buf[..5], b"hello");
        assert!(rb.is_empty());
    }

    #[test]
    fn test_wraparound() {
        let mut rb = RingBuf::new(8); // capacity = 7

        // Fill with 6 bytes
        assert_eq!(rb.write(b"abcdef"), 6);
        // Read 4 bytes
        let mut buf = [0u8; 4];
        assert_eq!(rb.read(&mut buf), 4);
        assert_eq!(&buf, b"abcd");

        // Write 5 more bytes (wraps around)
        assert_eq!(rb.write(b"ghijk"), 5);
        assert_eq!(rb.len(), 7); // 2 remaining + 5 new

        let mut buf = [0u8; 7];
        assert_eq!(rb.read(&mut buf), 7);
        assert_eq!(&buf, b"efghijk");
    }

    #[test]
    fn test_overflow_protection() {
        let mut rb = RingBuf::new(8); // capacity = 7
        assert_eq!(rb.write(b"1234567"), 7); // fills to capacity
        assert_eq!(rb.write(b"x"), 0); // no space
        assert_eq!(rb.avail(), 0);
    }

    #[test]
    fn test_peek() {
        let mut rb = RingBuf::new(16);
        rb.write(b"hello");

        let mut buf = [0u8; 5];
        assert_eq!(rb.peek(&mut buf), 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(rb.len(), 5); // not consumed
    }

    #[test]
    fn test_drain() {
        let mut rb = RingBuf::new(16);
        rb.write(b"hello world");
        assert_eq!(rb.drain(6), 6);
        assert_eq!(rb.len(), 5);

        let mut buf = [0u8; 5];
        rb.read(&mut buf);
        assert_eq!(&buf, b"world");
    }

    #[test]
    fn test_reset() {
        let mut rb = RingBuf::new(16);
        rb.write(b"test data");
        rb.reset();
        assert!(rb.is_empty());
        assert_eq!(rb.avail(), 15);
    }

    // ---------------------------------------------------------------
    // Tests ported from unit/test-ringbuf.c
    // ---------------------------------------------------------------

    /// test_power2 from test-ringbuf.c: verify next-power-of-two helpers.
    #[test]
    fn test_c_power2() {
        fn nlpo2(mut x: usize) -> usize {
            x = x.wrapping_sub(1);
            x |= x >> 1;
            x |= x >> 2;
            x |= x >> 4;
            x |= x >> 8;
            x |= x >> 16;
            x.wrapping_add(1)
        }

        fn align_power2(u: usize) -> usize {
            if u == 0 {
                return 0;
            }
            1usize << (usize::BITS - (u - 1).leading_zeros())
        }

        for i in 1..100_000usize {
            let size1 = nlpo2(i);
            let size2 = align_power2(i);
            let mut size3 = 1usize;
            while size3 < i && size3 < usize::MAX {
                size3 <<= 1;
            }
            assert_eq!(size1, size2, "nlpo2 vs align_power2 differ at {}", i);
            assert_eq!(size2, size3, "align_power2 vs brute force differ at {}", i);
        }
    }

    /// test_alloc from test-ringbuf.c: create ring buffers of various sizes,
    /// verify capacity equals available space when empty.
    #[test]
    fn test_c_ringbuf_alloc() {
        for i in 2..1000 {
            let rb = RingBuf::new(i);
            assert_eq!(
                rb.capacity(),
                rb.avail(),
                "capacity != avail for size={}",
                i
            );
        }
    }

    /// test_printf from test-ringbuf.c: repeated write-read cycles with
    /// varying data sizes, verifying lengths and content match.
    #[test]
    fn test_c_ringbuf_write_read_cycle() {
        let rb_size = 500;
        // Our ring buffer stores size as-is (not rounded to power of 2),
        // so capacity = size - 1
        let rb_capa = rb_size - 1;
        let mut rb = RingBuf::new(rb_size);
        assert_eq!(rb.capacity(), rb_capa);

        for i in 0..10_000 {
            let count = i % rb_capa;
            if count == 0 {
                continue;
            }

            // Create a string of 'x' repeated `count` times
            let data: Vec<u8> = vec![b'x'; count];

            let written = rb.write(&data);
            assert_eq!(written, count, "write returned wrong len at iter {}", i);
            assert_eq!(rb.len(), count, "len mismatch at iter {}", i);
            assert_eq!(rb.avail(), rb_capa - count, "avail mismatch at iter {}", i);

            // Peek and verify
            let mut peek_buf = vec![0u8; count];
            let peeked = rb.peek(&mut peek_buf);
            assert_eq!(peeked, count);
            assert_eq!(&peek_buf[..count], &data[..count]);

            // Drain
            let drained = rb.drain(count);
            assert_eq!(drained, count);
            assert_eq!(rb.len(), 0);
            assert_eq!(rb.avail(), rb_capa);
        }
    }
}
