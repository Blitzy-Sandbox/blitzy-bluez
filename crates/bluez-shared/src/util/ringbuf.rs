// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012-2014 Intel Corporation. All rights reserved.

//! Fixed-capacity circular byte buffer for protocol packet buffering.
//!
//! This module provides [`RingBuf`], a ring buffer implementation used
//! by the HFP AT command engine and serial transports for efficient
//! buffered I/O with scatter-gather support.
//!
//! ## Design
//!
//! The buffer capacity is always a power of two, enabling O(1) modular
//! arithmetic via bitmask operations (`index & (size - 1)`). Logical
//! cursors (`write_pos` and `read_pos`) grow monotonically and are
//! masked when indexing into the physical buffer. When the buffer is
//! fully drained, both cursors reset to zero to avoid unbounded growth.
//!
//! This is a direct behavioral clone of C `struct ringbuf` from
//! `src/shared/ringbuf.c`.

use std::cmp::min;
use std::fmt;
use std::io::{self, IoSlice, IoSliceMut};
use std::os::unix::io::BorrowedFd;

use nix::sys::uio;

/// Error returned by ring buffer write operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingBufError {
    /// The ring buffer has insufficient space for the write operation.
    BufferFull,
}

impl fmt::Display for RingBufError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RingBufError::BufferFull => f.write_str("ring buffer full"),
        }
    }
}

impl std::error::Error for RingBufError {}

/// Type alias for the input tracing callback closure.
///
/// Invoked with each contiguous data segment when data is written
/// into the buffer. Replaces C `ringbuf_tracing_func_t callback +
/// void *user_data`.
type TracingCallback = Box<dyn Fn(&[u8]) + Send>;

/// Fixed-capacity circular byte buffer.
///
/// Replaces the C `struct ringbuf` with identical semantics:
/// - Size is always rounded up to the next power of two for efficient
///   bitmask-based modular arithmetic.
/// - Supports scatter-gather I/O (`writev`/`readv`) for efficient
///   file-descriptor-based operations.
/// - Optional tracing callback monitors data written to the buffer.
/// - Cursor reset optimization when the buffer is fully drained.
///
/// # Examples
///
/// ```no_run
/// use bluez_shared::util::ringbuf::RingBuf;
///
/// let mut rb = RingBuf::new(128).expect("valid size");
/// assert_eq!(rb.capacity(), 128);
/// assert_eq!(rb.len(), 0);
///
/// rb.write_bytes(b"hello").unwrap();
/// assert_eq!(rb.len(), 5);
///
/// let (first, second) = rb.peek(0);
/// assert_eq!(first, b"hello");
/// assert!(second.is_none());
///
/// let drained = rb.drain(5);
/// assert_eq!(drained, 5);
/// assert!(rb.is_empty());
/// ```
pub struct RingBuf {
    /// Heap-allocated buffer (replaces `void *buffer` + `malloc`/`free`).
    buffer: Vec<u8>,
    /// Buffer capacity, always a power of two for efficient bitmask wrapping.
    size: usize,
    /// Write cursor (logical position, not bounded by size; masked for buffer indexing).
    write_pos: usize,
    /// Read cursor (logical position, not bounded by size; masked for buffer indexing).
    read_pos: usize,
    /// Optional tracing callback, invoked when data is written into the buffer.
    /// Replaces C `ringbuf_tracing_func_t callback + void *user_data` with a
    /// closure that captures any needed context.
    in_tracing: Option<TracingCallback>,
}

impl RingBuf {
    /// Create a new ring buffer with the given minimum size.
    ///
    /// The actual capacity is rounded up to the next power of two using
    /// `usize::next_power_of_two()` (Rust equivalent of C `align_power2`).
    ///
    /// Returns `None` if `size` is less than 2 or greater than `u32::MAX`,
    /// matching the C `ringbuf_new()` validation (lines 51–74 of ringbuf.c).
    ///
    /// # Arguments
    ///
    /// * `size` - Minimum buffer capacity in bytes. Must be `>= 2` and
    ///   `<= u32::MAX`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::ringbuf::RingBuf;
    ///
    /// // Rounds up to next power of two
    /// let rb = RingBuf::new(5).unwrap();
    /// assert_eq!(rb.capacity(), 8);
    ///
    /// // Below minimum
    /// assert!(RingBuf::new(1).is_none());
    /// ```
    pub fn new(size: usize) -> Option<Self> {
        if size < 2 || size > u32::MAX as usize {
            return None;
        }
        let real_size = size.next_power_of_two();
        Some(RingBuf {
            buffer: vec![0u8; real_size],
            size: real_size,
            write_pos: 0,
            read_pos: 0,
            in_tracing: None,
        })
    }

    /// Set the input tracing callback.
    ///
    /// The callback is invoked with each contiguous data segment when data
    /// is written into the buffer (via [`write_bytes`](Self::write_bytes),
    /// [`printf`](Self::printf), or [`read_from_fd`](Self::read_from_fd)).
    /// For wrap-around writes, the callback fires twice: once for the
    /// pre-wrap segment and once for the post-wrap segment.
    ///
    /// Replaces C `ringbuf_set_input_tracing(ringbuf, callback, user_data)`.
    /// The closure captures any user data directly, eliminating the
    /// `void *user_data` pattern.
    ///
    /// Always returns `true`, indicating the callback was set successfully.
    pub fn set_input_tracing(&mut self, callback: impl Fn(&[u8]) + Send + 'static) -> bool {
        self.in_tracing = Some(Box::new(callback));
        true
    }

    /// Remove the input tracing callback.
    ///
    /// After calling this, no tracing callback will fire on subsequent
    /// write operations.
    pub fn clear_input_tracing(&mut self) {
        self.in_tracing = None;
    }

    /// Return the total capacity of the buffer (always a power of two).
    ///
    /// This is the maximum number of bytes the buffer can hold at once,
    /// including currently used space.
    ///
    /// Matches C `ringbuf_capacity()`.
    pub fn capacity(&self) -> usize {
        self.size
    }

    /// Return the number of bytes available for reading.
    ///
    /// This is the difference between the write and read cursors.
    ///
    /// Matches C `ringbuf_len()`: `in - out`.
    pub fn len(&self) -> usize {
        self.write_pos - self.read_pos
    }

    /// Return `true` if no data is available for reading.
    pub fn is_empty(&self) -> bool {
        self.write_pos == self.read_pos
    }

    /// Return the number of free bytes available for writing.
    ///
    /// Matches C `ringbuf_avail()`: `size - in + out`.
    pub fn avail(&self) -> usize {
        self.size - self.write_pos + self.read_pos
    }

    /// Consume up to `count` bytes without reading data.
    ///
    /// Advances the read cursor by the lesser of `count` and the amount
    /// of data currently buffered. When the buffer becomes empty, both
    /// cursors are reset to zero (matching C `RINGBUF_RESET` behavior)
    /// to avoid unbounded cursor growth.
    ///
    /// Returns the actual number of bytes drained.
    ///
    /// Matches C `ringbuf_drain()`.
    pub fn drain(&mut self, count: usize) -> usize {
        let len = min(count, self.len());
        if len == 0 {
            return 0;
        }
        self.read_pos += len;
        if self.read_pos == self.write_pos {
            self.write_pos = 0;
            self.read_pos = 0;
        }
        len
    }

    /// Peek at buffered data starting at the given offset from the read cursor.
    ///
    /// Returns a tuple of:
    /// - First slice: contiguous data from the offset position to the end
    ///   of the physical buffer (or end of data, whichever comes first).
    /// - Second slice (`Option`): wrapped-around data from the buffer start,
    ///   if the data spans the physical buffer boundary.
    ///
    /// The C version (`ringbuf_peek`) returns a single pointer and
    /// `len_nowrap` (first contiguous segment length). This Rust version
    /// returns two slices for clarity, safety, and convenience.
    ///
    /// Uses bitmask for wrap: `(read_pos + offset) & (size - 1)`.
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset from the current read position. If the
    ///   offset exceeds the buffered data length, returns an empty slice.
    pub fn peek(&self, offset: usize) -> (&[u8], Option<&[u8]>) {
        let data_len = self.len();
        if offset >= data_len {
            return (&[], None);
        }

        let buf_offset = (self.read_pos + offset) & (self.size - 1);
        let remaining = data_len - offset;
        let first_len = min(remaining, self.size - buf_offset);

        let first = &self.buffer[buf_offset..buf_offset + first_len];

        if remaining > first_len {
            let second_len = remaining - first_len;
            (first, Some(&self.buffer[..second_len]))
        } else {
            (first, None)
        }
    }

    /// Write buffered data to a file descriptor using scatter-gather I/O.
    ///
    /// Constructs up to two `iovec` segments to handle wrap-around, then
    /// calls `writev()` via `nix::sys::uio::writev` for efficient data
    /// transfer. Advances the read cursor by the number of bytes written.
    /// When the buffer becomes empty, both cursors reset to zero.
    ///
    /// Accepts a [`BorrowedFd`] for I/O safety. Callers with a raw file
    /// descriptor can construct a `BorrowedFd` at the FFI boundary where
    /// `unsafe` is permitted.
    ///
    /// Returns the number of bytes written, or an I/O error.
    ///
    /// Matches C `ringbuf_write()`.
    pub fn write_to_fd(&mut self, fd: BorrowedFd<'_>) -> Result<usize, io::Error> {
        let len = self.len();
        if len == 0 {
            return Ok(0);
        }

        let offset = self.read_pos & (self.size - 1);
        let end = min(len, self.size - offset);
        let second_len = len - end;

        // Confine immutable borrows to a block so that cursor mutation
        // below does not conflict with the buffer references in IoSlice.
        let consumed = {
            let iovecs = [
                IoSlice::new(&self.buffer[offset..offset + end]),
                IoSlice::new(&self.buffer[..second_len]),
            ];
            uio::writev(fd, &iovecs).map_err(io::Error::from)?
        };

        self.read_pos += consumed;
        if self.read_pos == self.write_pos {
            self.write_pos = 0;
            self.read_pos = 0;
        }

        Ok(consumed)
    }

    /// Write raw bytes into the ring buffer.
    ///
    /// Handles wrap-around transparently. Invokes the tracing callback
    /// for each contiguous written segment (pre-wrap and post-wrap are
    /// reported as separate callback invocations, matching C behavior).
    ///
    /// Returns the number of bytes actually written. The written count
    /// may be less than `data.len()` if the buffer has insufficient free
    /// space. Returns [`RingBufError::BufferFull`] only when the buffer
    /// is completely full and `data` is non-empty.
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<usize, RingBufError> {
        if data.is_empty() {
            return Ok(0);
        }

        let avail = self.avail();
        if avail == 0 {
            return Err(RingBufError::BufferFull);
        }

        let to_write = min(data.len(), avail);
        let offset = self.write_pos & (self.size - 1);
        let end = min(to_write, self.size - offset);

        // First segment: from write cursor to end of physical buffer.
        self.buffer[offset..offset + end].copy_from_slice(&data[..end]);
        if let Some(ref cb) = self.in_tracing {
            cb(&self.buffer[offset..offset + end]);
        }

        // Second segment: wrapped-around portion at buffer start.
        if to_write > end {
            let remainder = to_write - end;
            self.buffer[..remainder].copy_from_slice(&data[end..end + remainder]);
            if let Some(ref cb) = self.in_tracing {
                cb(&self.buffer[..remainder]);
            }
        }

        self.write_pos += to_write;
        Ok(to_write)
    }

    /// Write formatted text into the ring buffer.
    ///
    /// Replaces C `ringbuf_vprintf()` which uses `vasprintf` for formatting.
    /// In Rust, uses [`fmt::format`] to produce the formatted string, then
    /// copies the bytes into the buffer with wrap-around handling.
    ///
    /// Invoke as: `ring.printf(format_args!("AT+COMMAND={}\r", value))`
    ///
    /// Returns the number of bytes written. Returns
    /// [`RingBufError::BufferFull`] if the formatted string does not fit
    /// in the available space (the entire formatted string is written
    /// atomically or not at all, matching C `ringbuf_vprintf` semantics).
    ///
    /// Matches C `ringbuf_vprintf()`.
    pub fn printf(&mut self, args: fmt::Arguments<'_>) -> Result<usize, RingBufError> {
        let formatted = fmt::format(args);
        let str_bytes = formatted.as_bytes();
        let len = str_bytes.len();

        if len == 0 {
            return Ok(0);
        }

        let avail = self.avail();
        if len > avail {
            return Err(RingBufError::BufferFull);
        }

        let offset = self.write_pos & (self.size - 1);
        let end = min(len, self.size - offset);

        // First segment: from write cursor to end of physical buffer.
        self.buffer[offset..offset + end].copy_from_slice(&str_bytes[..end]);
        if let Some(ref cb) = self.in_tracing {
            cb(&self.buffer[offset..offset + end]);
        }

        // Second segment: wrapped-around portion at buffer start.
        if len > end {
            let remainder = len - end;
            self.buffer[..remainder].copy_from_slice(&str_bytes[end..]);
            if let Some(ref cb) = self.in_tracing {
                cb(&self.buffer[..remainder]);
            }
        }

        self.write_pos += len;
        Ok(len)
    }

    /// Read data from a file descriptor into the ring buffer using
    /// scatter-gather I/O.
    ///
    /// Constructs up to two `iovec` segments to handle wrap-around, then
    /// calls `readv()` via `nix::sys::uio::readv` for efficient data
    /// transfer. Invokes the tracing callback for each contiguous segment
    /// of data actually read. Advances the write cursor by the number of
    /// bytes read.
    ///
    /// Accepts a [`BorrowedFd`] for I/O safety. Callers with a raw file
    /// descriptor can construct a `BorrowedFd` at the FFI boundary where
    /// `unsafe` is permitted.
    ///
    /// Returns the number of bytes read. Returns an I/O error if the
    /// buffer is full (no space for reading) or if `readv` fails.
    ///
    /// Matches C `ringbuf_read()`.
    pub fn read_from_fd(&mut self, fd: BorrowedFd<'_>) -> Result<usize, io::Error> {
        let avail = self.avail();
        if avail == 0 {
            return Err(io::Error::other("ring buffer full"));
        }

        let offset = self.write_pos & (self.size - 1);
        let end = min(avail, self.size - offset);
        let second_len = avail - end;

        // Confine mutable borrows to a block. `split_at_mut` produces
        // two non-overlapping mutable slices so that two IoSliceMut
        // segments can be created safely for readv.
        let consumed = {
            let (left, right) = self.buffer.split_at_mut(offset);
            let mut iovecs =
                [IoSliceMut::new(&mut right[..end]), IoSliceMut::new(&mut left[..second_len])];
            uio::readv(fd, &mut iovecs).map_err(io::Error::from)?
        };

        // Invoke tracing callback for each contiguous segment of data
        // that was actually read, matching C behavior where separate
        // callbacks fire for pre-wrap and post-wrap segments.
        if let Some(ref cb) = self.in_tracing {
            let first_traced = min(consumed, end);
            if first_traced > 0 {
                cb(&self.buffer[offset..offset + first_traced]);
            }
            if consumed > first_traced {
                cb(&self.buffer[..consumed - first_traced]);
            }
        }

        self.write_pos += consumed;

        Ok(consumed)
    }
}
