//! Filesystem MIME type driver — stub awaiting full implementation.
//!
//! Provides the types and helper functions re-exported by the plugins module
//! root.  This file will be replaced by the full implementation agent.

/// State tracker for incremental string reads in OBEX listing generation.
pub struct StringReadState {
    /// Buffer holding the full string data.
    pub data: Vec<u8>,
    /// Current read offset into `data`.
    pub offset: usize,
}

impl StringReadState {
    /// Create a new read state from a string.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }
}

/// Read from a `StringReadState` into the provided buffer.
///
/// Returns the number of bytes copied, or `Err(-EAGAIN)` on first call to
/// signal that data is ready.
pub fn string_read(state: &mut StringReadState, buf: &mut [u8]) -> Result<usize, i32> {
    if state.offset >= state.data.len() {
        return Ok(0);
    }
    let remaining = &state.data[state.offset..];
    let to_copy = remaining.len().min(buf.len());
    buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
    state.offset += to_copy;
    Ok(to_copy)
}

/// Check whether a filename is a valid OBEX filename (no path separators).
pub fn is_filename(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && name != "." && name != ".."
}

/// Verify that a path is within the allowed root directory and safe.
pub fn verify_path(path: &str) -> bool {
    !path.is_empty() && !path.contains("..") && !path.starts_with('/')
}
