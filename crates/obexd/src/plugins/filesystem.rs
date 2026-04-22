// SPDX-License-Identifier: GPL-2.0-or-later
//
//! Filesystem MIME type drivers for the OBEX daemon.
//!
//! Provides four MIME drivers:
//! 1. **Generic file** — raw file I/O for OPP/FTP transfers
//! 2. **Folder listing** — `x-obex/folder-listing` XML generation
//! 3. **Capability** — `x-obex/capability` static file or command execution
//! 4. **PC Suite folder listing** — Nokia PC Suite variant with `mem-type="DEV"`
//!
//! Also exports utility functions used by other plugin modules:
//! - [`string_read`] — incremental string buffer read
//! - [`is_filename`] — OBEX filename validation
//! - [`verify_path`] — root folder containment check
//!
//! Replaces `obexd/plugins/filesystem.c` (719 lines) and
//! `obexd/plugins/filesystem.h`.

// ---------------------------------------------------------------------------
// External imports
// ---------------------------------------------------------------------------

use std::any::Any;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::sys::statvfs;

// ---------------------------------------------------------------------------
// Internal imports
// ---------------------------------------------------------------------------

use crate::plugins::{
    ObexMimeTypeDriver, ObexPluginDesc, obex_mime_type_driver_register,
    obex_mime_type_driver_unregister,
};

// ---------------------------------------------------------------------------
// Configuration accessor stubs
// ---------------------------------------------------------------------------
//
// In the C codebase these live in obexd/src/obexd.h and are global
// functions populated by the daemon's main().  In the Rust binary
// target they live in main.rs.  The library-side accessors below
// delegate to a process-wide OnceLock that the binary populates at
// startup via `set_obex_options`.

use std::sync::OnceLock;

/// Process-wide OBEX option store, populated by the binary entry point.
struct ObexOptions {
    root_folder: PathBuf,
    symlinks: bool,
    capability: PathBuf,
}

static OBEX_OPTIONS: OnceLock<ObexOptions> = OnceLock::new();

/// Initialise the library-side OBEX option cache.
///
/// Called once from the binary entry point (`main.rs`) before any
/// plugin code runs.
pub fn set_obex_options(root_folder: PathBuf, symlinks: bool, capability: PathBuf) {
    let _ = OBEX_OPTIONS.set(ObexOptions { root_folder, symlinks, capability });
}

/// Return the resolved root folder path for OBEX file operations.
fn obex_option_root_folder() -> &'static Path {
    OBEX_OPTIONS.get().map_or(Path::new(""), |o| o.root_folder.as_path())
}

/// Return whether symlinks outside root are permitted.
fn obex_option_symlinks() -> bool {
    OBEX_OPTIONS.get().is_some_and(|o| o.symlinks)
}

/// Return the capability file path (or `!command`).
fn obex_option_capability() -> &'static Path {
    OBEX_OPTIONS.get().map_or(Path::new(""), |o| o.capability.as_path())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// FTP target UUID — identifies FTP service in OBEX Target header.
/// Matches the C `FTP_TARGET` byte array exactly.
const FTP_TARGET: [u8; 16] = [
    0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2, 0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09,
];

/// PC Suite WHO header identifier — `"PC Suite"` in ASCII.
const PCSUITE_WHO: [u8; 8] = [b'P', b'C', b' ', b'S', b'u', b'i', b't', b'e'];

// XML format strings — matched byte-for-byte against C original output.
const FL_VERSION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

const FL_TYPE: &str = "<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\">\n";

const FL_TYPE_PCSUITE: &str = "<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\"\n\
     \x20\x20[ <!ATTLIST folder mem-type CDATA #IMPLIED> ]>\n";

const FL_BODY_BEGIN: &str = "<folder-listing version=\"1.0\">\n";

const FL_BODY_END: &str = "</folder-listing>\n";

const FL_PARENT_FOLDER_ELEMENT: &str = "<parent-folder/>\n";

// ===========================================================================
// Public types
// ===========================================================================

/// State tracker for incremental string reads in OBEX content generation.
///
/// Used by folder listing, capability, and PC Suite drivers to serve
/// pre-generated XML or capability text via sequential [`string_read`]
/// calls.
pub struct StringReadState {
    /// The complete string data buffer.
    pub data: String,
    /// Current read offset (bytes consumed so far).
    pub offset: usize,
}

impl StringReadState {
    /// Create a new read state from the given string content.
    pub fn new(data: String) -> Self {
        Self { data, offset: 0 }
    }

    /// Create a new read state from a raw byte buffer.
    ///
    /// Converts the bytes to UTF-8 (lossy), used by MAP and other
    /// plugins that build binary-safe buffers.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self {
            data: String::from_utf8(data)
                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
            offset: 0,
        }
    }
}

// ===========================================================================
// Public utility functions (exported via plugins/mod.rs)
// ===========================================================================

/// Read from a [`StringReadState`] buffer into `buf`.
///
/// Copies up to `buf.len()` bytes starting at the current offset.
///
/// # Returns
///
/// - `Ok(n)` where `n` > 0 — number of bytes copied
/// - `Ok(0)` — EOF (all data consumed)
/// - `Err(-EAGAIN)` — data buffer is empty / not yet populated
pub fn string_read(state: &mut StringReadState, buf: &mut [u8]) -> Result<usize, i32> {
    // Data not populated yet — signal "not ready"
    if state.data.is_empty() {
        return Err(-(Errno::EAGAIN as i32));
    }

    let total = state.data.len();
    if state.offset >= total {
        // All data has been consumed — EOF
        return Ok(0);
    }

    let remaining = total - state.offset;
    let to_copy = remaining.min(buf.len());
    buf[..to_copy].copy_from_slice(&state.data.as_bytes()[state.offset..state.offset + to_copy]);
    state.offset += to_copy;
    Ok(to_copy)
}

/// Validate that `name` is a safe OBEX filename.
///
/// Returns `false` if `name` contains a path separator (`/`) or is the
/// special directory entries `"."` / `".."`.  Used by FTP and OPP drivers
/// for input validation before accepting an object name.
pub fn is_filename(name: &str) -> bool {
    if name.contains('/') {
        return false;
    }
    if name == "." || name == ".." {
        return false;
    }
    true
}

/// Verify that `path` is contained within the OBEX root folder.
///
/// Resolves `path` to its canonical (real) form via
/// [`std::fs::canonicalize`] and checks that it starts with the
/// configured root folder prefix.  If symlinks are allowed via
/// [`obex_option_symlinks`] the check is skipped entirely.
///
/// # Returns
///
/// - `Ok(())` — path is within the root folder (or symlinks allowed)
/// - `Err(-EPERM)` — path escapes the root folder sandbox
/// - `Err(-errno)` — canonical path resolution failed
pub fn verify_path(path: &str) -> Result<(), i32> {
    if obex_option_symlinks() {
        return Ok(());
    }

    let canonical =
        fs::canonicalize(path).map_err(|e| -(e.raw_os_error().unwrap_or(Errno::EPERM as i32)))?;

    let root = obex_option_root_folder();
    if !canonical.starts_with(root) {
        tracing::warn!("verify_path: '{}' escapes root folder '{}'", path, root.display());
        return Err(-(Errno::EPERM as i32));
    }

    Ok(())
}

// ===========================================================================
// Internal helpers — XML generation
// ===========================================================================

/// Escape XML special characters in a string.
///
/// Replaces `&`, `<`, `>`, `"`, and `'` with their XML entity
/// equivalents.  Equivalent to GLib's `g_markup_escape_text`.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Convert days since Unix epoch (1970-01-01) to `(year, month, day)`.
///
/// Uses the Howard Hinnant / `chrono` civil calendar algorithm,
/// which is exact for all dates in the Gregorian calendar.
fn days_to_civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Format a Unix timestamp (seconds since epoch) as an OBEX-standard
/// UTC timestamp string: `YYYYMMDDTHHMMSSZ`.
///
/// Replaces `gmtime_r` + `strftime` from the C implementation.
fn format_unix_timestamp(secs: i64) -> String {
    if secs < 0 {
        return "19700101T000000Z".to_owned();
    }
    let total_secs = secs as u64;
    let days = (total_secs / 86400) as i64;
    let tod = total_secs % 86400;
    let hours = tod / 3600;
    let minutes = (tod % 3600) / 60;
    let seconds = tod % 60;

    let (year, month, day) = days_to_civil(days);

    let mut buf = String::with_capacity(17);
    let _ =
        write!(buf, "{:04}{:02}{:02}T{:02}{:02}{:02}Z", year, month, day, hours, minutes, seconds);
    buf
}

/// Format a [`SystemTime`] as an OBEX-standard UTC timestamp.
///
/// Converts via [`duration_since`](SystemTime::duration_since) against
/// [`UNIX_EPOCH`] and delegates to [`format_unix_timestamp`].
pub fn format_system_time(time: SystemTime) -> String {
    match time.duration_since(UNIX_EPOCH) {
        Ok(dur) => format_unix_timestamp(dur.as_secs() as i64),
        Err(_) => "19700101T000000Z".to_owned(),
    }
}

/// Generate a single XML element for a directory entry.
///
/// Produces a `<file …/>` or `<folder …/>` line with OBEX-standard
/// attributes.  Returns `None` for entries that are neither regular
/// files nor directories (symlinks, devices, etc.).
///
/// The `dstat` parameter provides the **parent directory** metadata,
/// used to derive the OBEX "delete" permission (D) from the parent's
/// write bits — matching the C `file_stat_line` semantics exactly.
///
/// Note: the `pcsuite` parameter controls the Nokia-specific
/// `mem-type="DEV"` attribute on the "Data" folder in the root
/// directory.  In the C original, `append_listing` always passes
/// `FALSE` for this parameter, making the PC Suite folder element
/// dead code.  We replicate this behaviour for byte-identical output.
fn file_stat_line(
    filename: &str,
    fmeta: &fs::Metadata,
    dmeta: &fs::Metadata,
    root: bool,
    pcsuite: bool,
) -> Option<String> {
    let fmode = fmeta.mode();
    let dmode = dmeta.mode();

    // Build OBEX permission string — matches C snprintf exactly
    let perm = format!(
        "user-perm=\"{}{}{}\" group-perm=\"{}{}{}\" other-perm=\"{}{}{}\"",
        if fmode & 0o400 != 0 { "R" } else { "" },
        if fmode & 0o200 != 0 { "W" } else { "" },
        if dmode & 0o200 != 0 { "D" } else { "" },
        if fmode & 0o040 != 0 { "R" } else { "" },
        if fmode & 0o020 != 0 { "W" } else { "" },
        if dmode & 0o020 != 0 { "D" } else { "" },
        if fmode & 0o004 != 0 { "R" } else { "" },
        if fmode & 0o002 != 0 { "W" } else { "" },
        if dmode & 0o002 != 0 { "D" } else { "" },
    );

    // Format timestamps using raw Unix seconds from MetadataExt
    // The C code uses st_atime, st_ctime, st_mtime via gmtime_r.
    // Rust MetadataExt::atime/ctime/mtime return i64 seconds.
    let atime = format_unix_timestamp(fmeta.atime());
    let ctime_str = format_unix_timestamp(fmeta.ctime());
    let mtime = format_unix_timestamp(fmeta.mtime());

    let escaped = xml_escape(filename);

    let ft = fmeta.file_type();

    if ft.is_dir() {
        if pcsuite && root && filename == "Data" {
            // PC Suite: folder with mem-type="DEV" attribute
            Some(format!(
                "<folder name=\"{escaped}\" {perm} accessed=\"{atime}\" \
                 modified=\"{mtime}\" mem-type=\"DEV\" created=\"{ctime_str}\"/>\n"
            ))
        } else {
            Some(format!(
                "<folder name=\"{escaped}\" {perm} accessed=\"{atime}\" \
                 modified=\"{mtime}\" created=\"{ctime_str}\"/>\n"
            ))
        }
    } else if ft.is_file() {
        let size = fmeta.size();
        Some(format!(
            "<file name=\"{escaped}\" size=\"{size}\" \
             {perm} accessed=\"{atime}\" \
             modified=\"{mtime}\" created=\"{ctime_str}\"/>\n"
        ))
    } else {
        // Not a regular file or directory — skip
        None
    }
}

/// Build the body of a folder listing XML document by iterating a
/// directory's entries.
///
/// Appends `<parent-folder/>`, per-entry `<file …/>` / `<folder …/>`
/// elements, and the closing `</folder-listing>` tag to `buffer`.
///
/// The `pcsuite` parameter is accepted for API symmetry with the C
/// `append_listing` but is always passed as `false` to
/// [`file_stat_line`], replicating the C original behaviour.
fn append_listing(buffer: &mut String, name: &str, _pcsuite: bool) -> Result<usize, i32> {
    let root_str = obex_option_root_folder().to_str().unwrap_or("");
    let is_root = name == root_str;

    // Open directory
    let entries = fs::read_dir(name).map_err(|_| -(Errno::ENOENT as i32))?;

    // Emit parent-folder element (not at root level)
    if !is_root {
        buffer.push_str(FL_PARENT_FOLDER_ELEMENT);
    }

    // Verify the directory path stays within the sandbox
    verify_path(name)?;

    // Get parent directory metadata (for delete permission derivation)
    let dstat =
        fs::metadata(name).map_err(|e| -(e.raw_os_error().unwrap_or(Errno::ENOENT as i32)))?;

    // Iterate directory entries
    for entry_result in entries {
        let entry = match entry_result {
            Ok(e) => e,
            Err(_) => continue,
        };

        let os_name = entry.file_name();
        let name_str = match os_name.to_str() {
            Some(s) => s,
            None => {
                tracing::error!("filename is not valid UTF-8, skipping");
                continue;
            }
        };

        // Skip dotfiles — matches C `ep->d_name[0] == '.'`
        if name_str.starts_with('.') {
            continue;
        }

        // Get entry metadata via stat (follows symlinks)
        let fstat = match fs::metadata(entry.path()) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("stat: {} ({})", e, entry.path().display());
                continue;
            }
        };

        // Format XML element — always pass pcsuite=false
        // (replicating C original: line 529 passes FALSE)
        if let Some(line) = file_stat_line(name_str, &fstat, &dstat, is_root, false) {
            buffer.push_str(&line);
        }
    }

    // Close folder-listing element
    buffer.push_str(FL_BODY_END);

    Ok(buffer.len())
}

// ===========================================================================
// MIME driver object types
// ===========================================================================

/// Object state for the generic file MIME driver.
struct FilesystemObject {
    file: File,
}

/// Object state for the folder listing and PC Suite listing drivers.
struct FolderListingObject {
    state: StringReadState,
}

/// Object state for the capability MIME driver.
struct CapabilityObject {
    state: StringReadState,
}

// ===========================================================================
// Generic file MIME driver
// ===========================================================================

/// Generic file MIME driver — handles raw file I/O for OPP/FTP
/// transfers.
///
/// This is the fallback driver with no specific MIME type or target,
/// matching the C `static const struct obex_mime_type_driver file`.
struct FilesystemDriver;

impl ObexMimeTypeDriver for FilesystemDriver {
    fn open(
        &self,
        name: &str,
        flags: i32,
        mode: u32,
        _context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32> {
        use std::os::unix::fs::OpenOptionsExt;

        let file = if flags == libc::O_RDONLY {
            File::open(name)
        } else {
            let mut opts = fs::OpenOptions::new();
            // Map POSIX open flags to Rust OpenOptions
            if flags & libc::O_WRONLY != 0 {
                opts.write(true);
            }
            if flags & libc::O_RDWR != 0 {
                opts.read(true).write(true);
            }
            if flags & libc::O_CREAT != 0 {
                opts.create(true);
            }
            if flags & libc::O_TRUNC != 0 {
                opts.truncate(true);
            }
            if flags & libc::O_APPEND != 0 {
                opts.append(true);
            }
            opts.mode(mode);
            opts.open(name)
        }
        .map_err(|e| {
            let errno = e.raw_os_error().unwrap_or(libc::EIO);
            tracing::error!("open({}): {} ({})", name, e, errno);
            -errno
        })?;

        // Verify path stays within sandbox
        verify_path(name)?;

        // Check available disk space for write operations
        if flags != libc::O_RDONLY {
            match statvfs::statvfs(Path::new(name)) {
                Ok(stat) => {
                    let avail = stat.block_size() * stat.blocks_available();
                    if avail == 0 {
                        return Err(-(Errno::ENOSPC as i32));
                    }
                }
                Err(e) => {
                    tracing::error!("statvfs({}): {}", name, e);
                    return Err(-(e as i32));
                }
            }
        }

        Ok(Box::new(FilesystemObject { file }))
    }

    fn close(&self, _object: &mut dyn Any) -> Result<(), i32> {
        // File is closed by Drop when the Box is dropped
        Ok(())
    }

    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<FilesystemObject>().ok_or(-(libc::EBADF))?;

        obj.file.read(buf).map_err(|e| {
            let errno = e.raw_os_error().unwrap_or(libc::EIO);
            tracing::error!("read: {} ({})", e, errno);
            -errno
        })
    }

    fn write(&self, object: &mut dyn Any, buf: &[u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<FilesystemObject>().ok_or(-(libc::EBADF))?;

        obj.file.write(buf).map_err(|e| {
            let errno = e.raw_os_error().unwrap_or(libc::EIO);
            tracing::error!("write: {} ({})", e, errno);
            -errno
        })
    }

    fn remove(&self, name: &str) -> Result<(), i32> {
        // Try file removal first, then directory
        if let Err(e) = fs::remove_file(name) {
            if e.kind() == std::io::ErrorKind::IsADirectory || e.kind() == std::io::ErrorKind::Other
            {
                return fs::remove_dir(name).map_err(|e2| {
                    tracing::error!("remove({}): {}", name, e2);
                    -(e2.raw_os_error().unwrap_or(libc::EIO))
                });
            }
            tracing::error!("remove({}): {}", name, e);
            return Err(-(e.raw_os_error().unwrap_or(libc::EIO)));
        }
        Ok(())
    }

    fn rename(&self, source: &str, dest: &str) -> Result<(), i32> {
        fs::rename(source, dest).map_err(|e| {
            let errno = e.raw_os_error().unwrap_or(libc::EIO);
            tracing::error!("rename({}, {}): {} ({})", source, dest, e, errno);
            -errno
        })
    }

    fn copy(&self, source: &str, dest: &str) -> Result<(), i32> {
        let src = source.to_owned();
        let dst = dest.to_owned();

        // Offload potentially large copy to a blocking context via
        // tokio::task::spawn_blocking to avoid stalling the reactor.
        // Falls back to direct std::fs::copy outside a tokio runtime.
        let result = if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| {
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async {
                    tokio::task::spawn_blocking(move || fs::copy(&src, &dst)).await
                })
            })
        } else {
            Ok(fs::copy(&src, &dst))
        };

        match result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => {
                let errno = e.raw_os_error().unwrap_or(libc::EIO);
                tracing::error!("copy({}, {}): {} ({})", source, dest, e, errno);
                Err(-errno)
            }
            Err(e) => {
                tracing::error!("copy task failed: {}", e);
                Err(-(libc::EIO))
            }
        }
    }
}

// ===========================================================================
// Folder listing MIME driver
// ===========================================================================

/// Folder listing MIME driver — generates `x-obex/folder-listing` XML.
///
/// Matches the C `static const struct obex_mime_type_driver folder`.
struct FolderListingDriver;

impl ObexMimeTypeDriver for FolderListingDriver {
    fn mimetype(&self) -> Option<&str> {
        Some("x-obex/folder-listing")
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&FTP_TARGET)
    }

    fn open(
        &self,
        name: &str,
        _flags: i32,
        _mode: u32,
        _context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32> {
        // Build the complete XML document into a String buffer
        let mut xml = String::with_capacity(4096);
        xml.push_str(FL_VERSION);
        xml.push_str(FL_TYPE);
        xml.push_str(FL_BODY_BEGIN);

        append_listing(&mut xml, name, false)?;

        let state = StringReadState::new(xml);
        Ok(Box::new(FolderListingObject { state }))
    }

    fn close(&self, _object: &mut dyn Any) -> Result<(), i32> {
        // StringReadState is freed when the Box drops
        Ok(())
    }

    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<FolderListingObject>().ok_or(-(libc::EBADF))?;

        string_read(&mut obj.state, buf)
    }
}

// ===========================================================================
// Capability MIME driver
// ===========================================================================

/// Capability MIME driver — serves `x-obex/capability` objects.
///
/// Two modes:
/// 1. **Static file**: reads the capability file into memory
/// 2. **Command execution** (path starts with `!`): executes the command
///    and captures stdout
///
/// Matches the C `static const struct obex_mime_type_driver capability`.
struct CapabilityDriver;

/// Execute a capability command and capture its stdout.
///
/// Uses `tokio::process::Command` when a tokio runtime is available,
/// falling back to `std::process::Command` otherwise.
fn capability_exec(cmd: &str) -> Result<String, i32> {
    let cmd_owned = cmd.to_owned();

    let output = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        // Bridge async tokio process execution into sync context
        tokio::task::block_in_place(|| {
            handle.block_on(async move { tokio::process::Command::new(&cmd_owned).output().await })
        })
        .map_err(|e| {
            tracing::error!("capability command failed: {}", e);
            -(Errno::EPERM as i32)
        })?
    } else {
        // No tokio runtime — fall back to std blocking execution
        std::process::Command::new(&cmd_owned).output().map_err(|e| {
            tracing::error!("capability command failed: {}", e);
            -(Errno::EPERM as i32)
        })?
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            tracing::error!("{}", stderr);
        }
        return Err(-(Errno::EPERM as i32));
    }

    tracing::info!("executed capability command: {}", cmd);

    String::from_utf8(output.stdout).map_err(|_| {
        tracing::error!("capability command produced invalid UTF-8");
        -(Errno::EPERM as i32)
    })
}

impl ObexMimeTypeDriver for CapabilityDriver {
    fn mimetype(&self) -> Option<&str> {
        Some("x-obex/capability")
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&FTP_TARGET)
    }

    fn open(
        &self,
        _name: &str,
        flags: i32,
        _mode: u32,
        _context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32> {
        // Capability is read-only
        if flags != libc::O_RDONLY {
            return Err(-(Errno::EPERM as i32));
        }

        let cap_path = obex_option_capability();
        let cap_str = cap_path.to_str().unwrap_or("");

        let content = if let Some(cmd) = cap_str.strip_prefix('!') {
            // Command execution mode
            capability_exec(cmd)?
        } else {
            // Static file mode
            fs::read_to_string(cap_path).map_err(|e| {
                tracing::error!("failed to read capability file '{}': {}", cap_path.display(), e);
                -(Errno::EPERM as i32)
            })?
        };

        let state = StringReadState::new(content);
        Ok(Box::new(CapabilityObject { state }))
    }

    fn close(&self, _object: &mut dyn Any) -> Result<(), i32> {
        Ok(())
    }

    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<CapabilityObject>().ok_or(-(libc::EBADF))?;

        string_read(&mut obj.state, buf)
    }
}

// ===========================================================================
// PC Suite folder listing MIME driver
// ===========================================================================

/// PC Suite folder listing MIME driver — Nokia-specific variant of
/// folder listing with a different DOCTYPE declaration.
///
/// Matches the C `static const struct obex_mime_type_driver pcsuite`.
struct PcSuiteListingDriver;

impl ObexMimeTypeDriver for PcSuiteListingDriver {
    fn mimetype(&self) -> Option<&str> {
        Some("x-obex/folder-listing")
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&FTP_TARGET)
    }

    fn who(&self) -> Option<&[u8]> {
        Some(&PCSUITE_WHO)
    }

    fn open(
        &self,
        name: &str,
        _flags: i32,
        _mode: u32,
        _context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32> {
        // Build PC Suite-specific XML with different DOCTYPE
        let mut xml = String::with_capacity(4096);
        xml.push_str(FL_VERSION);
        xml.push_str(FL_TYPE_PCSUITE);
        xml.push_str(FL_BODY_BEGIN);

        append_listing(&mut xml, name, true)?;

        let state = StringReadState::new(xml);
        Ok(Box::new(FolderListingObject { state }))
    }

    fn close(&self, _object: &mut dyn Any) -> Result<(), i32> {
        Ok(())
    }

    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<FolderListingObject>().ok_or(-(libc::EBADF))?;

        string_read(&mut obj.state, buf)
    }
}

// ===========================================================================
// Plugin lifecycle
// ===========================================================================

/// Initialise the filesystem plugin — register all four MIME drivers.
///
/// Registration order matches the C `filesystem_init` exactly:
/// 1. Folder listing driver
/// 2. Capability driver
/// 3. PC Suite folder listing driver
/// 4. Generic file driver
fn filesystem_init() -> Result<(), i32> {
    tracing::debug!("filesystem plugin: registering MIME drivers");

    obex_mime_type_driver_register(Arc::new(FolderListingDriver) as Arc<dyn ObexMimeTypeDriver>)?;

    obex_mime_type_driver_register(Arc::new(CapabilityDriver) as Arc<dyn ObexMimeTypeDriver>)?;

    obex_mime_type_driver_register(Arc::new(PcSuiteListingDriver) as Arc<dyn ObexMimeTypeDriver>)?;

    obex_mime_type_driver_register(Arc::new(FilesystemDriver) as Arc<dyn ObexMimeTypeDriver>)?;

    tracing::debug!("filesystem plugin: all MIME drivers registered");
    Ok(())
}

/// Shut down the filesystem plugin — unregister MIME drivers.
///
/// Unregistration set matches the C `filesystem_exit` exactly:
/// folder, capability, file.  Note: the C original does NOT
/// unregister the PC Suite driver — we replicate that behaviour.
fn filesystem_exit() {
    tracing::debug!("filesystem plugin: unregistering MIME drivers");

    obex_mime_type_driver_unregister(&FolderListingDriver);
    obex_mime_type_driver_unregister(&CapabilityDriver);
    obex_mime_type_driver_unregister(&FilesystemDriver);

    tracing::debug!("filesystem plugin: MIME drivers unregistered");
}

// ===========================================================================
// Plugin registration via inventory
// ===========================================================================

inventory::submit! {
    ObexPluginDesc {
        name: "filesystem",
        init: filesystem_init,
        exit: filesystem_exit,
    }
}
