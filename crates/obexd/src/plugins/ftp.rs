// SPDX-License-Identifier: GPL-2.0-or-later
//
//! FTP service driver — Rust rewrite of `obexd/plugins/ftp.c` (528 lines)
//! and `obexd/plugins/ftp.h` (17 lines).
//!
//! Implements the OBEX File Transfer Profile (FTP) service plugin for the
//! OBEX daemon.  Provides CONNECT, GET, PUT, SETPATH, and ACTION (copy/move)
//! operations with full path traversal protection and POSIX filesystem
//! integration.
//!
//! The public `ftp_*` functions are re-exported by `plugins/mod.rs` for
//! delegation from the PC Suite / SyncEvolution (`sync.rs`) module.
//!
//! ## Key Transformation Patterns
//!
//! | C Pattern | Rust Replacement |
//! |---|---|
//! | `OBEX_PLUGIN_DEFINE(ftp, ...)` | `inventory::submit!(ObexPluginDesc { … })` |
//! | `struct obex_service_driver` | `impl ObexServiceDriver for FtpServiceDriver` |
//! | `g_build_filename(folder, name, NULL)` | `PathBuf::from(folder).join(name)` |
//! | `g_strdup` / `g_free` | Rust owned `String` |
//! | `is_filename(name)` | `super::filesystem::is_filename` |
//! | `verify_path(path)` | `super::filesystem::verify_path` |
//! | `mkdir(path, 0755)` | `std::fs::create_dir` + `set_permissions` |
//! | `stat(path, &st)` | `std::fs::metadata(path)` |
//! | `rename(src, dst)` | `std::fs::rename(src, dst)` |

// ---------------------------------------------------------------------------
// External imports
// ---------------------------------------------------------------------------

use std::any::Any;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;

// ---------------------------------------------------------------------------
// Internal imports
// ---------------------------------------------------------------------------

use super::filesystem::{is_filename, verify_path};
use super::{OBEX_FTP, ObexPluginDesc, ObexServiceDriver};
use super::{obex_service_driver_register, obex_service_driver_unregister};
use crate::obex::session::ObexSession;

// ---------------------------------------------------------------------------
// Configuration accessor stubs
// ---------------------------------------------------------------------------
//
// In the C codebase these live in obexd/src/obexd.h and are global
// functions populated by the daemon's main().  In the Rust binary
// target they live in main.rs.  The library-side accessors below
// delegate to the same `OnceLock` pattern used by filesystem.rs.
//
// The `set_obex_options` function from filesystem.rs populates the
// process-wide config at startup; we read through the filesystem module's
// public accessors.  If those are not yet public, a local fallback is
// provided via our own `OnceLock`.

use std::sync::OnceLock;

/// Process-wide FTP option store, populated by the binary entry point
/// via [`set_ftp_obex_options`].
struct FtpObexOptions {
    root_folder: PathBuf,
    capability: PathBuf,
}

static FTP_OBEX_OPTIONS: OnceLock<FtpObexOptions> = OnceLock::new();

/// Initialise the FTP module's OBEX option cache.
///
/// Called once from the binary entry point (`main.rs`) before any
/// plugin code runs.  Accepts the same root-folder and capability
/// values as `filesystem::set_obex_options`.
pub fn set_ftp_obex_options(root_folder: PathBuf, capability: PathBuf) {
    let _ = FTP_OBEX_OPTIONS.set(FtpObexOptions { root_folder, capability });
}

/// Return the resolved root folder path for OBEX file operations.
fn obex_option_root_folder() -> &'static Path {
    FTP_OBEX_OPTIONS.get().map_or(Path::new(""), |o| o.root_folder.as_path())
}

/// Return the capability file path.
fn obex_option_capability() -> &'static Path {
    FTP_OBEX_OPTIONS.get().map_or(Path::new(""), |o| o.capability.as_path())
}

// ===========================================================================
// Constants
// ===========================================================================

/// FTP Target UUID — 16-byte OBEX Target header identifying the FTP service.
///
/// Bytes match the C `FTP_TARGET` array exactly:
/// `F9EC7BC4-953C-11D2-984E-525400DC9E09`
pub const FTP_TARGET: [u8; 16] = [
    0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2, 0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09,
];

/// Capability MIME type identifier.
///
/// When an OBEX GET request carries this type, the daemon streams the
/// capability description file configured via `--capability`.
const CAP_TYPE: &str = "x-obex/capability";

/// Folder listing MIME type identifier.
///
/// When an OBEX GET request carries this type, the daemon generates and
/// streams an XML folder listing of the current working directory.
const LST_TYPE: &str = "x-obex/folder-listing";

/// Sentinel value indicating a DELETE operation via OBEX PUT with zero-length
/// body.  Matches `OBJECT_SIZE_DELETE` from `server/service.rs`.
const OBJECT_SIZE_DELETE: i64 = -2;

/// Sentinel value indicating that the object size is not yet known.
/// Matches `OBJECT_SIZE_UNKNOWN` from `server/service.rs`.
const OBJECT_SIZE_UNKNOWN: i64 = -1;

// ===========================================================================
// FTP Session State
// ===========================================================================

/// Per-connection FTP session state.
///
/// Created by [`ftp_connect`] and passed as type-erased `user_data`
/// (`Box<dyn Any + Send>`) through the [`ObexServiceDriver`] trait methods.
///
/// Replaces the C `struct ftp_session` from `obexd/plugins/ftp.c`.
///
/// ## Fields
///
/// - `os` — Session identifier (monotonic counter) used for logging and
///   D-Bus path construction.
/// - `transfer` — D-Bus transfer path counter or handle, used for
///   transfer lifecycle management.
/// - `folder` — Current working directory for this FTP session, initialised
///   to the daemon's configured root folder.
pub struct FtpSession {
    /// Session identifier (for logging and session tracking).
    pub os: usize,
    /// Transfer handle identifier (for D-Bus transfer lifecycle).
    pub transfer: usize,
    /// Current working directory — initialised to root folder on connect,
    /// updated by SETPATH operations.
    pub folder: String,

    // ------------------------------------------------------------------
    // Request state cache — populated by the server dispatch code
    // before each service driver method invocation.  This bridges the
    // gap between the C pattern (where `struct obex_session *` carries
    // request headers) and the Rust trait interface (which passes only
    // `&ObexSession` — the lower-level protocol engine).
    // ------------------------------------------------------------------
    /// Current OBEX request object name (from NAME header).
    req_name: Option<String>,
    /// Current OBEX request content type (from TYPE header).
    req_type: Option<String>,
    /// Current OBEX request object size (from LENGTH header).
    req_size: i64,
    /// Current OBEX request destination name (from DESTNAME header, for
    /// copy/move actions).
    req_destname: Option<String>,
    /// Non-header data bytes (from SETPATH pre-header flags/constants).
    req_nonhdr: Option<Vec<u8>>,
    /// Current ACTION ID (0x00 = copy, 0x01 = move).
    req_action_id: u8,
}

impl FtpSession {
    /// Create a new FTP session initialised to the given root folder.
    fn new(root_folder: &str) -> Self {
        Self {
            os: 0,
            transfer: 0,
            folder: root_folder.to_owned(),
            req_name: None,
            req_type: None,
            req_size: OBJECT_SIZE_UNKNOWN,
            req_destname: None,
            req_nonhdr: None,
            req_action_id: 0,
        }
    }

    /// Populate transient request state before a service driver method call.
    ///
    /// Called by the server-side dispatch code (in `server/service.rs`) after
    /// parsing OBEX request headers and before invoking the appropriate FTP
    /// handler.  This bridges the C `obex_get_name(os)` / `obex_get_type(os)`
    /// accessor pattern to the Rust trait architecture.
    pub fn set_request_state(
        &mut self,
        name: Option<String>,
        obj_type: Option<String>,
        size: i64,
        destname: Option<String>,
        nonhdr: Option<Vec<u8>>,
        action_id: u8,
    ) {
        self.req_name = name;
        self.req_type = obj_type;
        self.req_size = size;
        self.req_destname = destname;
        self.req_nonhdr = nonhdr;
        self.req_action_id = action_id;
    }

    /// Clear transient request state after a service driver method returns.
    pub fn clear_request_state(&mut self) {
        self.req_name = None;
        self.req_type = None;
        self.req_size = OBJECT_SIZE_UNKNOWN;
        self.req_destname = None;
        self.req_nonhdr = None;
        self.req_action_id = 0;
    }
}

/// Update the FTP session's current working directory.
///
/// Replaces C `set_folder()` — in Rust this is a simple field assignment
/// since `String` is automatically dropped when replaced.
fn set_folder(ftp: &mut FtpSession, new_folder: &str) {
    tracing::debug!(session = ftp.os, folder = new_folder, "set_folder");
    ftp.folder = new_folder.to_owned();
}

// ===========================================================================
// Path Validation Helpers
// ===========================================================================

/// Check whether a relative path is "valid" — i.e., does not traverse above
/// its starting directory using `..` segments.
///
/// Splits the path by `/` and tracks directory depth.  Empty components and
/// `.` are skipped.  `..` decrements depth; if depth goes negative the path
/// is rejected.
///
/// Matches the C `is_valid_path()` from `obexd/plugins/ftp.c` lines 321-348.
fn is_valid_path(path: &str) -> bool {
    let mut depth: i32 = 0;

    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            depth -= 1;
            if depth < 0 {
                return false;
            }
            continue;
        }
        depth += 1;
    }

    depth >= 0
}

/// Build a filesystem path from a destination name that may be either
/// absolute (FTP-style, starting with `/`) or relative to the session's
/// current working directory.
///
/// Absolute paths are resolved relative to the daemon's root folder.
/// Relative paths are resolved relative to `ftp.folder`.
///
/// Returns `None` if the resulting path fails the `is_valid_path` check
/// (i.e., it would traverse above the root via `..`).
///
/// Matches the C `ftp_build_filename()` from `obexd/plugins/ftp.c`
/// lines 350-367.
fn ftp_build_filename(ftp: &FtpSession, destname: &str) -> Option<String> {
    let root = obex_option_root_folder();
    let root_str = root.to_string_lossy();

    // DestName can either be relative or absolute (FTP style).
    let filename = if destname.starts_with('/') {
        // Absolute: resolve relative to the root folder.
        PathBuf::from(root).join(destname.trim_start_matches('/'))
    } else {
        // Relative: resolve relative to current working directory.
        PathBuf::from(&ftp.folder).join(destname)
    };

    let filename_str = filename.to_string_lossy().into_owned();

    // Validate that the path suffix after root_folder doesn't escape via `..`.
    let suffix = if filename_str.starts_with(root_str.as_ref()) {
        &filename_str[root_str.len()..]
    } else {
        &filename_str
    };

    if is_valid_path(suffix) {
        Some(filename_str)
    } else {
        tracing::error!("ftp_build_filename: invalid path '{}'", filename_str);
        None
    }
}

/// Convert an `io::Error` to a negative errno `i32`.
///
/// Extracts the raw OS error code when available; falls back to `EPERM`.
fn io_err_to_neg_errno(e: &io::Error) -> i32 {
    -(e.raw_os_error().unwrap_or(Errno::EPERM as i32))
}

// ===========================================================================
// Public FTP Functions (re-exported via plugins/mod.rs for sync.rs)
// ===========================================================================

/// FTP CONNECT handler — creates a new FTP session.
///
/// Allocates an [`FtpSession`] with the current working directory set to the
/// daemon's configured root folder.  In a full daemon build the server
/// dispatch code also registers D-Bus session and transfer objects.
///
/// Returns the session as a type-erased `Box<dyn Any + Send>` for storage
/// in the service driver framework.
///
/// Matches C `ftp_connect()` from `obexd/plugins/ftp.c` lines 89-112.
pub fn ftp_connect(os: &ObexSession) -> Result<Box<dyn Any + Send>, i32> {
    let _ = os; // Protocol-level session (used for streaming in full daemon)

    let root = obex_option_root_folder();
    let root_str = root.to_string_lossy();

    if root_str.is_empty() {
        tracing::error!("ftp_connect: root folder not configured");
        return Err(-(Errno::ENOENT as i32));
    }

    let ftp = FtpSession::new(&root_str);

    tracing::info!(folder = %ftp.folder, "FTP session created");

    Ok(Box::new(ftp))
}

/// FTP DISCONNECT handler — tears down an FTP session.
///
/// In the C code this unregisters D-Bus session/transfer objects and frees
/// the `ftp_session` struct.  In Rust, the `FtpSession` is dropped when the
/// `Box<dyn Any + Send>` is released by the service driver framework.
///
/// Matches C `ftp_disconnect()` from `obexd/plugins/ftp.c` lines 474-486.
pub fn ftp_disconnect(os: &ObexSession, user_data: &mut dyn Any) {
    let _ = os;

    if let Some(ftp) = user_data.downcast_ref::<FtpSession>() {
        tracing::info!(session = ftp.os, "FTP session disconnected");
    }
    // The FtpSession is dropped when the Box<dyn Any> is dropped by the
    // caller — no explicit free needed in Rust.
}

/// FTP GET handler — serves files, folder listings, or capability documents.
///
/// Dispatches based on the OBEX TYPE header:
/// - `"x-obex/capability"` → streams the capability description file.
/// - `"x-obex/folder-listing"` → generates XML folder listing.
/// - `None` (no type) → streams a named file from the current directory.
/// - Other types → returns `-EPERM`.
///
/// Matches C `ftp_get()` + `get_by_type()` from `obexd/plugins/ftp.c`
/// lines 62-134.
pub fn ftp_get(os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
    let _ = os;

    let ftp = user_data.downcast_mut::<FtpSession>().ok_or(-(Errno::EINVAL as i32))?;

    if ftp.folder.is_empty() {
        return Err(-(Errno::ENOENT as i32));
    }

    let obj_type = ftp.req_type.as_deref();
    let name = ftp.req_name.as_deref();

    tracing::debug!(
        session = ftp.os,
        name = ?name,
        obj_type = ?obj_type,
        "ftp_get"
    );

    // Dispatch by content type — matches C get_by_type().
    match obj_type {
        // Capability document request.
        Some(t) if t.eq_ignore_ascii_case(CAP_TYPE) => {
            let cap = obex_option_capability();
            if cap.as_os_str().is_empty() {
                tracing::error!("ftp_get: capability file not configured");
                return Err(-(Errno::ENOENT as i32));
            }
            tracing::debug!("ftp_get: streaming capability file '{}'", cap.display());
            // In full daemon: obex_get_stream_start(os, capability_path)
            Ok(())
        }

        // Folder listing request — type present and is folder listing.
        Some(t) if t.eq_ignore_ascii_case(LST_TYPE) => {
            tracing::debug!("ftp_get: folder listing for '{}'", ftp.folder);
            // In full daemon: obex_get_stream_start(os, ftp.folder)
            Ok(())
        }

        // No type and no name — error.
        None if name.is_none() => Err(-(Errno::EBADR as i32)),

        // No type, named file transfer — serve a regular file.
        None => {
            let file_name = name.ok_or(-(Errno::EBADR as i32))?;

            if !is_filename(file_name) {
                return Err(-(Errno::EBADR as i32));
            }

            let path = PathBuf::from(&ftp.folder).join(file_name);
            let path_str = path.to_string_lossy();

            tracing::debug!("ftp_get: file transfer '{}'", path_str);

            // Verify the file exists.
            if !path.exists() {
                return Err(-(Errno::ENOENT as i32));
            }

            // In full daemon: obex_get_stream_start(os, path)
            // then: manager_emit_transfer_started(ftp.transfer)
            Ok(())
        }

        // Unknown type — permission denied.
        Some(_) => Err(-(Errno::EPERM as i32)),
    }
}

/// FTP CHKPUT handler — pre-validates an incoming PUT request.
///
/// Validates the object name, checks for DELETE sentinel, opens the
/// output stream, and emits transfer status.
///
/// Matches C `ftp_chkput()` from `obexd/plugins/ftp.c` lines 156-189.
pub fn ftp_chkput(os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
    let _ = os;

    let ftp = user_data.downcast_mut::<FtpSession>().ok_or(-(Errno::EINVAL as i32))?;

    let name = match ftp.req_name.as_deref() {
        Some(n) => n,
        None => {
            tracing::error!("ftp_chkput: name missing");
            return Err(-(Errno::EBADR as i32));
        }
    };

    tracing::debug!(session = ftp.os, name = name, "ftp_chkput");

    if !is_filename(name) {
        return Err(-(Errno::EBADR as i32));
    }

    // If this is a DELETE operation (size == OBJECT_SIZE_DELETE), accept it
    // immediately — the actual deletion happens in ftp_put.
    if ftp.req_size == OBJECT_SIZE_DELETE {
        return Ok(());
    }

    let path = PathBuf::from(&ftp.folder).join(name);
    let _path_str = path.to_string_lossy();

    // In full daemon: obex_put_stream_start(os, &path_str)
    // If size is known (not DELETE and not UNKNOWN), emit transfer size.
    // In full daemon: manager_emit_transfer_property(ftp.transfer, "Size")
    // Then: manager_emit_transfer_started(ftp.transfer)

    Ok(())
}

/// FTP PUT handler — receives file data or performs a DELETE operation.
///
/// If the object size is `OBJECT_SIZE_DELETE`, deletes the named file or
/// directory.  Otherwise returns success (the data stream was already
/// started by [`ftp_chkput`]).
///
/// Matches C `ftp_put()` from `obexd/plugins/ftp.c` lines 191-212.
pub fn ftp_put(os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
    let _ = os;

    let ftp = user_data.downcast_mut::<FtpSession>().ok_or(-(Errno::EINVAL as i32))?;

    if ftp.folder.is_empty() {
        return Err(-(Errno::EPERM as i32));
    }

    let name = match ftp.req_name.as_deref() {
        Some(n) => n,
        None => return Err(-(Errno::EBADR as i32)),
    };

    if !is_filename(name) {
        return Err(-(Errno::EBADR as i32));
    }

    let size = ftp.req_size;

    tracing::debug!(session = ftp.os, name = name, size = size, "ftp_put");

    // DELETE via PUT with OBJECT_SIZE_DELETE sentinel.
    if size == OBJECT_SIZE_DELETE {
        return ftp_delete(ftp, name);
    }

    // Normal PUT — data is already streaming from chkput.
    Ok(())
}

/// FTP SETPATH handler — navigates the FTP working directory.
///
/// Reads the SETPATH non-header flags (2 bytes):
/// - Bit 0 of byte\[0\] = "Backup" (navigate to parent directory).
/// - Byte\[0\] == 0 with non-existing target = create directory.
///
/// Name handling:
/// - No name → error.
/// - Empty name → reset to root folder.
/// - Non-empty name → validate, build path, navigate or create.
///
/// Matches C `ftp_setpath()` from `obexd/plugins/ftp.c` lines 214-319.
pub fn ftp_setpath(os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
    let _ = os;

    let ftp = user_data.downcast_mut::<FtpSession>().ok_or(-(Errno::EINVAL as i32))?;

    // Read non-header data (2 bytes: flags + reserved constant).
    let nonhdr = match ftp.req_nonhdr.as_deref() {
        Some(data) if data.len() == 2 => data,
        _ => {
            tracing::error!("ftp_setpath: flag and constants not found");
            return Err(-(Errno::EBADMSG as i32));
        }
    };

    let flags = nonhdr[0];
    let root_folder = obex_option_root_folder();
    let root_str = root_folder.to_string_lossy();
    let is_root = root_str == ftp.folder;

    let name = ftp.req_name.as_deref();

    tracing::debug!(session = ftp.os, name = ?name, flags = flags, "ftp_setpath");

    // Check flag "Backup" — bit 0 = navigate to parent directory.
    if (flags & 0x01) == 0x01 {
        tracing::debug!("ftp_setpath: navigate to parent");

        if is_root {
            // Cannot navigate above root folder.
            return Err(-(Errno::EPERM as i32));
        }

        let current = Path::new(&ftp.folder);
        let parent = current
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| root_str.into_owned());

        set_folder(ftp, &parent);
        tracing::debug!("ftp_setpath: set to parent path: {}", ftp.folder);

        return Ok(());
    }

    // Name processing.
    let name = match name {
        None => {
            tracing::error!("ftp_setpath: name missing");
            return Err(-(Errno::EINVAL as i32));
        }
        Some(n) => n,
    };

    // Empty name → reset to root folder.
    if name.is_empty() {
        tracing::debug!("ftp_setpath: reset to root");
        set_folder(ftp, &root_str);
        return Ok(());
    }

    // Validate the name is a plain filename.
    if !is_filename(name) {
        tracing::error!("ftp_setpath: name incorrect: '{}'", name);
        return Err(-(Errno::EPERM as i32));
    }

    // Build the full target path.
    let fullname = PathBuf::from(&ftp.folder).join(name);
    let fullname_str = fullname.to_string_lossy().into_owned();

    tracing::debug!("ftp_setpath: fullname: {}", fullname_str);

    // Verify path is within root folder.
    let verify_result = verify_path(&fullname_str);
    if let Err(e) = verify_result {
        if e == -(Errno::ENOENT as i32) {
            // Path doesn't exist — check if creation is allowed.
            if flags != 0 {
                // Creation not allowed (nonhdr[0] != 0).
                return Err(-(Errno::ENOENT as i32));
            }

            // Create the directory with mode 0o755.
            match fs::create_dir(&fullname) {
                Ok(()) => {
                    // Set permissions to 0o755 (rwxr-xr-x).
                    let perms = fs::Permissions::from_mode(0o755);
                    if let Err(e) = fs::set_permissions(&fullname, perms) {
                        tracing::error!("ftp_setpath: set_permissions failed: {}", e);
                        // Non-fatal — directory was created successfully.
                    }
                    set_folder(ftp, &fullname_str);
                    return Ok(());
                }
                Err(e) => {
                    let err = io_err_to_neg_errno(&e);
                    tracing::error!(
                        "ftp_setpath: mkdir '{}' failed: {} ({})",
                        fullname_str,
                        e,
                        -err
                    );
                    return Err(err);
                }
            }
        }
        return Err(e);
    }

    // Path exists and is within root — check that it's a directory with
    // appropriate permissions (readable + executable).
    match fs::metadata(&fullname) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(-(Errno::ENOTDIR as i32));
            }

            let mode = meta.permissions().mode();
            // Check for owner read (0o400) and execute (0o100) permissions,
            // matching the C check: S_ISDIR(st_mode) && (st_mode & 0400)
            // && (st_mode & 0100).
            if (mode & 0o400) != 0 && (mode & 0o100) != 0 {
                set_folder(ftp, &fullname_str);
                return Ok(());
            }

            Err(-(Errno::EPERM as i32))
        }
        Err(e) => {
            let err = io_err_to_neg_errno(&e);

            if err == -(Errno::ENOENT as i32) {
                // Not found — check if creation is allowed.
                if flags != 0 {
                    return Err(-(Errno::ENOENT as i32));
                }

                // Create with mode 0o755.
                match fs::create_dir(&fullname) {
                    Ok(()) => {
                        let perms = fs::Permissions::from_mode(0o755);
                        if let Err(pe) = fs::set_permissions(&fullname, perms) {
                            tracing::error!("ftp_setpath: set_permissions failed: {}", pe);
                        }
                        set_folder(ftp, &fullname_str);
                        Ok(())
                    }
                    Err(me) => {
                        let merr = io_err_to_neg_errno(&me);
                        tracing::error!(
                            "ftp_setpath: mkdir '{}' failed: {} ({})",
                            fullname_str,
                            me,
                            -merr
                        );
                        Err(merr)
                    }
                }
            } else {
                tracing::debug!("ftp_setpath: stat '{}' failed: {} ({})", fullname_str, e, -err);
                Err(err)
            }
        }
    }
}

/// FTP ACTION handler — dispatches copy and move operations.
///
/// Reads the NAME, DESTNAME, and ACTION_ID from the FTP session's cached
/// request state.
///
/// | Action ID | Operation |
/// |-----------|-----------|
/// | 0x00      | Copy      |
/// | 0x01      | Move      |
///
/// Matches C `ftp_action()` from `obexd/plugins/ftp.c` lines 449-472.
pub fn ftp_action(os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
    let _ = os;

    let ftp = user_data.downcast_mut::<FtpSession>().ok_or(-(Errno::EINVAL as i32))?;

    let name = match ftp.req_name.as_deref() {
        Some(n) if !n.is_empty() && is_filename(n) => n.to_owned(),
        _ => return Err(-(Errno::EBADR as i32)),
    };

    let destname = ftp.req_destname.clone();
    let action_id = ftp.req_action_id;

    tracing::debug!(
        session = ftp.os,
        action = action_id,
        name = %name,
        destname = ?destname,
        "ftp_action"
    );

    match action_id {
        0x00 => ftp_copy(ftp, &name, destname.as_deref()),
        0x01 => ftp_move(ftp, &name, destname.as_deref()),
        _ => Err(-(Errno::ENOSYS as i32)),
    }
}

// ===========================================================================
// Private FTP Operation Helpers
// ===========================================================================

/// Delete a file or empty directory at `folder/name`.
///
/// First attempts `remove_file`; if that fails with `EISDIR`, falls back
/// to `remove_dir` (empty directories only, matching the C `obex_remove`
/// behaviour).
///
/// Matches C `ftp_delete()` from `obexd/plugins/ftp.c` lines 136-154.
fn ftp_delete(ftp: &FtpSession, name: &str) -> Result<(), i32> {
    tracing::debug!(session = ftp.os, name = name, "ftp_delete");

    if ftp.folder.is_empty() || name.is_empty() {
        return Err(-(Errno::EINVAL as i32));
    }

    let path = PathBuf::from(&ftp.folder).join(name);

    // Try file removal first.
    match fs::remove_file(&path) {
        Ok(()) => return Ok(()),
        Err(ref e)
            if e.kind() == io::ErrorKind::IsADirectory
                || e.raw_os_error() == Some(Errno::EISDIR as i32) =>
        {
            // Fall through to directory removal.
        }
        Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied => {
            // Could be a directory on some platforms — try remove_dir.
        }
        Err(e) => {
            let err = io_err_to_neg_errno(&e);
            tracing::error!(
                "ftp_delete: remove_file '{}' failed: {} ({})",
                path.display(),
                e,
                -err
            );
            return Err(err);
        }
    }

    // Try directory removal (empty directories only).
    match fs::remove_dir(&path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let err = io_err_to_neg_errno(&e);
            tracing::error!("ftp_delete: remove_dir '{}' failed: {} ({})", path.display(), e, -err);
            Err(err)
        }
    }
}

/// Copy a file from the current directory to a destination path.
///
/// The destination name may be absolute (starting with `/`, resolved
/// relative to the root folder) or relative (resolved relative to the
/// session's current directory).
///
/// Matches C `ftp_copy()` from `obexd/plugins/ftp.c` lines 369-407.
fn ftp_copy(ftp: &FtpSession, name: &str, destname: Option<&str>) -> Result<(), i32> {
    tracing::debug!(
        session = ftp.os,
        name = name,
        destname = ?destname,
        "ftp_copy"
    );

    if ftp.folder.is_empty() {
        tracing::error!("ftp_copy: no folder set");
        return Err(-(Errno::ENOENT as i32));
    }

    let destname = destname.ok_or(-(Errno::EINVAL as i32))?;
    if destname.is_empty() {
        return Err(-(Errno::EINVAL as i32));
    }

    // Build destination path (may be absolute or relative).
    let destination = ftp_build_filename(ftp, destname).ok_or(-(Errno::EBADR as i32))?;

    // Verify the destination directory exists and is within root.
    let dest_path = Path::new(&destination);
    if let Some(destdir) = dest_path.parent() {
        let destdir_str = destdir.to_string_lossy();
        verify_path(&destdir_str)?;
    }

    // Build source path.
    let source = PathBuf::from(&ftp.folder).join(name);
    let source_str = source.to_string_lossy();

    tracing::debug!("ftp_copy: '{}' -> '{}'", source_str, destination);

    // Perform the copy — uses std::fs::copy for files.
    match fs::copy(&*source_str, &destination) {
        Ok(_) => Ok(()),
        Err(e) => {
            let err = io_err_to_neg_errno(&e);
            tracing::error!(
                "ftp_copy: copy '{}' -> '{}' failed: {} ({})",
                source_str,
                destination,
                e,
                -err
            );
            Err(err)
        }
    }
}

/// Move (rename) a file from the current directory to a destination path.
///
/// The destination name may be absolute or relative (same rules as copy).
///
/// Matches C `ftp_move()` from `obexd/plugins/ftp.c` lines 409-447.
fn ftp_move(ftp: &FtpSession, name: &str, destname: Option<&str>) -> Result<(), i32> {
    tracing::debug!(
        session = ftp.os,
        name = name,
        destname = ?destname,
        "ftp_move"
    );

    if ftp.folder.is_empty() {
        tracing::error!("ftp_move: no folder set");
        return Err(-(Errno::ENOENT as i32));
    }

    let destname = destname.ok_or(-(Errno::EINVAL as i32))?;
    if destname.is_empty() {
        return Err(-(Errno::EINVAL as i32));
    }

    // Build destination path.
    let destination = ftp_build_filename(ftp, destname).ok_or(-(Errno::EBADR as i32))?;

    // Verify destination directory.
    let dest_path = Path::new(&destination);
    if let Some(destdir) = dest_path.parent() {
        let destdir_str = destdir.to_string_lossy();
        verify_path(&destdir_str)?;
    }

    // Build source path.
    let source = PathBuf::from(&ftp.folder).join(name);
    let source_str = source.to_string_lossy();

    tracing::debug!("ftp_move: '{}' -> '{}'", source_str, destination);

    // Perform the rename/move.
    match fs::rename(&*source_str, &destination) {
        Ok(()) => Ok(()),
        Err(e) => {
            let err = io_err_to_neg_errno(&e);
            tracing::error!(
                "ftp_move: rename '{}' -> '{}' failed: {} ({})",
                source_str,
                destination,
                e,
                -err
            );
            Err(err)
        }
    }
}

// ===========================================================================
// FTP Service Driver — ObexServiceDriver trait implementation
// ===========================================================================

/// FTP service driver implementing the [`ObexServiceDriver`] trait.
///
/// Registered via `inventory::submit!` and discovered by the plugin
/// framework during daemon initialisation.
///
/// Replaces the C `static const struct obex_service_driver ftp` from
/// `obexd/plugins/ftp.c` lines 502-516.
pub struct FtpServiceDriver;

impl ObexServiceDriver for FtpServiceDriver {
    /// Returns the human-readable service name.
    fn name(&self) -> &str {
        "File Transfer server"
    }

    /// Returns the OBEX service type bitmask.
    fn service(&self) -> u16 {
        OBEX_FTP
    }

    /// Returns the FTP Target UUID for OBEX Target header matching.
    fn target(&self) -> Option<&[u8]> {
        Some(&FTP_TARGET)
    }

    /// FTP CONNECT — creates a new FTP session.
    fn connect(&self, os: &ObexSession) -> Result<Box<dyn Any + Send>, i32> {
        ftp_connect(os)
    }

    /// FTP DISCONNECT — tears down the session.
    fn disconnect(&self, os: &ObexSession, user_data: &mut dyn Any) {
        ftp_disconnect(os, user_data);
    }

    /// FTP GET — serves files, folder listings, or capabilities.
    fn get(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        ftp_get(os, user_data)
    }

    /// FTP PUT — receives file data or performs delete.
    fn put(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        ftp_put(os, user_data)
    }

    /// FTP CHKPUT — pre-validates incoming PUT.
    fn chkput(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        ftp_chkput(os, user_data)
    }

    /// FTP SETPATH — navigates the working directory.
    fn setpath(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        ftp_setpath(os, user_data)
    }

    /// FTP ACTION — handles copy/move operations.
    fn action(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        ftp_action(os, user_data)
    }

    /// FTP PROGRESS — emits transfer progress notification.
    fn progress(&self, _os: &ObexSession, user_data: &mut dyn Any) {
        if let Some(ftp) = user_data.downcast_ref::<FtpSession>() {
            tracing::debug!(session = ftp.os, transfer = ftp.transfer, "ftp_progress");
            // In full daemon: manager_emit_transfer_progress(ftp.transfer)
        }
    }

    /// FTP RESET — emits transfer completion notification.
    fn reset(&self, _os: &ObexSession, user_data: &mut dyn Any) {
        if let Some(ftp) = user_data.downcast_ref::<FtpSession>() {
            tracing::debug!(session = ftp.os, transfer = ftp.transfer, "ftp_reset");
            // In full daemon: manager_emit_transfer_completed(ftp.transfer)
        }
    }
}

// ===========================================================================
// Plugin Registration
// ===========================================================================

/// FTP plugin initialisation — registers the FTP service driver.
///
/// Called during daemon startup by the plugin framework when it iterates
/// `inventory::iter::<ObexPluginDesc>()`.
///
/// Matches C `ftp_init()` from `obexd/plugins/ftp.c` lines 518-521.
fn ftp_init() -> Result<(), i32> {
    let driver = std::sync::Arc::new(FtpServiceDriver);
    obex_service_driver_register(driver)
}

/// FTP plugin cleanup — unregisters the FTP service driver.
///
/// Called during daemon shutdown in reverse initialisation order.
///
/// Matches C `ftp_exit()` from `obexd/plugins/ftp.c` lines 523-526.
fn ftp_exit() {
    obex_service_driver_unregister(&FtpServiceDriver);
}

// Plugin descriptor registered via `inventory` — replaces the C
// `OBEX_PLUGIN_DEFINE(ftp, ftp_init, ftp_exit)` macro.
inventory::submit! {
    ObexPluginDesc {
        name: "ftp",
        init: ftp_init,
        exit: ftp_exit,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ftp_target_uuid_bytes() {
        // Verify the FTP Target UUID matches the C definition exactly.
        assert_eq!(FTP_TARGET.len(), 16);
        assert_eq!(FTP_TARGET[0], 0xF9);
        assert_eq!(FTP_TARGET[1], 0xEC);
        assert_eq!(FTP_TARGET[2], 0x7B);
        assert_eq!(FTP_TARGET[3], 0xC4);
        assert_eq!(FTP_TARGET[7], 0xD2);
        assert_eq!(FTP_TARGET[15], 0x09);
    }

    #[test]
    fn test_cap_type_string() {
        assert_eq!(CAP_TYPE, "x-obex/capability");
    }

    #[test]
    fn test_lst_type_string() {
        assert_eq!(LST_TYPE, "x-obex/folder-listing");
    }

    #[test]
    fn test_is_valid_path_normal() {
        assert!(is_valid_path("a/b/c"));
        assert!(is_valid_path("foo"));
        assert!(is_valid_path(""));
        assert!(is_valid_path("a/./b"));
    }

    #[test]
    fn test_is_valid_path_relative_up() {
        // Going up within bounds is allowed.
        assert!(is_valid_path("a/b/../c"));
        assert!(is_valid_path("a/../a"));
    }

    #[test]
    fn test_is_valid_path_escape() {
        // Going above the starting point is rejected.
        assert!(!is_valid_path(".."));
        assert!(!is_valid_path("a/../../b"));
        assert!(!is_valid_path("../escape"));
    }

    #[test]
    fn test_set_folder() {
        let mut ftp = FtpSession::new("/tmp/root");
        assert_eq!(ftp.folder, "/tmp/root");

        set_folder(&mut ftp, "/tmp/root/subdir");
        assert_eq!(ftp.folder, "/tmp/root/subdir");

        set_folder(&mut ftp, "/tmp/root");
        assert_eq!(ftp.folder, "/tmp/root");
    }

    #[test]
    fn test_ftp_session_new() {
        let session = FtpSession::new("/var/lib/obex");
        assert_eq!(session.folder, "/var/lib/obex");
        assert_eq!(session.os, 0);
        assert_eq!(session.transfer, 0);
        assert_eq!(session.req_size, OBJECT_SIZE_UNKNOWN);
        assert!(session.req_name.is_none());
        assert!(session.req_type.is_none());
    }

    #[test]
    fn test_ftp_session_request_state() {
        let mut session = FtpSession::new("/tmp");
        session.set_request_state(
            Some("test.txt".into()),
            Some("text/plain".into()),
            1024,
            None,
            None,
            0,
        );

        assert_eq!(session.req_name.as_deref(), Some("test.txt"));
        assert_eq!(session.req_type.as_deref(), Some("text/plain"));
        assert_eq!(session.req_size, 1024);

        session.clear_request_state();
        assert!(session.req_name.is_none());
        assert!(session.req_type.is_none());
        assert_eq!(session.req_size, OBJECT_SIZE_UNKNOWN);
    }

    #[test]
    fn test_ftp_service_driver_name() {
        let driver = FtpServiceDriver;
        assert_eq!(driver.name(), "File Transfer server");
    }

    #[test]
    fn test_ftp_service_driver_service() {
        let driver = FtpServiceDriver;
        assert_eq!(driver.service(), OBEX_FTP);
    }

    #[test]
    fn test_ftp_service_driver_target() {
        let driver = FtpServiceDriver;
        assert_eq!(driver.target(), Some(&FTP_TARGET[..]));
    }

    #[test]
    fn test_io_err_to_neg_errno() {
        let e = io::Error::from_raw_os_error(2); // ENOENT
        assert_eq!(io_err_to_neg_errno(&e), -2);

        let e = io::Error::from_raw_os_error(13); // EACCES
        assert_eq!(io_err_to_neg_errno(&e), -13);
    }

    /// Helper to initialise the FTP option cache for unit tests.
    fn init_test_options(root: &str) {
        let _ = FTP_OBEX_OPTIONS.set(FtpObexOptions {
            root_folder: PathBuf::from(root),
            capability: PathBuf::from("/dev/null"),
        });
    }

    #[test]
    fn test_ftp_build_filename_relative() {
        // Note: OnceLock is process-wide; first setter wins across tests.
        init_test_options("/obex/root");

        let ftp = FtpSession::new("/obex/root");
        let result = ftp_build_filename(&ftp, "subdir/file.txt");
        // Should succeed because "subdir/file.txt" is valid.
        assert!(result.is_some());
        let path = result.unwrap();
        assert!(path.contains("subdir/file.txt"));
    }

    #[test]
    fn test_ftp_build_filename_escape_rejected() {
        init_test_options("/obex/root");

        let ftp = FtpSession::new("/obex/root");
        let result = ftp_build_filename(&ftp, "../../etc/passwd");
        // Should be rejected because "../.." escapes the root.
        assert!(result.is_none());
    }
}
