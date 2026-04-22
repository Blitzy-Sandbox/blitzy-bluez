// SPDX-License-Identifier: GPL-2.0-or-later
//
//! OBEX Object Push Profile (OPP) service plugin.
//!
//! Rust rewrite of `obexd/plugins/opp.c` (187 lines) — provides the OPP
//! server-side service driver that handles incoming object push operations.
//!
//! # Architecture
//!
//! OPP is a relatively simple OBEX service that supports:
//! - **GET** — returns the device's own vCard (`text/x-vcard`) from the
//!   configured root folder (`root_folder/vcard.vcf`).  Named GETs are
//!   forbidden; only the default vCard is served.
//! - **PUT** — accepts incoming file pushes.  Name validation is performed
//!   via [`is_filename`], size validation rejects delete markers, and
//!   auto-accept/authorization decisions are driven by the daemon's
//!   configuration.
//!
//! The service driver implements the [`ObexServiceDriver`] trait from the
//! plugin module and registers via the `inventory` crate, replacing the C
//! `OBEX_PLUGIN_DEFINE(opp, opp_init, opp_exit)` macro.
//!
//! # Transfer Lifecycle
//!
//! The OPP plugin tracks the transfer lifecycle through [`TransferStatus`]:
//! `Queued` → `Active` → `Complete` (or `Error`).  The server engine
//! is responsible for D-Bus signal emission (`transfer_emit_status`,
//! `transfer_emit_transferred`) and session/transfer D-Bus object
//! registration (`register_session`, `register_transfer`).
//!
//! # Configuration
//!
//! Runtime configuration (root folder path, auto-accept mode) is provided
//! via the [`set_opp_config`] function, which the binary entry point calls
//! at startup before any plugin initialisation occurs.  This follows the
//! same `OnceLock`-based pattern used by the filesystem module.

// ===========================================================================
// External imports
// ===========================================================================

use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

// ===========================================================================
// Internal imports — from parent plugin module (plugins/mod.rs)
// ===========================================================================

use super::{
    OBEX_OPP, ObexPluginDesc, ObexServiceDriver, is_filename, obex_service_driver_register,
    obex_service_driver_unregister,
};

// ===========================================================================
// Internal imports — from OBEX session layer
// ===========================================================================

use crate::obex::session::ObexSession;

// ===========================================================================
// Internal imports — from server service layer
// ===========================================================================

use crate::server::service::{OBJECT_SIZE_DELETE, OBJECT_SIZE_UNKNOWN, TransferStatus};

// ===========================================================================
// Errno-style constants (negated, matching MAP plugin convention)
// ===========================================================================

/// `-EPERM` — operation not permitted.
const EPERM: i32 = -1;

/// `-ENOENT` — no such file or directory.
const ENOENT: i32 = -2;

/// `-EINVAL` — invalid argument.
const EINVAL: i32 = -22;

/// `-ENOSYS` — function not implemented.
const ENOSYS: i32 = -38;

/// `-EBADR` — invalid request descriptor.
const EBADR: i32 = -53;

// ===========================================================================
// Constants
// ===========================================================================

/// The only MIME type that OPP GET supports — a personal vCard.
///
/// Matches C `#define VCARD_TYPE "text/x-vcard"` from `opp.c`.
const VCARD_TYPE: &str = "text/x-vcard";

/// Default vCard filename served for OPP GET requests.
const VCARD_FILE: &str = "vcard.vcf";

// ===========================================================================
// Configuration accessor (OnceLock pattern — matches filesystem.rs)
// ===========================================================================

/// Process-wide OPP option store, populated by the binary entry point.
struct OppConfig {
    /// Filesystem root folder for OPP file operations.
    root_folder: PathBuf,
    /// Whether incoming pushes are accepted automatically without agent
    /// authorization.
    auto_accept: bool,
}

/// Lazily initialised process-wide OPP configuration store.
static OPP_CONFIG: OnceLock<OppConfig> = OnceLock::new();

/// Initialise the OPP configuration cache.
///
/// Called once from the binary entry point (`main.rs`) before plugin
/// initialisation.  Subsequent calls are silently ignored (the first
/// value wins).
///
/// # Arguments
///
/// * `root_folder` — Resolved filesystem root for OPP transfers.
/// * `auto_accept` — If `true`, incoming pushes bypass agent authorization.
pub fn set_opp_config(root_folder: PathBuf, auto_accept: bool) {
    let _ = OPP_CONFIG.set(OppConfig { root_folder, auto_accept });
}

/// Return the configured root folder, or an empty path if not yet set.
///
/// Replaces `obex_option_root_folder()` from `obexd/src/obexd.h` for
/// OPP-specific access within the library crate.
fn opp_root_folder() -> &'static Path {
    OPP_CONFIG.get().map_or(Path::new(""), |c| c.root_folder.as_path())
}

/// Return whether auto-accept mode is active.
///
/// Replaces `obex_option_auto_accept()` from `obexd/src/obexd.h` for
/// OPP-specific access within the library crate.
fn opp_auto_accept() -> bool {
    OPP_CONFIG.get().is_some_and(|c| c.auto_accept)
}

// ===========================================================================
// Session-specific state (replaces C `void *user_data`)
// ===========================================================================

/// OPP per-session state, stored as the opaque `user_data` returned by
/// [`OppServiceDriver::connect`].
///
/// The server dispatch layer passes this back to all subsequent callbacks
/// (`get`, `put`, `chkput`, `progress`, `reset`, `disconnect`) via
/// `&mut dyn Any`, and OPP downcasts it to access transfer state.
struct OppSessionData {
    /// Current transfer lifecycle status.
    status: TransferStatus,

    /// Computed filesystem path for the active transfer:
    /// - GET: `root_folder/vcard.vcf`
    /// - PUT: `root_folder/<filename>` (set during chkput validation)
    path: Option<PathBuf>,

    /// Whether auto-accept is active for this session (captured at
    /// connect time so mid-session config changes don't affect an
    /// in-progress transfer).
    auto_accept: bool,
}

impl OppSessionData {
    /// Create a new session data instance with initial state.
    fn new() -> Self {
        Self { status: TransferStatus::Queued, path: None, auto_accept: opp_auto_accept() }
    }
}

// ===========================================================================
// Public validation helpers
// ===========================================================================
//
// These functions encapsulate OPP-specific validation logic that the server
// dispatch layer calls before/after invoking the service driver callbacks.
// They use imported items (`is_filename`, `VCARD_TYPE`, `OBJECT_SIZE_*`)
// that cannot be accessed through the `&ObexSession` parameter alone.

/// Validate a filename for OPP push operations.
///
/// Returns `Ok(())` if the name passes [`is_filename`] validation (no path
/// separators, no `.`/`..`, non-empty).  Returns `Err(EBADR)` otherwise.
///
/// Replaces the `is_filename(name)` check in C `opp_chkput()`.
pub fn validate_opp_push_name(name: &str) -> Result<(), i32> {
    if !is_filename(name) {
        tracing::error!("OPP: invalid push filename: '{}'", name);
        return Err(EBADR);
    }
    Ok(())
}

/// Validate that an OPP GET request type is the supported vCard MIME type.
///
/// OPP only supports GET for `text/x-vcard`.  Returns `Err(EPERM)` for
/// any other type or if no type is specified.
///
/// Replaces the type check in C `opp_get()`.
pub fn validate_opp_get_type(obj_type: Option<&str>) -> Result<(), i32> {
    match obj_type {
        Some(t) if t.eq_ignore_ascii_case(VCARD_TYPE) => Ok(()),
        Some(t) => {
            tracing::error!("OPP GET: unsupported type '{}', expected '{}'", t, VCARD_TYPE);
            Err(EPERM)
        }
        None => {
            tracing::error!("OPP GET: type header required (must be '{}')", VCARD_TYPE);
            Err(EPERM)
        }
    }
}

/// Validate that an OPP GET request has no name (named GET is forbidden).
///
/// OPP only serves the default vCard; requesting a named object is rejected
/// with `EPERM`.
///
/// Replaces the name-presence check in C `opp_get()`.
pub fn validate_opp_get_name(name: Option<&str>) -> Result<(), i32> {
    if let Some(n) = name {
        tracing::error!("OPP GET: named GET forbidden (name='{}')", n);
        return Err(EPERM);
    }
    Ok(())
}

/// Validate the size field for an OPP PUT request.
///
/// Rejects delete operations (`OBJECT_SIZE_DELETE`) which are not
/// supported by OPP.  Unknown sizes (`OBJECT_SIZE_UNKNOWN`) are
/// permitted — the transfer proceeds without a progress denominator.
///
/// Replaces the size check in C `opp_chkput()`.
pub fn validate_opp_put_size(size: i64) -> Result<(), i32> {
    if size == OBJECT_SIZE_DELETE {
        tracing::error!("OPP: delete via PUT not supported");
        return Err(ENOSYS);
    }
    Ok(())
}

/// Return whether the given size represents a concrete (known, non-special)
/// transfer size.
///
/// Returns `true` when the size is neither [`OBJECT_SIZE_UNKNOWN`] nor
/// [`OBJECT_SIZE_DELETE`].
pub fn is_concrete_size(size: i64) -> bool {
    size != OBJECT_SIZE_UNKNOWN && size != OBJECT_SIZE_DELETE
}

/// Build the vCard file path for an OPP GET request.
///
/// Returns the path `<root_folder>/vcard.vcf`, or an error if the root
/// folder is not configured.
pub fn build_vcard_path() -> Result<PathBuf, i32> {
    let root = opp_root_folder();
    if root.as_os_str().is_empty() {
        tracing::error!("OPP GET: root folder not configured");
        return Err(ENOENT);
    }
    Ok(root.join(VCARD_FILE))
}

/// Build the destination file path for an OPP PUT request.
///
/// # Arguments
///
/// * `folder` — Destination folder path (from authorization or auto-accept).
/// * `name`   — Validated filename for the incoming object.
///
/// Returns the full path `<folder>/<name>`.
pub fn build_put_path(folder: &Path, name: &str) -> PathBuf {
    folder.join(name)
}

// ===========================================================================
// OPP Service Driver
// ===========================================================================

/// Object Push Profile service driver.
///
/// Implements the [`ObexServiceDriver`] trait to handle OPP sessions.
/// Registered with the plugin framework during [`opp_init`] and discovered
/// at runtime via the `inventory`-based plugin system.
///
/// # Service Characteristics
///
/// | Property | Value |
/// |----------|-------|
/// | Name     | `"Object Push server"` |
/// | Service  | `OBEX_OPP` (0x02) |
/// | Channel  | 0 (auto-assign) |
/// | Secure   | `false` |
/// | Target   | None (OPP uses no target header) |
pub struct OppServiceDriver;

impl ObexServiceDriver for OppServiceDriver {
    /// Return the human-readable service name.
    ///
    /// Matches C `struct obex_service_driver .service = "Object Push server"`.
    fn name(&self) -> &str {
        "Object Push server"
    }

    /// Return the service-type bitmask identifying this as OPP.
    ///
    /// Matches C `struct obex_service_driver .service = OBEX_OPP`.
    fn service(&self) -> u16 {
        OBEX_OPP
    }

    /// Return the preferred RFCOMM channel (0 = auto-assign).
    ///
    /// Matches C `struct obex_service_driver .channel = OBEX_CHANNEL_ANY`.
    fn channel(&self) -> u8 {
        0
    }

    /// Whether this service requires an authenticated transport.
    ///
    /// OPP does not require security by default (matches C `.secure = FALSE`).
    fn secure(&self) -> bool {
        false
    }

    /// Handle an OPP session connect.
    ///
    /// Creates and returns OPP-specific session data.  The server engine
    /// handles D-Bus session and transfer registration separately.
    ///
    /// Replaces C `opp_connect()` from `opp.c` lines 34-50.
    fn connect(&self, _os: &ObexSession) -> Result<Box<dyn Any + Send>, i32> {
        tracing::debug!("OPP service driver: connect");
        let data = OppSessionData::new();
        tracing::info!("OPP session connected (auto_accept={})", data.auto_accept);
        Ok(Box::new(data))
    }

    /// Report transfer progress.
    ///
    /// Updates the internal status tracker to [`TransferStatus::Active`].
    /// The server engine handles D-Bus progress signal emission.
    ///
    /// Replaces C `opp_progress()` from `opp.c` lines 52-55.
    fn progress(&self, _os: &ObexSession, user_data: &mut dyn Any) {
        let Some(data) = user_data.downcast_mut::<OppSessionData>() else {
            tracing::error!("OPP progress: invalid user_data type");
            return;
        };
        data.status = TransferStatus::Active;
        tracing::debug!("OPP transfer progress");
    }

    /// Handle OPP session disconnect.
    ///
    /// The server engine handles D-Bus session and transfer unregistration.
    ///
    /// Replaces C `opp_disconnect()` from `opp.c` lines 57-64.
    fn disconnect(&self, _os: &ObexSession, user_data: &mut dyn Any) {
        if let Some(data) = user_data.downcast_ref::<OppSessionData>() {
            tracing::debug!(
                "OPP disconnect (status={}, path={:?})",
                data.status.as_str(),
                data.path
            );
        }
        tracing::info!("OPP service driver: disconnect");
    }

    /// Handle an OPP GET request.
    ///
    /// OPP GET serves a single default vCard from the configured root folder.
    /// Named GETs are forbidden, and the only supported MIME type is
    /// `text/x-vcard`.  Name and type validation is performed by the
    /// [`validate_opp_get_name`] and [`validate_opp_get_type`] public
    /// helpers, which the server dispatch layer invokes with header data
    /// from [`ServerObexSession`].
    ///
    /// This callback sets the vCard path in session data and returns success
    /// when the root folder is configured.
    ///
    /// Replaces C `opp_get()` from `opp.c` lines 66-96.
    fn get(&self, _os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        let data = user_data.downcast_mut::<OppSessionData>().ok_or(EINVAL)?;

        // Build and store the vCard path.
        let path = build_vcard_path()?;
        tracing::debug!("OPP GET: serving vCard from {}", path.display());
        data.path = Some(path);
        data.status = TransferStatus::Active;
        Ok(())
    }

    /// Handle an OPP PUT request (data transfer phase).
    ///
    /// Validates that the root folder is configured.  Actual filename and
    /// size validation occurs in [`chkput`](Self::chkput) before the data
    /// transfer begins.
    ///
    /// Replaces C `opp_put()` from `opp.c` lines 141-158.
    fn put(&self, _os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        let data = user_data.downcast_ref::<OppSessionData>().ok_or(EINVAL)?;

        // Verify root folder is configured.
        let root = opp_root_folder();
        if root.as_os_str().is_empty() {
            tracing::error!("OPP PUT: root folder not configured");
            return Err(EPERM);
        }

        // Verify a destination path was set during chkput.
        if data.path.is_none() {
            tracing::error!("OPP PUT: no destination path (chkput not called?)");
            return Err(EBADR);
        }

        tracing::debug!("OPP PUT: accepting data to {:?}", data.path);
        Ok(())
    }

    /// Pre-validate an incoming OPP PUT before accepting data.
    ///
    /// This callback is invoked by the server engine after parsing OBEX
    /// headers but before the data transfer begins.  It performs:
    ///
    /// 1. Status tracking — marks the transfer as [`TransferStatus::Queued`].
    /// 2. Auto-accept path setup — in auto-accept mode, builds the
    ///    destination path from the root folder.
    ///
    /// Additional validation (size check via [`validate_opp_put_size`],
    /// name check via [`validate_opp_push_name`]) is performed by the
    /// server dispatch layer using session header data, since the plugin
    /// callback does not have direct access to OBEX header fields.
    ///
    /// Replaces C `opp_chkput()` from `opp.c` lines 98-139.
    fn chkput(&self, _os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        let data = user_data.downcast_mut::<OppSessionData>().ok_or(EINVAL)?;

        // Mark transfer as queued.
        data.status = TransferStatus::Queued;

        // In auto-accept mode, prepare the destination folder path.
        if data.auto_accept {
            let root = opp_root_folder();
            if root.as_os_str().is_empty() {
                tracing::error!("OPP chkput: root folder not configured for auto-accept");
                return Err(EPERM);
            }
            data.path = Some(root.to_path_buf());
            tracing::debug!("OPP chkput: auto-accept to {}", root.display());
        } else {
            tracing::debug!("OPP chkput: awaiting agent authorization");
        }

        Ok(())
    }

    /// Handle transfer reset / completion.
    ///
    /// Marks the transfer as [`TransferStatus::Complete`] and clears the
    /// stored path.  The server engine handles D-Bus completion signals.
    ///
    /// Replaces C `opp_reset()` from `opp.c` lines 160-163.
    fn reset(&self, _os: &ObexSession, user_data: &mut dyn Any) {
        let Some(data) = user_data.downcast_mut::<OppSessionData>() else {
            tracing::error!("OPP reset: invalid user_data type");
            return;
        };
        data.status = TransferStatus::Complete;
        data.path = None;
        tracing::debug!("OPP reset: transfer complete");
    }
}

// ===========================================================================
// Plugin lifecycle
// ===========================================================================

/// Initialise the OPP plugin — register the service driver.
///
/// Replaces C `opp_init()` from `opp.c` lines 165-172.
fn opp_init() -> Result<(), i32> {
    tracing::info!("OPP plugin init");
    obex_service_driver_register(Arc::new(OppServiceDriver))?;
    tracing::info!("OPP plugin init complete: service driver registered");
    Ok(())
}

/// Shut down the OPP plugin — unregister the service driver.
///
/// Replaces C `opp_exit()` from `opp.c` lines 174-178.
fn opp_exit() {
    tracing::info!("OPP plugin exit");
    obex_service_driver_unregister(&OppServiceDriver);
}

// ===========================================================================
// Plugin registration (replaces OBEX_PLUGIN_DEFINE macro)
// ===========================================================================

inventory::submit! {
    ObexPluginDesc {
        name: "opp",
        init: opp_init,
        exit: opp_exit,
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opp_service_driver_metadata() {
        let drv = OppServiceDriver;
        assert_eq!(drv.name(), "Object Push server");
        assert_eq!(drv.service(), OBEX_OPP);
        assert_eq!(drv.channel(), 0);
        assert!(!drv.secure());
        assert!(drv.target().is_none());
        assert!(drv.who().is_none());
        assert!(drv.record().is_none());
    }

    #[test]
    fn test_validate_opp_get_type_accepts_vcard() {
        assert!(validate_opp_get_type(Some("text/x-vcard")).is_ok());
        assert!(validate_opp_get_type(Some("TEXT/X-VCARD")).is_ok());
        assert!(validate_opp_get_type(Some("Text/X-VCard")).is_ok());
    }

    #[test]
    fn test_validate_opp_get_type_rejects_other() {
        assert_eq!(validate_opp_get_type(None), Err(EPERM));
        assert_eq!(validate_opp_get_type(Some("text/plain")), Err(EPERM));
        assert_eq!(validate_opp_get_type(Some("application/json")), Err(EPERM));
    }

    #[test]
    fn test_validate_opp_get_name_rejects_named() {
        assert_eq!(validate_opp_get_name(Some("file.vcf")), Err(EPERM));
        assert_eq!(validate_opp_get_name(Some("")), Err(EPERM));
    }

    #[test]
    fn test_validate_opp_get_name_accepts_none() {
        assert!(validate_opp_get_name(None).is_ok());
    }

    #[test]
    fn test_validate_opp_push_name() {
        // Valid filenames
        assert!(validate_opp_push_name("photo.jpg").is_ok());
        assert!(validate_opp_push_name("document.pdf").is_ok());

        // Invalid filenames (path separators, special names)
        assert_eq!(validate_opp_push_name("../etc/passwd"), Err(EBADR));
        assert_eq!(validate_opp_push_name("/etc/passwd"), Err(EBADR));
    }

    #[test]
    fn test_validate_opp_put_size() {
        // Normal sizes are accepted.
        assert!(validate_opp_put_size(0).is_ok());
        assert!(validate_opp_put_size(1024).is_ok());

        // Unknown size is accepted (no denominator for progress).
        assert!(validate_opp_put_size(OBJECT_SIZE_UNKNOWN).is_ok());

        // Delete is rejected.
        assert_eq!(validate_opp_put_size(OBJECT_SIZE_DELETE), Err(ENOSYS));
    }

    #[test]
    fn test_is_concrete_size() {
        assert!(is_concrete_size(0));
        assert!(is_concrete_size(1024));
        assert!(is_concrete_size(i64::MAX));
        assert!(!is_concrete_size(OBJECT_SIZE_UNKNOWN));
        assert!(!is_concrete_size(OBJECT_SIZE_DELETE));
    }

    #[test]
    fn test_opp_config_default() {
        // Before config is set, root folder is empty, auto_accept is false.
        // Note: since OnceLock can only be set once per process, this test
        // verifies default behaviour relies on the OnceLock not being set
        // in this test context.  If set_opp_config was called elsewhere in
        // this test process, this test may see that value instead.
        let root = opp_root_folder();
        // Root is either empty (not set) or whatever was set first.
        let _ = root; // Verify it doesn't panic.

        let auto = opp_auto_accept();
        let _ = auto; // Verify it doesn't panic.
    }

    #[test]
    fn test_build_put_path() {
        let folder = Path::new("/tmp/bluetooth");
        let path = build_put_path(folder, "photo.jpg");
        assert_eq!(path, PathBuf::from("/tmp/bluetooth/photo.jpg"));
    }
}
