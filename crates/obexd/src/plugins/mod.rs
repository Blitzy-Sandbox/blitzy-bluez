//! OBEX daemon plugin framework — module root.
//!
//! Provides the inventory-based plugin registration system, driver trait
//! definitions (service, transport, MIME type), global driver registries,
//! and re-exports for the obexd plugin subsystem.
//!
//! Replaces the combined functionality of:
//! - `obexd/src/plugin.h` / `obexd/src/plugin.c` — Plugin descriptor & lifecycle
//! - `obexd/src/service.h` — OBEX service driver API
//! - `obexd/src/transport.h` — OBEX transport driver API
//! - `obexd/src/mimetype.h` — OBEX MIME type driver API

// ---------------------------------------------------------------------------
// Child module declarations
// ---------------------------------------------------------------------------

pub mod bluetooth;
pub mod filesystem;
pub mod ftp;
pub mod map;
pub mod opp;
pub mod pbap;
pub mod sync;

// ---------------------------------------------------------------------------
// External imports
// ---------------------------------------------------------------------------

use std::any::Any;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Internal imports
// ---------------------------------------------------------------------------

use crate::obex::session::ObexSession;
use crate::server::transport::ObexServer;

// ---------------------------------------------------------------------------
// Re-exports from child modules
// ---------------------------------------------------------------------------

pub use filesystem::{StringReadState, is_filename, string_read, verify_path};
pub use ftp::{ftp_action, ftp_chkput, ftp_connect, ftp_disconnect, ftp_get, ftp_put, ftp_setpath};
pub use pbap::{ApparamField, PhonebookCallType, PhonebookContact, PhonebookNumberType};

// ===========================================================================
// OBEX service type constants (from obexd/src/obexd.h)
// ===========================================================================

/// Object Push Profile service flag.
pub const OBEX_OPP: u16 = 1 << 1;
/// File Transfer Profile service flag.
pub const OBEX_FTP: u16 = 1 << 2;
/// Basic Imaging Profile service flag.
pub const OBEX_BIP: u16 = 1 << 3;
/// Phone Book Access Profile service flag.
pub const OBEX_PBAP: u16 = 1 << 4;
/// IrMC Sync service flag.
pub const OBEX_IRMC: u16 = 1 << 5;
/// Nokia PC Suite service flag.
pub const OBEX_PCSUITE: u16 = 1 << 6;
/// SyncEvolution service flag.
pub const OBEX_SYNCEVOLUTION: u16 = 1 << 7;
/// Message Access Service flag.
pub const OBEX_MAS: u16 = 1 << 8;
/// Message Notification Service flag.
pub const OBEX_MNS: u16 = 1 << 9;

// ===========================================================================
// Plugin descriptor (replaces OBEX_PLUGIN_DEFINE macro)
// ===========================================================================

/// Describes an OBEX plugin for inventory-based registration.
///
/// Each child module registers an instance via
/// `inventory::submit!(ObexPluginDesc { … })`.
///
/// Replaces the C `struct obex_plugin_desc` produced by the
/// `OBEX_PLUGIN_DEFINE(name, init, exit)` macro.
pub struct ObexPluginDesc {
    /// Human-readable plugin name used for include/exclude filtering.
    pub name: &'static str,
    /// Initialisation function called during [`plugin_init`].
    pub init: fn() -> Result<(), i32>,
    /// Cleanup function called during [`plugin_cleanup`].
    pub exit: fn(),
}

inventory::collect!(ObexPluginDesc);

// ===========================================================================
// Service driver trait  (from obexd/src/service.h)
// ===========================================================================

/// OBEX service driver — the interface that every service plugin implements.
///
/// Replaces the C `struct obex_service_driver` with its function-pointer
/// fields.  Implementations handle OBEX sessions for specific services
/// (OPP, FTP, PBAP, MAP, IrMC, SyncEvolution, PC Suite, …).
pub trait ObexServiceDriver: Send + Sync {
    /// Human-readable service name (e.g. `"Object Push server"`).
    fn name(&self) -> &str;

    /// Service-type bitmask (`OBEX_OPP`, `OBEX_FTP`, …).
    fn service(&self) -> u16;

    /// Preferred RFCOMM channel (0 = auto-assign).
    fn channel(&self) -> u8 {
        0
    }

    /// Whether this service requires a secure (authenticated) transport.
    fn secure(&self) -> bool {
        false
    }

    /// SDP record XML template string, if this service publishes one.
    fn record(&self) -> Option<&str> {
        None
    }

    /// OBEX *Target* header UUID bytes identifying this service.
    fn target(&self) -> Option<&[u8]> {
        None
    }

    /// Size of the target UUID in bytes.
    fn target_size(&self) -> usize {
        self.target().map_or(0, |t| t.len())
    }

    /// OBEX *Who* header bytes (e.g. PC Suite identification).
    fn who(&self) -> Option<&[u8]> {
        None
    }

    /// Size of the Who header in bytes.
    fn who_size(&self) -> usize {
        self.who().map_or(0, |w| w.len())
    }

    /// Called when a new OBEX session connects to this service.
    ///
    /// Returns service-specific session data as `Box<dyn Any + Send>`,
    /// replacing the C `void *` return from the connect callback.
    fn connect(&self, os: &ObexSession) -> Result<Box<dyn Any + Send>, i32>;

    /// Called when an OBEX session disconnects.
    fn disconnect(&self, os: &ObexSession, user_data: &mut dyn Any);

    /// Handles an OBEX GET request.
    fn get(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32>;

    /// Handles an OBEX PUT request.
    fn put(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32>;

    /// Pre-validates an incoming OBEX PUT before accepting data.
    fn chkput(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32>;

    /// Handles OBEX SETPATH (directory navigation).
    fn setpath(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        Err(-38) // ENOSYS
    }

    /// Handles OBEX ACTION (copy / move).
    fn action(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        Err(-38) // ENOSYS
    }

    /// Called to report transfer progress.
    fn progress(&self, _os: &ObexSession, _user_data: &mut dyn Any) {}

    /// Called when a transfer is reset or cancelled.
    fn reset(&self, _os: &ObexSession, _user_data: &mut dyn Any) {}
}

// ===========================================================================
// Transport driver trait  (from obexd/src/transport.h)
// ===========================================================================

/// OBEX transport driver — connection-level transport plugin interface.
///
/// Replaces the C `struct obex_transport_driver`.  The primary
/// implementation is the Bluetooth transport in [`bluetooth`].
pub trait ObexTransportDriver: Send + Sync {
    /// Unique transport name (e.g. `"bluetooth"`).
    fn name(&self) -> &str;

    /// Start listening for incoming connections.
    ///
    /// The `server` reference provides the list of service drivers bound
    /// to this server instance.
    fn start(&self, server: &ObexServer) -> Result<(), i32>;

    /// Stop listening and release all transport resources.
    fn stop(&self);

    /// Retrieve the remote peer address for an accepted connection fd.
    fn getpeername(&self, _fd: RawFd) -> Option<String> {
        None
    }

    /// Retrieve the local socket address for a connection fd.
    fn getsockname(&self, _fd: RawFd) -> Option<String> {
        None
    }
}

// ===========================================================================
// MIME type driver trait  (from obexd/src/mimetype.h)
// ===========================================================================

/// OBEX MIME type driver for handling specific content types.
///
/// Replaces the C `struct obex_mime_type_driver`.  Drivers are matched by
/// MIME type string and/or OBEX target / who headers.
pub trait ObexMimeTypeDriver: Send + Sync {
    /// MIME type this driver handles (e.g. `"x-obex/folder-listing"`).
    ///
    /// `None` for a generic / fallback driver.
    fn mimetype(&self) -> Option<&str> {
        None
    }

    /// OBEX *Target* header UUID bytes this driver binds to.
    fn target(&self) -> Option<&[u8]> {
        None
    }

    /// Size of the target UUID in bytes.
    fn target_size(&self) -> usize {
        self.target().map_or(0, |t| t.len())
    }

    /// OBEX *Who* header bytes (PC Suite identification).
    fn who(&self) -> Option<&[u8]> {
        None
    }

    /// Size of the Who header in bytes.
    fn who_size(&self) -> usize {
        self.who().map_or(0, |w| w.len())
    }

    /// Open an object for reading or writing.
    ///
    /// Returns an opaque object handle as `Box<dyn Any + Send>`.
    fn open(
        &self,
        name: &str,
        flags: i32,
        mode: u32,
        context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32>;

    /// Close and finalise an object.
    fn close(&self, object: &mut dyn Any) -> Result<(), i32>;

    /// Read data from an open object into `buf`.
    ///
    /// Returns bytes read, or `Err(-EAGAIN)` when data is not yet ready.
    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32>;

    /// Write data to an open object.
    ///
    /// Returns bytes written, or `Err(-ENOSYS)` if unsupported.
    fn write(&self, _object: &mut dyn Any, _buf: &[u8]) -> Result<usize, i32> {
        Err(-38) // ENOSYS
    }

    /// Flush pending writes.
    fn flush(&self, _object: &mut dyn Any) -> Result<(), i32> {
        Ok(())
    }

    /// Remove a file / object by path.
    fn remove(&self, _name: &str) -> Result<(), i32> {
        Err(-38) // ENOSYS
    }

    /// Copy a file / object from `source` to `dest`.
    fn copy(&self, _source: &str, _dest: &str) -> Result<(), i32> {
        Err(-38) // ENOSYS
    }

    /// Rename (move) a file / object from `source` to `dest`.
    fn rename(&self, _source: &str, _dest: &str) -> Result<(), i32> {
        Err(-38) // ENOSYS
    }

    /// Return the next OBEX response header to emit for this object.
    ///
    /// Yields `Some((header_id, data))` — typically used for APPARAM
    /// headers — or `None` when no more headers remain.
    fn get_next_header(&self, _object: &mut dyn Any) -> Option<(u8, Vec<u8>)> {
        None
    }
}

// ===========================================================================
// Global driver registries
// ===========================================================================

/// Registered OBEX service drivers.
static SERVICE_DRIVERS: OnceLock<Mutex<Vec<Arc<dyn ObexServiceDriver>>>> = OnceLock::new();

/// Registered OBEX transport drivers.
static TRANSPORT_DRIVERS: OnceLock<Mutex<Vec<Arc<dyn ObexTransportDriver>>>> = OnceLock::new();

/// Registered OBEX MIME type drivers.
static MIME_DRIVERS: OnceLock<Mutex<Vec<Arc<dyn ObexMimeTypeDriver>>>> = OnceLock::new();

/// Successfully initialised plugins — kept for ordered cleanup.
static INITIALIZED_PLUGINS: OnceLock<Mutex<Vec<&'static ObexPluginDesc>>> = OnceLock::new();

// ---- helpers for lazy initialisation ----

fn service_drivers() -> &'static Mutex<Vec<Arc<dyn ObexServiceDriver>>> {
    SERVICE_DRIVERS.get_or_init(|| Mutex::new(Vec::new()))
}

fn transport_drivers() -> &'static Mutex<Vec<Arc<dyn ObexTransportDriver>>> {
    TRANSPORT_DRIVERS.get_or_init(|| Mutex::new(Vec::new()))
}

fn mime_drivers() -> &'static Mutex<Vec<Arc<dyn ObexMimeTypeDriver>>> {
    MIME_DRIVERS.get_or_init(|| Mutex::new(Vec::new()))
}

fn initialized_plugins() -> &'static Mutex<Vec<&'static ObexPluginDesc>> {
    INITIALIZED_PLUGINS.get_or_init(|| Mutex::new(Vec::new()))
}

// ===========================================================================
// Service driver registration
// ===========================================================================

/// Return a snapshot of all currently registered service drivers.
///
/// Used by the Bluetooth transport plugin to discover service types and
/// their metadata (record templates, channel numbers, etc.) during
/// `start()`.
pub fn list_service_drivers() -> Vec<Arc<dyn ObexServiceDriver>> {
    service_drivers().lock().expect("service registry poisoned").clone()
}

/// Register a service driver with the global registry.
///
/// Returns `Ok(())` on success, or `Err(-EALREADY)` if a driver with the
/// same name is already registered.
pub fn obex_service_driver_register(driver: Arc<dyn ObexServiceDriver>) -> Result<(), i32> {
    let mut drivers = service_drivers().lock().expect("service registry poisoned");

    let name = driver.name();
    if drivers.iter().any(|d| d.name() == name) {
        tracing::warn!("service driver '{}' already registered", name);
        return Err(-114); // EALREADY
    }

    tracing::debug!("registering service driver: {}", name);
    drivers.push(driver);
    Ok(())
}

/// Unregister a service driver by matching its name.
pub fn obex_service_driver_unregister(driver: &dyn ObexServiceDriver) {
    let mut drivers = service_drivers().lock().expect("service registry poisoned");

    let name = driver.name();
    let before = drivers.len();
    drivers.retain(|d| d.name() != name);

    if drivers.len() < before {
        tracing::debug!("unregistered service driver: {}", name);
    }
}

/// Find a service driver matching the given OBEX target UUID and optional
/// WHO header.
///
/// Matching priority (matches C `obex_service_driver_find`):
/// 1. Target **and** who both match → return immediately.
/// 2. Target matches and driver has no who requirement → return.
/// 3. No match → `None`.
pub fn obex_service_driver_find(
    target: &[u8],
    who: Option<&[u8]>,
) -> Option<Arc<dyn ObexServiceDriver>> {
    let drivers = service_drivers().lock().expect("service registry poisoned");

    // Pass 1 — exact (target + who) match
    if let Some(who_bytes) = who {
        for d in drivers.iter() {
            if let Some(dt) = d.target() {
                if dt == target {
                    if let Some(dw) = d.who() {
                        if dw == who_bytes {
                            return Some(Arc::clone(d));
                        }
                    }
                }
            }
        }
    }

    // Pass 2 — target-only match (driver has no who requirement)
    for d in drivers.iter() {
        if let Some(dt) = d.target() {
            if dt == target && d.who().is_none() {
                return Some(Arc::clone(d));
            }
        }
    }

    None
}

// ===========================================================================
// Transport driver registration
// ===========================================================================

/// Register a transport driver with the global registry.
pub fn obex_transport_driver_register(driver: Arc<dyn ObexTransportDriver>) -> Result<(), i32> {
    let mut drivers = transport_drivers().lock().expect("transport registry poisoned");

    let name = driver.name();
    if drivers.iter().any(|d| d.name() == name) {
        tracing::warn!("transport driver '{}' already registered", name);
        return Err(-114); // EALREADY
    }

    tracing::debug!("registering transport driver: {}", name);
    drivers.push(driver);
    Ok(())
}

/// Unregister a transport driver by matching its name.
pub fn obex_transport_driver_unregister(driver: &dyn ObexTransportDriver) {
    let mut drivers = transport_drivers().lock().expect("transport registry poisoned");

    let name = driver.name();
    let before = drivers.len();
    drivers.retain(|d| d.name() != name);

    if drivers.len() < before {
        tracing::debug!("unregistered transport driver: {}", name);
    }
}

// ===========================================================================
// MIME type driver registration
// ===========================================================================

/// Register a MIME type driver with the global registry.
pub fn obex_mime_type_driver_register(driver: Arc<dyn ObexMimeTypeDriver>) -> Result<(), i32> {
    let mut drivers = mime_drivers().lock().expect("MIME registry poisoned");

    tracing::debug!(
        "registering MIME driver: mimetype={:?}, target_size={}",
        driver.mimetype(),
        driver.target_size(),
    );
    drivers.push(driver);
    Ok(())
}

/// Unregister a MIME type driver.
///
/// Matches by the `(mimetype, target, who)` tuple — identical to pointer
/// comparison in the C original since each unique combination appears at
/// most once.
pub fn obex_mime_type_driver_unregister(driver: &dyn ObexMimeTypeDriver) {
    let mut drivers = mime_drivers().lock().expect("MIME registry poisoned");

    let mt = driver.mimetype();
    let tgt = driver.target();
    let w = driver.who();

    let before = drivers.len();
    drivers.retain(|d| !(d.mimetype() == mt && d.target() == tgt && d.who() == w));

    if drivers.len() < before {
        tracing::debug!("unregistered MIME driver: mimetype={:?}", mt);
    }
}

/// Find the best-matching MIME type driver for the given criteria.
///
/// Matching priority (from C `obex_mime_type_driver_find`):
///
/// | Score | mimetype | target | who (driver specifies) |
/// |-------|----------|--------|------------------------|
/// |   6   |  match   | match  |  yes & matches         |
/// |   5   |  match   | match  |  no (don't care)       |
/// |   4   |    —     | match  |  yes & matches         |
/// |   3   |    —     | match  |  no (don't care)       |
/// |   2   |  match   |   —    |  no / none on driver   |
/// |   1   |    —     |   —    |  no / none on driver   |
pub fn obex_mime_type_driver_find(
    mimetype: &str,
    target: &[u8],
    who: Option<&[u8]>,
) -> Option<Arc<dyn ObexMimeTypeDriver>> {
    let drivers = mime_drivers().lock().expect("MIME registry poisoned");

    let mut best: Option<&Arc<dyn ObexMimeTypeDriver>> = None;
    let mut best_score: u8 = 0;

    for d in drivers.iter() {
        let d_mime = d.mimetype();
        let d_target = d.target();
        let d_who = d.who();

        // Who-compatibility gate: if the driver demands a who header the
        // caller must supply a matching one.
        let who_ok = match (d_who, who) {
            (Some(dw), Some(w)) => dw == w,
            (None, _) => true,
            (Some(_), None) => false,
        };
        if !who_ok {
            continue;
        }

        let mime_match = d_mime.is_some_and(|m| m == mimetype);
        let target_match = d_target.is_some_and(|t| t == target);

        let score =
            match (mime_match, target_match, d_who.is_some(), d_target.is_some(), d_mime.is_some())
            {
                // Exact: mime + target + who
                (true, true, true, _, _) => 6,
                // mime + target (driver ignores who)
                (true, true, false, _, _) => 5,
                // target + who only (no mime filter)
                (false, true, true, _, _) => 4,
                // target only
                (false, true, false, _, _) => 3,
                // mime only — generic driver (no target on driver)
                (true, false, _, false, _) => 2,
                // Pure fallback: driver has no constraints
                (false, false, false, false, false) => 1,
                _ => 0,
            };

        if score > best_score {
            best_score = score;
            best = Some(d);
        }
    }

    best.map(Arc::clone)
}

// ===========================================================================
// Plugin lifecycle
// ===========================================================================

/// Initialise the OBEX plugin framework.
///
/// Iterates all [`ObexPluginDesc`] instances registered via
/// `inventory::submit!`, applies include / exclude glob filters, sorts
/// alphabetically for deterministic ordering, and calls each plugin's
/// `init` function.
///
/// * `option_plugin` — comma / colon / space-separated glob patterns to
///   include.  `None` means "include all".
/// * `option_noplugin` — glob patterns to exclude.
pub fn plugin_init(option_plugin: Option<&str>, option_noplugin: Option<&str>) {
    let patterns: Vec<&str> = option_plugin.map(|p| split_filter_patterns(p)).unwrap_or_default();

    let excludes: Vec<&str> = option_noplugin.map(|p| split_filter_patterns(p)).unwrap_or_default();

    // Collect and sort for deterministic init order
    let mut descs: Vec<&ObexPluginDesc> = inventory::iter::<ObexPluginDesc>.into_iter().collect();
    descs.sort_by_key(|d| d.name);

    let mut inited = initialized_plugins().lock().expect("plugin list poisoned");

    for desc in descs {
        if !check_plugin(desc, &patterns, &excludes) {
            tracing::debug!("excluding plugin: {}", desc.name);
            continue;
        }

        tracing::info!("loading plugin: {}", desc.name);

        match (desc.init)() {
            Ok(()) => {
                tracing::info!("plugin '{}' loaded successfully", desc.name,);
                inited.push(desc);
            }
            Err(err) => {
                tracing::error!("failed to initialise plugin '{}': error {}", desc.name, err,);
            }
        }
    }
}

/// Shut down all successfully initialised plugins in reverse order.
pub fn plugin_cleanup() {
    let mut inited = initialized_plugins().lock().expect("plugin list poisoned");

    for desc in inited.drain(..).rev() {
        tracing::debug!("unloading plugin: {}", desc.name);
        (desc.exit)();
    }
}

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Split a filter string by `:`, `,`, or space — equivalent to GLib's
/// `g_strsplit_set(pattern, ":, ", -1)`.
fn split_filter_patterns(input: &str) -> Vec<&str> {
    input.split([':', ',', ' ']).filter(|s| !s.is_empty()).collect()
}

/// Decide whether a plugin should be loaded given include / exclude globs.
///
/// Logic (matches C `check_plugin()` from `obexd/src/plugin.c`):
/// 1. If the name matches any exclude pattern → **reject**.
/// 2. If include patterns exist and the name matches one → **accept**.
/// 3. If include patterns exist but none match → **reject**.
/// 4. No include patterns → **accept** (default allow-all).
fn check_plugin(desc: &ObexPluginDesc, patterns: &[&str], excludes: &[&str]) -> bool {
    for excl in excludes {
        if glob_match_simple(excl, desc.name) {
            return false;
        }
    }

    if !patterns.is_empty() {
        for pat in patterns {
            if glob_match_simple(pat, desc.name) {
                return true;
            }
        }
        return false;
    }

    true
}

/// Simple glob-style pattern matching supporting `*` (any string) and `?`
/// (any single character).
///
/// Equivalent to GLib's `g_pattern_match_simple()`.
fn glob_match_simple(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_inner(&p, 0, &t, 0)
}

/// Recursive glob matching engine.
fn glob_match_inner(pat: &[char], pi: usize, txt: &[char], ti: usize) -> bool {
    if pi == pat.len() {
        return ti == txt.len();
    }

    match pat[pi] {
        '*' => {
            // Skip consecutive '*' for efficiency
            let mut next = pi;
            while next < pat.len() && pat[next] == '*' {
                next += 1;
            }
            // Trailing '*' matches everything
            if next == pat.len() {
                return true;
            }
            // Try matching '*' against 0..=remaining characters
            for skip in 0..=(txt.len() - ti) {
                if glob_match_inner(pat, next, txt, ti + skip) {
                    return true;
                }
            }
            false
        }
        '?' => {
            if ti < txt.len() {
                glob_match_inner(pat, pi + 1, txt, ti + 1)
            } else {
                false
            }
        }
        ch => {
            if ti < txt.len() && txt[ti] == ch {
                glob_match_inner(pat, pi + 1, txt, ti + 1)
            } else {
                false
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- glob matching tests --

    #[test]
    fn glob_exact_match() {
        assert!(glob_match_simple("bluetooth", "bluetooth"));
    }

    #[test]
    fn glob_star_match() {
        assert!(glob_match_simple("blue*", "bluetooth"));
        assert!(glob_match_simple("*tooth", "bluetooth"));
        assert!(glob_match_simple("*", "anything"));
        assert!(glob_match_simple("**", "anything"));
    }

    #[test]
    fn glob_question_match() {
        assert!(glob_match_simple("ftp?", "ftp1"));
        assert!(!glob_match_simple("ftp?", "ftp"));
        assert!(!glob_match_simple("ftp?", "ftp12"));
    }

    #[test]
    fn glob_no_match() {
        assert!(!glob_match_simple("opp", "ftp"));
        assert!(!glob_match_simple("blue*", "red"));
    }

    #[test]
    fn glob_empty() {
        assert!(glob_match_simple("", ""));
        assert!(!glob_match_simple("", "a"));
        assert!(glob_match_simple("*", ""));
    }

    // -- filter logic tests --

    #[test]
    fn split_patterns_basic() {
        let parts = split_filter_patterns("a:b,c d");
        assert_eq!(parts, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn check_plugin_defaults() {
        let desc = ObexPluginDesc { name: "bluetooth", init: || Ok(()), exit: || {} };
        assert!(check_plugin(&desc, &[], &[]));
    }

    #[test]
    fn check_plugin_exclude() {
        let desc = ObexPluginDesc { name: "bluetooth", init: || Ok(()), exit: || {} };
        assert!(!check_plugin(&desc, &[], &["blue*"]));
    }

    #[test]
    fn check_plugin_include_match() {
        let desc = ObexPluginDesc { name: "ftp", init: || Ok(()), exit: || {} };
        assert!(check_plugin(&desc, &["ftp"], &[]));
    }

    #[test]
    fn check_plugin_include_no_match() {
        let desc = ObexPluginDesc { name: "opp", init: || Ok(()), exit: || {} };
        assert!(!check_plugin(&desc, &["ftp"], &[]));
    }

    // -- constant value tests --

    #[test]
    fn service_constants_are_distinct_powers_of_two() {
        let all = [
            OBEX_OPP,
            OBEX_FTP,
            OBEX_BIP,
            OBEX_PBAP,
            OBEX_IRMC,
            OBEX_PCSUITE,
            OBEX_SYNCEVOLUTION,
            OBEX_MAS,
            OBEX_MNS,
        ];
        // Each must be a power of two
        for &v in &all {
            assert!(v.is_power_of_two(), "0x{v:04x} is not a power of 2");
        }
        // All must be distinct
        for (i, &a) in all.iter().enumerate() {
            for &b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn service_constant_values() {
        assert_eq!(OBEX_OPP, 0x0002);
        assert_eq!(OBEX_FTP, 0x0004);
        assert_eq!(OBEX_BIP, 0x0008);
        assert_eq!(OBEX_PBAP, 0x0010);
        assert_eq!(OBEX_IRMC, 0x0020);
        assert_eq!(OBEX_PCSUITE, 0x0040);
        assert_eq!(OBEX_SYNCEVOLUTION, 0x0080);
        assert_eq!(OBEX_MAS, 0x0100);
        assert_eq!(OBEX_MNS, 0x0200);
    }
}
