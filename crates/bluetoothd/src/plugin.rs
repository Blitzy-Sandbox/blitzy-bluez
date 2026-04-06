// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (C) 2024 BlueZ Contributors
 */

//! Plugin framework for the `bluetoothd` daemon.
//!
//! This module implements plugin discovery, loading, initialization, and cleanup
//! for both built-in and external plugins. Built-in plugins register via
//! [`inventory::submit!`] and are collected at startup. External `.so` plugins
//! are loaded from [`PLUGINDIR`] using [`libloading`] when testing mode is
//! enabled in [`BtdOpts`](crate::config::BtdOpts).
//!
//! # Built-in Plugin Registration
//!
//! Built-in plugins use the [`inventory`] crate for compile-time registration,
//! replacing the C pattern where `BLUETOOTH_PLUGIN_DEFINE()` macros emitted
//! `struct bluetooth_plugin_desc` entries into linker sections and the generated
//! `src/builtin.h` collected them into the `__bluetooth_builtin[]` array.
//!
//! ```rust,ignore
//! use crate::plugin::{PluginDesc, PluginPriority};
//!
//! fn my_plugin_init() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize plugin resources
//!     Ok(())
//! }
//!
//! fn my_plugin_exit() {
//!     // Release plugin resources
//! }
//!
//! inventory::submit! {
//!     PluginDesc {
//!         name: "myplugin",
//!         version: env!("CARGO_PKG_VERSION"),
//!         priority: PluginPriority::Default,
//!         init: my_plugin_init,
//!         exit: my_plugin_exit,
//!     }
//! }
//! ```
//!
//! # External Plugin Loading
//!
//! When `BtdOpts::testing` is `true`, the daemon scans [`PLUGINDIR`] for `.so`
//! files (excluding `lib*` prefixed names) and loads them via `libloading`.
//! Each shared object must export a C-compatible `bluetooth_plugin_desc` symbol.
//! External plugin loading is a designated `unsafe` boundary site (AAP §0.7.4).
//!
//! # Priority Ordering
//!
//! Plugins are sorted by priority before initialization (high → low):
//! - **High** (100): initialized first, for foundational plugins
//! - **Default** (0): standard initialization order
//! - **Low** (-100): initialized last, for dependent plugins

use std::path::Path;
use std::sync::Mutex;

use crate::config::BtdOpts;
use crate::log::{btd_debug, btd_error, info};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Daemon version string used for external plugin version enforcement.
/// Matches the C `VERSION` constant set by `configure.ac` / `config.h`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default filesystem path for external plugin shared objects.
///
/// External `.so` plugins are scanned from this directory when testing mode
/// is enabled. Mirrors the C `PLUGINDIR` compile-time constant, which
/// defaults to `/usr/lib/bluetooth/plugins`.
pub const PLUGINDIR: &str = "/usr/lib/bluetooth/plugins";

/// Linux `ENOSYS` errno value (function not implemented).
const ENOSYS_VAL: i32 = 38;

/// Linux `ENOTSUP` errno value (operation not supported).
const ENOTSUP_VAL: i32 = 95;

// ---------------------------------------------------------------------------
// PluginPriority
// ---------------------------------------------------------------------------

/// Plugin initialization priority levels.
///
/// Higher-priority plugins are initialized before lower-priority ones.
/// Mirrors C `enum bluetooth_plugin_priority` from `src/plugin.h`:
/// - `BLUETOOTH_PLUGIN_PRIORITY_LOW    = -100`
/// - `BLUETOOTH_PLUGIN_PRIORITY_DEFAULT =    0`
/// - `BLUETOOTH_PLUGIN_PRIORITY_HIGH    =  100`
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PluginPriority {
    /// Low priority (-100): initialized last, for non-critical plugins.
    Low = -100,
    /// Default priority (0): standard initialization order.
    #[default]
    Default = 0,
    /// High priority (100): initialized first, for foundational plugins.
    High = 100,
}

impl PluginPriority {
    /// Returns the numeric priority value for sorting comparisons.
    #[inline]
    fn value(self) -> i32 {
        self as i32
    }

    /// Converts a raw `i32` priority value to the nearest variant.
    ///
    /// Values ≥ 100 map to [`High`](Self::High), values ≤ -100 map to
    /// [`Low`](Self::Low), and all others map to [`Default`](Self::Default).
    ///
    /// Used by the external plugin loader to convert the C `int priority`
    /// field from [`ExternalPluginDesc`] into a typed enum.
    pub fn from_raw(val: i32) -> Self {
        if val >= 100 {
            Self::High
        } else if val <= -100 {
            Self::Low
        } else {
            Self::Default
        }
    }
}

// ---------------------------------------------------------------------------
// BluetoothPlugin trait
// ---------------------------------------------------------------------------

/// Trait defining the interface for Bluetooth daemon plugins.
///
/// Each plugin provides metadata (name, version, priority) and lifecycle
/// hooks (init, exit). Built-in plugins implement this via [`PluginDesc`]
/// and register using [`inventory::submit!`]. External plugins are loaded
/// from shared objects using [`libloading`].
///
/// This replaces the C `struct bluetooth_plugin_desc` interface defined in
/// `src/plugin.h`.
pub trait BluetoothPlugin: Send + Sync {
    /// Returns the unique plugin name (e.g., `"autopair"`, `"policy"`).
    fn name(&self) -> &str;

    /// Returns the plugin version string (should match daemon VERSION).
    fn version(&self) -> &str;

    /// Returns the plugin initialization priority.
    fn priority(&self) -> PluginPriority;

    /// Initializes the plugin.
    ///
    /// Returns `Ok(())` on success, or an error describing the failure.
    /// Errors containing "ENOSYS", "ENOTSUP", or "not supported" are
    /// treated as non-fatal system capability issues rather than hard
    /// failures.
    fn init(&self) -> Result<(), Box<dyn std::error::Error>>;

    /// Cleans up the plugin on daemon shutdown.
    fn exit(&self);
}

// ---------------------------------------------------------------------------
// PluginDesc — Concrete built-in plugin descriptor
// ---------------------------------------------------------------------------

/// Concrete plugin descriptor for built-in plugins.
///
/// Each built-in plugin creates a static `PluginDesc` and registers it via
/// `inventory::submit!`. The plugin framework collects all registered
/// descriptors at startup via [`inventory::iter::<PluginDesc>()`].
///
/// Replaces C `struct bluetooth_plugin_desc` together with the
/// `BLUETOOTH_PLUGIN_DEFINE()` macro and linker-section descriptor tables.
///
/// # Fields
///
/// | Field      | C Equivalent                  | Description                       |
/// |------------|-------------------------------|-----------------------------------|
/// | `name`     | `desc->name`                  | Plugin identifier                 |
/// | `version`  | `desc->version`               | Version string for compatibility  |
/// | `priority` | `desc->priority`              | Initialization order              |
/// | `init`     | `desc->init`                  | Called during `plugin_init()`      |
/// | `exit`     | `desc->exit`                  | Called during `plugin_cleanup()`   |
pub struct PluginDesc {
    /// Plugin name (e.g., `"autopair"`, `"sixaxis"`).
    pub name: &'static str,
    /// Plugin version string (typically `env!("CARGO_PKG_VERSION")`).
    pub version: &'static str,
    /// Initialization priority determining load order.
    pub priority: PluginPriority,
    /// Initialization function called during [`plugin_init`].
    pub init: fn() -> Result<(), Box<dyn std::error::Error>>,
    /// Cleanup function called during [`plugin_cleanup`].
    pub exit: fn(),
}

// PluginDesc is automatically Send + Sync because:
// - &'static str: Send + Sync
// - PluginPriority: Copy + Send + Sync
// - fn() pointers: Send + Sync

/// Register [`PluginDesc`] with the [`inventory`] crate for compile-time
/// collection. This enables built-in plugins to self-register via
/// `inventory::submit!` and be iterated via `inventory::iter::<PluginDesc>()`.
#[allow(unsafe_code)]
mod _inventory_collect {
    inventory::collect!(super::PluginDesc);
}

impl BluetoothPlugin for PluginDesc {
    #[inline]
    fn name(&self) -> &str {
        self.name
    }

    #[inline]
    fn version(&self) -> &str {
        self.version
    }

    #[inline]
    fn priority(&self) -> PluginPriority {
        self.priority
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        (self.init)()
    }

    fn exit(&self) {
        (self.exit)()
    }
}

// ---------------------------------------------------------------------------
// ExternalPluginDesc — C-ABI compatible descriptor for .so plugins
// ---------------------------------------------------------------------------

/// C-ABI compatible plugin descriptor for external shared-object plugins.
///
/// This struct mirrors the C `struct bluetooth_plugin_desc` layout byte for
/// byte, enabling loaded `.so` files (compiled from C or Rust with
/// `#[repr(C)]`) to expose a `bluetooth_plugin_desc` symbol resolvable
/// via `dlsym`.
///
/// Fields `debug_start` and `debug_stop` are present for ABI compatibility
/// with the C struct but are unused in the Rust daemon (the `tracing` crate
/// handles debug-level control dynamically).
#[repr(C)]
#[allow(dead_code)]
struct ExternalPluginDesc {
    /// Plugin name (null-terminated C string pointer).
    name: *const std::ffi::c_char,
    /// Plugin version (null-terminated C string pointer).
    version: *const std::ffi::c_char,
    /// Numeric priority value.
    priority: std::ffi::c_int,
    /// Initialization function (returns 0 on success, negative errno on error).
    init: Option<unsafe extern "C" fn() -> std::ffi::c_int>,
    /// Cleanup function.
    exit: Option<unsafe extern "C" fn()>,
    /// Debug enable callback (unused in Rust).
    debug_start: Option<unsafe extern "C" fn()>,
    /// Debug disable callback (unused in Rust).
    debug_stop: Option<unsafe extern "C" fn()>,
}

// ---------------------------------------------------------------------------
// Internal State
// ---------------------------------------------------------------------------

/// A loaded and initialized plugin (either built-in or external).
struct LoadedPlugin {
    /// Plugin name.
    name: String,
    /// Whether the plugin was successfully initialized and is active.
    active: bool,
    /// Exit callback invoked during [`plugin_cleanup`].
    /// `None` if the plugin has no exit handler.
    exit_fn: Option<Box<dyn Fn() + Send + Sync>>,
    /// External library handle — kept alive to prevent code-page unloading.
    /// `None` for built-in plugins.
    _library: Option<libloading::Library>,
}

/// Global list of loaded plugins, protected by a mutex.
///
/// Plugins are stored in priority-sorted order (high priority first).
/// Built-in plugins are added during [`plugin_init`], followed by any
/// external plugins loaded from [`PLUGINDIR`].
static PLUGINS: Mutex<Vec<LoadedPlugin>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------------------
// Glob Pattern Matching
// ---------------------------------------------------------------------------

/// Simple glob pattern matching supporting `*` and `?` wildcards.
///
/// Replaces GLib's `g_pattern_match_simple()` used in the C
/// `enable_plugin()` function for matching plugin names against
/// enable/disable patterns.
///
/// - `*` matches zero or more arbitrary characters
/// - `?` matches exactly one arbitrary character
/// - All other characters match literally (case-sensitive)
fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_inner(pattern.as_bytes(), text.as_bytes())
}

/// Recursive byte-level glob matching implementation.
fn glob_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.first() {
        // Empty pattern matches only empty text.
        None => text.is_empty(),
        Some(b'*') => {
            let rest = &pattern[1..];
            // '*' matches zero or more characters — try every split point.
            for skip in 0..=text.len() {
                if glob_match_inner(rest, &text[skip..]) {
                    return true;
                }
            }
            false
        }
        Some(b'?') => {
            // '?' matches exactly one character.
            !text.is_empty() && glob_match_inner(&pattern[1..], &text[1..])
        }
        Some(&ch) => {
            // Literal character must match head of text.
            !text.is_empty() && text[0] == ch && glob_match_inner(&pattern[1..], &text[1..])
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin Enable/Disable Filtering
// ---------------------------------------------------------------------------

/// Determines whether a plugin should be loaded based on CLI enable/disable
/// glob patterns.
///
/// Mirrors the C `enable_plugin()` logic from `src/plugin.c`:
/// 1. If the plugin name matches any **disable** pattern → **excluded**
/// 2. If an enable list exists and the name matches any pattern → **included**
/// 3. If an enable list exists but the name does not match → **excluded**
/// 4. If no enable list is specified → **included** by default
fn enable_plugin(name: &str, cli_enable: &[String], cli_disable: &[String]) -> bool {
    // Check disable list first (takes precedence).
    for pattern in cli_disable {
        if glob_match(pattern, name) {
            let msg = format!("Excluding (cli) {}", name);
            tracing::info!("{}", msg);
            info(&msg);
            return false;
        }
    }

    // Check enable list (if provided, acts as an allowlist).
    if !cli_enable.is_empty() {
        for pattern in cli_enable {
            if glob_match(pattern, name) {
                return true;
            }
        }
        let msg = format!("Ignoring (cli) {}", name);
        tracing::info!("{}", msg);
        info(&msg);
        return false;
    }

    // No filtering → allow by default.
    true
}

// ---------------------------------------------------------------------------
// Plugin Initialization Helpers
// ---------------------------------------------------------------------------

/// Calls a built-in plugin's init function, handling known error patterns.
///
/// Mirrors C `init_plugin()` from `src/plugin.c`:
/// - Returns `true` on success
/// - ENOSYS/ENOTSUP-equivalent errors → warn log, return `false`
/// - Other errors → error log, return `false`
fn init_builtin_plugin(
    name: &str,
    init_fn: fn() -> Result<(), Box<dyn std::error::Error>>,
) -> bool {
    match init_fn() {
        Ok(()) => true,
        Err(e) => {
            let msg = e.to_string();
            let msg_lower = msg.to_lowercase();
            if msg_lower.contains("enosys")
                || msg_lower.contains("enotsup")
                || msg_lower.contains("not supported")
                || msg_lower.contains("not implemented")
            {
                let dbg_msg = format!("System does not support {} plugin", name);
                tracing::warn!("{}", dbg_msg);
                btd_debug(0, &dbg_msg);
            } else {
                let err_msg = format!("Failed to init {} plugin", name);
                tracing::error!("{}: {}", err_msg, msg);
                btd_error(0, &err_msg);
            }
            false
        }
    }
}

/// Initializes a built-in plugin descriptor and appends it to the list.
///
/// Mirrors C `add_plugin()` from `src/plugin.c`:
/// 1. Logs the loading attempt
/// 2. Calls the plugin's `init` function via [`init_builtin_plugin`]
/// 3. On success, wraps the descriptor in a [`LoadedPlugin`] and appends
/// 4. On failure, logs and skips
fn add_builtin_plugin(desc: &'static PluginDesc, plugins_list: &mut Vec<LoadedPlugin>) {
    tracing::debug!("Loading {} plugin", desc.name);
    btd_debug(0, &format!("Loading {} plugin", desc.name));

    if !init_builtin_plugin(desc.name, desc.init) {
        return;
    }

    let exit = desc.exit;
    plugins_list.push(LoadedPlugin {
        name: desc.name.to_owned(),
        active: true,
        exit_fn: Some(Box::new(exit)),
        _library: None,
    });

    let loaded_msg = format!("Plugin {} loaded", desc.name);
    tracing::debug!("{}", loaded_msg);
    btd_debug(0, &loaded_msg);
}

// ---------------------------------------------------------------------------
// External Plugin Loading (Designated Unsafe FFI Boundary — AAP §0.7.4)
// ---------------------------------------------------------------------------

/// Loads and initializes a single external plugin from a shared object.
///
/// This function is a designated `unsafe` FFI boundary site per AAP §0.7.4.
/// It contains `unsafe` blocks for C-string pointer dereferencing and C
/// function pointer invocation, each with a `// SAFETY:` comment.
///
/// Mirrors C `add_external_plugin()` from `src/plugin.c`:
/// 1. Validates the descriptor has a non-null init function
/// 2. Extracts and validates the name and version C strings
/// 3. Enforces version match against daemon [`VERSION`]
/// 4. Calls the external init function (returns 0 on success)
/// 5. On success, stores the plugin with its library handle kept alive
#[allow(unsafe_code)]
fn add_external_plugin(
    library: libloading::Library,
    desc: &ExternalPluginDesc,
    plugins_list: &mut Vec<LoadedPlugin>,
) -> bool {
    // Validate that the descriptor has an init function.
    if desc.init.is_none() {
        return false;
    }

    // --- Extract plugin name ---
    // SAFETY: The `name` pointer was loaded from a valid `bluetooth_plugin_desc`
    // symbol in the shared library. It points to static data in the library's
    // read-only data section, which remains valid while the `Library` handle is
    // alive. We explicitly check for null before dereferencing.
    let name_str = if desc.name.is_null() {
        let err_msg = "External plugin has null name";
        tracing::error!("{}", err_msg);
        btd_error(0, err_msg);
        return false;
    } else {
        // SAFETY: desc.name is a valid C string pointer from a loaded shared library.
        match unsafe { std::ffi::CStr::from_ptr(desc.name) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                let err_msg = "External plugin name is not valid UTF-8";
                tracing::error!("{}", err_msg);
                btd_error(0, err_msg);
                return false;
            }
        }
    };

    // --- Extract plugin version ---
    // SAFETY: The `version` pointer was loaded from a valid
    // `bluetooth_plugin_desc` symbol in the shared library. Same validity
    // guarantees as the `name` pointer above — static data in the library's
    // rodata section, checked for null before dereferencing.
    let version_str = if desc.version.is_null() {
        let err_msg = format!("External plugin {} has null version", name_str);
        tracing::error!("{}", err_msg);
        btd_error(0, &err_msg);
        return false;
    // SAFETY: desc.version is a valid C string pointer from a loaded shared library.
    } else {
        match unsafe { std::ffi::CStr::from_ptr(desc.version) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                let err_msg = format!("Version mismatch for {}", name_str);
                tracing::error!("{}", err_msg);
                btd_error(0, &err_msg);
                return false;
            }
        }
    };

    // Enforce version match against daemon version.
    if version_str != VERSION {
        let err_msg = format!("Version mismatch for {}", name_str);
        tracing::error!("{}", err_msg);
        btd_error(0, &err_msg);
        return false;
    }

    tracing::debug!("Loading {} plugin", name_str);
    btd_debug(0, &format!("Loading {} plugin", name_str));

    // --- Call the external init function ---
    let init_fn = desc.init.expect("init presence validated above");
    // The `init` function pointer was resolved from a valid symbol in the loaded
    // shared library, and the `Library` handle is kept alive so code remains mapped.
    // SAFETY: Function pointer resolved via RTLD_NOW from a validated `.so` library;
    // library handle is not dropped, so the function code remains valid and callable.
    let ret = unsafe { init_fn() };
    if ret != 0 {
        let neg_ret = -ret;
        if neg_ret == ENOSYS_VAL || neg_ret == ENOTSUP_VAL {
            let msg = format!("System does not support {} plugin", name_str);
            tracing::warn!("{}", msg);
            btd_debug(0, &msg);
        } else {
            let msg = format!("Failed to init {} plugin", name_str);
            tracing::error!("{}", msg);
            btd_error(0, &msg);
        }
        return false;
    }

    // Capture exit function pointer for use during cleanup.
    let exit_fn_ptr = desc.exit;
    let plugin_name = name_str.to_owned();

    plugins_list.push(LoadedPlugin {
        name: plugin_name.clone(),
        active: true,
        exit_fn: exit_fn_ptr.map(|f| -> Box<dyn Fn() + Send + Sync> {
            Box::new(move || {
                // SAFETY: The `exit` function pointer was resolved from a
                // valid symbol in the loaded shared library. The `Library`
                // handle is stored in the same `LoadedPlugin` struct and is
                // not dropped until `plugin_cleanup()` processes this entry,
                // guaranteeing the function code remains mapped for the
                // SAFETY: Calling the exit function pointer from a validated plugin descriptor.
                // entire lifetime of this closure.
                #[allow(unsafe_code)]
                unsafe {
                    f()
                }
            })
        }),
        _library: Some(library),
    });

    let loaded_msg = format!("Plugin {} loaded", plugin_name);
    tracing::debug!("{}", loaded_msg);
    btd_debug(0, &loaded_msg);
    true
}

/// Scans the external plugin directory and loads all valid `.so` plugins.
///
/// This function is a designated `unsafe` FFI boundary site per AAP §0.7.4.
/// It contains `unsafe` blocks for `libloading::Library::new()` (dlopen) and
/// `library.get()` (dlsym) operations.
///
/// Mirrors C `external_plugin_init()` from `src/plugin.c`:
/// 1. Warns that external plugins are not officially supported
/// 2. Opens the plugin directory and iterates entries
/// 3. For each `.so` file (excluding `lib*` prefix):
///    a. Loads the shared object via `Library::new()`
///    b. Resolves the `bluetooth_plugin_desc` symbol via `library.get()`
///    c. Applies enable/disable filtering
///    d. Calls [`add_external_plugin`] to initialize and register
#[allow(unsafe_code)]
fn external_plugin_init(
    cli_enable: &[String],
    cli_disable: &[String],
    plugins_list: &mut Vec<LoadedPlugin>,
) {
    let warn_msg = "Using external plugins is not officially supported.";
    tracing::info!("{}", warn_msg);
    info(warn_msg);

    let dir_msg = format!("Loading plugins {}", PLUGINDIR);
    tracing::debug!("{}", dir_msg);
    btd_debug(0, &dir_msg);

    let plugin_dir = Path::new(PLUGINDIR);
    if !plugin_dir.is_dir() {
        let msg = format!("Plugin directory {} does not exist", PLUGINDIR);
        tracing::debug!("{}", msg);
        btd_debug(0, &msg);
        return;
    }

    let entries = match std::fs::read_dir(plugin_dir) {
        Ok(entries) => entries,
        Err(e) => {
            let msg = format!("Can't open plugin directory {}: {}", PLUGINDIR, e);
            tracing::error!("{}", msg);
            btd_error(0, &msg);
            return;
        }
    };

    for entry_result in entries {
        let entry = match entry_result {
            Ok(e) => e,
            Err(_) => continue,
        };

        let file_name = entry.file_name();
        let file_name_str = match file_name.to_str() {
            Some(s) => s,
            None => continue,
        };

        // Skip library files with "lib" prefix (matching C behavior:
        // `g_str_has_prefix(entry, "lib")` check in external_plugin_init).
        if file_name_str.starts_with("lib") {
            continue;
        }

        // Only process shared-object files (matching C behavior:
        // `g_str_has_suffix(entry, ".so")` check).
        if !file_name_str.ends_with(".so") {
            continue;
        }

        let plugin_path = plugin_dir.join(file_name_str);

        // We are loading a shared library from the trusted plugin directory
        // (PLUGINDIR, default `/usr/lib/bluetooth/plugins`). The path has been
        // validated as a `.so` file without `lib` prefix.
        // SAFETY: Plugin path validated as existing `.so` file; `Library::new()`
        // uses RTLD_NOW semantics matching the C code's `dlopen(filename, RTLD_NOW)`.
        let library = match unsafe { libloading::Library::new(&plugin_path) } {
            Ok(lib) => lib,
            Err(e) => {
                let msg = format!("Can't load plugin {}: {}", file_name_str, e);
                tracing::error!("{}", msg);
                btd_error(0, &msg);
                continue;
            }
        };

        // SAFETY: We resolve the well-known `bluetooth_plugin_desc` symbol,
        // which must point to a static `ExternalPluginDesc` struct in the
        // loaded library's data section. The library was loaded successfully
        // with RTLD_NOW, so all referenced symbols are resolved. The nul
        // byte in the symbol name is required by `Library::get()`.
        // SAFETY: Resolving a known symbol from a validated shared library.
        let desc_ptr: libloading::Symbol<'_, *const ExternalPluginDesc> =
            match unsafe { library.get(b"bluetooth_plugin_desc\0") } {
                Ok(sym) => sym,
                Err(e) => {
                    let msg = format!("Can't load plugin description: {}", e);
                    tracing::error!("{}", msg);
                    btd_error(0, &msg);
                    continue;
                }
            };

        // The symbol was successfully resolved and `desc_ptr` is a
        // `*const ExternalPluginDesc` pointing to static data in the loaded library.
        // SAFETY: Library remains loaded (handle not dropped), so the pointer is
        // valid for the duration of this scope; we dereference to obtain a shared
        // reference for reading.
        let desc: &ExternalPluginDesc = unsafe { &**desc_ptr };

        // Extract plugin name for enable/disable filtering.
        // SAFETY: The `name` pointer points to static data in the loaded
        // library, validated as part of the well-known descriptor symbol.
        let plugin_name = if !desc.name.is_null() {
            unsafe { std::ffi::CStr::from_ptr(desc.name) }.to_str().unwrap_or(file_name_str)
        } else {
            file_name_str
        };

        if !enable_plugin(plugin_name, cli_enable, cli_disable) {
            // Library is dropped here, unloading the .so for skipped plugins.
            continue;
        }

        add_external_plugin(library, desc, plugins_list);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initializes all plugins (built-in and optionally external).
///
/// This is the main entry point for the plugin subsystem, called during
/// daemon startup. It replaces C `plugin_init()` from `src/plugin.c`.
///
/// # Process
///
/// 1. Parses comma-separated `enable`/`disable` pattern strings
/// 2. Collects all built-in plugin descriptors via [`inventory::iter`]
/// 3. Sorts descriptors by priority (high → low, descending)
/// 4. Filters each plugin through enable/disable glob patterns
/// 5. Initializes each accepted plugin via its `init()` function
/// 6. If `opts.testing` is `true`, loads external plugins from [`PLUGINDIR`]
///
/// # Arguments
///
/// - `enable` — Optional comma-separated glob patterns; only matching
///   plugins are loaded (allowlist). `None` means all plugins are allowed.
/// - `disable` — Optional comma-separated glob patterns; matching plugins
///   are excluded (blocklist). Takes precedence over `enable`.
/// - `opts` — Daemon configuration; `opts.testing` controls external loading.
///
/// # Returns
///
/// Always returns `true` (matching C behavior where `plugin_init` returns
/// `TRUE` unconditionally).
pub fn plugin_init(enable: Option<&str>, disable: Option<&str>, opts: &BtdOpts) -> bool {
    // Parse comma-separated enable/disable pattern strings into vectors.
    let cli_enable: Vec<String> = enable
        .map(|s| s.split(',').map(|p| p.trim().to_owned()).filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();

    let cli_disable: Vec<String> = disable
        .map(|s| s.split(',').map(|p| p.trim().to_owned()).filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();

    tracing::debug!("Loading builtin plugins");
    btd_debug(0, "Loading builtin plugins");

    // Collect all built-in plugin descriptors registered via inventory::submit!
    let mut descs: Vec<&'static PluginDesc> = inventory::iter::<PluginDesc>().collect();

    // Sort by priority descending (high priority first), matching C's
    // compare_priority: plugin2->desc->priority - plugin1->desc->priority
    descs.sort_by(|a, b| b.priority.value().cmp(&a.priority.value()));

    let mut plugins_list: Vec<LoadedPlugin> = Vec::new();

    // Initialize each built-in plugin in priority order.
    for desc in &descs {
        if !enable_plugin(desc.name, &cli_enable, &cli_disable) {
            continue;
        }
        add_builtin_plugin(desc, &mut plugins_list);
    }

    // Load external plugins if testing mode is enabled (replaces C's
    // compile-time EXTERNAL_PLUGINS conditional).
    if opts.testing {
        external_plugin_init(&cli_enable, &cli_disable, &mut plugins_list);
    }

    // Store the plugin list in global state for cleanup and querying.
    let mut global = PLUGINS.lock().expect("plugin mutex poisoned");
    *global = plugins_list;

    true
}

/// Cleans up all loaded plugins and releases resources.
///
/// Calls `exit()` on each active plugin in forward order (matching C
/// `plugin_cleanup()` which iterates `GSList *plugins` forward), then
/// drops all plugin state including external library handles (triggering
/// `dlclose` for external plugins).
///
/// This is called during daemon shutdown.
pub fn plugin_cleanup() {
    let mut plugins = PLUGINS.lock().expect("plugin mutex poisoned");

    // Call exit on each active plugin in forward order (matching C behavior).
    for plugin in plugins.iter() {
        if plugin.active {
            if let Some(ref exit_fn) = plugin.exit_fn {
                exit_fn();
            }
        }
    }

    // Drop all plugins. For external plugins, this drops the Library handle,
    // which calls dlclose() to unload the shared object.
    plugins.clear();
}

/// Returns the names of all currently loaded plugins.
///
/// The returned list is in priority-sorted order (high priority first).
pub fn plugin_get_list() -> Vec<String> {
    let plugins = PLUGINS.lock().expect("plugin mutex poisoned");
    plugins.iter().map(|p| p.name.clone()).collect()
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Glob matching tests --

    #[test]
    fn test_glob_exact_match() {
        assert!(glob_match("autopair", "autopair"));
        assert!(!glob_match("autopair", "policy"));
    }

    #[test]
    fn test_glob_star_wildcard() {
        assert!(glob_match("auto*", "autopair"));
        assert!(glob_match("*pair", "autopair"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b", "ab"));
        assert!(glob_match("a*b", "aXb"));
        assert!(glob_match("a*b", "aXYZb"));
        assert!(!glob_match("a*b", "aXYZc"));
    }

    #[test]
    fn test_glob_question_wildcard() {
        assert!(glob_match("auto?air", "autopair"));
        assert!(!glob_match("auto?air", "autoair"));
        assert!(glob_match("?", "a"));
        assert!(!glob_match("?", ""));
        assert!(!glob_match("?", "ab"));
    }

    #[test]
    fn test_glob_combined_wildcards() {
        assert!(glob_match("a?c*", "abcdef"));
        assert!(glob_match("*?*", "x"));
        assert!(!glob_match("*?*", ""));
    }

    #[test]
    fn test_glob_empty_patterns() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "notempty"));
        assert!(!glob_match("notempty", ""));
    }

    // -- Enable/disable filtering tests --

    #[test]
    fn test_enable_plugin_no_filters() {
        assert!(enable_plugin("autopair", &[], &[]));
    }

    #[test]
    fn test_enable_plugin_disabled() {
        let disable = vec!["auto*".to_owned()];
        assert!(!enable_plugin("autopair", &[], &disable));
        assert!(enable_plugin("policy", &[], &disable));
    }

    #[test]
    fn test_enable_plugin_enabled_only() {
        let enable = vec!["policy".to_owned()];
        assert!(enable_plugin("policy", &enable, &[]));
        assert!(!enable_plugin("autopair", &enable, &[]));
    }

    #[test]
    fn test_enable_plugin_disable_takes_precedence() {
        let enable = vec!["*".to_owned()];
        let disable = vec!["autopair".to_owned()];
        assert!(!enable_plugin("autopair", &enable, &disable));
        assert!(enable_plugin("policy", &enable, &disable));
    }

    // -- PluginPriority tests --

    #[test]
    fn test_priority_values() {
        assert_eq!(PluginPriority::Low.value(), -100);
        assert_eq!(PluginPriority::Default.value(), 0);
        assert_eq!(PluginPriority::High.value(), 100);
    }

    #[test]
    fn test_priority_from_raw() {
        assert_eq!(PluginPriority::from_raw(200), PluginPriority::High);
        assert_eq!(PluginPriority::from_raw(100), PluginPriority::High);
        assert_eq!(PluginPriority::from_raw(50), PluginPriority::Default);
        assert_eq!(PluginPriority::from_raw(0), PluginPriority::Default);
        assert_eq!(PluginPriority::from_raw(-50), PluginPriority::Default);
        assert_eq!(PluginPriority::from_raw(-100), PluginPriority::Low);
        assert_eq!(PluginPriority::from_raw(-200), PluginPriority::Low);
    }

    #[test]
    fn test_priority_default() {
        assert_eq!(PluginPriority::default(), PluginPriority::Default);
    }

    // -- PluginDesc trait impl tests --

    fn test_init() -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn test_exit() {}

    #[test]
    fn test_plugin_desc_trait() {
        let desc = PluginDesc {
            name: "test",
            version: "1.0.0",
            priority: PluginPriority::High,
            init: test_init,
            exit: test_exit,
        };

        assert_eq!(desc.name(), "test");
        assert_eq!(desc.version(), "1.0.0");
        assert_eq!(desc.priority(), PluginPriority::High);
        assert!(desc.init().is_ok());
        desc.exit(); // should not panic
    }

    // -- Plugin list tests --

    #[test]
    fn test_plugin_get_list_empty() {
        // Ensure clean state for this test.
        let mut plugins = PLUGINS.lock().expect("mutex poisoned");
        let saved = std::mem::take(&mut *plugins);
        drop(plugins);

        let list = plugin_get_list();
        assert!(list.is_empty());

        // Restore state.
        let mut plugins = PLUGINS.lock().expect("mutex poisoned");
        *plugins = saved;
    }
}
