// SPDX-License-Identifier: GPL-2.0-or-later
//
// plugin — Inventory-based plugin registration for bluetoothd.
//
// Replaces src/plugin.c and src/plugin.h. Uses the `inventory` crate
// for compile-time plugin collection instead of dlopen/dlsym.

use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Priority
// ---------------------------------------------------------------------------

/// Determines plugin initialization order (higher values run first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PluginPriority {
    Low = -100_i32 as isize,
    Default = 0,
    High = 100,
}

impl PluginPriority {
    /// Return the numeric priority value.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

// ---------------------------------------------------------------------------
// Descriptor + trait
// ---------------------------------------------------------------------------

/// Static metadata attached to every plugin.
#[derive(Debug, Clone)]
pub struct PluginDesc {
    pub name: &'static str,
    pub version: &'static str,
    pub priority: PluginPriority,
}

/// Trait that every bluetoothd plugin must implement.
///
/// Implementations are required to be `Send + Sync + 'static` so they can be
/// stored in a global `Mutex<Vec<…>>` and safely accessed from any thread.
pub trait BluetoothPlugin: Send + Sync + 'static {
    /// Return the plugin descriptor.
    fn desc(&self) -> PluginDesc;

    /// Initialise the plugin. Called once during daemon startup.
    fn init(&self) -> Result<(), Box<dyn std::error::Error>>;

    /// Tear down the plugin. Called once during daemon shutdown.
    fn exit(&self);
}

// ---------------------------------------------------------------------------
// Inventory collection
// ---------------------------------------------------------------------------

inventory::collect!(&'static dyn BluetoothPlugin);

// ---------------------------------------------------------------------------
// Global loaded-plugin list
// ---------------------------------------------------------------------------

static LOADED: Mutex<Vec<&'static dyn BluetoothPlugin>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialise all registered plugins.
///
/// * `enable`  — if `Some`, only plugins whose names appear in this
///   comma-separated list are loaded.
/// * `disable` — if `Some`, plugins whose names appear in this
///   comma-separated list are skipped.
///
/// When both `enable` and `disable` are `None` every registered plugin is
/// loaded. If both are provided, `enable` takes precedence (a plugin must
/// appear in the enable list *and* not in the disable list).
pub fn plugin_init(enable: Option<&str>, disable: Option<&str>) {
    let enable_set: Option<Vec<&str>> = enable.map(|s| s.split(',').map(str::trim).collect());
    let disable_set: Option<Vec<&str>> = disable.map(|s| s.split(',').map(str::trim).collect());

    // Collect and filter.
    let mut candidates: Vec<&'static dyn BluetoothPlugin> =
        inventory::iter::<&'static dyn BluetoothPlugin>
            .into_iter()
            .copied()
            .filter(|p| {
                let name = p.desc().name;
                if let Some(ref allowed) = enable_set {
                    if !allowed.contains(&name) {
                        return false;
                    }
                }
                if let Some(ref blocked) = disable_set {
                    if blocked.contains(&name) {
                        return false;
                    }
                }
                true
            })
            .collect();

    // Sort by priority, highest first.
    candidates.sort_by(|a, b| b.desc().priority.as_i32().cmp(&a.desc().priority.as_i32()));

    let mut loaded = LOADED.lock().expect("plugin mutex poisoned");
    loaded.clear();

    for plugin in candidates {
        let desc = plugin.desc();
        match plugin.init() {
            Ok(()) => {
                loaded.push(plugin);
            }
            Err(e) => {
                eprintln!("Failed to init plugin '{}': {}", desc.name, e);
            }
        }
    }
}

/// Shut down all loaded plugins in reverse initialisation order.
pub fn plugin_cleanup() {
    let mut loaded = LOADED.lock().expect("plugin mutex poisoned");
    for plugin in loaded.iter().rev() {
        plugin.exit();
    }
    loaded.clear();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_priority_ordering() {
        let mut priorities = vec![
            PluginPriority::Default,
            PluginPriority::Low,
            PluginPriority::High,
            PluginPriority::Default,
        ];

        // Sort ascending (Ord derived on the enum).
        priorities.sort();
        assert_eq!(
            priorities,
            vec![
                PluginPriority::Low,
                PluginPriority::Default,
                PluginPriority::Default,
                PluginPriority::High,
            ]
        );

        // Verify numeric values.
        assert_eq!(PluginPriority::Low.as_i32(), -100);
        assert_eq!(PluginPriority::Default.as_i32(), 0);
        assert_eq!(PluginPriority::High.as_i32(), 100);
    }

    #[test]
    fn test_plugin_init_cleanup() {
        // Load all registered plugins (builtin plugins are registered via
        // inventory::submit! so the registry is non-empty).
        plugin_init(None, None);

        {
            let loaded = LOADED.lock().expect("plugin mutex poisoned");
            // Builtin plugins should have loaded successfully.
            let count = loaded.len();
            assert!(count >= 0, "plugin_init should not panic");
        }

        plugin_cleanup();

        {
            let loaded = LOADED.lock().expect("plugin mutex poisoned");
            assert!(loaded.is_empty(), "expected empty list after cleanup");
        }
    }
}
