// BlueZ Bluetooth daemon entry point
// Stub file - will be replaced by implementation agents

pub mod config;
pub mod dbus_common;
pub mod error;
pub mod gatt;
pub mod legacy_gatt;
pub mod log;
pub mod plugin;
pub mod plugins;
pub mod profiles;
pub mod sdp;

fn main() {
    println!("bluetoothd stub");
}
