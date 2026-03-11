// Bluetooth Mesh daemon entry point
// Stub file - will be replaced by implementation agents

/// Mesh utility functions: hex conversion, timestamps, directory helpers.
/// Consumed by rpl, net_keys, net, model, node, and main subsystems.
pub mod util;

/// Mesh configuration persistence layer (mod.rs + json.rs).
/// Consumed by node, mesh, and manager subsystems.
pub mod config;

/// Provisioning subsystem (mod.rs, pb_adv.rs, acceptor.rs, initiator.rs).
/// Consumed by mesh, node, and manager subsystems.
pub mod provisioning;

fn main() {
    println!("bluetooth-meshd stub");
}
