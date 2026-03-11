// Bluetooth Mesh daemon entry point
// Stub file - will be replaced by implementation agents

// util module: consumed by rpl, net_keys, net, model, node, and main
// once those sibling modules are implemented. allow(dead_code) until then.
#[allow(dead_code)]
mod util;

// config module: mesh configuration persistence layer (mod.rs + json.rs).
// allow(dead_code) until sibling modules (node, mesh, etc.) are implemented.
#[allow(dead_code)]
mod config;

// provisioning module: provisioning subsystem (mod.rs, pb_adv.rs, acceptor.rs, initiator.rs).
// allow(dead_code) until mesh/node/manager modules are implemented.
#[allow(dead_code)]
mod provisioning;

fn main() {
    println!("bluetooth-meshd stub");
}
