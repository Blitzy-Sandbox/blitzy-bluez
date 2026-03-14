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

/// Mesh-specific cryptographic functions: KDFs, AES-CCM, nonce builders,
/// network packet encode/decode, privacy obfuscation, FCS computation.
pub mod crypto;

/// Replay Protection List (RPL) persistence: per-source sequence-number
/// high-water-marks stored on disk, keyed by IV index.
pub mod rpl;

/// Mesh I/O subsystem: backend trait, broker, type definitions, and
/// backend implementations (generic, mgmt, unit).
pub mod io;

/// Mesh coordinator: singleton state, configuration parsing, D-Bus Network1
/// interface, constants from mesh-defs.h/mesh.h, and protocol helpers.
pub mod mesh;

/// Centralized D-Bus connection storage, mesh error-to-D-Bus error mapping,
/// message helper utilities, and send-with-timeout facility.
pub mod dbus;

/// Network key management: derives and stores NetKey material (K2/K3,
/// beacon/private keys), performs network PDU encode/decode, authenticates
/// SNB/MPB beacons, and schedules beacon transmission through mesh I/O.
pub mod net_keys;

/// Keyring persistence: stores NetKeys, AppKeys, and remote DevKeys on disk
/// in C-compatible binary format, and builds the D-Bus ExportKeys reply.
pub mod keyring;

/// Provisioning agent management: tracks D-Bus ProvisionAgent1 objects,
/// parses capabilities/OOB info, and serialises async prompt/display/key
/// requests with cancellation support.
pub mod agent;

fn main() {
    println!("bluetooth-meshd stub");
}
