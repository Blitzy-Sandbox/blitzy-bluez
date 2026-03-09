// SPDX-License-Identifier: GPL-2.0-or-later
//
// bluetooth-meshd — Bluetooth Mesh daemon entry point
// Replaces mesh/main.c

use std::process;

use tracing::{error, info};

const MESH_DBUS_NAME: &str = "org.bluez.mesh";

struct Args {
    nodetach: bool,
    config_path: Option<String>,
    debug: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        nodetach: false,
        config_path: None,
        debug: false,
    };

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--nodetach" | "-n" => args.nodetach = true,
            "--debug" | "-d" => args.debug = true,
            "--config" | "-c" => {
                args.config_path = iter.next();
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ => {
                eprintln!("Unknown option: {arg}");
                print_usage();
                process::exit(1);
            }
        }
    }

    args
}

fn print_usage() {
    eprintln!("bluetooth-meshd - Bluetooth Mesh daemon");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  bluetooth-meshd [options]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -n, --nodetach   Don't run as daemon in background");
    eprintln!("  -c, --config     Configuration file path");
    eprintln!("  -d, --debug      Enable extra debug output");
    eprintln!("  -h, --help       Show this help");
}

#[tokio::main]
async fn main() {
    let args = parse_args();

    let level = if args.debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    let config_path = args.config_path
        .as_deref()
        .unwrap_or("/etc/bluetooth/mesh-main.conf");

    let _config = match bluetooth_meshd_lib::mesh_config::MeshConfig::load(config_path) {
        Ok(c) => {
            info!("Loaded config from {config_path}");
            c
        }
        Err(_) => {
            info!("Using default mesh config");
            bluetooth_meshd_lib::mesh_config::MeshConfig::default()
        }
    };

    info!(
        "Starting {} (nodetach={})",
        MESH_DBUS_NAME, args.nodetach
    );

    // Connect to D-Bus and register mesh service
    let connection = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect to D-Bus: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = connection.request_name(MESH_DBUS_NAME).await {
        error!("Failed to acquire D-Bus name {MESH_DBUS_NAME}: {e}");
        process::exit(1);
    }

    info!("{MESH_DBUS_NAME} ready");

    // Wait for shutdown signal
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("Received shutdown signal"),
        Err(e) => error!("Signal handler error: {e}"),
    }
}
