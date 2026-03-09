// SPDX-License-Identifier: GPL-2.0-or-later
//! OBEX daemon entry point — replaces obexd/src/main.c.

use std::process;

/// Daemon configuration parsed from command-line arguments.
#[derive(Default)]
struct Config {
    no_detach: bool,
    debug: bool,
    root: Option<String>,
    symlinks: bool,
    capability: Option<String>,
}

fn parse_args() -> Option<Config> {
    let mut config = Config::default();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-n" | "--nodetach" => config.no_detach = true,
            "-d" | "--debug" => config.debug = true,
            "-l" | "--symlinks" => config.symlinks = true,
            "-r" | "--root" => {
                config.root = args.next();
                if config.root.is_none() {
                    eprintln!("Error: --root requires a path argument");
                    return None;
                }
            }
            "-c" | "--capability" => {
                config.capability = args.next();
                if config.capability.is_none() {
                    eprintln!("Error: --capability requires a file argument");
                    return None;
                }
            }
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            other => {
                eprintln!("Unknown option: {other}");
                print_usage();
                return None;
            }
        }
    }

    Some(config)
}

fn print_usage() {
    println!("obexd - OBEX daemon");
    println!();
    println!("Usage: obexd [options]");
    println!();
    println!("Options:");
    println!("  -n, --nodetach     Run in foreground");
    println!("  -d, --debug        Enable debug output");
    println!("  -r, --root <path>  Specify root folder location");
    println!("  -l, --symlinks     Allow symlinks in root folder");
    println!("  -c, --capability   Specify capability file");
    println!("  -h, --help         Show this help");
}

fn main() {
    let config = match parse_args() {
        Some(c) => c,
        None => process::exit(1),
    };

    if config.debug {
        tracing::info!("Debug mode enabled");
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(async {
        tracing::info!("Starting OBEX daemon (org.bluez.obex)");

        if let Some(ref root) = config.root {
            tracing::info!(root = %root, "Using custom root folder");
        }

        if config.symlinks {
            tracing::info!("Symlinks allowed in root folder");
        }

        // TODO: Register D-Bus service org.bluez.obex
        // TODO: Start OBEX server
        // TODO: Wait for shutdown signal

        match tokio::signal::ctrl_c().await {
            Ok(()) => tracing::info!("Shutting down OBEX daemon"),
            Err(e) => tracing::error!(error = %e, "Failed to listen for shutdown signal"),
        }
    });
}
