// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
// bluetoothctl — CLI entry point

use bluetoothctl_lib::shell::Shell;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parsed command-line arguments.
struct Args {
    /// Adapter index (-i)
    adapter: Option<String>,
    /// Print version and exit (-v)
    version: bool,
    /// Monitor mode (-m)
    monitor: bool,
    /// Timeout in seconds (-t)
    timeout: Option<u64>,
    /// One-shot command words (everything after flags)
    command: Vec<String>,
}

fn parse_args() -> Args {
    let mut args = Args {
        adapter: None,
        version: false,
        monitor: false,
        timeout: None,
        command: Vec::new(),
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "-v" | "--version" => {
                args.version = true;
            }
            "-m" | "--monitor" => {
                args.monitor = true;
            }
            "-i" | "--adapter" => {
                args.adapter = iter.next();
            }
            "-t" | "--timeout" => {
                args.timeout = iter.next().and_then(|s| s.parse().ok());
            }
            other => {
                args.command.push(other.to_string());
                // Remaining args are part of the command
                args.command.extend(iter.by_ref());
                break;
            }
        }
    }
    args
}

fn print_usage() {
    println!("bluetoothctl ver {VERSION}");
    println!("Usage:");
    println!("  bluetoothctl [options] [command [args]]");
    println!();
    println!("Options:");
    println!("  -h, --help       Show this help");
    println!("  -v, --version    Show version");
    println!("  -i, --adapter    Specify adapter index");
    println!("  -m, --monitor    Enable monitor mode");
    println!("  -t, --timeout    Timeout in seconds for non-interactive mode");
}

fn main() {
    let args = parse_args();

    if args.version {
        println!("bluetoothctl: {VERSION}");
        return;
    }

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    rt.block_on(async move {
        let mut shell = Shell::new(args.adapter.as_deref(), args.monitor);

        if args.command.is_empty() {
            // Interactive mode
            shell.run_interactive().await;
        } else {
            let line = args.command.join(" ");
            shell.run_command(&line, args.timeout).await;
        }
    });
}
