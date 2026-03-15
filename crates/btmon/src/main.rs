// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2011-2014  Intel Corporation
// Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
//
// main.rs — btmon entry point: Bluetooth packet monitor.
//
// Complete Rust rewrite of monitor/main.c (308 lines) from BlueZ v5.86.
// Replaces getopt_long CLI argument parsing with manual argument parsing,
// sets up the tokio current-thread runtime, signal handling, mode dispatch,
// and module lifecycle.

use std::env;
use std::process;

use tokio::signal::unix::{SignalKind, signal};

use btmon::analyze;
use btmon::backends::ellisys;
use btmon::control;
use btmon::display::{self, MonitorColor};
use btmon::dissectors::lmp;
use btmon::keys;
use btmon::packet::{self, PacketFilter};

/// BlueZ version string matching the C `VERSION` macro from config.h.
const VERSION: &str = "5.86";

/// Maximum length for a Unix domain socket path, matching
/// `sizeof(struct sockaddr_un::sun_path) - 1` on Linux.
const SUN_PATH_MAX: usize = 107;

/// Print usage text matching EXACTLY the C format (monitor/main.c lines 46-79).
///
/// Every option line is character-identical to the C `usage()` output
/// produced by the three `printf` calls in the original source.
fn usage() {
    print!(
        "btmon - Bluetooth monitor\n\
         Usage:\n\
         \tbtmon [options]\n\
         options:\n\
         \t-r, --read <file>      Read traces in btsnoop format\n\
         \t-w, --write <file>     Save traces in btsnoop format\n\
         \t-a, --analyze <file>   Analyze traces in btsnoop format\n\
         \t                       If gnuplot is installed on the\n\
         \t                       system it will also attempt to plot\n\
         \t                       packet latency graph.\n\
         \t-s, --server <socket>  Start monitor server socket\n\
         \t-p, --priority <level> Show only priority or lower\n\
         \t-i, --index <num>      Show only specified controller\n\
         \t-d, --tty <tty>        Read data from TTY\n\
         \t-B, --tty-speed <rate> Set TTY speed (default 115200)\n\
         \t-V, --vendor <compid>  Set default company identifier\n\
         \t-M, --mgmt             Open channel for mgmt events\n\
         \t-K, --kernel           Open kmsg for kernel messages\n\
         \t-t, --time             Show time instead of time offset\n\
         \t-T, --date             Show time and date information\n\
         \t-S, --sco              Dump SCO traffic\n\
         \t-A, --a2dp             Dump A2DP stream traffic\n\
         \t-I, --iso              Dump ISO traffic\n\
         \t-E, --ellisys [ip]     Send Ellisys HCI Injection\n\
         \t-P, --no-pager         Disable pager usage\n\
         \t-J  --jlink <device>,[<serialno>],[<interface>],[<speed>]\n\
         \t                       Read data from RTT\n\
         \t-R  --rtt [<address>],[<area>],[<name>]\n\
         \t                       RTT control block parameters\n\
         \t-C, --columns [width]  Output width if not a terminal\n\
         \t-c, --color [mode]     Output color: auto/always/never\n\
         \t-h, --help             Show help options\n"
    );
}

/// Consume and return the next argument from the command line, or exit
/// with an error if no argument is available.
///
/// Advances `*idx` to the position of the consumed value so the caller's
/// main loop continues from the correct index.
fn require_arg(args: &[String], idx: &mut usize, opt: &str) -> String {
    *idx += 1;
    match args.get(*idx) {
        Some(val) => val.clone(),
        None => {
            eprintln!("Option '{}' requires an argument", opt);
            process::exit(1);
        }
    }
}

/// Resolve an option value from either an attached value (e.g. `-rfile`
/// or `--read=file`) or the next positional argument (e.g. `-r file`
/// or `--read file`).
fn resolve_value(attached: Option<String>, args: &[String], idx: &mut usize, opt: &str) -> String {
    match attached {
        Some(v) => v,
        None => require_arg(args, idx, opt),
    }
}

/// Parse an HCI controller index from a string.
///
/// Accepts both `"hciN"` prefix format and plain decimal numbers.
/// Returns `Some(index)` on success, `None` on parse failure.
fn parse_index(s: &str) -> Option<u16> {
    let numeric = if s.len() > 3 && s.starts_with("hci") { &s[3..] } else { s };

    // Validate the first character is a digit (matching C isdigit check)
    if numeric.is_empty() || !numeric.as_bytes()[0].is_ascii_digit() {
        return None;
    }

    numeric.parse::<u16>().ok()
}

/// Entry point for the btmon Bluetooth packet monitor.
///
/// Uses the tokio current-thread runtime per AAP Section 0.7.1 (btmon uses
/// `current_thread`). Replaces the C `mainloop_init()` / `mainloop_run_with_signal()`
/// lifecycle with `#[tokio::main]` and `tokio::signal::unix::signal()`.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // ── State variables matching monitor/main.c lines 113-124 ───────────
    let mut filter_mask = PacketFilter::SHOW_TIME_OFFSET;
    let mut use_pager = true;
    let mut reader_path: Option<String> = None;
    let mut writer_path: Option<String> = None;
    let mut analyze_path: Option<String> = None;
    let mut ellisys_server: Option<String> = None;
    let mut tty: Option<String> = None;
    let mut tty_speed: u32 = libc::B115200;
    let mut ellisys_port: u16 = 0;
    let mut jlink: Option<String> = None;
    let mut rtt: Option<String> = None;

    // ── CLI argument parsing (replaces getopt_long, lines 131-255) ──────
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].clone();

        // End-of-options marker
        if arg == "--" {
            i += 1;
            break;
        }

        if let Some(option_body) = arg.strip_prefix("--") {
            // Long option: split on '=' for inline values
            let (key, inline_val) = match option_body.find('=') {
                Some(pos) => (&option_body[..pos], Some(option_body[pos + 1..].to_string())),
                None => (option_body, None),
            };

            match key {
                "read" => {
                    reader_path = Some(resolve_value(inline_val, &args, &mut i, "--read"));
                }
                "write" => {
                    writer_path = Some(resolve_value(inline_val, &args, &mut i, "--write"));
                }
                "analyze" => {
                    analyze_path = Some(resolve_value(inline_val, &args, &mut i, "--analyze"));
                }
                "server" => {
                    let path = resolve_value(inline_val, &args, &mut i, "--server");
                    if path.len() > SUN_PATH_MAX {
                        eprintln!("Socket name too long");
                        process::exit(1);
                    }
                    control::control_server(&path);
                }
                "priority" => {
                    let level = resolve_value(inline_val, &args, &mut i, "--priority");
                    packet::set_priority(&level);
                }
                "index" => {
                    let val = resolve_value(inline_val, &args, &mut i, "--index");
                    match parse_index(&val) {
                        Some(idx) => packet::select_index(idx),
                        None => {
                            usage();
                            process::exit(1);
                        }
                    }
                }
                "tty" => {
                    tty = Some(resolve_value(inline_val, &args, &mut i, "--tty"));
                }
                "tty-speed" => {
                    let rate_str = resolve_value(inline_val, &args, &mut i, "--tty-speed");
                    let rate_num: i32 = rate_str.parse().unwrap_or(0);
                    match control::tty_get_speed(rate_num) {
                        Some(speed) => tty_speed = speed,
                        None => {
                            eprintln!("Unknown speed: {}", rate_str);
                            process::exit(1);
                        }
                    }
                }
                "vendor" => {
                    let val = resolve_value(inline_val, &args, &mut i, "--vendor");
                    let id: u16 = val.parse().unwrap_or(0);
                    packet::set_fallback_manufacturer(id);
                }
                "mgmt" => {
                    filter_mask |= PacketFilter::SHOW_MGMT_SOCKET;
                }
                "kernel" => {
                    filter_mask |= PacketFilter::SHOW_KMSG;
                }
                "no-time" => {
                    filter_mask &= !PacketFilter::SHOW_TIME_OFFSET;
                }
                "time" => {
                    filter_mask &= !PacketFilter::SHOW_TIME_OFFSET;
                    filter_mask |= PacketFilter::SHOW_TIME;
                }
                "date" => {
                    filter_mask &= !PacketFilter::SHOW_TIME_OFFSET;
                    filter_mask |= PacketFilter::SHOW_TIME;
                    filter_mask |= PacketFilter::SHOW_DATE;
                }
                "sco" => {
                    filter_mask |= PacketFilter::SHOW_SCO_DATA;
                }
                "a2dp" => {
                    filter_mask |= PacketFilter::SHOW_A2DP_STREAM;
                }
                "iso" => {
                    filter_mask |= PacketFilter::SHOW_ISO_DATA;
                }
                "ellisys" => {
                    ellisys_server = Some(resolve_value(inline_val, &args, &mut i, "--ellisys"));
                    ellisys_port = 24352;
                }
                "no-pager" => {
                    use_pager = false;
                }
                "jlink" => {
                    jlink = Some(resolve_value(inline_val, &args, &mut i, "--jlink"));
                }
                "rtt" => {
                    rtt = Some(resolve_value(inline_val, &args, &mut i, "--rtt"));
                }
                "columns" => {
                    let val = resolve_value(inline_val, &args, &mut i, "--columns");
                    let cols: i32 = val.parse().unwrap_or(0);
                    display::set_default_pager_num_columns(cols);
                }
                "color" => {
                    let val = resolve_value(inline_val, &args, &mut i, "--color");
                    match val.as_str() {
                        "always" => display::set_monitor_color(MonitorColor::Always),
                        "never" => display::set_monitor_color(MonitorColor::Never),
                        "auto" => display::set_monitor_color(MonitorColor::Auto),
                        _ => {
                            eprintln!("Color option must be one of auto/always/never");
                            process::exit(1);
                        }
                    }
                }
                "todo" => {
                    packet::packet_todo();
                    lmp::lmp_todo();
                    process::exit(0);
                }
                "version" => {
                    println!("{}", VERSION);
                    process::exit(0);
                }
                "help" => {
                    usage();
                    process::exit(0);
                }
                _ => {
                    eprintln!("Unknown option: --{}", key);
                    process::exit(1);
                }
            }
        } else if arg.starts_with('-') && arg.len() > 1 {
            // Short option processing
            let opt_char = arg.as_bytes()[1];
            // Check for attached value (e.g. -rfile)
            let attached = if arg.len() > 2 { Some(arg[2..].to_string()) } else { None };

            match opt_char {
                b'r' => {
                    reader_path = Some(resolve_value(attached, &args, &mut i, "-r"));
                }
                b'w' => {
                    writer_path = Some(resolve_value(attached, &args, &mut i, "-w"));
                }
                b'a' => {
                    analyze_path = Some(resolve_value(attached, &args, &mut i, "-a"));
                }
                b's' => {
                    let path = resolve_value(attached, &args, &mut i, "-s");
                    if path.len() > SUN_PATH_MAX {
                        eprintln!("Socket name too long");
                        process::exit(1);
                    }
                    control::control_server(&path);
                }
                b'p' => {
                    let level = resolve_value(attached, &args, &mut i, "-p");
                    packet::set_priority(&level);
                }
                b'i' => {
                    let val = resolve_value(attached, &args, &mut i, "-i");
                    match parse_index(&val) {
                        Some(idx) => packet::select_index(idx),
                        None => {
                            usage();
                            process::exit(1);
                        }
                    }
                }
                b'd' => {
                    tty = Some(resolve_value(attached, &args, &mut i, "-d"));
                }
                b'B' => {
                    let rate_str = resolve_value(attached, &args, &mut i, "-B");
                    let rate_num: i32 = rate_str.parse().unwrap_or(0);
                    match control::tty_get_speed(rate_num) {
                        Some(speed) => tty_speed = speed,
                        None => {
                            eprintln!("Unknown speed: {}", rate_str);
                            process::exit(1);
                        }
                    }
                }
                b'V' => {
                    let val = resolve_value(attached, &args, &mut i, "-V");
                    let id: u16 = val.parse().unwrap_or(0);
                    packet::set_fallback_manufacturer(id);
                }
                b'M' => {
                    filter_mask |= PacketFilter::SHOW_MGMT_SOCKET;
                }
                b'K' => {
                    filter_mask |= PacketFilter::SHOW_KMSG;
                }
                b'N' => {
                    filter_mask &= !PacketFilter::SHOW_TIME_OFFSET;
                }
                b't' => {
                    filter_mask &= !PacketFilter::SHOW_TIME_OFFSET;
                    filter_mask |= PacketFilter::SHOW_TIME;
                }
                b'T' => {
                    filter_mask &= !PacketFilter::SHOW_TIME_OFFSET;
                    filter_mask |= PacketFilter::SHOW_TIME;
                    filter_mask |= PacketFilter::SHOW_DATE;
                }
                b'S' => {
                    filter_mask |= PacketFilter::SHOW_SCO_DATA;
                }
                b'A' => {
                    filter_mask |= PacketFilter::SHOW_A2DP_STREAM;
                }
                b'I' => {
                    filter_mask |= PacketFilter::SHOW_ISO_DATA;
                }
                b'E' => {
                    ellisys_server = Some(resolve_value(attached, &args, &mut i, "-E"));
                    ellisys_port = 24352;
                }
                b'P' => {
                    use_pager = false;
                }
                b'J' => {
                    jlink = Some(resolve_value(attached, &args, &mut i, "-J"));
                }
                b'R' => {
                    rtt = Some(resolve_value(attached, &args, &mut i, "-R"));
                }
                b'C' => {
                    let val = resolve_value(attached, &args, &mut i, "-C");
                    let cols: i32 = val.parse().unwrap_or(0);
                    display::set_default_pager_num_columns(cols);
                }
                b'c' => {
                    let val = resolve_value(attached, &args, &mut i, "-c");
                    match val.as_str() {
                        "always" => display::set_monitor_color(MonitorColor::Always),
                        "never" => display::set_monitor_color(MonitorColor::Never),
                        "auto" => display::set_monitor_color(MonitorColor::Auto),
                        _ => {
                            eprintln!("Color option must be one of auto/always/never");
                            process::exit(1);
                        }
                    }
                }
                b'#' => {
                    packet::packet_todo();
                    lmp::lmp_todo();
                    process::exit(0);
                }
                b'v' => {
                    println!("{}", VERSION);
                    process::exit(0);
                }
                b'h' => {
                    usage();
                    process::exit(0);
                }
                _ => {
                    eprintln!("Unknown option: -{}", arg.chars().nth(1).unwrap_or('?'));
                    process::exit(1);
                }
            }
        } else {
            // Non-option positional argument — not expected
            break;
        }

        i += 1;
    }

    // ── Post-parse validation (lines 257-265) ───────────────────────────

    // Check for remaining non-option arguments
    if i < args.len() {
        eprintln!("Invalid command line parameters");
        process::exit(1);
    }

    // Reader and analyzer modes are mutually exclusive
    if reader_path.is_some() && analyze_path.is_some() {
        eprintln!("Display and analyze can't be combined");
        process::exit(1);
    }

    // ── Version banner (line 267) ───────────────────────────────────────
    println!("Bluetooth monitor ver {}", VERSION);

    // ── Module initialization (lines 269-271) ───────────────────────────
    keys::keys_setup();
    packet::set_filter(filter_mask);

    // ── Mode dispatch (lines 273-301) ───────────────────────────────────

    // Analyze mode: synchronous offline trace analysis
    if let Some(ref path) = analyze_path {
        analyze::analyze_trace(path);
        keys::keys_cleanup();
        process::exit(0);
    }

    // Reader mode: synchronous btsnoop file replay
    if let Some(ref path) = reader_path {
        if let Some(ref server) = ellisys_server {
            let _ = ellisys::ellisys_enable(server, ellisys_port);
        }
        control::control_reader(path, use_pager);
        keys::keys_cleanup();
        process::exit(0);
    }

    // Writer mode: open btsnoop output file for live capture
    if let Some(ref path) = writer_path {
        if !control::control_writer(path) {
            println!("Failed to open '{}'", path);
            keys::keys_cleanup();
            process::exit(1);
        }
    }

    // Ellisys injection: enable UDP HCI packet forwarding
    if let Some(ref server) = ellisys_server {
        let _ = ellisys::ellisys_enable(server, ellisys_port);
    }

    // Default tracing mode: open HCI monitor + control channels
    if tty.is_none() && jlink.is_none() && control::control_tracing().is_err() {
        keys::keys_cleanup();
        process::exit(1);
    }

    // TTY mode: read HCI frames from serial port
    if let Some(ref tty_path) = tty {
        if control::control_tty(tty_path, tty_speed).is_err() {
            keys::keys_cleanup();
            process::exit(1);
        }
    }

    // J-Link RTT mode: read HCI frames via SEGGER J-Link
    if let Some(ref jlink_cfg) = jlink {
        if control::control_rtt(jlink_cfg, rtt.as_deref()).is_err() {
            keys::keys_cleanup();
            process::exit(1);
        }
    }

    // ── Event loop: wait for SIGINT or SIGTERM (replaces
    //    mainloop_run_with_signal, line 303) ─────────────────────────────

    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }

    // ── Cleanup (line 305) ──────────────────────────────────────────────
    keys::keys_cleanup();
}
