// SPDX-License-Identifier: GPL-2.0-or-later
//
// btmon — Bluetooth packet monitor and analyzer
//
// Replaces monitor/main.c. Parses CLI arguments and drives the monitor
// or analyzer depending on the mode selected.

use std::process;

use btmon_lib::analyze::Analyzer;
use btmon_lib::control::Control;
use btmon_lib::display;
use btmon_lib::packet;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() {
    println!("btmon - Bluetooth monitor ver {}", VERSION);
    println!("Usage:");
    println!("\tbtmon [options]");
    println!("options:");
    println!("\t-r, --read <file>      Read traces in btsnoop format");
    println!("\t-w, --write <file>     Save traces in btsnoop format");
    println!("\t-a, --analyze <file>   Analyze traces in btsnoop format");
    println!("\t-i, --index <num>      Show only specified controller");
    println!("\t-t, --time             Show time instead of time offset");
    println!("\t-T, --date             Show time and date information");
    println!("\t-S, --sco              Dump SCO traffic");
    println!("\t-A, --a2dp             Dump A2DP stream traffic");
    println!("\t-I, --iso              Dump ISO traffic");
    println!("\t-c, --color <mode>     Output color: auto/always/never");
    println!("\t-h, --help             Show help options");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut filter_mask: u64 = packet::FILTER_SHOW_TIME;
    let mut reader_path: Option<String> = None;
    let mut writer_path: Option<String> = None;
    let mut analyze_path: Option<String> = None;
    let mut index_filter: Option<u16> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-r" | "--read" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --read");
                    process::exit(1);
                }
                reader_path = Some(args[i].clone());
            }
            "-w" | "--write" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --write");
                    process::exit(1);
                }
                writer_path = Some(args[i].clone());
            }
            "-a" | "--analyze" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --analyze");
                    process::exit(1);
                }
                analyze_path = Some(args[i].clone());
            }
            "-i" | "--index" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --index");
                    process::exit(1);
                }
                let s = args[i].strip_prefix("hci").unwrap_or(&args[i]);
                match s.parse::<u16>() {
                    Ok(idx) => index_filter = Some(idx),
                    Err(_) => {
                        eprintln!("Invalid index: {}", args[i]);
                        process::exit(1);
                    }
                }
            }
            "-t" | "--time" => {
                filter_mask &= !packet::FILTER_SHOW_TIME_OFFSET;
                filter_mask |= packet::FILTER_SHOW_TIME;
            }
            "-T" | "--date" => {
                filter_mask &= !packet::FILTER_SHOW_TIME_OFFSET;
                filter_mask |= packet::FILTER_SHOW_TIME | packet::FILTER_SHOW_DATE;
            }
            "-S" | "--sco" => {
                filter_mask |= packet::FILTER_SHOW_SCO_DATA;
            }
            "-A" | "--a2dp" => {
                filter_mask |= packet::FILTER_SHOW_A2DP_STREAM;
            }
            "-I" | "--iso" => {
                filter_mask |= packet::FILTER_SHOW_ISO_DATA;
            }
            "-c" | "--color" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --color");
                    process::exit(1);
                }
                match args[i].as_str() {
                    "always" => display::set_color_mode(display::ColorMode::Always),
                    "never" => display::set_color_mode(display::ColorMode::Never),
                    "auto" => display::set_color_mode(display::ColorMode::Auto),
                    _ => {
                        eprintln!("Color option must be one of auto/always/never");
                        process::exit(1);
                    }
                }
            }
            "-h" | "--help" => {
                usage();
                process::exit(0);
            }
            "-v" | "--version" => {
                println!("btmon ver {}", VERSION);
                process::exit(0);
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    if reader_path.is_some() && analyze_path.is_some() {
        eprintln!("Display and analyze can't be combined");
        process::exit(1);
    }

    println!("Bluetooth monitor ver {}", VERSION);

    // Analyze mode
    if let Some(path) = analyze_path {
        Analyzer::analyze_trace(&path);
        return;
    }

    // Reader mode
    let mut ctrl = Control::new();
    ctrl.state_mut().set_filter(filter_mask);

    if let Some(idx) = index_filter {
        ctrl.state_mut().select_index(idx);
        ctrl.state_mut().add_filter(packet::FILTER_SHOW_INDEX);
    }

    if let Some(ref path) = writer_path {
        if !ctrl.set_writer(path) {
            eprintln!("Failed to open '{}'", path);
            process::exit(1);
        }
    }

    if let Some(path) = reader_path {
        ctrl.read_file(&path);
        return;
    }

    // Live tracing mode — requires Linux HCI monitor socket
    #[cfg(target_os = "linux")]
    {
        use btmon_lib::control::open_monitor_socket;

        let monitor_fd = match open_monitor_socket() {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("Failed to open monitor socket: {}", e);
                eprintln!("Make sure you have appropriate permissions (try running as root)");
                process::exit(1);
            }
        };

        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(async {
            use std::os::unix::io::AsRawFd;
            use tokio::io::unix::AsyncFd;

            let async_fd = match AsyncFd::new(monitor_fd) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("Failed to register monitor fd: {}", e);
                    process::exit(1);
                }
            };

            let mut buf = vec![0u8; 4096];

            eprintln!("= Note: Linux btmon live trace started =");

            loop {
                tokio::select! {
                    result = async_fd.readable() => {
                        if let Ok(mut guard) = result {
                            match guard.try_io(|inner| {
                                let raw = inner.get_ref().as_raw_fd();
                                // Safety: recv() on a valid monitor socket fd
                                // with a valid buffer.
                                let ret = unsafe {
                                    libc::recv(
                                        raw,
                                        buf.as_mut_ptr() as *mut libc::c_void,
                                        buf.len(),
                                        0,
                                    )
                                };
                                if ret < 0 {
                                    Err(std::io::Error::last_os_error())
                                } else {
                                    Ok(ret as usize)
                                }
                            }) {
                                Ok(Ok(n)) if n >= 6 => {
                                    // Monitor packet header:
                                    //   opcode(2) + index(2) + len(2) + payload
                                    let opcode = u16::from_le_bytes([buf[0], buf[1]]);
                                    let pkt_index = u16::from_le_bytes([buf[2], buf[3]]);
                                    let _plen = u16::from_le_bytes([buf[4], buf[5]]) as usize;
                                    let payload = &buf[6..n];

                                    if let Some(idx) = index_filter {
                                        if pkt_index != idx {
                                            continue;
                                        }
                                    }

                                    ctrl.state_mut().packet_monitor(
                                        None,
                                        pkt_index,
                                        opcode,
                                        payload,
                                    );
                                }
                                Ok(Ok(_)) => {} // Too short, ignore
                                Ok(Err(e)) => {
                                    eprintln!("recv error: {}", e);
                                    break;
                                }
                                Err(_would_block) => {}
                            }
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("Shutting down...");
                        break;
                    }
                }
            }
        });
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Live tracing requires Linux");
        process::exit(1);
    }
}
