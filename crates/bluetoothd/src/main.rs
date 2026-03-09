// SPDX-License-Identifier: GPL-2.0-or-later
//
// bluetoothd — Bluetooth daemon entry point
//
// Replaces src/main.c. Parses configuration, initializes subsystems,
// and runs the async event loop.

use std::process;

use bluetoothd_lib::config;
use bluetoothd_lib::adapter;
use bluetoothd_lib::plugin;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BLUEZ_NAME: &str = "org.bluez";
const DEFAULT_CONFIG_PATH: &str = "/etc/bluetooth/main.conf";

fn usage() {
    println!("bluetoothd - Bluetooth daemon ver {}", VERSION);
    println!("Usage:");
    println!("\tbluetoothd [options]");
    println!("options:");
    println!("\t-n, --nodetach          Run in foreground");
    println!("\t-f, --configfile <file> Configuration file path");
    println!("\t-d, --debug             Enable debug output");
    println!("\t-p, --plugin <name>     Specify plugins to load");
    println!("\t-P, --noplugin <name>   Specify plugins to not load");
    println!("\t-E, --experimental      Enable experimental interfaces");
    println!("\t-C, --compat            Enable deprecated interfaces");
    println!("\t-h, --help              Show help options");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut config_file = DEFAULT_CONFIG_PATH.to_string();
    let mut nodetach = false;
    let mut enable_plugins: Option<String> = None;
    let mut disable_plugins: Option<String> = None;
    let mut experimental = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-n" | "--nodetach" => {
                nodetach = true;
            }
            "-f" | "--configfile" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --configfile");
                    process::exit(1);
                }
                config_file = args[i].clone();
            }
            "-d" | "--debug" => {
                // Debug logging enabled (handled by tracing)
            }
            "-p" | "--plugin" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --plugin");
                    process::exit(1);
                }
                enable_plugins = Some(args[i].clone());
            }
            "-P" | "--noplugin" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Missing argument for --noplugin");
                    process::exit(1);
                }
                disable_plugins = Some(args[i].clone());
            }
            "-E" | "--experimental" => {
                experimental = true;
            }
            "-h" | "--help" => {
                usage();
                process::exit(0);
            }
            "-v" | "--version" => {
                println!("bluetoothd ver {}", VERSION);
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

    println!("Bluetooth daemon ver {}", VERSION);
    println!("D-Bus service: {}", BLUEZ_NAME);

    // Load configuration
    let mut btd_config = config::load_config(&config_file);
    if experimental {
        btd_config.experimental = true;
    }
    let _ = nodetach; // Will be used for daemonization

    // Initialize subsystems
    adapter::adapter_init();

    // Initialize plugins
    plugin::plugin_init(
        enable_plugins.as_deref(),
        disable_plugins.as_deref(),
    );

    // On Linux, start the tokio runtime, open the management socket,
    // enumerate adapters, and run the event loop.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::OwnedFd;

        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(async {
            // Open management socket: AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI
            // then bind to HCI_CHANNEL_CONTROL.
            let mgmt_fd = match open_mgmt_socket() {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("Failed to open management socket: {}", e);
                    process::exit(1);
                }
            };

            let mgmt = match bluez_shared::mgmt::client::MgmtClient::new(mgmt_fd) {
                Ok(m) => std::sync::Arc::new(m),
                Err(e) => {
                    eprintln!("Failed to create management client: {}", e);
                    process::exit(1);
                }
            };

            // Read management version
            let version_resp = mgmt
                .send(
                    bluez_shared::mgmt::defs::MGMT_OP_READ_VERSION,
                    0xFFFF,
                    &[],
                )
                .await;
            match version_resp {
                Ok(resp) if resp.status == 0 && resp.data.len() >= 3 => {
                    let ver = resp.data[0];
                    let rev = u16::from_le_bytes([resp.data[1], resp.data[2]]);
                    eprintln!("Management version {}.{}", ver, rev);
                }
                Ok(resp) => {
                    eprintln!(
                        "Read version failed with status 0x{:02x}",
                        resp.status
                    );
                }
                Err(e) => {
                    eprintln!("Failed to read management version: {}", e);
                    process::exit(1);
                }
            }

            // Read controller index list
            let index_resp = mgmt
                .send(
                    bluez_shared::mgmt::defs::MGMT_OP_READ_INDEX_LIST,
                    0xFFFF,
                    &[],
                )
                .await;
            let indices: Vec<u16> = match index_resp {
                Ok(resp) if resp.status == 0 && resp.data.len() >= 2 => {
                    let count =
                        u16::from_le_bytes([resp.data[0], resp.data[1]]) as usize;
                    let mut list = Vec::with_capacity(count);
                    for i in 0..count {
                        let offset = 2 + i * 2;
                        if offset + 1 < resp.data.len() {
                            list.push(u16::from_le_bytes([
                                resp.data[offset],
                                resp.data[offset + 1],
                            ]));
                        }
                    }
                    eprintln!("Found {} controller(s): {:?}", list.len(), list);
                    list
                }
                Ok(resp) => {
                    eprintln!(
                        "Read index list failed with status 0x{:02x}",
                        resp.status
                    );
                    Vec::new()
                }
                Err(e) => {
                    eprintln!("Failed to read index list: {}", e);
                    Vec::new()
                }
            };

            // For each controller, create adapter and read info
            for idx in &indices {
                let a = adapter::BtdAdapter::new(
                    *idx,
                    bluez_shared::addr::BdAddr::ANY,
                );
                a.set_mgmt_client(mgmt.clone());
                adapter::adapter_register(a.clone());

                match a.read_info().await {
                    Ok(info) => {
                        eprintln!(
                            "hci{}: {} ({})",
                            idx, info.name, info.address
                        );
                    }
                    Err(e) => {
                        eprintln!("hci{}: read_info failed: {}", idx, e);
                    }
                }
            }

            // Spawn event listener for each adapter
            for idx in &indices {
                if let Some(a) = adapter::adapter_find(*idx) {
                    if let Err(e) =
                        adapter::spawn_mgmt_event_handler(a, &mgmt).await
                    {
                        eprintln!("hci{}: failed to spawn event handler: {}", idx, e);
                    }
                }
            }

            eprintln!("bluetoothd running (press Ctrl+C to stop)");

            tokio::signal::ctrl_c()
                .await
                .expect("signal handler failed");

            eprintln!("Shutting down...");
            mgmt.shutdown();
            plugin::plugin_cleanup();
            adapter::adapter_cleanup();
        });

        /// Open the BlueZ management socket.
        ///
        /// Creates an `AF_BLUETOOTH` / `SOCK_RAW` / `BTPROTO_HCI` socket,
        /// binds it to `HCI_DEV_NONE` on `HCI_CHANNEL_CONTROL`, sets it
        /// non-blocking, and returns an `OwnedFd`.
        fn open_mgmt_socket() -> std::io::Result<OwnedFd> {
            use std::os::unix::io::FromRawFd;

            const AF_BLUETOOTH: libc::c_int = 31;
            const BTPROTO_HCI: libc::c_int = 1;
            const HCI_CHANNEL_CONTROL: u16 = 3;
            const HCI_DEV_NONE: u16 = 0xFFFF;

            // sockaddr_hci layout (from include/net/bluetooth/hci.h):
            //   u16 hci_family;   // AF_BLUETOOTH
            //   u16 hci_dev;      // HCI_DEV_NONE
            //   u16 hci_channel;  // HCI_CHANNEL_CONTROL
            #[repr(C)]
            struct SockaddrHci {
                hci_family: u16,
                hci_dev: u16,
                hci_channel: u16,
            }

            // Safety: socket() is a standard POSIX syscall.  We check the
            // return value for errors.
            let fd = unsafe {
                libc::socket(AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, BTPROTO_HCI)
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let addr = SockaddrHci {
                hci_family: AF_BLUETOOTH as u16,
                hci_dev: HCI_DEV_NONE,
                hci_channel: HCI_CHANNEL_CONTROL,
            };

            // Safety: bind() with a correctly sized sockaddr_hci.  The fd is
            // valid (checked above) and addr lives for the duration of the call.
            let ret = unsafe {
                libc::bind(
                    fd,
                    &addr as *const SockaddrHci as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrHci>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                // Safety: fd is valid; we are cleaning up after a failed bind.
                unsafe { libc::close(fd) };
                return Err(err);
            }

            // Set non-blocking for async I/O.
            // Safety: fcntl with F_SETFL is a standard POSIX operation on a
            // valid fd.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            }
            let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            }

            // Safety: fd is a valid, open file descriptor that we own.
            // Wrapping in OwnedFd transfers ownership so it will be
            // closed on drop.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("bluetoothd requires Linux");
        process::exit(1);
    }
}
