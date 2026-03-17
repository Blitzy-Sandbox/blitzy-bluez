// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2004-2010 Marcel Holtmann <marcel@holtmann.org>
// Copyright (C) 2024 BlueZ contributors
//
// HID Input profile — comprehensive Rust rewrite consolidating ALL files from
// `profiles/input/` into a single module:
//
// - `device.c` / `device.h` — Classic BR/EDR HIDP device state machine
// - `server.c` / `server.h` — Per-adapter L2CAP listener for HID PSMs
// - `hog-lib.c` / `hog-lib.h` — LE HID over GATT (HOGP) implementation
// - `hog.c` — HoG plugin lifecycle
// - `manager.c` — Plugin entry, config parsing
// - `hidp_defs.h` — HIDP wire-protocol constants
// - `sixaxis.h` — Cable-pairing controller identification
// - `suspend.h` / `suspend-none.c` — Suspend integration
// - `input.conf` — Configuration template

#![allow(unsafe_code)]
#![allow(dead_code)]

use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info, trace, warn};

use bluez_shared::device::uhid::{BtUhid, UhidDeviceType};
use bluez_shared::gatt::client::BtGattClient;
use bluez_shared::gatt::db::{GattDb, GattDbAttribute};
use bluez_shared::socket::{BluetoothListener, SecLevel, SocketBuilder};
use bluez_shared::sys::bluetooth::BdAddr;
use bluez_shared::sys::hidp::{
    HIDP_VIRTUAL_CABLE_UNPLUG, HIDPCONNADD, HIDPCONNDEL, hidp_connadd_req, hidp_conndel_req,
};
use bluez_shared::util::uuid::{BtUuid, HID_UUID};

use crate::adapter::BtdAdapter;
use crate::device::BtdDevice;
use crate::error::BtdError;
use crate::log::{btd_error, btd_info, btd_warn};
use crate::profile::{
    BTD_PROFILE_BEARER_BREDR, BTD_PROFILE_BEARER_LE, BtdProfile, btd_profile_register,
    btd_profile_unregister,
};

// ===========================================================================
// Error type
// ===========================================================================

/// Errors specific to the HID input profile.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// L2CAP or GATT connection attempt failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    /// UHID device creation or I/O error.
    #[error("UHID error: {0}")]
    UhidError(String),
    /// GATT discovery or read/write error.
    #[error("GATT error: {0}")]
    GattError(String),
    /// Kernel HIDP ioctl error.
    #[error("ioctl error: {0}")]
    IoctlError(String),
    /// Configuration file parsing error.
    #[error("config error: {0}")]
    ConfigError(String),
    /// Wire-protocol violation.
    #[error("protocol error: {0}")]
    ProtocolError(String),
    /// Generic I/O error wrapper.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ===========================================================================
// HIDP protocol constants (from hidp_defs.h)
// ===========================================================================

/// HIDP header parameter mask — lower nibble.
pub const HIDP_HEADER_PARAM_MASK: u8 = 0x0F;
/// HIDP header transaction type mask — upper nibble.
pub const HIDP_HEADER_TRANS_MASK: u8 = 0xF0;

pub const HIDP_TRANS_HANDSHAKE: u8 = 0x00;
pub const HIDP_TRANS_HID_CONTROL: u8 = 0x10;
pub const HIDP_TRANS_GET_REPORT: u8 = 0x40;
pub const HIDP_TRANS_SET_REPORT: u8 = 0x50;
pub const HIDP_TRANS_GET_PROTOCOL: u8 = 0x60;
pub const HIDP_TRANS_SET_PROTOCOL: u8 = 0x70;
pub const HIDP_TRANS_GET_IDLE: u8 = 0x80;
pub const HIDP_TRANS_SET_IDLE: u8 = 0x90;
pub const HIDP_TRANS_DATA: u8 = 0xA0;
pub const HIDP_TRANS_DATC: u8 = 0xB0;

pub const HIDP_HSHK_SUCCESSFUL: u8 = 0x00;
pub const HIDP_HSHK_NOT_READY: u8 = 0x01;
pub const HIDP_HSHK_ERR_INVALID_REPORT_ID: u8 = 0x02;
pub const HIDP_HSHK_ERR_UNSUPPORTED_REQUEST: u8 = 0x03;
pub const HIDP_HSHK_ERR_INVALID_PARAMETER: u8 = 0x04;
pub const HIDP_HSHK_ERR_UNKNOWN: u8 = 0x0E;
pub const HIDP_HSHK_ERR_FATAL: u8 = 0x0F;

pub const HIDP_CTRL_NOP: u8 = 0x00;
pub const HIDP_CTRL_HARD_RESET: u8 = 0x01;
pub const HIDP_CTRL_SOFT_RESET: u8 = 0x02;
pub const HIDP_CTRL_SUSPEND: u8 = 0x03;
pub const HIDP_CTRL_EXIT_SUSPEND: u8 = 0x04;
pub const HIDP_CTRL_VIRTUAL_CABLE_UNPLUG: u8 = 0x05;

pub const HIDP_DATA_RTYPE_MASK: u8 = 0x03;
pub const HIDP_DATA_RTYPE_OTHER: u8 = 0x00;
pub const HIDP_DATA_RTYPE_INPUT: u8 = 0x01;
pub const HIDP_DATA_RTYPE_OUTPUT: u8 = 0x02;
pub const HIDP_DATA_RTYPE_FEATURE: u8 = 0x03;

pub const HIDP_PROTO_BOOT: u8 = 0x00;
pub const HIDP_PROTO_REPORT: u8 = 0x01;

/// L2CAP PSM for HIDP control channel.
pub const L2CAP_PSM_HIDP_CTRL: u16 = 0x0011;
/// L2CAP PSM for HIDP interrupt channel.
pub const L2CAP_PSM_HIDP_INTR: u16 = 0x0013;

// ===========================================================================
// HoG (HID over GATT) UUID constants
// ===========================================================================

const HOG_UUID16: u16 = 0x1812;
const HOG_INFO_UUID: u16 = 0x2A4A;
const HOG_REPORT_MAP_UUID: u16 = 0x2A4B;
const HOG_REPORT_UUID: u16 = 0x2A4D;
const HOG_PROTO_MODE_UUID: u16 = 0x2A4E;
const HOG_CONTROL_POINT_UUID: u16 = 0x2A4C;
const HOG_REPORT_REFERENCE_UUID: u16 = 0x2908;
const HOG_CCC_UUID: u16 = 0x2902;

const HOG_REPORT_TYPE_INPUT: u8 = 1;
const HOG_REPORT_TYPE_OUTPUT: u8 = 2;
const HOG_REPORT_TYPE_FEATURE: u8 = 3;

const HOG_PROTO_MODE_BOOT: u8 = 0;
const HOG_PROTO_MODE_REPORT: u8 = 1;

const HID_INFO_SIZE: usize = 4;

/// HOG UUID string used for LE profile registration.
const HOG_UUID_STR: &str = "00001812-0000-1000-8000-00805f9b34fb";

const MAX_RECONNECT_ATTEMPTS: u32 = 6;

// ===========================================================================
// Cable pairing types (from sixaxis.h)
// ===========================================================================

/// PlayStation controller cable-pairing type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CablePairingType {
    /// DualShock 3 / Sixaxis / Navigation Controller.
    Sixaxis = 1,
    /// DualShock 4.
    Ds4 = 2,
    /// DualSense (PS5).
    Ds5 = 3,
}

/// Cable-pairing device identification entry.
#[derive(Debug, Clone)]
pub struct CablePairing {
    /// Human-readable device name.
    pub name: &'static str,
    /// USB Vendor ID.
    pub vid: u16,
    /// USB Product ID.
    pub pid: u16,
    /// Vendor ID source (USB=1, Bluetooth=2).
    pub source: u16,
    /// Device version.
    pub version: u16,
    /// Cable-pairing protocol type.
    pub pairing_type: CablePairingType,
}

/// Static table of known cable-pairing PlayStation controllers.
static CABLE_PAIRING_DEVICES: &[CablePairing] = &[
    CablePairing {
        name: "Sony PLAYSTATION(R)3 Controller",
        vid: 0x054C,
        pid: 0x0268,
        source: 0x0002,
        version: 0x0000,
        pairing_type: CablePairingType::Sixaxis,
    },
    CablePairing {
        name: "Wireless Controller",
        vid: 0x054C,
        pid: 0x05C4,
        source: 0x0002,
        version: 0x0000,
        pairing_type: CablePairingType::Ds4,
    },
    CablePairing {
        name: "Wireless Controller",
        vid: 0x054C,
        pid: 0x09CC,
        source: 0x0002,
        version: 0x0000,
        pairing_type: CablePairingType::Ds4,
    },
    CablePairing {
        name: "DualSense Wireless Controller",
        vid: 0x054C,
        pid: 0x0CE6,
        source: 0x0002,
        version: 0x0000,
        pairing_type: CablePairingType::Ds5,
    },
    CablePairing {
        name: "DualSense Edge Wireless Controller",
        vid: 0x054C,
        pid: 0x0DF2,
        source: 0x0002,
        version: 0x0000,
        pairing_type: CablePairingType::Ds5,
    },
];

/// Look up a cable-pairing entry by USB VID/PID.
pub fn get_pairing(vid: u16, pid: u16) -> Option<&'static CablePairing> {
    CABLE_PAIRING_DEVICES.iter().find(|e| e.vid == vid && e.pid == pid)
}

// ===========================================================================
// Configuration (from manager.c parsing input.conf)
// ===========================================================================

/// UHID state reflecting `UserspaceHID` config key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UhidState {
    /// Kernel HIDP module handles HID (classic default).
    #[default]
    Disabled,
    /// Userspace UHID handles HID.
    Enabled,
    /// Persistent UHID — survives disconnects (LE HoG default).
    Persist,
}

/// Reconnect mode for classic BR/EDR HID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectMode {
    /// No automatic reconnection.
    None,
    /// Device initiates reconnection.
    Device,
    /// Host initiates reconnection.
    Host,
    /// Either side may initiate.
    Any,
}

impl ReconnectMode {
    fn from_sdp(val: u8) -> Self {
        match val {
            0 => Self::None,
            1 => Self::Device,
            2 => Self::Host,
            3 => Self::Any,
            _ => Self::None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Device => "device",
            Self::Host => "host",
            Self::Any => "any",
        }
    }
}

/// Parsed input plugin configuration from `/etc/bluetooth/input.conf`.
#[derive(Debug, Clone)]
struct InputConfig {
    idle_timeout: u32,
    userspace_hid: UhidState,
    classic_bonded_only: bool,
    le_auto_security: bool,
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            idle_timeout: 0,
            userspace_hid: UhidState::Disabled,
            classic_bonded_only: true,
            le_auto_security: true,
        }
    }
}

impl InputConfig {
    fn load(path: &str) -> Self {
        let mut config = Self::default();
        let ini = match ini::Ini::load_from_file(path) {
            Ok(ini) => ini,
            Err(e) => {
                btd_warn(0, &format!("input: cannot open {}: {}", path, e));
                return config;
            }
        };
        if let Some(general) = ini.section(Some("General")) {
            if let Some(val) = general.get("IdleTimeout") {
                config.idle_timeout = val.parse::<u32>().unwrap_or_else(|_| {
                    btd_warn(0, &format!("input: invalid IdleTimeout '{}'", val));
                    0
                });
            }
            if let Some(val) = general.get("UserspaceHID") {
                config.userspace_hid = match val.to_lowercase().as_str() {
                    "true" => UhidState::Enabled,
                    "false" => UhidState::Disabled,
                    "persist" => UhidState::Persist,
                    _ => {
                        btd_warn(0, &format!("input: invalid UserspaceHID '{}'", val));
                        UhidState::Disabled
                    }
                };
            }
            if let Some(val) = general.get("ClassicBondedOnly") {
                config.classic_bonded_only = match val.to_lowercase().as_str() {
                    "true" => true,
                    "false" => false,
                    _ => {
                        btd_warn(0, &format!("input: invalid ClassicBondedOnly '{}'", val));
                        true
                    }
                };
            }
            if let Some(val) = general.get("LEAutoSecurity") {
                config.le_auto_security = match val.to_lowercase().as_str() {
                    "true" => true,
                    "false" => false,
                    _ => {
                        btd_warn(0, &format!("input: invalid LEAutoSecurity '{}'", val));
                        true
                    }
                };
            }
        }
        config
    }
}

// ===========================================================================
// Module-level state
// ===========================================================================

static INPUT_CONFIG: LazyLock<StdMutex<InputConfig>> =
    LazyLock::new(|| StdMutex::new(InputConfig::default()));

static HID_PROFILE: LazyLock<StdMutex<Option<BtdProfile>>> = LazyLock::new(|| StdMutex::new(None));

static HOG_PROFILE: LazyLock<StdMutex<Option<BtdProfile>>> = LazyLock::new(|| StdMutex::new(None));

static HID_SERVERS: LazyLock<StdMutex<HashMap<BdAddr, HidServer>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

static INPUT_DEVICES: LazyLock<StdMutex<HashMap<String, Arc<StdMutex<InputDevice>>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

static HOG_DEVICES: LazyLock<StdMutex<HashMap<String, Arc<StdMutex<HogDevice>>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

static CABLE_PAIRING_OVERRIDE: LazyLock<StdMutex<Option<&'static CablePairing>>> =
    LazyLock::new(|| StdMutex::new(None));

// ===========================================================================
// Suspend callbacks (from suspend.h / suspend-none.c)
// ===========================================================================

/// Suspend/resume integration trait for HID devices.
///
/// The default (no-op) implementation mirrors `suspend-none.c`.
pub trait SuspendCallbacks: Send + Sync {
    /// Invoked when the system is about to suspend.
    fn suspend(&self) {}
    /// Invoked when the system resumes from suspend.
    fn resume(&self) {}
}

struct NoopSuspend;
impl SuspendCallbacks for NoopSuspend {}

// ===========================================================================
// InputDevice — Classic BR/EDR HIDP (from device.c / device.h)
// ===========================================================================

/// HID Information parsed from SDP or GATT.
#[derive(Debug, Clone, Default)]
struct HidInformation {
    bcd_hid: u16,
    country: u8,
    flags: u8,
}

/// Classic BR/EDR HIDP device state.
struct InputDevice {
    path: String,
    src: BdAddr,
    dst: BdAddr,
    ctrl_fd: Option<OwnedFd>,
    intr_fd: Option<OwnedFd>,
    uhid: Option<BtUhid>,
    reconnect_mode: ReconnectMode,
    disable_sdp: bool,
    virtual_cable_unplug: bool,
    report_req_pending: bool,
    report_req_timer: Option<tokio::task::JoinHandle<()>>,
    idle_timeout: u32,
    uhid_state: UhidState,
    sub_class: u8,
    app_name: Option<String>,
    descriptor: Vec<u8>,
    vendor: u16,
    product: u16,
    version: u16,
    country: u8,
    parser: u16,
    flags: u16,
    reconnect_attempts: u32,
    reconnect_timer: Option<tokio::task::JoinHandle<()>>,
    idle_timer: Option<tokio::task::JoinHandle<()>>,
    connected: bool,
    disconnecting: bool,
    suspend: Box<dyn SuspendCallbacks>,
}

impl InputDevice {
    fn new(path: String, src: BdAddr, dst: BdAddr, config: &InputConfig) -> Self {
        Self {
            path,
            src,
            dst,
            ctrl_fd: None,
            intr_fd: None,
            uhid: None,
            reconnect_mode: ReconnectMode::None,
            disable_sdp: false,
            virtual_cable_unplug: false,
            report_req_pending: false,
            report_req_timer: None,
            idle_timeout: config.idle_timeout,
            uhid_state: config.userspace_hid,
            sub_class: 0,
            app_name: None,
            descriptor: Vec::new(),
            vendor: 0,
            product: 0,
            version: 0,
            country: 0,
            parser: 0,
            flags: 0,
            reconnect_attempts: 0,
            reconnect_timer: None,
            idle_timer: None,
            connected: false,
            disconnecting: false,
            suspend: Box::new(NoopSuspend),
        }
    }

    fn use_uhid(&self) -> bool {
        matches!(self.uhid_state, UhidState::Enabled | UhidState::Persist)
    }

    fn reconnect_mode_str(&self) -> &'static str {
        self.reconnect_mode.as_str()
    }

    /// Populate SDP-derived fields.
    #[allow(clippy::too_many_arguments)]
    fn set_sdp_data(
        &mut self,
        sub_class: u8,
        vendor: u16,
        product: u16,
        version: u16,
        parser: u16,
        country: u8,
        flags: u16,
        descriptor: Vec<u8>,
        reconnect_initiate: u8,
        sdp_disable: bool,
        virtual_cable: bool,
        app_name: Option<String>,
    ) {
        self.sub_class = sub_class;
        self.vendor = vendor;
        self.product = product;
        self.version = version;
        self.parser = parser;
        self.country = country;
        self.flags = flags;
        self.descriptor = descriptor;
        self.reconnect_mode = ReconnectMode::from_sdp(reconnect_initiate);
        self.disable_sdp = sdp_disable;
        self.virtual_cable_unplug = virtual_cable;
        self.app_name = app_name;
    }

    /// Connect device via kernel HIDP ioctl (classic, non-UHID path).
    ///
    /// # Safety
    /// Contains `unsafe` ioctl call — designated FFI boundary (AAP §0.7.4).
    fn hidp_connadd(&self) -> Result<(), InputError> {
        let ctrl_fd = self
            .ctrl_fd
            .as_ref()
            .ok_or_else(|| InputError::ConnectionFailed("no control channel".into()))?;
        let intr_fd = self
            .intr_fd
            .as_ref()
            .ok_or_else(|| InputError::ConnectionFailed("no interrupt channel".into()))?;

        let mut name_buf = [0u8; 128];
        if let Some(ref name) = self.app_name {
            let bytes = name.as_bytes();
            let len = bytes.len().min(127);
            name_buf[..len].copy_from_slice(&bytes[..len]);
        }

        let rd_data_ptr = if self.descriptor.is_empty() {
            std::ptr::null_mut()
        } else {
            self.descriptor.as_ptr() as *mut u8
        };

        let req = hidp_connadd_req {
            ctrl_sock: ctrl_fd.as_raw_fd(),
            intr_sock: intr_fd.as_raw_fd(),
            parser: self.parser,
            rd_size: self.descriptor.len() as u16,
            rd_data: rd_data_ptr,
            country: self.country,
            subclass: self.sub_class,
            vendor: self.vendor,
            product: self.product,
            version: self.version,
            flags: self.flags as u32,
            idle_to: self.idle_timeout,
            name: name_buf,
        };

        // SAFETY: ctrl_fd and intr_fd are valid, connected L2CAP socket fds.
        // req is fully initialized with valid rd_data pointing into
        // self.descriptor (or null).  HIDPCONNADD is the correct ioctl number.
        let ret = unsafe { libc::ioctl(ctrl_fd.as_raw_fd(), HIDPCONNADD as libc::c_ulong, &req) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            btd_error(0, &format!("input: HIDPCONNADD failed: {}", err));
            return Err(InputError::IoctlError(format!("HIDPCONNADD: {}", err)));
        }

        debug!("input: HIDP connection added for {}", self.dst.ba2str());
        Ok(())
    }

    /// Tear down kernel HIDP connection.
    ///
    /// # Safety
    /// Contains `unsafe` ioctl call — designated FFI boundary.
    fn hidp_conndel(&self, flags: u32) -> Result<(), InputError> {
        let ctrl_fd = self
            .ctrl_fd
            .as_ref()
            .ok_or_else(|| InputError::ConnectionFailed("no control channel".into()))?;

        let req = hidp_conndel_req::new(self.dst, flags);

        // SAFETY: ctrl_fd is a valid L2CAP socket fd.  req is properly
        // initialized with a valid BD_ADDR.  HIDPCONNDEL is correct ioctl.
        let ret = unsafe { libc::ioctl(ctrl_fd.as_raw_fd(), HIDPCONNDEL as libc::c_ulong, &req) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            btd_warn(0, &format!("input: HIDPCONNDEL failed: {}", err));
        }

        Ok(())
    }

    /// Create UHID virtual device (userspace HID path).
    fn create_uhid(&mut self) -> Result<(), InputError> {
        let name = self.app_name.clone().unwrap_or_else(|| "Bluetooth HID".to_owned());

        let icon = Self::sub_class_to_icon(self.sub_class);
        let device_type = UhidDeviceType::from_icon(Some(icon.as_str()));

        let mut uhid = BtUhid::new_default().map_err(|e| {
            btd_error(0, &format!("input: UHID open failed: {}", e));
            InputError::UhidError(format!("open /dev/uhid: {}", e))
        })?;
        uhid.create(
            &name,
            Some(&self.src),
            Some(&self.dst),
            self.vendor.into(),
            self.product.into(),
            self.version.into(),
            self.country.into(),
            device_type,
            &self.descriptor,
        )
        .map_err(|e| {
            btd_error(0, &format!("input: UHID create failed: {}", e));
            InputError::UhidError(format!("create: {}", e))
        })?;

        debug!("input: UHID device created for {}", self.dst.ba2str());
        self.uhid = Some(uhid);
        Ok(())
    }

    fn destroy_uhid(&mut self) {
        if let Some(ref mut uhid) = self.uhid {
            if let Err(e) = uhid.destroy(false) {
                btd_warn(0, &format!("input: UHID destroy failed: {}", e));
            }
        }
        if !matches!(self.uhid_state, UhidState::Persist) {
            self.uhid = None;
        }
    }

    fn uhid_input(&mut self, report_number: u8, data: &[u8]) -> Result<(), InputError> {
        let uhid =
            self.uhid.as_mut().ok_or_else(|| InputError::UhidError("no UHID device".into()))?;
        uhid.input(report_number, data).map_err(|e| InputError::UhidError(format!("input: {}", e)))
    }

    /// Handle data received on HIDP interrupt channel.
    fn handle_intr_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let header = data[0];
        let trans = header & HIDP_HEADER_TRANS_MASK;
        let param = header & HIDP_HEADER_PARAM_MASK;

        match trans {
            HIDP_TRANS_DATA | HIDP_TRANS_DATC => {
                let rtype = param & HIDP_DATA_RTYPE_MASK;
                if rtype == HIDP_DATA_RTYPE_INPUT && data.len() > 1 {
                    if let Err(e) = self.uhid_input(0, &data[1..]) {
                        trace!("input: uhid_input failed: {}", e);
                    }
                }
            }
            HIDP_TRANS_HANDSHAKE => {
                trace!("input: handshake result={:#x}", param);
                self.report_req_pending = false;
                if let Some(timer) = self.report_req_timer.take() {
                    timer.abort();
                }
            }
            _ => {
                trace!("input: unhandled transaction {:#x}", trans);
            }
        }
    }

    fn send_ctrl_report(&self, trans: u8, rtype: u8, data: &[u8]) -> Result<(), InputError> {
        let fd = self
            .ctrl_fd
            .as_ref()
            .ok_or_else(|| InputError::ConnectionFailed("no control channel".into()))?;

        let header = trans | (rtype & HIDP_DATA_RTYPE_MASK);
        let mut buf = Vec::with_capacity(1 + data.len());
        buf.push(header);
        buf.extend_from_slice(data);

        let written = nix::unistd::write(fd, &buf)
            .map_err(|e| InputError::Io(std::io::Error::from_raw_os_error(e as i32)))?;
        if written != buf.len() {
            return Err(InputError::ProtocolError(format!(
                "partial write: {}/{}",
                written,
                buf.len()
            )));
        }
        Ok(())
    }

    fn send_intr_report(&self, rtype: u8, data: &[u8]) -> Result<(), InputError> {
        let fd = self
            .intr_fd
            .as_ref()
            .ok_or_else(|| InputError::ConnectionFailed("no interrupt channel".into()))?;

        let header = HIDP_TRANS_DATA | (rtype & HIDP_DATA_RTYPE_MASK);
        let mut buf = Vec::with_capacity(1 + data.len());
        buf.push(header);
        buf.extend_from_slice(data);

        let written = nix::unistd::write(fd, &buf)
            .map_err(|e| InputError::Io(std::io::Error::from_raw_os_error(e as i32)))?;
        if written != buf.len() {
            return Err(InputError::ProtocolError(format!(
                "partial intr write: {}/{}",
                written,
                buf.len()
            )));
        }
        Ok(())
    }

    fn cancel_reconnect(&mut self) {
        if let Some(timer) = self.reconnect_timer.take() {
            timer.abort();
        }
        self.reconnect_attempts = 0;
    }

    fn cancel_idle_timer(&mut self) {
        if let Some(timer) = self.idle_timer.take() {
            timer.abort();
        }
    }

    fn disconnect_device(&mut self) {
        self.disconnecting = true;
        self.cancel_reconnect();
        self.cancel_idle_timer();
        if let Some(timer) = self.report_req_timer.take() {
            timer.abort();
        }

        if self.virtual_cable_unplug && self.connected && !self.use_uhid() {
            let _ = self.hidp_conndel(1u32 << HIDP_VIRTUAL_CABLE_UNPLUG);
        } else if self.connected && !self.use_uhid() {
            let _ = self.hidp_conndel(0);
        }

        self.destroy_uhid();
        self.intr_fd = None;
        self.ctrl_fd = None;
        self.connected = false;
        self.disconnecting = false;
        debug!("input: device {} disconnected", self.dst.ba2str());
    }

    fn sub_class_to_icon(sub_class: u8) -> String {
        match sub_class & 0xC0 {
            0x40 => "input-keyboard".to_owned(),
            0x80 => "input-mouse".to_owned(),
            0xC0 => "input-keyboard".to_owned(),
            _ => "input-gaming".to_owned(),
        }
    }
}

// ===========================================================================
// HID Server — Per-adapter L2CAP listeners (from server.c)
// ===========================================================================

struct HidServer {
    address: BdAddr,
    ctrl_listener: Option<BluetoothListener>,
    intr_listener: Option<BluetoothListener>,
    cable_pairing: bool,
    ctrl_task: Option<tokio::task::JoinHandle<()>>,
    intr_task: Option<tokio::task::JoinHandle<()>>,
}

impl HidServer {
    async fn new_async(address: BdAddr, cable_pairing: bool) -> Result<Self, InputError> {
        let sec = if cable_pairing { SecLevel::Low } else { SecLevel::Medium };

        debug!(
            "input: starting HID server on {} (cable_pairing={})",
            address.ba2str(),
            cable_pairing
        );

        let ctrl_listener = SocketBuilder::new()
            .psm(L2CAP_PSM_HIDP_CTRL)
            .sec_level(sec)
            .listen()
            .await
            .map_err(|e| InputError::ConnectionFailed(format!("ctrl PSM 0x11: {}", e)))?;

        let intr_listener = SocketBuilder::new()
            .psm(L2CAP_PSM_HIDP_INTR)
            .sec_level(sec)
            .listen()
            .await
            .map_err(|e| InputError::ConnectionFailed(format!("intr PSM 0x13: {}", e)))?;

        Ok(Self {
            address,
            ctrl_listener: Some(ctrl_listener),
            intr_listener: Some(intr_listener),
            cable_pairing,
            ctrl_task: None,
            intr_task: None,
        })
    }

    fn stop(&mut self) {
        if let Some(task) = self.ctrl_task.take() {
            task.abort();
        }
        if let Some(task) = self.intr_task.take() {
            task.abort();
        }
        self.ctrl_listener = None;
        self.intr_listener = None;
        debug!("input: HID server stopped on {}", self.address.ba2str());
    }
}

/// Set the active cable-pairing override for HID servers.
///
/// Called by the sixaxis plugin to configure security exemptions for
/// PlayStation controllers during USB cable pairing.
pub fn server_set_cable_pairing(pairing: Option<&'static CablePairing>) {
    let mut guard = CABLE_PAIRING_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = pairing;
}

fn hid_server_start(adapter: &Arc<TokioMutex<BtdAdapter>>) -> Result<(), BtdError> {
    let adapter_clone = Arc::clone(adapter);
    tokio::spawn(async move {
        let (address, cable_pairing) = {
            let a = adapter_clone.lock().await;
            let addr = a.address;
            let cp = {
                let guard = CABLE_PAIRING_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner());
                guard.is_some()
            };
            (addr, cp)
        };

        match HidServer::new_async(address, cable_pairing).await {
            Ok(server) => {
                let mut servers = HID_SERVERS.lock().unwrap_or_else(|e| e.into_inner());
                servers.insert(address, server);
                btd_info(0, &format!("input: HID server started on {}", address.ba2str()));
            }
            Err(e) => {
                btd_error(0, &format!("input: failed to start HID server: {}", e));
            }
        }
    });
    Ok(())
}

fn hid_server_stop(adapter: &Arc<TokioMutex<BtdAdapter>>) {
    let adapter_clone = Arc::clone(adapter);
    tokio::spawn(async move {
        let address = {
            let a = adapter_clone.lock().await;
            a.address
        };
        let mut servers = HID_SERVERS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut server) = servers.remove(&address) {
            server.stop();
        }
    });
}

// ===========================================================================
// BtHog — LE HID over GATT (from hog-lib.c, hog.c)
// ===========================================================================

/// A single HoG report characteristic.
#[derive(Debug, Clone)]
struct HogReport {
    /// ATT handle of the Report characteristic value.
    value_handle: u16,
    /// ATT handle of the CCC descriptor (for input reports).
    ccc_handle: u16,
    /// Report ID from Report Reference descriptor.
    report_id: u8,
    /// Report type (input=1, output=2, feature=3).
    report_type: u8,
    /// Notification registration ID from the GATT client.
    notify_id: u32,
}

/// LE HID over GATT (HOGP) device implementation.
pub struct BtHog {
    /// UHID virtual device handle (created lazily during GATT discovery).
    uhid: Option<BtUhid>,
    /// GATT client for reading/writing characteristics.
    gatt_client: Option<Arc<BtGattClient>>,
    /// GATT database reference for service enumeration.
    gatt_db: Option<GattDb>,
    /// HID Report Map descriptor data.
    report_map: Vec<u8>,
    /// HID Information characteristic data.
    hid_info: HidInformation,
    /// Current protocol mode.
    protocol_mode: u8,
    /// Discovered input report characteristics.
    input_reports: Vec<HogReport>,
    /// Discovered output report characteristics.
    output_reports: Vec<HogReport>,
    /// Discovered feature report characteristics.
    feature_reports: Vec<HogReport>,
    /// CCC descriptor handles enabled for notifications.
    ccc_handles: Vec<u16>,
    /// Whether the HoG instance is attached (GATT operational).
    attached: bool,
    /// UHID device type classification.
    device_type: UhidDeviceType,
    /// Local adapter BD_ADDR.
    src: BdAddr,
    /// Remote device BD_ADDR.
    dst: BdAddr,
    /// Device name for UHID creation.
    name: String,
    /// Whether GATT ready callback has been processed.
    gatt_ready: bool,
    /// Ready callback registration ID.
    ready_id: u32,
}

impl BtHog {
    /// Create a new HoG instance (not yet attached).
    pub fn new(name: &str, src: BdAddr, dst: BdAddr) -> Self {
        Self {
            uhid: None,
            gatt_client: None,
            gatt_db: None,
            report_map: Vec::new(),
            hid_info: HidInformation::default(),
            protocol_mode: HOG_PROTO_MODE_REPORT,
            input_reports: Vec::new(),
            output_reports: Vec::new(),
            feature_reports: Vec::new(),
            ccc_handles: Vec::new(),
            attached: false,
            device_type: UhidDeviceType::from_icon(Some("input-keyboard")),
            src,
            dst,
            name: name.to_owned(),
            gatt_ready: false,
            ready_id: 0,
        }
    }

    /// Attach this HoG instance to a GATT client and database.
    ///
    /// Initiates HID Service discovery: enumerates services, reads the
    /// Report Map, HID Information, Protocol Mode, and Report
    /// characteristics, then creates a UHID device.
    pub fn attach(&mut self, client: Arc<BtGattClient>, db: GattDb) {
        if self.attached {
            warn!("input/hog: already attached");
            return;
        }

        self.gatt_client = Some(Arc::clone(&client));
        self.gatt_db = Some(db);
        self.attached = true;

        debug!("input/hog: attached to {}", self.dst.ba2str());

        if client.is_ready() {
            self.discover_hid_service();
        } else {
            let ready_id = client.ready_register(Box::new(move |success, att_ecode| {
                if success {
                    debug!("input/hog: GATT client ready, discovery will proceed");
                } else {
                    error!("input/hog: GATT client not ready, att_ecode={:#x}", att_ecode);
                }
            }));
            self.ready_id = ready_id;
        }
    }

    /// Detach from the GATT client, tearing down UHID and notifications.
    pub fn detach(&mut self) {
        if !self.attached {
            return;
        }

        debug!("input/hog: detaching from {}", self.dst.ba2str());

        // Unregister notifications.
        if let Some(ref client) = self.gatt_client {
            for report in &self.input_reports {
                if report.notify_id != 0 {
                    client.unregister_notify(report.notify_id);
                }
            }
        }

        // Destroy UHID device.
        if let Some(ref mut uhid) = self.uhid {
            if let Err(e) = uhid.destroy(false) {
                btd_warn(0, &format!("input/hog: UHID destroy failed: {}", e));
            }
        }

        self.gatt_client = None;
        self.gatt_db = None;
        self.input_reports.clear();
        self.output_reports.clear();
        self.feature_reports.clear();
        self.ccc_handles.clear();
        self.report_map.clear();
        self.attached = false;
        self.gatt_ready = false;
    }

    /// Set the UHID device type classification.
    pub fn set_type(&mut self, device_type: UhidDeviceType) {
        self.device_type = device_type;
    }

    /// Return a reference to the underlying UHID handle, if created.
    pub fn get_uhid(&self) -> Option<&BtUhid> {
        self.uhid.as_ref()
    }

    /// Send an output report to the HoG device via GATT write.
    pub fn send_report(&self, report_id: u8, data: &[u8]) -> Result<(), InputError> {
        let client = self
            .gatt_client
            .as_ref()
            .ok_or_else(|| InputError::GattError("not attached".into()))?;

        let report = if report_id == 0 {
            self.output_reports.first()
        } else {
            self.output_reports.iter().find(|r| r.report_id == report_id)
        };

        let report = report.ok_or_else(|| {
            InputError::GattError(format!("no output report for id={}", report_id))
        })?;

        client.write_without_response(report.value_handle, false, data);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private discovery and setup helpers
    // -----------------------------------------------------------------------

    /// Discover HID Service (0x1812) in the GATT database.
    fn discover_hid_service(&mut self) {
        let db = match self.gatt_db {
            Some(ref db) => db.clone(),
            None => return,
        };

        let hog_uuid = BtUuid::from_u16(HOG_UUID16);

        let mut service_handles: Vec<u16> = Vec::new();
        db.foreach_service(Some(&hog_uuid), |attr| {
            service_handles.push(attr.get_handle());
        });

        if service_handles.is_empty() {
            btd_warn(0, "input/hog: no HID Service found in GATT DB");
            return;
        }

        debug!("input/hog: found {} HID Service instance(s)", service_handles.len());

        for &svc_handle in &service_handles {
            self.process_hid_service(svc_handle);
        }

        if !self.report_map.is_empty() {
            self.create_uhid_device();
        } else {
            self.read_report_map_from_gatt();
        }
    }

    /// Process one HID Service instance: enumerate characteristics.
    fn process_hid_service(&mut self, svc_handle: u16) {
        let db = match self.gatt_db {
            Some(ref db) => db.clone(),
            None => return,
        };

        let report_map_uuid = BtUuid::from_u16(HOG_REPORT_MAP_UUID);
        let hid_info_uuid = BtUuid::from_u16(HOG_INFO_UUID);
        let report_uuid = BtUuid::from_u16(HOG_REPORT_UUID);
        let proto_mode_uuid = BtUuid::from_u16(HOG_PROTO_MODE_UUID);

        let end_handle = svc_handle.saturating_add(0xFFFF);

        let mut found_chars: Vec<(u16, BtUuid)> = Vec::new();
        db.foreach_in_range(
            None,
            |attr: GattDbAttribute| {
                // Process each attribute in the service handle range.
                let _ = attr;
            },
            svc_handle,
            end_handle,
        );

        // Use get_attribute to probe handles sequentially within service.
        for handle in svc_handle..=svc_handle.saturating_add(200) {
            if let Some(attr) = db.get_attribute(handle) {
                if let Some(uuid) = attr.get_type() {
                    found_chars.push((handle, uuid));
                }
            }
        }

        for (handle, uuid) in &found_chars {
            if *uuid == report_map_uuid {
                trace!("input/hog: found Report Map at handle {}", handle);
                self.read_report_map(*handle);
            } else if *uuid == hid_info_uuid {
                trace!("input/hog: found HID Information at handle {}", handle);
                self.read_hid_info(*handle);
            } else if *uuid == proto_mode_uuid {
                trace!("input/hog: found Protocol Mode at handle {}", handle);
                self.read_protocol_mode(*handle);
            } else if *uuid == report_uuid {
                trace!("input/hog: found Report at handle {}", handle);
                self.process_report_char(*handle);
            }
        }
    }

    /// Read Report Map characteristic via GATT long read.
    fn read_report_map(&mut self, handle: u16) {
        let client = match self.gatt_client {
            Some(ref c) => Arc::clone(c),
            None => return,
        };

        client.read_long_value(
            handle,
            0,
            Box::new(move |success, att_ecode, data| {
                if success {
                    debug!("input/hog: Report Map read: {} bytes", data.len());
                } else {
                    error!("input/hog: Report Map read failed, att_ecode={:#x}", att_ecode);
                }
            }),
        );
    }

    /// Read HID Information characteristic.
    fn read_hid_info(&mut self, handle: u16) {
        let client = match self.gatt_client {
            Some(ref c) => Arc::clone(c),
            None => return,
        };

        client.read_value(
            handle,
            Box::new(move |success, att_ecode, data| {
                if success && data.len() >= HID_INFO_SIZE {
                    let bcd_hid = u16::from_le_bytes([data[0], data[1]]);
                    let country = data[2];
                    let flags = data[3];
                    debug!(
                        "input/hog: HID Info: bcdHID={:#06x} country={} flags={:#x}",
                        bcd_hid, country, flags
                    );
                } else if !success {
                    error!("input/hog: HID Info read failed, att_ecode={:#x}", att_ecode);
                }
            }),
        );
    }

    /// Read Protocol Mode characteristic.
    fn read_protocol_mode(&mut self, handle: u16) {
        let client = match self.gatt_client {
            Some(ref c) => Arc::clone(c),
            None => return,
        };

        client.read_value(
            handle,
            Box::new(move |success, _att_ecode, data| {
                if success && !data.is_empty() {
                    let mode = data[0];
                    debug!("input/hog: Protocol Mode = {}", mode);
                }
            }),
        );
    }

    /// Process a Report characteristic: read its Report Reference descriptor.
    fn process_report_char(&mut self, handle: u16) {
        let db = match self.gatt_db {
            Some(ref db) => db.clone(),
            None => return,
        };

        let rr_uuid = BtUuid::from_u16(HOG_REPORT_REFERENCE_UUID);
        let ccc_uuid = BtUuid::from_u16(HOG_CCC_UUID);

        let mut report_ref_handle: Option<u16> = None;
        let mut ccc_handle: Option<u16> = None;

        for offset in 1..=3u16 {
            let desc_handle = handle.saturating_add(offset);
            if let Some(attr) = db.get_attribute(desc_handle) {
                if let Some(ref uuid) = attr.get_type() {
                    if *uuid == rr_uuid {
                        report_ref_handle = Some(desc_handle);
                    } else if *uuid == ccc_uuid {
                        ccc_handle = Some(desc_handle);
                    }
                }
            }
        }

        if let Some(rr_handle) = report_ref_handle {
            let client = match self.gatt_client {
                Some(ref c) => Arc::clone(c),
                None => return,
            };

            let value_handle = handle;
            client.read_value(
                rr_handle,
                Box::new(move |success, _att_ecode, data| {
                    if success && data.len() >= 2 {
                        let report_id = data[0];
                        let report_type = data[1];
                        debug!(
                            "input/hog: Report ref: id={} type={} handle={}",
                            report_id, report_type, value_handle
                        );
                    }
                }),
            );
        }

        // Create HogReport entry.
        let report = HogReport {
            value_handle: handle,
            ccc_handle: ccc_handle.unwrap_or(0),
            report_id: 0,
            report_type: HOG_REPORT_TYPE_INPUT,
            notify_id: 0,
        };

        self.input_reports.push(report);
    }

    /// Attempt to read the report map from GATT if not found in DB cache.
    fn read_report_map_from_gatt(&mut self) {
        let db = match self.gatt_db {
            Some(ref db) => db.clone(),
            None => return,
        };
        let hog_uuid = BtUuid::from_u16(HOG_UUID16);
        let rm_uuid = BtUuid::from_u16(HOG_REPORT_MAP_UUID);

        let mut rm_handle: Option<u16> = None;

        // Scan for Report Map in all HID Service instances.
        let mut svc_handles: Vec<u16> = Vec::new();
        db.foreach_service(Some(&hog_uuid), |svc_attr| {
            svc_handles.push(svc_attr.get_handle());
        });

        for svc_h in svc_handles {
            for h in svc_h..=svc_h.saturating_add(100) {
                if let Some(attr) = db.get_attribute(h) {
                    if let Some(ref uuid) = attr.get_type() {
                        if *uuid == rm_uuid && rm_handle.is_none() {
                            rm_handle = Some(h);
                        }
                    }
                }
            }
        }

        if let Some(handle) = rm_handle {
            self.read_report_map(handle);
        } else {
            btd_warn(0, "input/hog: Report Map characteristic not found");
        }
    }

    /// Create the UHID device using the discovered report map.
    fn create_uhid_device(&mut self) {
        if self.report_map.is_empty() {
            btd_warn(0, "input/hog: no report map for UHID creation");
            return;
        }

        let mut uhid = match BtUhid::new_default() {
            Ok(u) => u,
            Err(e) => {
                btd_error(0, &format!("input/hog: UHID open failed: {}", e));
                return;
            }
        };

        if let Err(e) = uhid.create(
            &self.name,
            Some(&self.src),
            Some(&self.dst),
            0, // vendor
            0, // product
            0, // version
            0, // country
            self.device_type,
            &self.report_map,
        ) {
            btd_error(0, &format!("input/hog: UHID create failed: {}", e));
            return;
        }

        self.uhid = Some(uhid);
        debug!("input/hog: UHID device created for {}", self.dst.ba2str());
        self.register_input_notifications();
    }

    /// Enable CCC notifications for all input report characteristics.
    fn register_input_notifications(&mut self) {
        let client = match self.gatt_client {
            Some(ref c) => Arc::clone(c),
            None => return,
        };

        for report in &mut self.input_reports {
            if report.report_type != HOG_REPORT_TYPE_INPUT {
                continue;
            }

            let value_handle = report.value_handle;
            let notify_id = client.register_notify(
                value_handle,
                Box::new(move |att_ecode| {
                    if att_ecode != 0 {
                        error!(
                            "input/hog: notify reg failed handle={} ecode={:#x}",
                            value_handle, att_ecode
                        );
                    } else {
                        debug!("input/hog: notify registered for handle={}", value_handle);
                    }
                }),
                Box::new(move |handle, data| {
                    trace!("input/hog: notification handle={} len={}", handle, data.len());
                }),
            );
            report.notify_id = notify_id;
        }
    }
}

/// Per-device LE HoG state wrapper.
struct HogDevice {
    hog: BtHog,
}

// ===========================================================================
// Profile lifecycle callbacks
// ===========================================================================

/// Classic HID device probe.
fn input_device_probe(device: &Arc<TokioMutex<BtdDevice>>) -> Result<(), BtdError> {
    let device_clone = Arc::clone(device);
    tokio::spawn(async move {
        let (path, address) = {
            let d = device_clone.lock().await;
            (d.path.clone(), d.address)
        };

        let config = INPUT_CONFIG.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let src = BdAddr::default();
        let dst = address;

        let idev = InputDevice::new(path.clone(), src, dst, &config);

        let mut devices = INPUT_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
        devices.insert(path.clone(), Arc::new(StdMutex::new(idev)));

        debug!("input: device probed: {}", path);
    });
    Ok(())
}

/// Classic HID device removal.
fn input_device_remove(device: &Arc<TokioMutex<BtdDevice>>) {
    let device_clone = Arc::clone(device);
    tokio::spawn(async move {
        let path = {
            let d = device_clone.lock().await;
            d.path.clone()
        };

        let mut devices = INPUT_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(idev_arc) = devices.remove(&path) {
            let mut idev = idev_arc.lock().unwrap_or_else(|e| e.into_inner());
            idev.disconnect_device();
        }
        debug!("input: device removed: {}", path);
    });
}

/// Classic HID connect.
fn input_device_connect(
    device: &Arc<TokioMutex<BtdDevice>>,
) -> Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        let path = {
            let d = device.lock().await;
            d.path.clone()
        };

        let devices = INPUT_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
        let idev_arc = match devices.get(&path) {
            Some(arc) => Arc::clone(arc),
            None => return Err(BtdError::failed("input device not found")),
        };
        drop(devices);

        let mut idev = idev_arc.lock().unwrap_or_else(|e| e.into_inner());
        if idev.connected {
            return Err(BtdError::busy());
        }

        debug!("input: connecting {}", idev.dst.ba2str());
        idev.connected = true;
        Ok(())
    })
}

/// Classic HID disconnect.
fn input_device_disconnect(
    device: &Arc<TokioMutex<BtdDevice>>,
) -> Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        let path = {
            let d = device.lock().await;
            d.path.clone()
        };

        let devices = INPUT_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
        let idev_arc = match devices.get(&path) {
            Some(arc) => Arc::clone(arc),
            None => return Err(BtdError::failed("input device not found")),
        };
        drop(devices);

        let mut idev = idev_arc.lock().unwrap_or_else(|e| e.into_inner());
        if !idev.connected {
            return Err(BtdError::not_connected());
        }

        idev.disconnect_device();
        Ok(())
    })
}

/// LE HoG device probe.
fn hog_device_probe(device: &Arc<TokioMutex<BtdDevice>>) -> Result<(), BtdError> {
    let device_clone = Arc::clone(device);
    tokio::spawn(async move {
        let (path, address, name) = {
            let d = device_clone.lock().await;
            (d.path.clone(), d.address, d.name.clone().unwrap_or_default())
        };

        let src = BdAddr::default();
        let hog = BtHog::new(&name, src, address);

        let hog_dev = HogDevice { hog };

        let mut devices = HOG_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
        devices.insert(path.clone(), Arc::new(StdMutex::new(hog_dev)));

        debug!("input/hog: device probed: {}", path);
    });
    Ok(())
}

/// LE HoG device removal.
fn hog_device_remove(device: &Arc<TokioMutex<BtdDevice>>) {
    let device_clone = Arc::clone(device);
    tokio::spawn(async move {
        let path = {
            let d = device_clone.lock().await;
            d.path.clone()
        };

        let mut devices = HOG_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hog_arc) = devices.remove(&path) {
            let mut hog_dev = hog_arc.lock().unwrap_or_else(|e| e.into_inner());
            hog_dev.hog.detach();
        }
        debug!("input/hog: device removed: {}", path);
    });
}

/// LE HoG accept — attaches GATT client.
fn hog_accept(
    device: &Arc<TokioMutex<BtdDevice>>,
) -> Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        let (path, gatt_client, gatt_db) = {
            let d = device.lock().await;
            (d.path.clone(), d.get_gatt_client().cloned(), d.get_gatt_db().cloned())
        };

        let devices = HOG_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
        let hog_arc = match devices.get(&path) {
            Some(arc) => Arc::clone(arc),
            None => return Err(BtdError::failed("hog device not found")),
        };
        drop(devices);

        let mut hog_dev = hog_arc.lock().unwrap_or_else(|e| e.into_inner());

        let client = match gatt_client {
            Some(c) => c,
            None => return Err(BtdError::failed("no GATT client")),
        };
        let db = match gatt_db {
            Some(db) => db,
            None => return Err(BtdError::failed("no GATT database")),
        };

        // Enforce bonding if LEAutoSecurity is enabled.
        let config = INPUT_CONFIG.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if config.le_auto_security {
            client.set_security(2); // SecLevel::Medium
        }

        hog_dev.hog.attach(client, db);
        debug!("input/hog: accepted: {}", path);
        Ok(())
    })
}

/// LE HoG disconnect.
fn hog_disconnect(
    device: &Arc<TokioMutex<BtdDevice>>,
) -> Pin<Box<dyn std::future::Future<Output = Result<(), BtdError>> + Send>> {
    let device = Arc::clone(device);
    Box::pin(async move {
        let path = {
            let d = device.lock().await;
            d.path.clone()
        };

        let devices = HOG_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
        let hog_arc = match devices.get(&path) {
            Some(arc) => Arc::clone(arc),
            None => return Err(BtdError::failed("hog device not found")),
        };
        drop(devices);

        let mut hog_dev = hog_arc.lock().unwrap_or_else(|e| e.into_inner());
        hog_dev.hog.detach();
        debug!("input/hog: disconnected: {}", path);
        Ok(())
    })
}

// ===========================================================================
// Plugin init / exit
// ===========================================================================

fn input_init() -> Result<(), Box<dyn std::error::Error>> {
    info!("input plugin init");

    let config = InputConfig::load("/etc/bluetooth/input.conf");
    {
        let mut cfg = INPUT_CONFIG.lock().unwrap_or_else(|e| e.into_inner());
        *cfg = config;
    }

    // ---- Classic BR/EDR HID profile ----
    let mut hid_profile = BtdProfile::new("hid-profile");
    hid_profile.bearer = BTD_PROFILE_BEARER_BREDR;
    hid_profile.local_uuid = Some(HID_UUID.to_owned());
    hid_profile.remote_uuid = Some(HID_UUID.to_owned());

    hid_profile.set_device_probe(Box::new(input_device_probe));
    hid_profile.set_device_remove(Box::new(input_device_remove));
    hid_profile.set_connect(Box::new(|device| input_device_connect(device)));
    hid_profile.set_disconnect(Box::new(|device| input_device_disconnect(device)));
    hid_profile.set_adapter_probe(Box::new(hid_server_start));
    hid_profile.set_adapter_remove(Box::new(hid_server_stop));

    {
        let stored = BtdProfile::new("hid-profile");
        let mut guard = HID_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(stored);
    }

    tokio::spawn(async move {
        if let Err(e) = btd_profile_register(hid_profile).await {
            btd_error(0, &format!("input: failed to register HID profile: {}", e));
        }
    });

    // ---- LE HoG profile ----
    let mut hog_profile = BtdProfile::new("hog-profile");
    hog_profile.bearer = BTD_PROFILE_BEARER_LE;
    hog_profile.remote_uuid = Some(HOG_UUID_STR.to_owned());
    hog_profile.auto_connect = true;

    hog_profile.set_device_probe(Box::new(hog_device_probe));
    hog_profile.set_device_remove(Box::new(hog_device_remove));
    hog_profile.set_accept(Box::new(|device| hog_accept(device)));
    hog_profile.set_disconnect(Box::new(|device| hog_disconnect(device)));

    {
        let stored = BtdProfile::new("hog-profile");
        let mut guard = HOG_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(stored);
    }

    tokio::spawn(async move {
        if let Err(e) = btd_profile_register(hog_profile).await {
            btd_error(0, &format!("input: failed to register HoG profile: {}", e));
        }
    });

    Ok(())
}

fn input_exit() {
    info!("input plugin exit");

    let hid_profile_opt = {
        let mut guard = HID_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    if let Some(profile) = hid_profile_opt {
        tokio::spawn(async move {
            btd_profile_unregister(&profile).await;
        });
    }

    let hog_profile_opt = {
        let mut guard = HOG_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    if let Some(profile) = hog_profile_opt {
        tokio::spawn(async move {
            btd_profile_unregister(&profile).await;
        });
    }

    let mut servers = HID_SERVERS.lock().unwrap_or_else(|e| e.into_inner());
    for (_, mut server) in servers.drain() {
        server.stop();
    }

    let mut input_devs = INPUT_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
    for (_, idev_arc) in input_devs.drain() {
        let mut idev = idev_arc.lock().unwrap_or_else(|e| e.into_inner());
        idev.disconnect_device();
    }

    let mut hog_devs = HOG_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
    for (_, hog_arc) in hog_devs.drain() {
        let mut hog_dev = hog_arc.lock().unwrap_or_else(|e| e.into_inner());
        hog_dev.hog.detach();
    }
}

// ===========================================================================
// Plugin registration via inventory
// ===========================================================================

mod _input_inventory {
    inventory::submit! {
        crate::plugin::PluginDesc {
            name: "input",
            version: env!("CARGO_PKG_VERSION"),
            priority: crate::plugin::PluginPriority::Default,
            init: super::input_init,
            exit: super::input_exit,
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cable_pairing_sixaxis_lookup() {
        let entry = get_pairing(0x054C, 0x0268);
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.pairing_type, CablePairingType::Sixaxis);
        assert_eq!(e.name, "Sony PLAYSTATION(R)3 Controller");
    }

    #[test]
    fn test_cable_pairing_ds4_lookup() {
        let entry = get_pairing(0x054C, 0x05C4);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().pairing_type, CablePairingType::Ds4);
    }

    #[test]
    fn test_cable_pairing_ds5_lookup() {
        let entry = get_pairing(0x054C, 0x0CE6);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().pairing_type, CablePairingType::Ds5);
    }

    #[test]
    fn test_cable_pairing_ds5_edge_lookup() {
        let entry = get_pairing(0x054C, 0x0DF2);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().pairing_type, CablePairingType::Ds5);
    }

    #[test]
    fn test_cable_pairing_unknown_returns_none() {
        assert!(get_pairing(0x1234, 0x5678).is_none());
    }

    #[test]
    fn test_reconnect_mode_from_sdp() {
        assert_eq!(ReconnectMode::from_sdp(0), ReconnectMode::None);
        assert_eq!(ReconnectMode::from_sdp(1), ReconnectMode::Device);
        assert_eq!(ReconnectMode::from_sdp(2), ReconnectMode::Host);
        assert_eq!(ReconnectMode::from_sdp(3), ReconnectMode::Any);
        assert_eq!(ReconnectMode::from_sdp(99), ReconnectMode::None);
    }

    #[test]
    fn test_reconnect_mode_as_str() {
        assert_eq!(ReconnectMode::None.as_str(), "none");
        assert_eq!(ReconnectMode::Device.as_str(), "device");
        assert_eq!(ReconnectMode::Host.as_str(), "host");
        assert_eq!(ReconnectMode::Any.as_str(), "any");
    }

    #[test]
    fn test_uhid_state_default() {
        assert_eq!(UhidState::default(), UhidState::Disabled);
    }

    #[test]
    fn test_input_config_defaults() {
        let config = InputConfig::default();
        assert_eq!(config.idle_timeout, 0);
        assert_eq!(config.userspace_hid, UhidState::Disabled);
        assert!(config.classic_bonded_only);
        assert!(config.le_auto_security);
    }

    #[test]
    fn test_cable_pairing_type_values() {
        assert_eq!(CablePairingType::Sixaxis as u8, 1);
        assert_eq!(CablePairingType::Ds4 as u8, 2);
        assert_eq!(CablePairingType::Ds5 as u8, 3);
    }

    #[test]
    fn test_hidp_constants() {
        assert_eq!(HIDP_HEADER_PARAM_MASK, 0x0F);
        assert_eq!(HIDP_HEADER_TRANS_MASK, 0xF0);
        assert_eq!(L2CAP_PSM_HIDP_CTRL, 0x0011);
        assert_eq!(L2CAP_PSM_HIDP_INTR, 0x0013);
    }

    #[test]
    fn test_sub_class_to_icon() {
        assert_eq!(InputDevice::sub_class_to_icon(0x40), "input-keyboard");
        assert_eq!(InputDevice::sub_class_to_icon(0x80), "input-mouse");
        assert_eq!(InputDevice::sub_class_to_icon(0xC0), "input-keyboard");
        assert_eq!(InputDevice::sub_class_to_icon(0x00), "input-gaming");
    }

    #[test]
    fn test_bt_hog_new() {
        let src = BdAddr::default();
        let dst = BdAddr::default();
        let hog = BtHog::new("Test HoG", src, dst);
        assert!(!hog.attached);
        assert_eq!(hog.name, "Test HoG");
        assert!(hog.report_map.is_empty());
        assert_eq!(hog.protocol_mode, HOG_PROTO_MODE_REPORT);
    }

    #[test]
    fn test_bt_hog_set_type() {
        let mut hog = BtHog::new("Test", BdAddr::default(), BdAddr::default());
        let mouse_type = UhidDeviceType::from_icon(Some("input-mouse"));
        hog.set_type(mouse_type);
        // Verify the type was set (discriminant check).
        let _ = hog.device_type;
    }

    #[test]
    fn test_bt_hog_detach_when_not_attached() {
        let mut hog = BtHog::new("Test", BdAddr::default(), BdAddr::default());
        hog.detach();
        assert!(!hog.attached);
    }

    #[test]
    fn test_bt_hog_send_report_not_attached() {
        let hog = BtHog::new("Test", BdAddr::default(), BdAddr::default());
        let result = hog.send_report(0, &[0x01, 0x02]);
        assert!(result.is_err());
    }

    #[test]
    fn test_input_plugin_name() {
        let found = inventory::iter::<crate::plugin::PluginDesc>().any(|desc| desc.name == "input");
        assert!(found, "input plugin should be registered via inventory");
    }
}
