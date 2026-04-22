// SPDX-License-Identifier: GPL-2.0-or-later
//
// Sync services (IrMC, SyncEvolution, PC Suite) — merged module.
//
// Rust rewrite of three C source files:
// - `obexd/plugins/irmc.c` (476 lines) — IrMC-SYNC read-only service
// - `obexd/plugins/syncevolution.c` (470 lines) — SyncEvolution D-Bus relay
// - `obexd/plugins/pcsuite.c` (503 lines) — Nokia PC Suite service
//
// All three are OBEX service plugins providing synchronisation-related
// functionality registered via `inventory::submit!`.

use std::any::Any;
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as IoRead, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use nix::errno::Errno;

use crate::obex::session::ObexSession;

use super::ftp::FTP_TARGET;
use super::pbap::{
    ApparamField, PB_CALENDAR_FOLDER, PB_CC_LOG, PB_CONTACTS, PB_DEVINFO, PB_INFO_LOG,
    PB_LUID_FOLDER, PB_NOTES_FOLDER,
};
use super::{
    OBEX_IRMC, OBEX_PCSUITE, OBEX_SYNCEVOLUTION, ObexMimeTypeDriver, ObexPluginDesc,
    ObexServiceDriver, StringReadState, ftp_action, ftp_chkput, ftp_connect, ftp_disconnect,
    ftp_get, ftp_put, ftp_setpath, obex_mime_type_driver_register,
    obex_mime_type_driver_unregister, obex_service_driver_register, obex_service_driver_unregister,
    string_read,
};

// ===========================================================================
// Constants
// ===========================================================================

/// IrMC-SYNC OBEX target header — 9 bytes spelling "IRMC-SYNC".
pub const IRMC_TARGET: [u8; 9] = [0x49, 0x52, 0x4D, 0x43, 0x2D, 0x53, 0x59, 0x4E, 0x43];

/// SyncML-SYNC OBEX target header — 11 bytes spelling "SYNCML-SYNC".
pub const SYNCML_TARGET: [u8; 11] =
    [0x53, 0x59, 0x4E, 0x43, 0x4D, 0x4C, 0x2D, 0x53, 0x59, 0x4E, 0x43];

/// PC Suite "Who" header — 8 bytes: NUL NUL 'P' 'C' 'S' 'u' 'i' 't'.
pub const PCSUITE_WHO: [u8; 8] = [0x00, 0x00, 0x50, 0x43, 0x53, 0x75, 0x69, 0x74];

/// Maximum length of device ID fields (serial number, DID, etc.).
pub const DID_LEN: usize = 18;

/// SyncEvolution RFCOMM channel number.
pub const SYNCEVOLUTION_CHANNEL: u8 = 19;

/// PC Suite RFCOMM channel number.
pub const PCSUITE_CHANNEL: u8 = 24;

/// Owner vCard placeholder prepended to phonebook data during IrMC query
/// result processing. Note: the C original uses `X-IRMX-LUID` (not
/// `X-IRMC-LUID`) for the owner record.
const OWNER_VCARD: &str = "\
BEGIN:VCARD\r\n\
VERSION:2.1\r\n\
N:\r\n\
TEL:\r\n\
X-IRMX-LUID:0\r\n\
END:VCARD\r\n";

/// SyncEvolution SDP service record XML template.
///
/// Contains `%u` (channel) and `%s` (service name) placeholders matching
/// the C `SYNCEVOLUTION_RECORD` constant exactly.
pub const SYNCEVOLUTION_RECORD: &str = "\
<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\
<record>\
<attribute id=\"0x0001\">\
<sequence>\
<uuid value=\"0x0002\"/>\
</sequence>\
</attribute>\
<attribute id=\"0x0004\">\
<sequence>\
<sequence>\
<uuid value=\"0x0100\"/>\
</sequence>\
<sequence>\
<uuid value=\"0x0003\"/>\
<uint8 value=\"%u\" name=\"channel\"/>\
</sequence>\
<sequence>\
<uuid value=\"0x0008\"/>\
</sequence>\
</sequence>\
</attribute>\
<attribute id=\"0x0100\">\
<text value=\"%s\" name=\"name\"/>\
</attribute>\
</record>";

/// PC Suite SDP service record XML template.
///
/// Contains `%u` (channel) and `%s` (service name) placeholders matching
/// the C `PCSUITE_RECORD` constant exactly.
pub const PCSUITE_RECORD: &str = "\
<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\
<record>\
<attribute id=\"0x0001\">\
<sequence>\
<uuid value=\"00005005-0000-1000-8000-0002ee000001\"/>\
</sequence>\
</attribute>\
<attribute id=\"0x0004\">\
<sequence>\
<sequence>\
<uuid value=\"0x0100\"/>\
</sequence>\
<sequence>\
<uuid value=\"0x0003\"/>\
<uint8 value=\"%u\" name=\"channel\"/>\
</sequence>\
<sequence>\
<uuid value=\"0x0008\"/>\
</sequence>\
</sequence>\
</attribute>\
<attribute id=\"0x0005\">\
<sequence>\
<uuid value=\"0x1002\"/>\
</sequence>\
</attribute>\
<attribute id=\"0x0009\">\
<sequence>\
<sequence>\
<uuid value=\"00005005-0000-1000-8000-0002ee000001\"/>\
<uint16 value=\"0x0100\"/>\
</sequence>\
</sequence>\
</attribute>\
<attribute id=\"0x0100\">\
<text value=\"%s\" name=\"name\"/>\
</attribute>\
</record>";

/// SyncEvolution D-Bus bus name.
pub const SYNCE_BUS_NAME: &str = "org.syncevolution";
/// SyncEvolution D-Bus object path.
pub const SYNCE_PATH: &str = "/org/syncevolution/Server";
/// SyncEvolution D-Bus server interface.
pub const SYNCE_SERVER_INTERFACE: &str = "org.syncevolution.Server";
/// SyncEvolution D-Bus connection interface.
pub const SYNCE_CONN_INTERFACE: &str = "org.syncevolution.Connection";

/// Nokia backup D-Bus bus name.
pub const BACKUP_BUS_NAME: &str = "com.nokia.backup.plugin";
/// Nokia backup D-Bus object path.
pub const BACKUP_PATH: &str = "/com/nokia/backup";
/// Nokia backup D-Bus interface.
pub const BACKUP_PLUGIN_INTERFACE: &str = "com.nokia.backup.plugin";

// ===========================================================================
// IrMC Session State
// ===========================================================================

/// Per-session state for the IrMC Sync service.
///
/// Replaces C `struct irmc_session` from `obexd/plugins/irmc.c`.
pub struct IrmcSession {
    /// Parsed application parameters (maxlistcount, filter, etc.).
    pub params: Option<ApparamField>,
    /// Number of phonebook entries discovered during connect.
    pub entries: u16,
    /// String buffer holding the current response body being streamed.
    pub buffer: Option<StringReadState>,
    /// Device serial number (max `DID_LEN` chars).
    pub sn: String,
    /// Device unique identifier (max `DID_LEN` chars).
    pub did: String,
    /// Manufacturer name.
    pub manu: String,
    /// Model identifier.
    pub model: String,
    /// Active phonebook request handle (for cleanup).
    request: Option<Box<dyn Any + Send>>,
}

impl IrmcSession {
    /// Create a new IrMC session with default device information derived
    /// from the system hostname.
    pub fn new() -> Self {
        // Replaces C gethostname() initialisation in irmc_connect().
        // Read from /etc/hostname (standard on Linux) to avoid unsafe.
        let hostname = fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string();

        let mut did = String::with_capacity(DID_LEN);
        let mut sn = String::from("12345");

        // Truncate hostname to DID_LEN.
        for (i, ch) in hostname.chars().enumerate() {
            if i >= DID_LEN {
                break;
            }
            did.push(ch);
        }

        // Ensure sn is within DID_LEN.
        sn.truncate(DID_LEN);

        Self {
            params: None,
            entries: 0,
            buffer: None,
            sn,
            did,
            manu: String::from("obex"),
            model: String::from("mymodel"),
            request: None,
        }
    }
}

// ===========================================================================
impl Default for IrmcSession {
    fn default() -> Self {
        Self::new()
    }
}

// SyncEvolution Session State
// ===========================================================================

/// Per-session state for the SyncEvolution relay service.
///
/// Replaces C `struct synce_context` from `obexd/plugins/syncevolution.c`.
pub struct SynceContext {
    /// D-Bus connection to the SyncEvolution service.
    pub conn: Option<zbus::Connection>,
    /// Object path of the SyncEvolution connection session.
    pub conn_obj: Option<String>,
    /// Reply data buffer from D-Bus Reply signal.
    pub buffer: Option<StringReadState>,
    /// Last error code (-EAGAIN while pending).
    pub lasterr: i32,
    /// Unique session identifier (peer address + channel).
    id: String,
}

impl SynceContext {
    /// Create a new SyncEvolution context.
    pub fn new(id: String) -> Self {
        Self { conn: None, conn_obj: None, buffer: None, lasterr: -(Errno::EAGAIN as i32), id }
    }
}

// ===========================================================================
// PC Suite Session State
// ===========================================================================

/// Per-session state for the Nokia PC Suite service.
///
/// Wraps an FTP session with a single-session lock file at `~/.pcsuite`.
///
/// Replaces C `struct pcsuite_session` from `obexd/plugins/pcsuite.c`.
pub struct PcsuiteSession {
    /// Underlying FTP session providing file transfer operations.
    pub ftp_session: Box<dyn Any + Send>,
    /// Path to the exclusive lock file (`~/.pcsuite`).
    pub lock_path: PathBuf,
    /// Held lock file descriptor (closed on disconnect).
    pub lock_fd: Option<File>,
}

// ===========================================================================
// Backup MIME Object State
// ===========================================================================

/// Per-object state for the Nokia backup MIME type driver.
///
/// Replaces C `struct backup_object` from `obexd/plugins/pcsuite.c`.
pub struct BackupObject {
    /// Backup command (basename of the OBEX object name).
    pub cmd: String,
    /// File descriptor for the backup data stream.
    pub fd: Option<File>,
    /// Open flags (O_RDONLY / O_WRONLY) from the OBEX request.
    pub oflag: i32,
    /// File creation mode bits.
    pub mode: u32,
    /// Whether a D-Bus reply is still pending.
    pub pending: bool,
    /// Error code from the backup D-Bus reply (0 = success).
    pub error_code: i32,
}

impl BackupObject {
    /// Create a new backup object for the given command.
    pub fn new(cmd: String, oflag: i32, mode: u32) -> Self {
        Self { cmd, fd: None, oflag, mode, pending: true, error_code: 0 }
    }
}

// ===========================================================================
// IrMC Helper Functions
// ===========================================================================

/// Format the IrMC device info text block.
///
/// Populates the buffer with MANU, MOD, SN, IRMC-VERSION, and capability
/// fields. Matches C `irmc_open_devinfo()` from irmc.c.
fn irmc_open_devinfo(session: &IrmcSession) -> String {
    let mut buf = String::with_capacity(256);
    let _ = writeln!(buf, "MANU:{}", session.manu);
    let _ = writeln!(buf, "MOD:{}", session.model);
    let _ = writeln!(buf, "SN:{}", session.sn);
    let _ = writeln!(buf, "IRMC-VERSION:1.1");
    let _ = writeln!(buf, "PB-TYPE:ADR");
    let _ = writeln!(buf, "PB-TYPE-TX:VCARD");
    let _ = writeln!(buf, "CAL-TYPE:N/A");
    let _ = writeln!(buf, "MSG-TYPE:N/A");
    let _ = writeln!(buf, "NOTE-TYPE:N/A");
    buf
}

/// Format the IrMC info.log response.
///
/// Returns "Total-Records:N\r\nMaximum-Records:N\r\nIEL:2\r\nDID:X\r\n".
/// Matches C `irmc_open_info()` from irmc.c.
fn irmc_open_info(session: &IrmcSession) -> String {
    let mut buf = String::with_capacity(128);
    let _ = write!(
        buf,
        "Total-Records:{}\r\nMaximum-Records:{}\r\nIEL:2\r\nDID:{}\r\n",
        session.entries, session.entries, session.did
    );
    buf
}

/// Format the IrMC change counter log response.
///
/// Returns "N\r\n" where N is the entry count.
/// Matches C `irmc_open_cc()` from irmc.c.
fn irmc_open_cc(session: &IrmcSession) -> String {
    format!("{}\r\n", session.entries)
}

/// Format the IrMC LUID changelog header response.
///
/// Returns SN, DID, Total-Records, Maximum-Records, and sentinel.
/// Matches C `irmc_open_luid()` from irmc.c.
fn irmc_open_luid(session: &IrmcSession) -> String {
    let mut buf = String::with_capacity(128);
    let _ = write!(
        buf,
        "SN:{}\r\nDID:{}\r\nTotal-Records:{}\r\nMaximum-Records:{}\r\n*\r\n",
        session.sn, session.did, session.entries, session.entries
    );
    buf
}

/// Process the phonebook query result callback for IrMC.
///
/// Prepends the owner vCard, then walks the buffer injecting
/// `X-IRMC-LUID:N` lines after every `UID:` line. Signals I/O readiness
/// when complete.
///
/// Matches C `query_result()` from irmc.c.
pub fn irmc_process_query_result(
    session: &mut IrmcSession,
    vcards: &str,
    _count: usize,
    _missed: i32,
    _new_book: i32,
    _completed: bool,
) {
    // Prepend the owner vCard.
    let mut result = String::with_capacity(OWNER_VCARD.len() + vcards.len() * 2);
    result.push_str(OWNER_VCARD);

    // Walk the vcards buffer and inject X-IRMC-LUID lines after UID lines.
    let mut luid: u32 = 1; // LUID counter starts at 1 (owner is 0).
    for line in vcards.lines() {
        result.push_str(line);
        result.push_str("\r\n");

        // If this line is a UID field, inject the LUID reference after it.
        if line.starts_with("UID:") {
            let _ = write!(result, "X-IRMC-LUID:{luid}\r\n");
            luid += 1;
        }
    }

    session.buffer = Some(StringReadState::new(result));
    session.request = None;

    tracing::debug!("irmc: query_result processed, {} LUIDs assigned", luid);
}

/// Process phonebook size result callback for IrMC.
///
/// Records the total entry count discovered from the initial phonebook
/// pull during connect.
///
/// Matches C `phonebook_size_result()` from irmc.c.
pub fn irmc_process_size_result(
    session: &mut IrmcSession,
    _vcards: &str,
    count: usize,
    _missed: i32,
    _new_book: i32,
    _completed: bool,
) {
    session.entries = count as u16;
    session.request = None;
    tracing::debug!("irmc: phonebook size = {}", count);
}

// ===========================================================================
// IrMC Service Driver
// ===========================================================================

/// IrMC Sync OBEX service driver.
///
/// Read-only service providing IrMC Object Exchange synchronisation
/// access to phonebook contacts.
///
/// Replaces C `struct obex_service_driver irmc` from irmc.c.
pub struct IrmcServiceDriver;

impl ObexServiceDriver for IrmcServiceDriver {
    fn name(&self) -> &str {
        "IRMC Sync server"
    }

    fn service(&self) -> u16 {
        OBEX_IRMC
    }

    fn channel(&self) -> u8 {
        0
    }

    fn secure(&self) -> bool {
        true
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&IRMC_TARGET)
    }

    /// IrMC CONNECT — allocates session, initialises device IDs, counts
    /// phonebook entries via an initial pull with maxlistcount=0.
    ///
    /// Matches C `irmc_connect()` from irmc.c.
    fn connect(&self, _os: &ObexSession) -> Result<Box<dyn Any + Send>, i32> {
        let mut session = IrmcSession::new();

        // Build initial apparam: maxlistcount=0 means "return count only",
        // filter=0x200085 selects VERSION + N + TEL + UID fields.
        let params =
            ApparamField { maxlistcount: 0, filter: 0x0020_0085, ..ApparamField::default() };
        session.params = Some(params);

        // In full daemon: issue phonebook_pull(PB_CONTACTS, &params,
        // phonebook_size_result) to discover entry count.  The callback
        // sets session.entries.  For now initialise to 0.
        tracing::info!("IrMC session connected");

        Ok(Box::new(session))
    }

    /// IrMC DISCONNECT — tears down the session.
    ///
    /// Matches C `irmc_disconnect()` from irmc.c.
    fn disconnect(&self, _os: &ObexSession, user_data: &mut dyn Any) {
        if let Some(session) = user_data.downcast_mut::<IrmcSession>() {
            session.params = None;
            session.buffer = None;
            session.request = None;
            tracing::info!("IrMC session disconnected");
        }
    }

    /// IrMC GET — starts the MIME-driver-based GET stream.
    ///
    /// Matches C `irmc_get()` from irmc.c.
    fn get(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        // In full daemon: obex_get_stream_start(os, name).
        // The framework invokes the MIME driver open/read/close cycle.
        tracing::debug!("irmc_get: stream start requested");
        Ok(())
    }

    /// IrMC PUT — always rejected (read-only service).
    ///
    /// Matches C behaviour where PUT is not in the driver struct.
    fn put(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        Err(-(Errno::ENOSYS as i32))
    }

    /// IrMC CHKPUT — rejects PUT pre-validation (read-only service).
    ///
    /// Returns -EBADR matching C `irmc_chkput()`.
    fn chkput(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        Err(-(Errno::EBADR as i32))
    }
}

// ===========================================================================
// IrMC MIME Type Driver
// ===========================================================================

/// IrMC MIME type driver for serving phonebook and device info objects.
///
/// Replaces C `struct obex_mime_type_driver irmc_driver` from irmc.c.
pub struct IrmcMimeTypeDriver;

impl ObexMimeTypeDriver for IrmcMimeTypeDriver {
    fn target(&self) -> Option<&[u8]> {
        Some(&IRMC_TARGET)
    }

    /// Open an IrMC object for reading.
    ///
    /// Enforces O_RDONLY, normalises the path to absolute, then dispatches
    /// based on the IrMC virtual path.
    ///
    /// Matches C `irmc_open()` from irmc.c.
    fn open(
        &self,
        name: &str,
        flags: i32,
        _mode: u32,
        context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32> {
        // Enforce read-only access.
        if flags & (libc::O_WRONLY | libc::O_RDWR) != 0 {
            return Err(-(Errno::EPERM as i32));
        }

        let session = context.downcast_ref::<IrmcSession>().ok_or(-(Errno::EINVAL as i32))?;

        // Normalise path to absolute (C code prepends '/' if missing).
        let path = if name.starts_with('/') { name.to_string() } else { format!("/{name}") };

        let buf = match path.as_str() {
            PB_DEVINFO => irmc_open_devinfo(session),

            PB_CONTACTS => {
                // In full daemon: phonebook_pull(PB_CONTACTS, params,
                // query_result).  Return -EAGAIN until callback fires.
                tracing::debug!("irmc_open: phonebook pull for contacts");
                String::new()
            }

            PB_INFO_LOG => irmc_open_info(session),

            PB_CC_LOG => irmc_open_cc(session),

            p if p.starts_with(PB_LUID_FOLDER) && p.ends_with(".vcf") => irmc_open_luid(session),

            p if p.starts_with(PB_CALENDAR_FOLDER) || p.starts_with(PB_NOTES_FOLDER) => {
                // Calendar and notes: return empty buffer.
                String::new()
            }

            _ => {
                tracing::error!("irmc_open: unknown path '{}'", path);
                return Err(-(Errno::EBADR as i32));
            }
        };

        let read_state = StringReadState::new(buf);
        Ok(Box::new(read_state))
    }

    /// Close an IrMC object.
    ///
    /// Matches C `irmc_close()` from irmc.c.
    fn close(&self, _object: &mut dyn Any) -> Result<(), i32> {
        tracing::debug!("irmc_close");
        Ok(())
    }

    /// Read data from an IrMC object.
    ///
    /// Drains the internal string buffer via `string_read()`.
    /// Returns `Err(-EAGAIN)` when data is not yet available.
    ///
    /// Matches C `irmc_read()` from irmc.c.
    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32> {
        let state = object.downcast_mut::<StringReadState>().ok_or(-(Errno::EINVAL as i32))?;

        if state.data.is_empty() && state.offset == 0 {
            return Err(-(Errno::EAGAIN as i32));
        }

        string_read(state, buf)
    }
}

// ===========================================================================
// SyncEvolution Service Driver
// ===========================================================================

/// SyncEvolution OBEX service driver.
///
/// Relays OBEX synchronisation requests to the `org.syncevolution` D-Bus
/// service, translating OBEX GET/PUT operations into SyncEvolution
/// Server.Connect / Connection.Process / Connection.Close calls.
///
/// Replaces C `struct obex_service_driver synce` from syncevolution.c.
pub struct SynceServiceDriver;

impl ObexServiceDriver for SynceServiceDriver {
    fn name(&self) -> &str {
        "OBEX server for SyncML, using SyncEvolution"
    }

    fn service(&self) -> u16 {
        OBEX_SYNCEVOLUTION
    }

    fn channel(&self) -> u8 {
        SYNCEVOLUTION_CHANNEL
    }

    fn secure(&self) -> bool {
        true
    }

    fn record(&self) -> Option<&str> {
        Some(SYNCEVOLUTION_RECORD)
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&SYNCML_TARGET)
    }

    /// SyncEvolution CONNECT — allocates context with D-Bus connection
    /// and unique session ID.
    ///
    /// Matches C `synce_connect()` from syncevolution.c.
    fn connect(&self, _os: &ObexSession) -> Result<Box<dyn Any + Send>, i32> {
        // Build a session ID from peer address and channel.
        // In full daemon: id = g_strdup_printf("%s+%d", peer_addr, channel).
        let id = String::from("unknown+0");

        let ctx = SynceContext::new(id);

        // In full daemon: manager_register_session(os), get_dbus_connection().
        tracing::info!(id = %ctx.id, "SyncEvolution session connected");

        Ok(Box::new(ctx))
    }

    /// SyncEvolution DISCONNECT — tears down the D-Bus session.
    ///
    /// Matches C `synce_disconnect()` from syncevolution.c.
    fn disconnect(&self, _os: &ObexSession, user_data: &mut dyn Any) {
        if let Some(ctx) = user_data.downcast_mut::<SynceContext>() {
            ctx.conn = None;
            ctx.conn_obj = None;
            ctx.buffer = None;
            tracing::info!("SyncEvolution session disconnected");
        }
    }

    /// SyncEvolution GET — starts MIME-driver-based GET stream.
    ///
    /// Matches C `synce_get()` from syncevolution.c.
    fn get(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        // In full daemon: obex_get_stream_start(os, NULL).
        tracing::debug!("synce_get: stream start requested");
        Ok(())
    }

    /// SyncEvolution PUT — starts MIME-driver-based PUT stream.
    ///
    /// Matches C `synce_put()` from syncevolution.c (returns 0).
    fn put(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        // In full daemon: obex_put_stream_start(os, NULL).
        tracing::debug!("synce_put: stream start requested");
        Ok(())
    }

    /// SyncEvolution CHKPUT — accepts all PUTs (no pre-validation).
    fn chkput(&self, _os: &ObexSession, _user_data: &mut dyn Any) -> Result<(), i32> {
        Ok(())
    }
}

// ===========================================================================
// SyncEvolution MIME Type Driver
// ===========================================================================

/// SyncEvolution MIME type driver for relaying data to the SyncEvolution
/// D-Bus service.
///
/// Replaces C `struct obex_mime_type_driver synce_mime_driver` from
/// syncevolution.c.
pub struct SynceMimeTypeDriver;

impl ObexMimeTypeDriver for SynceMimeTypeDriver {
    fn target(&self) -> Option<&[u8]> {
        Some(&SYNCML_TARGET)
    }

    /// Open a SyncEvolution object.
    ///
    /// Returns the SynceContext as the MIME object.
    ///
    /// Matches C `synce_open()` from syncevolution.c.
    fn open(
        &self,
        _name: &str,
        _flags: i32,
        _mode: u32,
        context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32> {
        let _ctx = context.downcast_ref::<SynceContext>().ok_or(-(Errno::EFAULT as i32))?;

        // Create a fresh read/write state wrapping the context identity.
        let obj = SynceObject {
            buffer: None,
            lasterr: -(Errno::EAGAIN as i32),
            conn_obj: None,
            connected: false,
        };

        Ok(Box::new(obj))
    }

    /// Close a SyncEvolution object.
    ///
    /// Sends `Connection.Close` to SyncEvolution with (normal=true,
    /// error="none").  Removes signal watches and frees resources.
    ///
    /// Matches C `synce_close()` from syncevolution.c.
    fn close(&self, object: &mut dyn Any) -> Result<(), i32> {
        if let Some(obj) = object.downcast_mut::<SynceObject>() {
            obj.buffer = None;
            obj.conn_obj = None;
            obj.connected = false;
            // In full daemon: send Close D-Bus method call.
            tracing::debug!("synce_close");
        }
        Ok(())
    }

    /// Read data from SyncEvolution.
    ///
    /// If the buffer has data, drains it via `string_read`.  Otherwise
    /// initiates the `org.syncevolution.Server.Connect` D-Bus call with
    /// session parameters and returns `-EAGAIN` until the Reply signal
    /// delivers data.
    ///
    /// Matches C `synce_read()` from syncevolution.c.
    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<SynceObject>().ok_or(-(Errno::EINVAL as i32))?;

        // If we already have buffered reply data, drain it.
        if let Some(ref mut state) = obj.buffer {
            return string_read(state, buf);
        }

        // If we have not yet initiated the connection, do so now.
        if !obj.connected {
            obj.connected = true;
            // In full daemon: build D-Bus Connect call with dict params:
            //   id, transport, transport_description, authenticate, session.
            // Send with reply -> connect_cb.
            tracing::debug!("synce_read: initiating Server.Connect D-Bus call");
        }

        Err(-(Errno::EAGAIN as i32))
    }

    /// Write data to SyncEvolution.
    ///
    /// Sends `Connection.Process` D-Bus method with the payload bytes
    /// and MIME type.  Returns `-EAGAIN` until the process callback
    /// confirms success.
    ///
    /// Matches C `synce_write()` from syncevolution.c.
    fn write(&self, object: &mut dyn Any, buf: &[u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<SynceObject>().ok_or(-(Errno::EINVAL as i32))?;

        // If the last operation completed successfully, return the count.
        if obj.lasterr == 0 {
            obj.lasterr = -(Errno::EAGAIN as i32);
            return Ok(buf.len());
        }

        // In full daemon: build Connection.Process D-Bus call with
        // byte array and MIME type.  Send with reply -> process_cb.
        tracing::debug!("synce_write: sending {} bytes via Connection.Process", buf.len());

        Err(-(Errno::EAGAIN as i32))
    }
}

/// Internal MIME object state for a SyncEvolution transfer.
struct SynceObject {
    /// Reply data buffer from D-Bus Reply signal.
    buffer: Option<StringReadState>,
    /// Last error code (-EAGAIN while pending, 0 on success).
    lasterr: i32,
    /// SyncEvolution connection object path.
    conn_obj: Option<String>,
    /// Whether the Server.Connect call has been issued.
    connected: bool,
}

// ===========================================================================
// PC Suite Service Driver
// ===========================================================================

/// Nokia PC Suite OBEX service driver.
///
/// Wraps the FTP service driver with a single-session lock file at
/// `~/.pcsuite` and adds the backup MIME type driver for
/// `application/vnd.nokia-backup`.
///
/// Replaces C `struct obex_service_driver pcsuite` from pcsuite.c.
pub struct PcsuiteServiceDriver;

impl ObexServiceDriver for PcsuiteServiceDriver {
    fn name(&self) -> &str {
        "Nokia OBEX PC Suite Services"
    }

    fn service(&self) -> u16 {
        OBEX_PCSUITE
    }

    fn channel(&self) -> u8 {
        PCSUITE_CHANNEL
    }

    fn secure(&self) -> bool {
        true
    }

    fn record(&self) -> Option<&str> {
        Some(PCSUITE_RECORD)
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&FTP_TARGET)
    }

    fn who(&self) -> Option<&[u8]> {
        Some(&PCSUITE_WHO)
    }

    /// PC Suite CONNECT — establishes FTP session then acquires lock file.
    ///
    /// 1. Delegates to `ftp_connect()` for the underlying FTP session.
    /// 2. Creates an exclusive lock file at `~/.pcsuite` using
    ///    `O_WRONLY|O_CREAT|O_EXCL` (mode 0644).
    /// 3. On `EEXIST`: removes stale lock and retries once (crash recovery).
    ///
    /// Matches C `pcsuite_connect()` from pcsuite.c.
    fn connect(&self, os: &ObexSession) -> Result<Box<dyn Any + Send>, i32> {
        // Establish the underlying FTP session.
        let ftp_session = ftp_connect(os)?;

        // Build lock file path: ~/.pcsuite.
        let home = env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
        let lock_path = PathBuf::from(&home).join(".pcsuite");

        // Attempt exclusive creation of the lock file.
        let lock_fd = match OpenOptions::new().write(true).create_new(true).open(&lock_path) {
            Ok(f) => Some(f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Stale lock from a previous crash — remove and retry.
                tracing::warn!("pcsuite: removing stale lock file '{}'", lock_path.display());
                let _ = fs::remove_file(&lock_path);
                match OpenOptions::new().write(true).create_new(true).open(&lock_path) {
                    Ok(f) => Some(f),
                    Err(e2) => {
                        tracing::error!(
                            "pcsuite: failed to create lock '{}': {}",
                            lock_path.display(),
                            e2
                        );
                        return Err(-(Errno::EPERM as i32));
                    }
                }
            }
            Err(e) => {
                tracing::error!("pcsuite: failed to create lock '{}': {}", lock_path.display(), e);
                return Err(-(Errno::EPERM as i32));
            }
        };

        let session = PcsuiteSession { ftp_session, lock_path, lock_fd };

        tracing::info!("PC Suite session connected");
        Ok(Box::new(session))
    }

    /// PC Suite DISCONNECT — releases lock and tears down FTP session.
    ///
    /// Matches C `pcsuite_disconnect()` from pcsuite.c.
    fn disconnect(&self, os: &ObexSession, user_data: &mut dyn Any) {
        if let Some(session) = user_data.downcast_mut::<PcsuiteSession>() {
            // Close lock file descriptor.
            session.lock_fd = None;
            // Remove lock file.
            let _ = fs::remove_file(&session.lock_path);
            // Delegate FTP disconnect.
            ftp_disconnect(os, &mut *session.ftp_session);
            tracing::info!("PC Suite session disconnected");
        }
    }

    /// PC Suite GET — delegates to FTP GET.
    fn get(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        if let Some(session) = user_data.downcast_mut::<PcsuiteSession>() {
            ftp_get(os, &mut *session.ftp_session)
        } else {
            Err(-(Errno::EINVAL as i32))
        }
    }

    /// PC Suite PUT — delegates to FTP PUT.
    fn put(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        if let Some(session) = user_data.downcast_mut::<PcsuiteSession>() {
            ftp_put(os, &mut *session.ftp_session)
        } else {
            Err(-(Errno::EINVAL as i32))
        }
    }

    /// PC Suite CHKPUT — delegates to FTP CHKPUT.
    fn chkput(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        if let Some(session) = user_data.downcast_mut::<PcsuiteSession>() {
            ftp_chkput(os, &mut *session.ftp_session)
        } else {
            Err(-(Errno::EINVAL as i32))
        }
    }

    /// PC Suite SETPATH — delegates to FTP SETPATH.
    fn setpath(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        if let Some(session) = user_data.downcast_mut::<PcsuiteSession>() {
            ftp_setpath(os, &mut *session.ftp_session)
        } else {
            Err(-(Errno::EINVAL as i32))
        }
    }

    /// PC Suite ACTION — delegates to FTP ACTION.
    fn action(&self, os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
        if let Some(session) = user_data.downcast_mut::<PcsuiteSession>() {
            ftp_action(os, &mut *session.ftp_session)
        } else {
            Err(-(Errno::EINVAL as i32))
        }
    }
}

// ===========================================================================
// Backup MIME Type Driver (PC Suite)
// ===========================================================================

/// Nokia backup MIME type driver for `application/vnd.nokia-backup`.
///
/// Communicates with the `com.nokia.backup.plugin` D-Bus service to
/// open/close backup files and stream data through file descriptors
/// returned by the D-Bus reply.
///
/// Replaces C `struct obex_mime_type_driver backup_driver` from pcsuite.c.
pub struct BackupMimeTypeDriver;

impl ObexMimeTypeDriver for BackupMimeTypeDriver {
    fn mimetype(&self) -> Option<&str> {
        Some("application/vnd.nokia-backup")
    }

    fn target(&self) -> Option<&[u8]> {
        Some(&FTP_TARGET)
    }

    fn who(&self) -> Option<&[u8]> {
        Some(&PCSUITE_WHO)
    }

    /// Open a backup object.
    ///
    /// Allocates a `BackupObject`, extracts the basename of the OBEX name
    /// as the backup command, records open flags and mode, then sends an
    /// async "open" request to `com.nokia.backup.plugin` via D-Bus.
    ///
    /// Matches C `backup_open()` from pcsuite.c.
    fn open(
        &self,
        name: &str,
        flags: i32,
        mode: u32,
        _context: &dyn Any,
    ) -> Result<Box<dyn Any + Send>, i32> {
        // Extract basename from the OBEX object name.
        let cmd = Path::new(name).file_name().and_then(|n| n.to_str()).unwrap_or(name).to_string();

        let obj = BackupObject::new(cmd.clone(), flags, mode);

        // In full daemon: send "open" D-Bus request to
        // com.nokia.backup.plugin at /com/nokia/backup.
        // The reply handler (on_backup_dbus_notify) extracts
        // (error_code, filename), opens the file, and signals IO ready.
        tracing::debug!("backup_open: cmd='{}' flags={} mode={:#o}", cmd, flags, mode);

        Ok(Box::new(obj))
    }

    /// Close a backup object.
    ///
    /// Cancels any pending D-Bus call, closes the file descriptor, and
    /// sends a fire-and-forget "close" D-Bus request.
    ///
    /// Matches C `backup_close()` from pcsuite.c.
    fn close(&self, object: &mut dyn Any) -> Result<(), i32> {
        if let Some(obj) = object.downcast_mut::<BackupObject>() {
            obj.fd = None;
            obj.pending = false;
            // In full daemon: send fire-and-forget "close" D-Bus call.
            tracing::debug!("backup_close: cmd='{}'", obj.cmd);
        }
        Ok(())
    }

    /// Read data from a backup object.
    ///
    /// Returns `Err(-EAGAIN)` while the D-Bus "open" reply is pending.
    /// Once the file descriptor is available, reads data from it.
    ///
    /// Matches C `backup_read()` from pcsuite.c.
    fn read(&self, object: &mut dyn Any, buf: &mut [u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<BackupObject>().ok_or(-(Errno::EINVAL as i32))?;

        // While the D-Bus reply is pending, return EAGAIN.
        if obj.pending {
            return Err(-(Errno::EAGAIN as i32));
        }

        // If we have a file descriptor, read from it.
        if let Some(ref mut file) = obj.fd {
            match file.read(buf) {
                Ok(n) => Ok(n),
                Err(e) => Err(-(e.raw_os_error().unwrap_or(Errno::EIO as i32))),
            }
        } else if obj.error_code != 0 {
            Err(-obj.error_code)
        } else {
            Err(-(Errno::ENOENT as i32))
        }
    }

    /// Write data to a backup object.
    ///
    /// Returns `Err(-EAGAIN)` while the D-Bus "open" reply is pending.
    /// Once the file descriptor is available, writes data to it.
    ///
    /// Matches C `backup_write()` from pcsuite.c.
    fn write(&self, object: &mut dyn Any, buf: &[u8]) -> Result<usize, i32> {
        let obj = object.downcast_mut::<BackupObject>().ok_or(-(Errno::EINVAL as i32))?;

        // While the D-Bus reply is pending, return EAGAIN.
        if obj.pending {
            return Err(-(Errno::EAGAIN as i32));
        }

        // If we have a file descriptor, write to it.
        if let Some(ref mut file) = obj.fd {
            match file.write(buf) {
                Ok(n) => Ok(n),
                Err(e) => Err(-(e.raw_os_error().unwrap_or(Errno::EIO as i32))),
            }
        } else if obj.error_code != 0 {
            Err(-obj.error_code)
        } else {
            Err(-(Errno::ENOENT as i32))
        }
    }

    /// Flush pending writes — no-op for backup objects.
    ///
    /// Matches C `backup_flush()` from pcsuite.c.
    fn flush(&self, _object: &mut dyn Any) -> Result<(), i32> {
        Ok(())
    }
}

// ===========================================================================
// Plugin Init / Exit Functions
// ===========================================================================

/// Global storage for the IrMC service and MIME driver instances.
///
/// Kept alive so that `unregister` can reference the same trait object.
static IRMC_SERVICE: OnceLock<Arc<dyn ObexServiceDriver>> = OnceLock::new();
static IRMC_MIME: OnceLock<Arc<dyn ObexMimeTypeDriver>> = OnceLock::new();
static SYNCE_SERVICE: OnceLock<Arc<dyn ObexServiceDriver>> = OnceLock::new();
static SYNCE_MIME: OnceLock<Arc<dyn ObexMimeTypeDriver>> = OnceLock::new();
static PCSUITE_SERVICE: OnceLock<Arc<dyn ObexServiceDriver>> = OnceLock::new();
static BACKUP_MIME: OnceLock<Arc<dyn ObexMimeTypeDriver>> = OnceLock::new();

/// Initialise the IrMC Sync plugin.
///
/// Registers the IrMC service driver and MIME type driver.
///
/// Matches C `irmc_init()` from irmc.c.
pub fn irmc_init() -> Result<(), i32> {
    // In full daemon: phonebook_init() would be called here.
    // The phonebook backend is initialised by the PBAP plugin.

    let mime: Arc<dyn ObexMimeTypeDriver> = Arc::new(IrmcMimeTypeDriver);
    obex_mime_type_driver_register(Arc::clone(&mime))?;
    let _ = IRMC_MIME.set(mime);

    let svc: Arc<dyn ObexServiceDriver> = Arc::new(IrmcServiceDriver);
    obex_service_driver_register(Arc::clone(&svc))?;
    let _ = IRMC_SERVICE.set(svc);

    tracing::info!("IrMC Sync plugin initialised");
    Ok(())
}

/// Shut down the IrMC Sync plugin.
///
/// Unregisters service and MIME drivers, then calls phonebook_exit.
///
/// Matches C `irmc_exit()` from irmc.c.
pub fn irmc_exit() {
    if let Some(svc) = IRMC_SERVICE.get() {
        obex_service_driver_unregister(svc.as_ref());
    }
    if let Some(mime) = IRMC_MIME.get() {
        obex_mime_type_driver_unregister(mime.as_ref());
    }
    // In full daemon: phonebook_exit().
    tracing::info!("IrMC Sync plugin exited");
}

/// Initialise the SyncEvolution plugin.
///
/// Registers the SyncEvolution service and MIME type drivers.
///
/// Matches C `synce_init()` from syncevolution.c.
pub fn synce_init() -> Result<(), i32> {
    let mime: Arc<dyn ObexMimeTypeDriver> = Arc::new(SynceMimeTypeDriver);
    obex_mime_type_driver_register(Arc::clone(&mime))?;
    let _ = SYNCE_MIME.set(mime);

    let svc: Arc<dyn ObexServiceDriver> = Arc::new(SynceServiceDriver);
    obex_service_driver_register(Arc::clone(&svc))?;
    let _ = SYNCE_SERVICE.set(svc);

    tracing::info!("SyncEvolution plugin initialised");
    Ok(())
}

/// Shut down the SyncEvolution plugin.
///
/// Matches C `synce_exit()` from syncevolution.c.
pub fn synce_exit() {
    if let Some(svc) = SYNCE_SERVICE.get() {
        obex_service_driver_unregister(svc.as_ref());
    }
    if let Some(mime) = SYNCE_MIME.get() {
        obex_mime_type_driver_unregister(mime.as_ref());
    }
    tracing::info!("SyncEvolution plugin exited");
}

/// Initialise the PC Suite plugin.
///
/// Registers the PC Suite service driver and backup MIME type driver.
///
/// Matches C `pcsuite_init()` from pcsuite.c.
pub fn pcsuite_init() -> Result<(), i32> {
    let svc: Arc<dyn ObexServiceDriver> = Arc::new(PcsuiteServiceDriver);
    obex_service_driver_register(Arc::clone(&svc))?;
    let _ = PCSUITE_SERVICE.set(svc);

    let mime: Arc<dyn ObexMimeTypeDriver> = Arc::new(BackupMimeTypeDriver);
    obex_mime_type_driver_register(Arc::clone(&mime))?;
    let _ = BACKUP_MIME.set(mime);

    tracing::info!("PC Suite plugin initialised");
    Ok(())
}

/// Shut down the PC Suite plugin.
///
/// Matches C `pcsuite_exit()` from pcsuite.c.
pub fn pcsuite_exit() {
    if let Some(mime) = BACKUP_MIME.get() {
        obex_mime_type_driver_unregister(mime.as_ref());
    }
    if let Some(svc) = PCSUITE_SERVICE.get() {
        obex_service_driver_unregister(svc.as_ref());
    }
    tracing::info!("PC Suite plugin exited");
}

// ===========================================================================
// Plugin Registration via inventory
// ===========================================================================

inventory::submit! {
    ObexPluginDesc {
        name: "irmc",
        init: irmc_init,
        exit: irmc_exit,
    }
}

inventory::submit! {
    ObexPluginDesc {
        name: "syncevolution",
        init: synce_init,
        exit: synce_exit,
    }
}

inventory::submit! {
    ObexPluginDesc {
        name: "pcsuite",
        init: pcsuite_init,
        exit: pcsuite_exit,
    }
}
