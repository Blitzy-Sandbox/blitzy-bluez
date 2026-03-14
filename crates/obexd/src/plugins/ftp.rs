//! FTP service driver — stub awaiting full implementation.
//!
//! Provides the functions re-exported by the plugins module root.
//! This file will be replaced by the full implementation agent.

use crate::obex::session::ObexSession;
use std::any::Any;

/// Connect handler for FTP service.
pub fn ftp_connect(os: &ObexSession) -> Result<Box<dyn Any + Send>, i32> {
    let _ = os;
    Ok(Box::new(()))
}

/// Disconnect handler for FTP service.
pub fn ftp_disconnect(os: &ObexSession, user_data: &mut dyn Any) {
    let _ = (os, user_data);
}

/// GET handler for FTP service.
pub fn ftp_get(os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
    let _ = (os, user_data);
    Err(-38) // ENOSYS
}

/// PUT handler for FTP service.
pub fn ftp_put(os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
    let _ = (os, user_data);
    Err(-38) // ENOSYS
}

/// Pre-PUT validation for FTP service.
pub fn ftp_chkput(os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
    let _ = (os, user_data);
    Err(-38) // ENOSYS
}

/// SETPATH handler for FTP service.
pub fn ftp_setpath(os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
    let _ = (os, user_data);
    Err(-38) // ENOSYS
}

/// ACTION handler for FTP service (copy/move).
pub fn ftp_action(os: &ObexSession, user_data: &mut dyn Any) -> Result<(), i32> {
    let _ = (os, user_data);
    Err(-38) // ENOSYS
}
