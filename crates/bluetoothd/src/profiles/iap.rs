// SPDX-License-Identifier: GPL-2.0-or-later
//
// iAP (MFi) profile implementation (~454 LOC C).
//
// Apple iAP (iPod Accessory Protocol) stub — enough structure to detect
// and register with Apple MFi devices over RFCOMM/L2CAP.

/// iAP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IapVersion {
    /// iAP1 (legacy 30-pin protocol).
    Iap1,
    /// iAP2 (Lightning / Bluetooth).
    Iap2,
}

/// iAP session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IapState {
    #[default]
    Idle,
    Identifying,
    Authenticated,
    SessionOpen,
    Disconnecting,
}


/// iAP transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IapTransport {
    Rfcomm,
    L2cap,
}

/// iAP profile plugin.
#[derive(Debug)]
pub struct IapProfile {
    pub version: IapVersion,
    pub state: IapState,
    pub transport: IapTransport,
    /// Apple device model identifier string.
    pub model_identifier: Option<String>,
    /// Firmware version reported by accessory.
    pub firmware_version: Option<String>,
    /// Protocol tokens supported by the accessory.
    pub supported_protocols: Vec<String>,
    /// Session identifier when a session is open.
    pub session_id: Option<u16>,
}

impl IapProfile {
    pub fn new(version: IapVersion) -> Self {
        Self {
            version,
            state: IapState::default(),
            transport: IapTransport::Rfcomm,
            model_identifier: None,
            firmware_version: None,
            supported_protocols: Vec::new(),
            session_id: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iap_defaults() {
        let iap = IapProfile::new(IapVersion::Iap2);
        assert_eq!(iap.state, IapState::Idle);
        assert_eq!(iap.version, IapVersion::Iap2);
        assert!(iap.supported_protocols.is_empty());
    }

    #[test]
    fn test_iap_transport() {
        let iap = IapProfile::new(IapVersion::Iap1);
        assert_eq!(iap.transport, IapTransport::Rfcomm);
    }
}
