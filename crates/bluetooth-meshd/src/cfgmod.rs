// SPDX-License-Identifier: GPL-2.0-or-later
//
// Configuration model — replaces mesh/cfgmod-server.c
//
// Handles configuration model messages (opcodes) for a mesh node.

/// Configuration model opcodes (Mesh Profile spec section 4.3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[allow(dead_code)]
pub enum ConfigOpcode {
    AppKeyAdd = 0x00,
    AppKeyUpdate = 0x01,
    CompositionDataStatus = 0x02,
    ModelPublicationSet = 0x03,
    // 2-byte opcodes (0x80xx)
    AppKeyDelete = 0x8000,
    AppKeyGet = 0x8001,
    AppKeyList = 0x8002,
    AppKeyStatus = 0x8003,
    CompositionDataGet = 0x8008,
    BeaconGet = 0x8009,
    BeaconSet = 0x800A,
    BeaconStatus = 0x800B,
    DefaultTtlGet = 0x800C,
    DefaultTtlSet = 0x800D,
    DefaultTtlStatus = 0x800E,
    FriendGet = 0x800F,
    FriendSet = 0x8010,
    FriendStatus = 0x8011,
    GattProxyGet = 0x8012,
    GattProxySet = 0x8013,
    GattProxyStatus = 0x8014,
    RelayGet = 0x8026,
    RelaySet = 0x8027,
    RelayStatus = 0x8028,
    ModelPublicationGet = 0x8018,
    ModelPublicationStatus = 0x8019,
    ModelSubscriptionAdd = 0x801B,
    ModelSubscriptionDelete = 0x801C,
    ModelSubscriptionStatus = 0x801F,
    NetKeyAdd = 0x8040,
    NetKeyDelete = 0x8041,
    NetKeyGet = 0x8042,
    NetKeyList = 0x8043,
    NetKeyStatus = 0x8044,
    NetKeyUpdate = 0x8045,
    NodeIdentityGet = 0x8046,
    NodeIdentitySet = 0x8047,
    NodeIdentityStatus = 0x8048,
    NodeReset = 0x8049,
    NodeResetStatus = 0x804A,
    ModelAppBind = 0x803D,
    ModelAppUnbind = 0x803F,
    ModelAppStatus = 0x803E,
}

/// Status codes returned in configuration model status messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfigStatus {
    Success = 0x00,
    InvalidAddress = 0x01,
    InvalidModel = 0x02,
    InvalidAppKeyIndex = 0x03,
    InvalidNetKeyIndex = 0x04,
    InsufficientResources = 0x05,
    KeyIndexAlreadyStored = 0x06,
    InvalidPublishParameters = 0x07,
    NotASubscribeModel = 0x08,
    StorageFailure = 0x09,
    FeatureNotSupported = 0x0A,
    CannotUpdate = 0x0B,
    CannotRemove = 0x0C,
    CannotBind = 0x0D,
    TemporarilyUnableToChangeState = 0x0E,
    CannotSet = 0x0F,
    UnspecifiedError = 0x10,
    InvalidBinding = 0x11,
}

/// Configuration server model handler.
#[derive(Debug, Default)]
pub struct ConfigServer {
    /// Whether secure network beacon is enabled.
    pub beacon_enabled: bool,
    /// Default TTL.
    pub default_ttl: u8,
    /// Whether relay is enabled.
    pub relay_enabled: bool,
    /// Relay retransmit count.
    pub relay_retransmit_count: u8,
    /// Relay retransmit interval steps.
    pub relay_retransmit_interval: u8,
    /// Whether friend feature is enabled.
    pub friend_enabled: bool,
    /// Whether GATT proxy is enabled.
    pub proxy_enabled: bool,
}

impl ConfigServer {
    pub fn new() -> Self {
        Self {
            beacon_enabled: true,
            default_ttl: 7,
            relay_enabled: true,
            relay_retransmit_count: 2,
            relay_retransmit_interval: 1,
            friend_enabled: false,
            proxy_enabled: false,
        }
    }

    /// Handle a configuration model message. Returns a response PDU.
    pub fn handle_message(&mut self, opcode: ConfigOpcode, _data: &[u8]) -> Vec<u8> {
        match opcode {
            ConfigOpcode::BeaconGet => {
                vec![
                    (ConfigOpcode::BeaconStatus as u16 >> 8) as u8,
                    (ConfigOpcode::BeaconStatus as u16 & 0xff) as u8,
                    u8::from(self.beacon_enabled),
                ]
            }
            ConfigOpcode::BeaconSet => {
                if let Some(&val) = _data.first() {
                    self.beacon_enabled = val != 0;
                }
                vec![
                    (ConfigOpcode::BeaconStatus as u16 >> 8) as u8,
                    (ConfigOpcode::BeaconStatus as u16 & 0xff) as u8,
                    u8::from(self.beacon_enabled),
                ]
            }
            ConfigOpcode::DefaultTtlGet => {
                vec![
                    (ConfigOpcode::DefaultTtlStatus as u16 >> 8) as u8,
                    (ConfigOpcode::DefaultTtlStatus as u16 & 0xff) as u8,
                    self.default_ttl,
                ]
            }
            ConfigOpcode::DefaultTtlSet => {
                if let Some(&val) = _data.first() {
                    if val != 1 && val <= 127 {
                        self.default_ttl = val;
                    }
                }
                vec![
                    (ConfigOpcode::DefaultTtlStatus as u16 >> 8) as u8,
                    (ConfigOpcode::DefaultTtlStatus as u16 & 0xff) as u8,
                    self.default_ttl,
                ]
            }
            ConfigOpcode::RelayGet => {
                vec![
                    (ConfigOpcode::RelayStatus as u16 >> 8) as u8,
                    (ConfigOpcode::RelayStatus as u16 & 0xff) as u8,
                    u8::from(self.relay_enabled),
                    (self.relay_retransmit_count & 0x07)
                        | ((self.relay_retransmit_interval & 0x1f) << 3),
                ]
            }
            _ => {
                // Unhandled opcode — return empty for now
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beacon_get_set() {
        let mut server = ConfigServer::new();
        assert!(server.beacon_enabled);

        let resp = server.handle_message(ConfigOpcode::BeaconSet, &[0]);
        assert_eq!(resp.last(), Some(&0)); // disabled
        assert!(!server.beacon_enabled);

        let resp = server.handle_message(ConfigOpcode::BeaconGet, &[]);
        assert_eq!(resp.last(), Some(&0));
    }

    #[test]
    fn test_default_ttl_get_set() {
        let mut server = ConfigServer::new();
        assert_eq!(server.default_ttl, 7);

        server.handle_message(ConfigOpcode::DefaultTtlSet, &[10]);
        assert_eq!(server.default_ttl, 10);

        // TTL=1 is invalid, should not change
        server.handle_message(ConfigOpcode::DefaultTtlSet, &[1]);
        assert_eq!(server.default_ttl, 10);
    }
}
