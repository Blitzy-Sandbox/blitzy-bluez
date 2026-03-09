// SPDX-License-Identifier: GPL-2.0-or-later
//
// GATT (Generic Attribute Profile) implementation.
// Replaces src/shared/gatt-db.c, gatt-helpers.c, gatt-client.c, gatt-server.c

pub mod db;
pub mod helpers;
pub mod client;
pub mod server;

// Well-known GATT UUIDs (16-bit values)
pub const GATT_PRIM_SVC_UUID: u16 = 0x2800;
pub const GATT_SND_SVC_UUID: u16 = 0x2801;
pub const GATT_INCLUDE_UUID: u16 = 0x2802;
pub const GATT_CHARAC_UUID: u16 = 0x2803;

// GATT descriptor UUIDs
pub const GATT_CHARAC_EXT_PROPER_UUID: u16 = 0x2900;
pub const GATT_CHARAC_USER_DESC_UUID: u16 = 0x2901;
pub const GATT_CLIENT_CHARAC_CFG_UUID: u16 = 0x2902;
pub const GATT_SERVER_CHARAC_CFG_UUID: u16 = 0x2903;
pub const GATT_CHARAC_FMT_UUID: u16 = 0x2904;
pub const GATT_CHARAC_AGREG_FMT_UUID: u16 = 0x2905;

// GATT service UUIDs
pub const GATT_GAP_UUID: u16 = 0x1800;
pub const GATT_SVC_UUID: u16 = 0x1801;

// Service Changed characteristic
pub const GATT_SVC_CHNGD_UUID: u16 = 0x2A05;

// Client/Server Supported Features
pub const GATT_CLIENT_FEATURES_UUID: u16 = 0x2B29;
pub const GATT_SERVER_FEATURES_UUID: u16 = 0x2B3A;
pub const GATT_DB_HASH_UUID: u16 = 0x2B2A;

// Characteristic properties
pub const BT_GATT_CHRC_PROP_BROADCAST: u8 = 0x01;
pub const BT_GATT_CHRC_PROP_READ: u8 = 0x02;
pub const BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP: u8 = 0x04;
pub const BT_GATT_CHRC_PROP_WRITE: u8 = 0x08;
pub const BT_GATT_CHRC_PROP_NOTIFY: u8 = 0x10;
pub const BT_GATT_CHRC_PROP_INDICATE: u8 = 0x20;
pub const BT_GATT_CHRC_PROP_AUTH: u8 = 0x40;
pub const BT_GATT_CHRC_PROP_EXT_PROP: u8 = 0x80;
