// SPDX-License-Identifier: GPL-2.0-or-later
//
// BlueZ shared utility module — Rust implementation

//! Utility modules for the BlueZ shared library.
//!
//! This module provides foundational data structures, endianness helpers,
//! Bluetooth advertising data construction/parsing, UUID handling, and
//! ring buffer implementations used throughout the BlueZ stack.
//!
//! # Submodules
//!
//! - [`ad`] — Advertising Data (AD) and Scan Response Data (SD) builder/parser,
//!   replacing C `struct bt_ad` from `src/shared/ad.c`.
//! - [`eir`] — Extended Inquiry Response (EIR) parsing and generation,
//!   replacing C `src/eir.c`.
//! - [`endian`] — Endianness conversion, unaligned byte access, [`IoBuf`]
//!   read/write buffer, LTV (Length-Type-Value) helpers, iovec utilities,
//!   string utilities (strdelimit, strsuffix, strstrip, strnlen_utf8,
//!   stris_utf8, str_to_utf8), hex dump, and getrandom. Replaces C
//!   `src/shared/util.c` / `src/shared/util.h`.
//! - [`queue`] — Generic queue wrapping `VecDeque` (replaces C `struct queue`
//!   from `src/shared/queue.c`).
//! - [`ringbuf`] — Fixed-capacity circular ring buffer for protocol packet
//!   buffering (replaces C `struct ringbuf` from `src/shared/ringbuf.c`).
//! - [`uuid`] — Bluetooth UUID normalization, SIG-assigned UUID lookup tables
//!   (~915 UUID16 entries, ~80 UUID128 entries, ~345 appearance entries),
//!   and string conversion functions. Replaces the UUID portions of
//!   `src/shared/util.c`.

// ---------------------------------------------------------------------------
// Submodule declarations (alphabetical order)
// ---------------------------------------------------------------------------

pub mod ad;
pub mod eir;
pub mod endian;
pub mod queue;
pub mod ringbuf;
pub mod uuid;

// ---------------------------------------------------------------------------
// Re-exports — Primary types for ergonomic access
// ---------------------------------------------------------------------------
//
// These re-exports allow callers to write `use bluez_shared::util::Queue;`
// instead of the longer `use bluez_shared::util::queue::Queue;`.

pub use self::ad::BtAd;
pub use self::eir::EirData;
pub use self::endian::IoBuf;
pub use self::queue::Queue;
pub use self::ringbuf::RingBuf;
pub use self::uuid::BtUuid;

// ---------------------------------------------------------------------------
// Re-exports — Endian conversion and unaligned access functions
// ---------------------------------------------------------------------------

pub use self::endian::{
    get_be16, get_be32, get_be64, get_le16, get_le32, get_le64, get_u8, put_be16, put_be32,
    put_be64, put_le16, put_le32, put_le64, put_u8,
};

// ---------------------------------------------------------------------------
// Re-exports — LTV (Length-Type-Value) helpers
// ---------------------------------------------------------------------------

pub use self::endian::{ltv_foreach, ltv_push};

// ---------------------------------------------------------------------------
// Re-exports — General utility functions (hex dump, random, bitfield, strings)
// ---------------------------------------------------------------------------

pub use self::endian::{
    bitfield_has_parity, getrandom, hexdump, str_to_utf8, strdelimit, stris_utf8, strnlen_utf8,
    strstrip, strsuffix,
};

// ---------------------------------------------------------------------------
// Re-exports — UUID lookup functions
// ---------------------------------------------------------------------------

pub use self::uuid::{
    bt_appear_to_str, bt_uuid16_to_str, bt_uuid32_to_str, bt_uuid128_to_str, bt_uuidstr_to_str,
};

// ---------------------------------------------------------------------------
// Tests — Verify re-exports are accessible and functional
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify all primary type re-exports are accessible at the module level.
    #[test]
    fn test_type_reexports_accessible() {
        // Queue<T>
        let mut q = Queue::<u32>::new();
        q.push_tail(42);
        assert_eq!(q.pop_head(), Some(42));
        assert!(q.is_empty());

        // RingBuf
        let rb = RingBuf::new(16).unwrap();
        assert_eq!(rb.capacity(), 16);
        assert!(rb.is_empty());

        // IoBuf
        let mut iobuf = IoBuf::new();
        iobuf.push_u8(0xAB);
        assert_eq!(iobuf.len(), 1);

        // BtAd
        let ad_obj = BtAd::new();
        assert!(ad_obj.is_empty());

        // EirData via eir::eir_parse
        let eir_data = eir::eir_parse(&[]);
        assert!(eir_data.name.is_none());

        // BtUuid
        let uuid_val = BtUuid::from_u16(0x1800);
        assert!(matches!(uuid_val, BtUuid::Uuid16(0x1800)));
    }

    /// Verify all endian read/write function re-exports work correctly.
    #[test]
    fn test_endian_reexports() {
        assert_eq!(get_le16(&[0x01, 0x02]), 0x0201);
        assert_eq!(get_be16(&[0x01, 0x02]), 0x0102);
        assert_eq!(get_le32(&[0x04, 0x03, 0x02, 0x01]), 0x01020304);
        assert_eq!(get_be32(&[0x04, 0x03, 0x02, 0x01]), 0x04030201);
        assert_eq!(get_le64(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]), 0x0102030405060708);
        assert_eq!(get_be64(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]), 0x0807060504030201);
        assert_eq!(get_u8(&[0xFF]), 0xFF);

        let mut buf2 = [0u8; 2];
        put_le16(0x0102, &mut buf2);
        assert_eq!(buf2, [0x02, 0x01]);
        put_be16(0x0102, &mut buf2);
        assert_eq!(buf2, [0x01, 0x02]);

        let mut buf4 = [0u8; 4];
        put_le32(0x01020304, &mut buf4);
        assert_eq!(buf4, [0x04, 0x03, 0x02, 0x01]);
        put_be32(0x01020304, &mut buf4);
        assert_eq!(buf4, [0x01, 0x02, 0x03, 0x04]);

        let mut buf8 = [0u8; 8];
        put_le64(0x0102030405060708, &mut buf8);
        assert_eq!(buf8, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        put_be64(0x0102030405060708, &mut buf8);
        assert_eq!(buf8, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        put_u8(0xAA, &mut [0u8; 1]);
    }

    /// Verify LTV helpers round-trip correctly via re-exports.
    #[test]
    fn test_ltv_reexports() {
        let mut output = IoBuf::new();
        ltv_push(&mut output, 0x01, &[0xAA, 0xBB]);

        let data_ltv = output.as_bytes().to_vec();
        let mut found = false;
        ltv_foreach(&data_ltv, |t, d| {
            assert_eq!(t, 0x01);
            assert_eq!(d, &[0xAA, 0xBB]);
            found = true;
            true
        });
        assert!(found);
    }

    /// Verify all general utility function re-exports.
    #[test]
    fn test_utility_reexports() {
        // hexdump
        let mut lines = Vec::new();
        hexdump("test ", &[0x01, 0x02], |line: &str| {
            lines.push(line.to_string());
        });
        assert!(!lines.is_empty());

        // bitfield_has_parity
        assert!(bitfield_has_parity(0));

        // strdelimit
        assert_eq!(strdelimit("a.b.c", ".", '_'), "a_b_c");

        // strsuffix
        assert!(strsuffix("hello.txt", ".txt"));
        assert!(!strsuffix("hello.txt", ".rs"));

        // strstrip
        assert_eq!(strstrip("  hi  "), "hi");

        // strnlen_utf8
        assert_eq!(strnlen_utf8("abc", 2), 2);

        // stris_utf8
        assert!(stris_utf8(b"abc"));
        assert!(!stris_utf8(&[0xFF, 0xFE]));

        // str_to_utf8
        assert_eq!(str_to_utf8(b"hello"), "hello");
    }

    /// Verify UUID lookup function re-exports.
    #[test]
    fn test_uuid_reexports() {
        assert_eq!(bt_uuid16_to_str(0x0001), "SDP");
        assert_eq!(bt_uuid32_to_str(0x00000001), "SDP");
        let s = bt_appear_to_str(0);
        assert!(!s.is_empty());
    }

    /// Verify all submodules are accessible through pub mod declarations.
    #[test]
    fn test_submodule_access() {
        let _ = ad::BtAd::new();
        let _ = eir::eir_parse(&[]);
        let _ = endian::IoBuf::new();
        let _ = queue::Queue::<i32>::new();
        let _ = ringbuf::RingBuf::new(8);
        let _ = uuid::BtUuid::from_u16(0x0001);
    }
}
