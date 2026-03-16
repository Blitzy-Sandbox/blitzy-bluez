//! Bluetooth profile plugin implementations.
//!
//! Profile modules provide Bluetooth protocol implementations registered
//! as plugins with the daemon's profile framework.

pub mod audio;
pub mod gap;
pub mod midi;
pub mod ranging;
pub mod scanparam;
