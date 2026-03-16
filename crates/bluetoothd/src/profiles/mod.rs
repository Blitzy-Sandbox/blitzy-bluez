//! Bluetooth profile plugin implementations.
//!
//! Profile modules provide Bluetooth protocol implementations registered
//! as plugins with the daemon's profile framework.

pub mod audio;
pub mod battery;
pub mod deviceinfo;
pub mod gap;
pub mod input;
pub mod midi;
pub mod network;
pub mod ranging;
pub mod scanparam;
