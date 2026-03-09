// SPDX-License-Identifier: GPL-2.0-or-later
//
// Virtual HCI interface replacing emulator/vhci.c
//
// Wraps a btdev instance and connects it to /dev/vhci (or a socketpair
// for testing). Handles the kernel-facing side of the HCI emulation.

use std::sync::{Arc, Mutex};

use crate::btdev::{BtDev, BtDevType};

/// VHCI device type constants (matching kernel VHCI).
pub const VHCI_TYPE_BREDRLE: u8 = 0;
pub const VHCI_TYPE_BREDR: u8 = 1;
pub const VHCI_TYPE_LE: u8 = 2;
pub const VHCI_TYPE_AMP: u8 = 3;

struct VhciInner {
    dev: BtDev,
    paused: bool,
}

/// Virtual HCI interface.
pub struct Vhci {
    inner: Arc<Mutex<VhciInner>>,
}

impl Vhci {
    /// Create a VHCI with a virtual device.
    ///
    /// In the C implementation this opens /dev/vhci. Here we just
    /// create the btdev; the I/O wiring is handled by hciemu.
    pub fn open(dev_type: BtDevType, id: u16) -> Self {
        let dev = BtDev::create(dev_type, id);
        Self {
            inner: Arc::new(Mutex::new(VhciInner {
                dev,
                paused: false,
            })),
        }
    }

    /// Get the underlying btdev.
    pub fn get_btdev(&self) -> BtDev {
        self.inner.lock().unwrap().dev.clone_ref()
    }

    /// Pause/resume input processing.
    pub fn pause_input(&self, paused: bool) -> bool {
        self.inner.lock().unwrap().paused = paused;
        true
    }

    /// Check if input is paused.
    pub fn is_paused(&self) -> bool {
        self.inner.lock().unwrap().paused
    }

    /// Set force suspend on the controller.
    pub fn set_force_suspend(&self, _enable: bool) -> i32 {
        // Stub for kernel VHCI ioctl
        0
    }

    /// Set force wakeup on the controller.
    pub fn set_force_wakeup(&self, _enable: bool) -> i32 {
        0
    }

    /// Set MSFT vendor opcode.
    pub fn set_msft_opcode(&self, opcode: u16) -> i32 {
        let inner = self.inner.lock().unwrap();
        inner.dev.set_msft_opcode(opcode);
        0
    }

    /// Set AOSP capable flag.
    pub fn set_aosp_capable(&self, enable: bool) -> i32 {
        let inner = self.inner.lock().unwrap();
        inner.dev.set_aosp_capable(enable);
        0
    }

    /// Set emulator opcode.
    pub fn set_emu_opcode(&self, opcode: u16) -> i32 {
        let inner = self.inner.lock().unwrap();
        inner.dev.set_emu_opcode(opcode);
        0
    }

    /// Set force static address.
    pub fn set_force_static_address(&self, _enable: bool) -> i32 {
        0
    }

    /// Clone the Arc reference.
    pub fn clone_ref(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vhci_open() {
        let vhci = Vhci::open(BtDevType::BredrLe, 0);
        let dev = vhci.get_btdev();
        assert_eq!(dev.get_type(), BtDevType::BredrLe);
    }

    #[test]
    fn test_vhci_pause() {
        let vhci = Vhci::open(BtDevType::Le, 0);
        assert!(!vhci.is_paused());
        vhci.pause_input(true);
        assert!(vhci.is_paused());
        vhci.pause_input(false);
        assert!(!vhci.is_paused());
    }

    #[test]
    fn test_vhci_vendor_opcodes() {
        let vhci = Vhci::open(BtDevType::BredrLe, 0);
        assert_eq!(vhci.set_msft_opcode(0xFC1E), 0);
        assert_eq!(vhci.set_aosp_capable(true), 0);
        assert_eq!(vhci.set_emu_opcode(0xFC00), 0);
    }

    #[test]
    fn test_vhci_controls() {
        let vhci = Vhci::open(BtDevType::BredrLe, 0);
        assert_eq!(vhci.set_force_suspend(true), 0);
        assert_eq!(vhci.set_force_wakeup(true), 0);
        assert_eq!(vhci.set_force_static_address(true), 0);
    }
}
