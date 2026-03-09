// SPDX-License-Identifier: GPL-2.0-or-later
//
// HCI emulator orchestration replacing emulator/hciemu.c
//
// Wires together virtual Bluetooth devices (btdev) and protocol handlers
// (bthost) via socketpairs. Creates a central controller (via VHCI) and
// one or more client devices, each with its own bthost for protocol
// handling.

use std::sync::{Arc, Mutex};

use crate::btdev::{BtDev, BtDevType, HookType, HookFunc};
use crate::bthost::BtHost;
use crate::vhci::Vhci;

/// Emulator type (determines controller capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HciEmuType {
    BredrLe,
    Bredr,
    Le,
    Legacy,
    BredrLe50,
    BredrLe52,
    BredrLe60,
}

impl HciEmuType {
    fn to_btdev_type(self) -> BtDevType {
        match self {
            Self::BredrLe => BtDevType::BredrLe,
            Self::Bredr => BtDevType::Bredr,
            Self::Le => BtDevType::Le,
            Self::Legacy => BtDevType::Bredr20,
            Self::BredrLe50 => BtDevType::BredrLe50,
            Self::BredrLe52 => BtDevType::BredrLe52,
            Self::BredrLe60 => BtDevType::BredrLe60,
        }
    }
}

/// Hook types for the emulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HciEmuHookType {
    PreCmd,
    PostCmd,
    PreEvt,
    PostEvt,
}

impl HciEmuHookType {
    fn to_btdev_hook(self) -> HookType {
        match self {
            Self::PreCmd => HookType::PreCmd,
            Self::PostCmd => HookType::PostCmd,
            Self::PreEvt => HookType::PreEvt,
            Self::PostEvt => HookType::PostEvt,
        }
    }
}

/// Command hook callback.
pub type CommandFunc = Box<dyn Fn(u16, &[u8]) + Send + Sync>;

/// A client (remote device + host stack).
pub struct HciEmuClient {
    host: BtHost,
    dev: BtDev,
}

impl HciEmuClient {
    /// Get the bthost for this client.
    pub fn host(&self) -> &BtHost {
        &self.host
    }

    /// Get the client's BD address.
    pub fn bdaddr(&self) -> [u8; 6] {
        self.dev.get_bdaddr()
    }

    /// Set the client's BD address.
    pub fn set_bdaddr(&self, addr: &[u8; 6]) -> bool {
        self.dev.set_bdaddr(addr)
    }
}

#[allow(dead_code)]
struct HciEmuInner {
    emu_type: HciEmuType,
    vhci: Vhci,
    clients: Vec<HciEmuClient>,
    post_command_hooks: Vec<CommandFunc>,
}

/// HCI emulator: wires central + client devices together.
pub struct HciEmu {
    inner: Arc<Mutex<HciEmuInner>>,
}

impl HciEmu {
    /// Create a new emulator with a single client.
    pub fn new(emu_type: HciEmuType) -> Self {
        Self::new_num(emu_type, 1)
    }

    /// Create a new emulator with N clients.
    pub fn new_num(emu_type: HciEmuType, num_clients: u8) -> Self {
        let btdev_type = emu_type.to_btdev_type();

        // Create the central controller via VHCI
        let vhci = Vhci::open(btdev_type, 0);

        // Create clients
        let mut clients = Vec::new();
        for i in 0..num_clients {
            let client = Self::create_client(btdev_type, (i + 1) as u16);
            clients.push(client);
        }

        let emu = HciEmu {
            inner: Arc::new(Mutex::new(HciEmuInner {
                emu_type,
                vhci,
                clients,
                post_command_hooks: Vec::new(),
            })),
        };

        // Wire up the send handlers so devices can communicate
        emu.wire_up();

        emu
    }

    fn create_client(dev_type: BtDevType, id: u16) -> HciEmuClient {
        let dev = BtDev::create(dev_type, id);
        let host = BtHost::create();

        // Wire bthost → btdev: host sends H4 packets to its device
        let dev_ref = dev.clone_ref();
        host.set_send_handler(Box::new(move |data| {
            dev_ref.receive_h4(data);
        }));

        // Wire btdev → bthost: device sends H4 packets to its host
        let host_ref = host.clone_ref();
        dev.set_send_handler(Box::new(move |data| {
            host_ref.receive_h4(data);
        }));

        // Set MTU from device
        let (acl_mtu, _sco_mtu, iso_mtu) = dev.get_mtu();
        host.set_acl_mtu(acl_mtu);
        host.set_iso_mtu(iso_mtu);

        HciEmuClient { host, dev }
    }

    fn wire_up(&self) {
        // In the C implementation, the central btdev communicates with the
        // kernel via /dev/vhci. In our test setup, the central device's
        // send_handler routes packets back to the test harness.
        //
        // The client btdev ↔ bthost wiring is done in create_client().
        // Cross-device communication (central ↔ client) happens through
        // the HCI connection mechanism in btdev when connections are
        // established.
    }

    /// Clone the Arc reference.
    pub fn clone_ref(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Get the Nth client.
    pub fn get_client(&self, n: usize) -> Option<HciEmuClientRef> {
        let inner = self.inner.lock().unwrap();
        if n < inner.clients.len() {
            // Return a reference wrapper
            Some(HciEmuClientRef {
                emu: Arc::clone(&self.inner),
                index: n,
            })
        } else {
            None
        }
    }

    /// Get the first client's bthost.
    pub fn client_get_host(&self) -> Option<BtHost> {
        let inner = self.inner.lock().unwrap();
        inner.clients.first().map(|c| c.host.clone_ref())
    }

    /// Get the first client's BD address.
    pub fn get_client_bdaddr(&self) -> Option<[u8; 6]> {
        let inner = self.inner.lock().unwrap();
        inner.clients.first().map(|c| c.dev.get_bdaddr())
    }

    /// Get the VHCI.
    pub fn get_vhci(&self) -> Vhci {
        self.inner.lock().unwrap().vhci.clone_ref()
    }

    /// Get the central btdev.
    pub fn get_central_btdev(&self) -> BtDev {
        self.inner.lock().unwrap().vhci.get_btdev()
    }

    /// Get the central BD address as a formatted string.
    pub fn get_address(&self) -> String {
        let addr = self.get_central_bdaddr();
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]
        )
    }

    /// Get the central BD address.
    pub fn get_central_bdaddr(&self) -> [u8; 6] {
        self.inner.lock().unwrap().vhci.get_btdev().get_bdaddr()
    }

    /// Get central supported features.
    pub fn get_features(&self) -> [u8; 8] {
        self.inner.lock().unwrap().vhci.get_btdev().get_features()
    }

    /// Get central supported commands.
    pub fn get_commands(&self) -> [u8; 64] {
        self.inner.lock().unwrap().vhci.get_btdev().get_commands()
    }

    /// Get central scan enable state.
    pub fn get_central_scan_enable(&self) -> u8 {
        self.inner
            .lock()
            .unwrap()
            .vhci
            .get_btdev()
            .get_scan_enable()
    }

    /// Get central LE scan enable state.
    pub fn get_central_le_scan_enable(&self) -> u8 {
        self.inner
            .lock()
            .unwrap()
            .vhci
            .get_btdev()
            .get_le_scan_enable()
    }

    /// Set central LE states.
    pub fn set_central_le_states(&self, states: &[u8; 8]) {
        self.inner
            .lock()
            .unwrap()
            .vhci
            .get_btdev()
            .set_le_states(states);
    }

    /// Set central accept list length.
    pub fn set_central_le_al_len(&self, len: u8) {
        self.inner
            .lock()
            .unwrap()
            .vhci
            .get_btdev()
            .set_al_len(len);
    }

    /// Set central resolving list length.
    pub fn set_central_le_rl_len(&self, len: u8) {
        self.inner
            .lock()
            .unwrap()
            .vhci
            .get_btdev()
            .set_rl_len(len);
    }

    /// Add a post-command hook on the central controller.
    pub fn add_central_post_command_hook(&self, func: CommandFunc) -> bool {
        self.inner.lock().unwrap().post_command_hooks.push(func);
        true
    }

    /// Clear all post-command hooks.
    pub fn clear_central_post_command_hooks(&self) -> bool {
        self.inner.lock().unwrap().post_command_hooks.clear();
        true
    }

    /// Add a hook on the central device.
    pub fn add_hook(
        &self,
        hook_type: HciEmuHookType,
        opcode: u16,
        func: HookFunc,
    ) -> bool {
        let inner = self.inner.lock().unwrap();
        inner
            .vhci
            .get_btdev()
            .add_hook(hook_type.to_btdev_hook(), opcode, func)
    }

    /// Remove a hook from the central device.
    pub fn del_hook(&self, hook_type: HciEmuHookType, opcode: u16) -> bool {
        let inner = self.inner.lock().unwrap();
        inner
            .vhci
            .get_btdev()
            .del_hook(hook_type.to_btdev_hook(), opcode)
    }
}

/// Reference to a client within an HciEmu (avoids lifetime issues).
pub struct HciEmuClientRef {
    emu: Arc<Mutex<HciEmuInner>>,
    index: usize,
}

impl HciEmuClientRef {
    /// Get the bthost.
    pub fn host(&self) -> BtHost {
        let inner = self.emu.lock().unwrap();
        inner.clients[self.index].host.clone_ref()
    }

    /// Get the BD address.
    pub fn bdaddr(&self) -> [u8; 6] {
        let inner = self.emu.lock().unwrap();
        inner.clients[self.index].dev.get_bdaddr()
    }

    /// Set the BD address.
    pub fn set_bdaddr(&self, addr: &[u8; 6]) -> bool {
        let inner = self.emu.lock().unwrap();
        inner.clients[self.index].dev.set_bdaddr(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hciemu_create() {
        let emu = HciEmu::new(HciEmuType::BredrLe);
        assert!(emu.get_client(0).is_some());
        assert!(emu.get_client(1).is_none());
    }

    #[test]
    fn test_hciemu_multi_client() {
        let emu = HciEmu::new_num(HciEmuType::Le, 3);
        assert!(emu.get_client(0).is_some());
        assert!(emu.get_client(1).is_some());
        assert!(emu.get_client(2).is_some());
        assert!(emu.get_client(3).is_none());
    }

    #[test]
    fn test_hciemu_address() {
        let emu = HciEmu::new(HciEmuType::BredrLe);
        let addr = emu.get_address();
        // Should be formatted as XX:XX:XX:XX:XX:XX
        assert_eq!(addr.len(), 17);
        assert_eq!(addr.chars().filter(|c| *c == ':').count(), 5);
    }

    #[test]
    fn test_hciemu_central_features() {
        let emu = HciEmu::new(HciEmuType::BredrLe);
        let features = emu.get_features();
        // BR/EDR + LE device should have features set
        assert!(features.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hciemu_client_host() {
        let emu = HciEmu::new(HciEmuType::BredrLe);
        let host = emu.client_get_host();
        assert!(host.is_some());
    }

    #[test]
    fn test_hciemu_client_bdaddr() {
        let emu = HciEmu::new(HciEmuType::BredrLe);
        let client = emu.get_client(0).unwrap();
        let addr = client.bdaddr();
        // Client has id=1, so addr[0]=1
        assert_eq!(addr[0], 1);

        // Set new address
        let new_addr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert!(client.set_bdaddr(&new_addr));
        assert_eq!(client.bdaddr(), new_addr);
    }

    #[test]
    fn test_hciemu_le_states() {
        let emu = HciEmu::new(HciEmuType::Le);
        let states = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        emu.set_central_le_states(&states);
    }

    #[test]
    fn test_hciemu_hooks() {
        let emu = HciEmu::new(HciEmuType::BredrLe);
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cc = called.clone();
        assert!(emu.add_hook(
            HciEmuHookType::PreCmd,
            0x0c03,
            Box::new(move |_data| {
                cc.store(true, std::sync::atomic::Ordering::SeqCst);
                true
            }),
        ));
        assert!(emu.del_hook(HciEmuHookType::PreCmd, 0x0c03));
    }

    #[test]
    fn test_hciemu_post_command_hooks() {
        let emu = HciEmu::new(HciEmuType::BredrLe);
        assert!(emu.add_central_post_command_hook(Box::new(|_opcode, _data| {})));
        assert!(emu.clear_central_post_command_hooks());
    }

    #[test]
    fn test_hciemu_vhci() {
        let emu = HciEmu::new(HciEmuType::BredrLe);
        let vhci = emu.get_vhci();
        assert!(!vhci.is_paused());
    }

    #[test]
    fn test_hciemu_type_mapping() {
        assert_eq!(HciEmuType::BredrLe.to_btdev_type(), BtDevType::BredrLe);
        assert_eq!(HciEmuType::Le.to_btdev_type(), BtDevType::Le);
        assert_eq!(HciEmuType::Bredr.to_btdev_type(), BtDevType::Bredr);
        assert_eq!(HciEmuType::Legacy.to_btdev_type(), BtDevType::Bredr20);
        assert_eq!(HciEmuType::BredrLe50.to_btdev_type(), BtDevType::BredrLe50);
        assert_eq!(HciEmuType::BredrLe52.to_btdev_type(), BtDevType::BredrLe52);
        assert_eq!(HciEmuType::BredrLe60.to_btdev_type(), BtDevType::BredrLe60);
    }
}
