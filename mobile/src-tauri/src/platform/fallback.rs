use crate::{types::VpnError, InstalledApp};

pub struct Session {
    mtu: usize,
}

pub struct Packet {
    data: Vec<u8>,
}

impl Session {
    pub fn new(_: i32, mtu: usize, _: bool) -> Self {
        Self { mtu }
    }
}

impl async_smoltcp::Tun for Session {
    type Packet = Packet;

    fn receive(&self) -> std::io::Result<Option<Self::Packet>> {
        Err(std::io::ErrorKind::WouldBlock.into())
    }

    fn send(&self, _: Self::Packet) -> std::io::Result<()> {
        Ok(())
    }

    fn allocate_packet(&self, len: usize) -> std::io::Result<Self::Packet> {
        Ok(Packet { data: vec![0; len] })
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

impl async_smoltcp::Packet for Packet {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

pub fn init_log(_: &String) {}

pub fn start_vpn(
    _: impl AsRef<str>,
    _: i32,
    _: impl AsRef<str>,
    _: impl AsRef<str>,
) -> Result<(), VpnError> {
    Err(VpnError::NoPlatformContext)
}

pub fn stop_vpn() -> Result<(), VpnError> {
    Err(VpnError::NoPlatformContext)
}

pub fn check_self_permission(_: impl AsRef<str>) -> Result<bool, VpnError> {
    Ok(false)
}

pub fn request_permission(_: impl AsRef<str>) -> Result<(), VpnError> {
    Err(VpnError::NoPlatformContext)
}

pub fn should_show_permission_rationale(_: impl AsRef<str>) -> Result<bool, VpnError> {
    Ok(false)
}

pub fn update_notification(_: impl AsRef<str>) -> Result<(), VpnError> {
    Err(VpnError::NoPlatformContext)
}

pub fn save_data(_: impl AsRef<str>, _: impl AsRef<str>) -> Result<(), VpnError> {
    Err(VpnError::NoPlatformContext)
}

pub fn load_data(_: impl AsRef<str>) -> Result<String, VpnError> {
    Ok(String::new())
}

pub fn list_installed_apps() -> Result<Vec<InstalledApp>, VpnError> {
    Ok(Vec::new())
}

pub fn start_vpn_process() -> Result<(), VpnError> {
    Err(VpnError::NoPlatformContext)
}
