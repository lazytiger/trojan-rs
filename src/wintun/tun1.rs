use smoltcp::{
    iface::Interface,
    phy::{Device, DeviceCapabilities, Medium},
    time::Instant,
};
use std::{ptr, sync::Arc};
use wintun::{Packet, Session};

pub struct WintunInterface {
    session: Arc<Session>,
    interface: *mut Interface<'static, WintunInterface>,
    mtu: usize,
}

impl WintunInterface {
    pub fn new(session: Arc<Session>, mtu: usize) -> Self {
        Self {
            session,
            mtu,
            interface: ptr::null_mut(),
        }
    }
}

impl<'d> Device<'d> for WintunInterface {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn receive(&'d mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.session
            .try_receive()
            .ok()
            .map(|packet| {
                packet.map(|packet| {
                    unsafe {
                        let interface = &mut *self.interface;
                        interface.sockets();
                    }
                    let rx = RxToken { packet };
                    let tx = TxToken {
                        session: self.session.clone(),
                    };
                    (rx, tx)
                })
            })
            .unwrap_or(None)
    }

    fn transmit(&'d mut self) -> Option<Self::TxToken> {
        None
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut dc = DeviceCapabilities::default();
        dc.medium = Medium::Ip;
        dc.max_transmission_unit = self.mtu;
        dc
    }
}

pub struct TxToken {
    session: Arc<Session>,
}

pub struct RxToken {
    packet: Packet,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(self.packet.bytes_mut())
    }
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        self.session
            .allocate_send_packet(len as u16)
            .map(|mut packet| {
                let r = f(packet.bytes_mut());
                self.session.send_packet(packet);
                r
            })
            .unwrap_or(Err(smoltcp::Error::Exhausted))
    }
}
