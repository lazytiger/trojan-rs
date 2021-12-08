use crossbeam::channel::Receiver;
use std::sync::Arc;

use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium},
    time::Instant,
    wire::{IpAddress, IpEndpoint},
};
use wintun::Session;

//TODO ipv6
pub fn is_private(endpoint: IpEndpoint) -> bool {
    if let IpAddress::Ipv4(ip) = endpoint.addr {
        ip.is_unspecified() //0.0.0.0/8
            || ip.0[0] == 10 //10.0.0.0/8
            || ip.is_loopback() //127.0.0.0/8
            || ip.is_link_local() //169.254.0.0/16
            || ip.0[0] == 172 && ip.0[1] &0xf0 == 16 //172.16.0.0/12
            || ip.0[0] == 192 && ip.0[1] == 168 //192.168.0.0/16
            || ip.is_multicast() //224.0.0.0/4
            || ip.0[0] & 0xf0 == 240 // 240.0.0.0/4
            || ip.is_broadcast() //255.255.255.255/32
    } else {
        true
    }
}

pub struct TunInterface {
    session: Arc<Session>,
    receiver: Receiver<Vec<u8>>,
    mtu: usize,
}

impl TunInterface {
    pub fn new(session: Arc<Session>, receiver: Receiver<Vec<u8>>, mtu: usize) -> Self {
        TunInterface {
            session,
            mtu,
            receiver,
        }
    }
}

impl<'d> Device<'d> for TunInterface {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn receive(&'d mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        match self.receiver.try_recv() {
            Ok(packet) => {
                let rx = RxToken { buffer: packet };
                let tx = TxToken {
                    session: self.session.clone(),
                };
                Some((rx, tx))
            }
            Err(_) => None,
        }
    }

    fn transmit(&'d mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            session: self.session.clone(),
        })
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
    buffer: Vec<u8>,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(self.buffer.as_mut_slice())
    }
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut packet = self.session.allocate_send_packet(len as u16).unwrap();
        let result = f(packet.bytes_mut());
        self.session.send_packet(packet);
        result
    }
}
