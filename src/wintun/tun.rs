use crossbeam::channel::{Receiver, Sender};

use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium},
    time::Instant,
};

pub struct TunInterface {
    sender: Sender<Vec<u8>>,
    receiver: Receiver<Vec<u8>>,
    mtu: usize,
}

impl TunInterface {
    pub fn new(sender: Sender<Vec<u8>>, receiver: Receiver<Vec<u8>>, mtu: usize) -> Self {
        TunInterface {
            sender,
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
                    sender: self.sender.clone(),
                };
                Some((rx, tx))
            }
            Err(_) => None,
        }
    }

    fn transmit(&'d mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            sender: self.sender.clone(),
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
    sender: Sender<Vec<u8>>,
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
        let mut buffer = vec![0; len];
        let result = f(buffer.as_mut_slice());
        if let Err(err) = self.sender.try_send(buffer) {
            log::error!("send data to wintun failed:{}", err);
        }
        result
    }
}
