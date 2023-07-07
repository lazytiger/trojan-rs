use std::{io::ErrorKind, net::SocketAddr};

use smoltcp::wire::IpEndpoint;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::TypeConverter;

pub struct UdpSocket {
    peer_addr: IpEndpoint,
    receiver: Receiver<(IpEndpoint, Vec<u8>)>,
    sender: Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
}

impl UdpSocket {
    pub(crate) fn new(
        peer_addr: IpEndpoint,
        receiver: Receiver<(IpEndpoint, Vec<u8>)>,
        sender: Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
    ) -> Self {
        Self {
            peer_addr,
            receiver,
            sender,
        }
    }
    pub async fn recv_from(&mut self) -> std::io::Result<(SocketAddr, Vec<u8>)> {
        self.receiver
            .recv()
            .await
            .ok_or(ErrorKind::BrokenPipe.into())
            .map(|(addr, data)| (addr.convert(), data))
    }

    pub async fn send_to(&mut self, from: SocketAddr, data: &[u8]) -> std::io::Result<usize> {
        let len = data.len();
        self.sender
            .send((from.into(), self.peer_addr, data.to_vec()))
            .await
            .map(|_| len)
            .map_err(|_| ErrorKind::BrokenPipe.into())
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr.convert()
    }
}
