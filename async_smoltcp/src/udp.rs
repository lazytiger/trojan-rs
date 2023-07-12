use std::{io::ErrorKind, net::SocketAddr};

use smoltcp::wire::IpEndpoint;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::TypeConverter;

pub struct UdpSocket {
    peer_addr: IpEndpoint,
    receiver: Receiver<(IpEndpoint, Vec<u8>)>,
    write_half: UdpWriteHalf,
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
            write_half: UdpWriteHalf { sender, peer_addr },
        }
    }

    pub fn peer_addr(&self) -> IpEndpoint {
        self.peer_addr
    }

    pub fn peer_addr_std(&self) -> SocketAddr {
        self.peer_addr.convert()
    }
    pub async fn recv_from(&mut self) -> std::io::Result<(IpEndpoint, Vec<u8>)> {
        self.receiver
            .recv()
            .await
            .ok_or(ErrorKind::BrokenPipe.into())
            .map(|(addr, data)| (addr, data))
    }

    pub async fn recv_from_std(&mut self) -> std::io::Result<(SocketAddr, Vec<u8>)> {
        self.recv_from()
            .await
            .map(|(addr, data)| (addr.convert(), data))
    }
    pub async fn send_to(
        &self,
        data: &[u8],
        from: impl Into<IpEndpoint>,
    ) -> std::io::Result<usize> {
        self.write_half.send_to(data, from).await
    }
    pub async fn send_to_std(&self, data: &[u8], from: SocketAddr) -> std::io::Result<usize> {
        self.write_half.send_to_std(data, from).await
    }
    pub fn writer(&self) -> UdpWriteHalf {
        self.write_half.clone()
    }
    pub async fn close(&mut self) {
        let _ = self.write_half.send_to(&[], self.peer_addr).await;
        self.receiver.close();
    }
}

#[derive(Clone)]
pub struct UdpWriteHalf {
    sender: Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
    peer_addr: IpEndpoint,
}

impl UdpWriteHalf {
    pub async fn send_to(
        &self,
        data: &[u8],
        from: impl Into<IpEndpoint>,
    ) -> std::io::Result<usize> {
        let len = data.len();
        self.sender
            .send((from.into(), self.peer_addr, data.to_vec()))
            .await
            .map(|_| len)
            .map_err(|_| ErrorKind::BrokenPipe.into())
    }

    pub async fn send_to_std(&self, data: &[u8], from: SocketAddr) -> std::io::Result<usize> {
        self.send_to(data, from).await
    }

    pub fn peer_addr(&self) -> IpEndpoint {
        self.peer_addr
    }

    pub fn peer_addr_std(&self) -> SocketAddr {
        self.peer_addr.convert()
    }
}
