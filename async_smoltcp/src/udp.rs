use std::{io::ErrorKind, net::SocketAddr};

use bytes::BytesMut;
use smoltcp::wire::IpEndpoint;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::TypeConverter;

pub struct UdpSocket {
    peer_addr: IpEndpoint,
    receiver: Receiver<(IpEndpoint, BytesMut)>,
    write_half: UdpWriteHalf,
}

impl UdpSocket {
    pub(crate) fn new(
        peer_addr: IpEndpoint,
        receiver: Receiver<(IpEndpoint, BytesMut)>,
        sender: Sender<(IpEndpoint, IpEndpoint, BytesMut)>,
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
    pub async fn recv_from(&mut self) -> std::io::Result<(IpEndpoint, BytesMut)> {
        self.receiver
            .recv()
            .await
            .ok_or(ErrorKind::BrokenPipe.into())
            .map(|(addr, data)| (addr, data))
    }

    pub async fn recv_from_std(&mut self) -> std::io::Result<(SocketAddr, BytesMut)> {
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
    sender: Sender<(IpEndpoint, IpEndpoint, BytesMut)>,
    peer_addr: IpEndpoint,
}

impl UdpWriteHalf {
    pub async fn send_to(
        &self,
        data: &[u8],
        from: impl Into<IpEndpoint>,
    ) -> std::io::Result<usize> {
        let len = data.len();
        if self
            .sender
            .send((from.into(), self.peer_addr, data.into()))
            .await
            .is_err()
        {
            log::error!("send udp response failed, trying to enlarge channel buffer size");
        }
        Ok(len)
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
