use std::{
    io::ErrorKind,
    net::SocketAddr,
    pin::Pin,
    task::{ready, Context, Poll},
};

use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::mpsc::{Receiver, Sender},
};

pub struct UdpSocket {
    local_addr: IpEndpoint,
    receiver: Receiver<(IpEndpoint, Vec<u8>)>,
    sender: Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
}

impl UdpSocket {
    pub(crate) fn new(
        local_addr: IpEndpoint,
        receiver: Receiver<(IpEndpoint, Vec<u8>)>,
        sender: Sender<(IpEndpoint, IpEndpoint, Vec<u8>)>,
    ) -> Self {
        Self {
            local_addr,
            receiver,
            sender,
        }
    }
    pub async fn recv_to(&mut self) -> std::io::Result<(SocketAddr, Vec<u8>)> {
        self.receiver
            .recv()
            .await
            .ok_or(ErrorKind::BrokenPipe.into())
    }

    pub async fn send_from(&mut self, from: SocketAddr, data: &[u8]) -> std::io::Result<usize> {
        let len = data.len();
        self.sender
            .send((self.local_addr, from, data.to_vec()))
            .await
            .map(|_| len)
            .map_err(|_| ErrorKind::BrokenPipe.into())
    }
}
