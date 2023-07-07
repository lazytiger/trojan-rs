use std::{
    io::Error,
    net::SocketAddr,
    pin::Pin,
    task::{ready, Context, Poll},
};

use crate::TypeConverter;
use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{Receiver, Sender},
};
use tokio_util::sync::PollSender;

pub struct TcpStream {
    receiver: Receiver<Vec<u8>>,
    sender: PollSender<(IpEndpoint, Vec<u8>)>,
    local_addr: IpEndpoint,
    peer_addr: IpEndpoint,
}

impl TcpStream {
    pub(crate) fn new(
        receiver: Receiver<Vec<u8>>,
        sender: Sender<(IpEndpoint, Vec<u8>)>,
        local_addr: IpEndpoint,
        peer_addr: IpEndpoint,
    ) -> Self {
        Self {
            receiver,
            sender: PollSender::new(sender),
            local_addr,
            peer_addr,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr.convert()
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr.convert()
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        if let Some(data) = ready!(pin.receiver.poll_recv(cx)) {
            let _ = &buf.initialize_unfilled()[..data.len()].copy_from_slice(data.as_slice());
            buf.set_filled(buf.filled().len() + data.len());
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let pin = self.get_mut();
        if let Ok(_) = ready!(pin.sender.poll_reserve(cx)) {
            let buf = buf.to_vec();
            let len = buf.len();
            if let Ok(_) = pin.sender.send_item((pin.local_addr, buf)) {
                return Poll::Ready(Ok(len));
            }
        }
        Poll::Ready(Ok(0))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.get_mut().sender.close();
        Poll::Ready(Ok(()))
    }
}
