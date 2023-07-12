use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    task::{ready, Context, Poll},
};

use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{Receiver, Sender},
};
use tokio_util::sync::PollSender;

use crate::TypeConverter;

pub struct TcpReadHalf {
    receiver: Receiver<Vec<u8>>,
    peer_addr: IpEndpoint,
}

impl TcpReadHalf {
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr.convert()
    }
    pub fn close(&mut self) {
        self.receiver.close();
    }
}

pub struct TcpWriteHalf {
    sender: PollSender<(IpEndpoint, Vec<u8>)>,
    local_addr: IpEndpoint,
}

pub struct TcpStream {
    reader: TcpReadHalf,
    writer: TcpWriteHalf,
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
            reader: TcpReadHalf {
                receiver,
                peer_addr,
            },
            writer: TcpWriteHalf {
                sender: PollSender::new(sender),
                local_addr,
            },
            local_addr,
            peer_addr,
        }
    }

    pub fn into_split(self) -> (TcpReadHalf, TcpWriteHalf) {
        (self.reader, self.writer)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr.convert()
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr.convert()
    }
}

impl AsyncRead for TcpReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        if let Some(data) = ready!(pin.receiver.poll_recv(cx)) {
            if data.len() > buf.initialize_unfilled().len() {
                log::error!(
                    "received {} bytes, but available space is {}",
                    data.len(),
                    buf.initialize_unfilled().len()
                );
                return Poll::Ready(Err(ErrorKind::OutOfMemory.into()));
            }
            let _ = &buf.initialize_unfilled()[..data.len()].copy_from_slice(data.as_slice());
            buf.set_filled(buf.filled().len() + data.len());
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let pin = self.get_mut();
        if ready!(pin.sender.poll_reserve(cx)).is_ok() {
            let buf = buf.to_vec();
            let len = buf.len();
            if pin.sender.send_item((pin.local_addr, buf)).is_ok() {
                return Poll::Ready(Ok(len));
            }
        }
        Poll::Ready(Ok(0))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.poll_write(cx, &[]).map(|ret| ret.map(|_| ()))
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        Pin::new(&mut pin.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let pin = self.get_mut();
        Pin::new(&mut pin.writer).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        Pin::new(&mut pin.writer).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        pin.reader.receiver.close();
        Pin::new(&mut pin.writer).poll_shutdown(cx)
    }
}
