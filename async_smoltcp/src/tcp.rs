use std::{
    io::Error,
    net::SocketAddr,
    pin::Pin,
    task::{ready, Context, Poll},
};

use bytes::{Buf, BytesMut};
use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{Receiver, Sender},
};
use tokio_util::sync::PollSender;

use crate::TypeConverter;

pub struct TcpReadHalf {
    receiver: Receiver<BytesMut>,
    peer_addr: IpEndpoint,
    buffer: BytesMut,
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
    sender: PollSender<(IpEndpoint, BytesMut)>,
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
        receiver: Receiver<BytesMut>,
        sender: Sender<(IpEndpoint, BytesMut)>,
        local_addr: IpEndpoint,
        peer_addr: IpEndpoint,
    ) -> Self {
        Self {
            reader: TcpReadHalf {
                receiver,
                peer_addr,
                buffer: BytesMut::new(),
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
        if !pin.buffer.is_empty() {
            let dst_buffer = buf.initialize_unfilled();
            let len = dst_buffer.len().min(pin.buffer.len());
            let _ = &dst_buffer[..len].copy_from_slice(&pin.buffer.as_ref()[..len]);
            pin.buffer.advance(len);
            buf.set_filled(buf.filled().len() + len);
            Poll::Ready(Ok(()))
        } else if let Some(data) = ready!(pin.receiver.poll_recv(cx)) {
            pin.buffer = data;
            Pin::new(pin).poll_read(cx, buf)
        } else {
            Poll::Ready(Ok(()))
        }
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
            if pin.sender.send_item((pin.local_addr, buf.into())).is_ok() {
                return Poll::Ready(Ok(buf.len()));
            } else {
                log::error!("tcp send response failed: trying to enlarge channel buffer size");
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
