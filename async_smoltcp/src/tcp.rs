use std::{
    io::Error,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};

use bytes::{Buf, BytesMut};
use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{
        mpsc::{Receiver, Sender},
        Notify,
    },
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
    wake: Arc<Notify>,
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
        wake: Arc<Notify>,
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
                wake,
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
            if let Err(err) = pin.sender.send_item((pin.local_addr, buf.into())) {
                log::error!("tcp send response failed: {}", err);
            } else {
                pin.wake.notify_one();
                return Poll::Ready(Ok(buf.len()));
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

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    };

    use smoltcp::wire::{IpAddress, IpEndpoint};
    use tokio::sync::{mpsc::channel, Notify};

    use super::*;

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    #[test]
    fn tcp_write_notifies_device_after_queueing_egress() {
        let (sender, mut receiver) = channel(1);
        let wake = std::sync::Arc::new(Notify::new());
        let mut writer = TcpWriteHalf {
            sender: PollSender::new(sender),
            local_addr: IpEndpoint::new(IpAddress::v4(10, 10, 10, 1), 12345),
            wake: wake.clone(),
        };
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let written = Pin::new(&mut writer).poll_write(&mut cx, b"packet");

        assert!(matches!(written, Poll::Ready(Ok(6))));
        assert!(receiver.try_recv().is_ok());

        let mut notified = Box::pin(wake.notified());
        assert!(matches!(notified.as_mut().poll(&mut cx), Poll::Ready(())));
    }
}
