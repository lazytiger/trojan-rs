use std::{io::ErrorKind, net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use smoltcp::wire::IpEndpoint;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Notify,
};

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
        wake: Arc<Notify>,
    ) -> Self {
        Self {
            peer_addr,
            receiver,
            write_half: UdpWriteHalf {
                sender,
                peer_addr,
                wake,
            },
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
    wake: Arc<Notify>,
}

impl UdpWriteHalf {
    pub async fn send_to(
        &self,
        data: &[u8],
        from: impl Into<IpEndpoint>,
    ) -> std::io::Result<usize> {
        let len = data.len();
        if let Err(err) = self
            .sender
            .send((from.into(), self.peer_addr, data.into()))
            .await
        {
            log::error!("send udp response failed:{}", err);
        } else {
            self.wake.notify_one();
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

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
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
    fn udp_write_notifies_device_after_queueing_egress() {
        let (sender, mut receiver) = channel(1);
        let wake = std::sync::Arc::new(Notify::new());
        let writer = UdpWriteHalf {
            sender,
            peer_addr: IpEndpoint::new(IpAddress::v4(8, 8, 8, 8), 53),
            wake: wake.clone(),
        };
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut send = Box::pin(writer.send_to(
            b"packet",
            IpEndpoint::new(IpAddress::v4(10, 10, 10, 1), 12345),
        ));

        assert!(matches!(send.as_mut().poll(&mut cx), Poll::Ready(Ok(6))));
        assert!(receiver.try_recv().is_ok());

        let mut notified = Box::pin(wake.notified());
        assert!(matches!(notified.as_mut().poll(&mut cx), Poll::Ready(())));
    }
}
