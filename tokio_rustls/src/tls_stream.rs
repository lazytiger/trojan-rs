use std::{
    io::{Error, ErrorKind, Read, Write},
    marker::PhantomData,
    net::SocketAddr,
    ops::DerefMut,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use rustls::{
    client::ClientConnectionData, server::ServerConnectionData, ClientConnection, ConnectionCommon,
    ServerConnection,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::Mutex,
};

pub type TlsServerStream = TlsStream<ServerConnection, ServerConnectionData>;
pub type TlsServerReadHalf = TlsReadHalf<ServerConnection, ServerConnectionData>;
pub type TlsServerWriteHalf = TlsWriteHalf<ServerConnection, ServerConnectionData>;
pub type TlsClientStream = TlsStream<ClientConnection, ClientConnectionData>;
pub type TlsClientReadHalf = TlsReadHalf<ClientConnection, ClientConnectionData>;
pub type TlsClientWriteHalf = TlsWriteHalf<ClientConnection, ClientConnectionData>;

macro_rules! lock {
    ($lock:expr, $cx:expr) => {
        match $lock.try_lock() {
            Ok(lock) => lock,
            Err(_) => {
                $cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    };
}

pub struct TlsReadHalf<T, D> {
    stream: Arc<Mutex<TlsStream<T, D>>>,
}

impl<T, D> AsyncRead for TlsReadHalf<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
    D: Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        let mut lock = lock!(pin.stream, cx);
        Pin::new(lock.deref_mut()).poll_read(cx, buf)
    }
}

pub struct TlsWriteHalf<T, D> {
    stream: Arc<Mutex<TlsStream<T, D>>>,
}

impl<T, D> TlsWriteHalf<T, D> {
    pub async fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.lock().await.stream.local_addr()
    }

    pub async fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.lock().await.stream.peer_addr()
    }
}

impl<T, D> TlsReadHalf<T, D> {
    pub async fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.lock().await.stream.local_addr()
    }

    pub async fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.lock().await.stream.peer_addr()
    }
}

impl<T, D> AsyncWrite for TlsWriteHalf<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
    D: Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let pin = self.get_mut();
        let mut lock = lock!(pin.stream, cx);
        Pin::new(lock.deref_mut()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        let mut lock = lock!(pin.stream, cx);
        Pin::new(lock.deref_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        let mut lock = lock!(pin.stream, cx);
        Pin::new(lock.deref_mut()).poll_shutdown(cx)
    }
}

pub struct TlsStream<T, D> {
    stream: TcpStream,
    session: T,
    recv_buf: Vec<u8>,
    send_buf: BytesMut,
    _phantom: PhantomData<D>,
}

impl<T, D> TlsStream<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
{
    pub fn new(stream: TcpStream, mut session: T) -> Self {
        session.set_buffer_limit(None);
        Self {
            stream,
            session,
            recv_buf: vec![0u8; 4096],
            send_buf: BytesMut::new(),
            _phantom: Default::default(),
        }
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    pub fn into_split(self) -> (TlsReadHalf<T, D>, TlsWriteHalf<T, D>) {
        let stream = Arc::new(Mutex::new(self));
        (
            TlsReadHalf {
                stream: stream.clone(),
            },
            TlsWriteHalf { stream },
        )
    }

    fn poll_tls_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        while self.session.wants_write() || !self.send_buf.is_empty() {
            if self.session.wants_write() {
                let mut send_buf = self.send_buf.split().writer();
                if let Err(err) = self.session.write_tls(&mut send_buf) {
                    return Poll::Ready(Err(err));
                } else {
                    self.send_buf.unsplit(send_buf.into_inner());
                }
            }

            if !self.send_buf.is_empty() {
                match Pin::new(&mut self.stream).poll_write(cx, self.send_buf.as_ref()) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
                    }
                    Poll::Ready(Ok(n)) => {
                        self.send_buf.advance(n);
                    }
                    Poll::Ready(Err(err)) => {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<T, D> AsyncRead for TlsStream<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
    D: Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        match pin.session.reader().read(buf.initialize_unfilled()) {
            Err(err) => {
                if err.kind() != ErrorKind::WouldBlock {
                    return Poll::Ready(Err(err));
                }
            }
            Ok(n) => {
                buf.set_filled(buf.filled().len() + n);
                return Poll::Ready(Ok(()));
            }
        }
        let mut raw_buf = ReadBuf::new(pin.recv_buf.as_mut_slice());
        match Pin::new(&mut pin.stream).poll_read(cx, &mut raw_buf) {
            Poll::Ready(Ok(_)) => {
                if raw_buf.filled().is_empty() {
                    Poll::Ready(Ok(()))
                } else if let Err(err) = {
                    let mut data = raw_buf.filled();
                    loop {
                        match pin.session.read_tls(&mut data) {
                            Err(err) => break Err(err),
                            Ok(0) => unreachable!(),
                            Ok(_) => {
                                if data.is_empty() {
                                    break Ok(());
                                }
                                log::error!("data not flushed into tls once");
                            }
                        }
                    }
                } {
                    Poll::Ready(Err(err))
                } else if pin.session.process_new_packets().is_err() {
                    Poll::Ready(Err(ErrorKind::InvalidData.into()))
                } else if let Poll::Ready(Err(err)) = pin.poll_tls_flush(cx) {
                    Poll::Ready(Err(err))
                } else {
                    Pin::new(pin).poll_read(cx, buf)
                }
            }
            ret => ret,
        }
    }
}

impl<T, D> AsyncWrite for TlsStream<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
    D: Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let pin = self.get_mut();
        match pin.poll_tls_flush(cx) {
            Poll::Pending => {
                return Poll::Pending;
            }
            Poll::Ready(Err(err)) => {
                return Poll::Ready(Err(err));
            }
            _ => {}
        }
        match pin.session.writer().write(buf) {
            // read actual data from session, drain the session.
            Ok(n) => match pin.poll_tls_flush(cx) {
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                _ => Poll::Ready(Ok(n)),
            },
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        pin.poll_tls_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        Pin::new(&mut pin.stream).poll_shutdown(cx)
    }
}

mod test {
    #[test]
    fn test_bytes() {
        use bytes::{BufMut, BytesMut};
        use std::io::Write;
        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(b"hello, world.");
        let mut writer = buffer.split().writer();
        writer.write_all(b"world, hello.").unwrap();
        buffer.unsplit(writer.into_inner());
        println!("{}", String::from_utf8_lossy(buffer.as_ref()));
    }
}
