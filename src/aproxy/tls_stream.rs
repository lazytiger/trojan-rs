#![allow(dead_code)]

use std::{
    io::{Error, ErrorKind, Read, Write},
    marker::PhantomData,
    ops::DerefMut,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{
    client::ClientConnectionData, server::ServerConnectionData, ClientConnection, ConnectionCommon,
    ServerConnection,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::Mutex,
};

use crate::types;

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
    send_buf: Vec<u8>,
    _phantom: PhantomData<D>,
}

impl<T, D> TlsStream<T, D>
where
    T: DerefMut<Target = ConnectionCommon<D>>,
    T: Unpin,
{
    pub(crate) fn new(stream: TcpStream, session: T, buffer_size: usize) -> types::Result<Self> {
        Ok(Self {
            stream,
            session,
            recv_buf: vec![0u8; buffer_size],
            send_buf: Vec::new(),
            _phantom: Default::default(),
        })
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

    fn poll_tls_write(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, Error>> {
        if self.session.wants_write() {
            if let Err(err) = self.session.write_tls(&mut self.send_buf) {
                return Poll::Ready(Err(err));
            }
        }
        if self.send_buf.is_empty() {
            Poll::Ready(Ok(0))
        } else {
            match Pin::new(&mut self.stream).poll_write(cx, self.send_buf.as_slice()) {
                Poll::Ready(Ok(n)) => {
                    if self.send_buf.len() == n {
                        self.send_buf.clear();
                    } else {
                        self.send_buf.copy_within(n.., 0);
                        unsafe {
                            self.send_buf.set_len(self.send_buf.len() - n);
                        }
                    }
                    Poll::Ready(Ok(n))
                }
                ret => ret,
            }
        }
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
                } else if let Err(err) = pin.session.read_tls(&mut raw_buf.filled()) {
                    Poll::Ready(Err(err))
                } else if let Err(_) = pin.session.process_new_packets() {
                    Poll::Ready(Err(ErrorKind::InvalidData.into()))
                } else {
                    if let Poll::Ready(Err(err)) = pin.poll_tls_write(cx) {
                        Poll::Ready(Err(err))
                    } else {
                        Pin::new(pin).poll_read(cx, buf)
                    }
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
        match pin.session.writer().write(buf) {
            // read actual data from session, drain the session.
            Ok(n) => match pin.poll_tls_write(cx) {
                // trying to flush data
                Poll::Ready(Ok(_)) | Poll::Pending => Poll::Ready(Ok(n)),
                ret => ret,
            },
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        pin.poll_tls_write(cx).map(|r| r.map(|_| ()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        Pin::new(&mut pin.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use rustls::{ClientConfig, ClientConnection};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use hyper_rustls::ConfigBuilderExt;

    use crate::tls_stream::TlsClientStream;

    #[test]
    fn test_async() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        println!("start testing now");
        runtime.block_on(async {
            let stream = TcpStream::connect("110.242.68.3:443").await.unwrap();
            let client_config = Arc::new(
                ClientConfig::builder()
                    .with_safe_defaults()
                    .with_native_roots()
                    .with_no_client_auth(),
            );
            let session =
                ClientConnection::new(client_config, "www.baidu.com".try_into().unwrap()).unwrap();
            let client = TlsClientStream::new(stream, session).unwrap();
            let (mut read_half, mut write_half) = client.into_split();
            println!("start sending request");
            write_half
                .write_all("GET / HTTP/1.1\r\n".as_bytes())
                .await
                .unwrap();
            write_half
                .write_all("Host: www.baidu.com\r\n".as_bytes())
                .await
                .unwrap();
            write_half
                .write_all("User-Agent: test\r\n".as_bytes())
                .await
                .unwrap();
            write_half
                .write_all("Accept: */*\r\n".as_bytes())
                .await
                .unwrap();
            println!("write request finished");
            write_half.write_all("\r\n".as_bytes()).await.unwrap();
            let mut data = vec![0u8; 4096];
            let size = read_half.read(data.as_mut_slice()).await.unwrap();
            if size == 0 {
                println!("read from client failed");
            } else {
                unsafe { data.set_len(size) }
                println!(
                    "read {} bytes, response:{}",
                    size,
                    String::from_utf8(data).unwrap()
                );
            }
        });
    }
}
