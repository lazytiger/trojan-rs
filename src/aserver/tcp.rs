use std::{net::SocketAddr, time::Duration};

use bytes::BytesMut;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    spawn,
};
use tokio_rustls::TlsServerStream;

use crate::{config::OPTIONS, types::Result};

pub async fn start_tcp(
    mut source: TlsServerStream,
    target_addr: SocketAddr,
    mut buffer: BytesMut,
    src_addr: SocketAddr,
) -> Result<()> {
    if target_addr == *OPTIONS.back_addr.as_ref().unwrap() {
        let mut headers = [httparse::EMPTY_HEADER; 100];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(buffer.as_ref()) {
            Ok(httparse::Status::Complete(offset)) => {
                log::error!("X-Forwarded-For: {}", src_addr);
                let data = buffer.split_off(offset - 2);
                buffer.extend_from_slice(b"X-Forwarded-For: ");
                buffer.extend_from_slice(src_addr.ip().to_string().as_bytes());
                buffer.extend_from_slice(b"\r\n");
                buffer.unsplit(data);
            }
            _ => {
                log::error!("http request not completed, ignore now");
            }
        }
    }

    let mut target = TcpStream::connect(target_addr).await?;
    if let Err(err) = target.write_all(buffer.as_ref()).await {
        let _ = target.shutdown().await;
        let _ = source.shutdown().await;
        log::error!("tcp send data to target failed:{}", err);
        return Ok(());
    }
    let (source_read, source_write) = source.into_split();
    let (target_read, target_write) = target.into_split();
    spawn(copy(
        source_read,
        target_write,
        "tcp source to target".to_string(),
        OPTIONS.tcp_idle_timeout,
    ));
    spawn(copy(
        target_read,
        source_write,
        "tcp target to source".to_string(),
        OPTIONS.tcp_idle_timeout,
    ));
    Ok(())
}

async fn copy<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    mut read: R,
    mut write: W,
    message: String,
    timeout: u64,
) {
    let mut buffer = vec![0u8; 4096];
    loop {
        if let Ok(Ok(n)) = tokio::time::timeout(
            Duration::from_secs(timeout),
            read.read(buffer.as_mut_slice()),
        )
        .await
        {
            if let Err(err) = write.write_all(&buffer.as_slice()[..n]).await {
                log::error!("{} write failed:{}", message, err);
                break;
            } else {
                log::error!("{} read failed", message);
            }
        }
    }
    let _ = write.shutdown().await;
}
