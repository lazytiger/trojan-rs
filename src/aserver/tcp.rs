use std::{net::SocketAddr, time::Duration};

use bytes::BytesMut;
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    spawn,
};
use tokio_rustls::server::TlsStream;

use crate::{async_utils::copy, config::OPTIONS, types::Result, utils::is_private};

pub async fn start_tcp(
    mut source: TlsStream<TcpStream>,
    target_addr: SocketAddr,
    mut buffer: BytesMut,
    src_addr: SocketAddr,
) -> Result<()> {
    if target_addr == *OPTIONS.back_addr.as_ref().unwrap() {
        let mut proxy_added = false;
        for _ in 0..10 {
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
                    proxy_added = true;
                    break;
                }
                _ => {
                    if tokio::time::timeout(Duration::from_secs(1), source.read_buf(&mut buffer))
                        .await??
                        == 0
                    {
                        log::error!("read http header failed");
                        let _ = source.shutdown().await;
                        return Ok(());
                    }
                }
            }
        }
        if !proxy_added {
            log::error!(
                "[{}] header not completed after 10 retries:{}",
                src_addr,
                String::from_utf8_lossy(buffer.as_ref())
            );
        }
    } else if !OPTIONS.server_args().allow_private && is_private(&target_addr) {
        log::error!("address:{} is private which is not allowed", target_addr);
        let _ = source.shutdown().await;
        return Ok(());
    }

    log::info!("tcp backend:{}", target_addr);
    let mut target = TcpStream::connect(target_addr).await?;
    if let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_secs(5), target.write_all(buffer.as_ref())).await
    {
        log::info!("tcp send data to target:{} ok", target_addr);
    } else {
        log::error!("tcp send data to target:{} failed", target_addr);
        let _ = target.shutdown().await;
        let _ = source.shutdown().await;
        return Ok(());
    }
    let (source_read, source_write) = split(source);
    let (target_read, target_write) = target.into_split();
    spawn(copy(
        source_read,
        target_write,
        format!("tcp {} to {}", src_addr, target_addr),
        OPTIONS.tcp_idle_timeout,
    ));
    copy(
        target_read,
        source_write,
        format!("tcp {} to {}", target_addr, src_addr),
        OPTIONS.tcp_idle_timeout,
    )
    .await;
    Ok(())
}
