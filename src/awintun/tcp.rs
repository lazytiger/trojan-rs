use std::{net::SocketAddr, time::Duration};

use bytes::BytesMut;
use rustls_pki_types::ServerName;
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    spawn,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use async_smoltcp::{TcpReadHalf, TcpStream, TcpWriteHalf};

use crate::{
    awintun::init_tls_conn,
    config::OPTIONS,
    proto::{TrojanRequest, CONNECT},
};

pub async fn start_tcp(
    local: TcpStream,
    connector: TlsConnector,
    server_name: ServerName<'static>,
) {
    let client = init_tls_conn(connector, server_name).await;
    if let Ok(client) = client {
        let dst_addr = client.get_ref().0.peer_addr().unwrap();
        let (read_half, write_half) = split(client);
        let (reader, writer) = local.into_split();
        spawn(local_to_remote(reader, write_half));
        spawn(remote_to_local(dst_addr, read_half, writer));
    }
}

pub async fn local_to_remote(
    mut local: TcpReadHalf,
    mut remote: WriteHalf<TlsStream<tokio::net::TcpStream>>,
) {
    let mut request = BytesMut::new();
    TrojanRequest::generate(&mut request, CONNECT, &local.peer_addr());
    if let Err(err) = remote.write_all(request.as_ref()).await {
        log::error!("send request to remote server failed:{}", err);
        let _ = remote.shutdown().await;
        return;
    }
    let dst_addr = local.peer_addr();
    let _ = copy_stream(
        &mut local,
        &mut remote,
        format!("local to remote:{}", dst_addr),
    )
    .await;
    local.close();
    let _ = remote.shutdown().await;
    log::info!("local to remote closed");
}

pub async fn remote_to_local(
    dst_addr: SocketAddr,
    mut remote: ReadHalf<TlsStream<tokio::net::TcpStream>>,
    mut local: TcpWriteHalf,
) {
    let _ = copy_stream(
        &mut remote,
        &mut local,
        format!("remote:{:?} to local", dst_addr),
    )
    .await;
    log::info!("remote to local closed");
    let _ = local.shutdown().await;
}

async fn copy_stream<R, W>(reader: &mut R, writer: &mut W, message: String)
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buffer = vec![0u8; 4096];
    while let Ok(Ok(n)) = tokio::time::timeout(
        Duration::from_secs(OPTIONS.tcp_idle_timeout),
        reader.read(buffer.as_mut_slice()),
    )
    .await
    {
        if n == 0 {
            log::warn!("tcp {} failed, read shutdown", message);
            break;
        }
        if writer.write_all(&buffer.as_slice()[..n]).await.is_err() {
            log::warn!("tcp {} failed, write shutdown", message);
            break;
        }
    }
}
