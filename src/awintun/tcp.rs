use std::{net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use rustls::{ClientConfig, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    spawn,
};

use async_smoltcp::{TcpReadHalf, TcpStream, TcpWriteHalf};
use tokio_rustls::{TlsClientReadHalf, TlsClientWriteHalf};

use crate::{
    awintun::init_tls_conn,
    proto::{TrojanRequest, CONNECT},
};

pub async fn start_tcp(
    local: TcpStream,
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    server_name: ServerName,
    mtu: usize,
) {
    let client = init_tls_conn(config.clone(), mtu, server_addr, server_name).await;
    if let Ok(client) = client {
        let (read_half, write_half) = client.into_split();
        let (reader, writer) = local.into_split();
        spawn(local_to_remote(reader, write_half, mtu));
        spawn(remote_to_local(read_half, writer, mtu));
    }
}

pub async fn local_to_remote(mut local: TcpReadHalf, mut remote: TlsClientWriteHalf, mtu: usize) {
    let mut request = BytesMut::new();
    TrojanRequest::generate(&mut request, CONNECT, &local.peer_addr());
    if let Err(err) = remote.write_all(request.as_ref()).await {
        log::error!("send request to remote server failed:{}", err);
        let _ = remote.shutdown().await;
        return;
    }
    let _ = copy_stream(&mut local, &mut remote, mtu).await;
    local.close();
    let _ = remote.shutdown().await;
    log::info!("local to remote closed");
}

pub async fn remote_to_local(mut remote: TlsClientReadHalf, mut local: TcpWriteHalf, mtu: usize) {
    let _ = copy_stream(&mut remote, &mut local, mtu).await;
    log::info!("remote to local closed");
    let _ = local.shutdown().await;
}

async fn copy_stream<R, W>(reader: &mut R, writer: &mut W, mtu: usize)
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    //This should be more than mtu
    let mut buffer = vec![0u8; mtu];
    while let Ok(n) = reader.read(buffer.as_mut_slice()).await {
        if n == 0 {
            break;
        }
        if let Err(_) = writer.write_all(&buffer.as_slice()[..n]).await {
            break;
        }
    }
}
