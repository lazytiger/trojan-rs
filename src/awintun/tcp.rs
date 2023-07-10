use std::{net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use rustls::{ClientConfig, ServerName};
use tokio::{io::AsyncWriteExt, spawn};

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
    buffer_size: usize,
) {
    let client = init_tls_conn(config.clone(), buffer_size, server_addr, server_name).await;
    if let Ok(client) = client {
        let (read_half, write_half) = client.into_split();
        let (reader, writer) = local.into_split();
        spawn(local_to_remote(reader, write_half));
        spawn(remote_to_local(read_half, writer));
    }
}

pub async fn local_to_remote(mut local: TcpReadHalf, mut remote: TlsClientWriteHalf) {
    let mut request = BytesMut::new();
    TrojanRequest::generate(&mut request, CONNECT, &local.peer_addr());
    if let Err(err) = remote.write_all(request.as_ref()).await {
        log::error!("send request to remote server failed:{}", err);
        let _ = remote.shutdown().await;
        return;
    }
    let _ = tokio::io::copy(&mut local, &mut remote).await;
    local.close();
    let _ = remote.shutdown().await;
    log::info!("local to remote closed");
}

pub async fn remote_to_local(mut remote: TlsClientReadHalf, mut local: TcpWriteHalf) {
    let _ = tokio::io::copy(&mut remote, &mut local).await;
    log::info!("remote to local closed");
    let _ = local.shutdown().await;
}
