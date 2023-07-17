use std::{net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use rustls::{ClientConfig, ServerName};
use tokio::{io::AsyncWriteExt, spawn};

use async_smoltcp::{TcpReadHalf, TcpStream, TcpWriteHalf};
use tokio_rustls::{TlsClientReadHalf, TlsClientWriteHalf};

use crate::atun::{
    init_tls_conn,
    proto::{TrojanRequest, CONNECT},
};

pub async fn start_tcp(
    mut local: TcpStream,
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    server_name: ServerName,
    pass: String,
) {
    if local.peer_addr().ip() == server_addr.ip() {
        if let Ok(remote) = tokio::net::TcpStream::connect(local.peer_addr()).await {
            let (mut local_read, mut local_write) = local.into_split();
            let (mut remote_read, mut remote_write) = remote.into_split();
            spawn(async move {
                let _ = tokio::io::copy(&mut local_read, &mut remote_write).await;
                let _ = remote_write.shutdown().await;
                local_read.close();
            });
            spawn(async move {
                let _ = tokio::io::copy(&mut remote_read, &mut local_write).await;
                let _ = local_write.shutdown().await;
            });
        } else {
            let _ = local.shutdown().await;
        }
    } else {
        let client = init_tls_conn(config.clone(), server_addr, server_name).await;
        if let Ok(client) = client {
            let (read_half, write_half) = client.into_split();
            let (reader, writer) = local.into_split();
            spawn(local_to_remote(reader, write_half, pass));
            spawn(remote_to_local(read_half, writer));
        }
    }
}

pub async fn local_to_remote(mut local: TcpReadHalf, mut remote: TlsClientWriteHalf, pass: String) {
    let mut request = BytesMut::new();
    TrojanRequest::generate(&mut request, CONNECT, pass.as_bytes(), &local.peer_addr());
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
