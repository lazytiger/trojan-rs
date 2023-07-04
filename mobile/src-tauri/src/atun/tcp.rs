use bytes::BytesMut;
use rustls::{ClientConfig, ClientConnection, ServerName};
use std::{net::SocketAddr, sync::Arc};
use tokio::{io::AsyncWriteExt, spawn};

use crate::atun::{
    device::TcpStream,
    init_tls_conn,
    proto::{TrojanRequest, CONNECT},
    tls_stream::{TlsClientReadHalf, TlsClientWriteHalf},
};

pub async fn start_tcp(
    local: TcpStream,
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    server_name: ServerName,
    buffer_size: usize,
    pass: String,
) {
    match init_tls_conn(config.clone(), buffer_size, server_addr, server_name).await {
        Ok(client) => {
            let (read_half, write_half) = client.into_split();
            spawn(local_to_remote(local.clone(), write_half, pass));
            spawn(remote_to_local(read_half, local));
        }
        Err(err) => {
            log::error!("create connection to server failed:{:?}", err);
        }
    }
}

pub async fn local_to_remote(mut local: TcpStream, mut remote: TlsClientWriteHalf, pass: String) {
    let mut request = BytesMut::new();
    TrojanRequest::generate_endpoint(&mut request, CONNECT, pass.as_bytes(), &local.target);
    if let Err(err) = remote.write_all(request.as_ref()).await {
        let _ = remote.shutdown().await;
        let _ = local.shutdown().await;
        return;
    }
    if let Err(err) = tokio::io::copy(&mut local, &mut remote).await {
        log::info!("tcp local to remote failed:{}", err);
        let _ = remote.shutdown().await;
        let _ = local.shutdown().await;
    }
}

pub async fn remote_to_local(mut remote: TlsClientReadHalf, mut local: TcpStream) {
    if let Err(err) = tokio::io::copy(&mut remote, &mut local).await {
        log::info!("tcp remote to local failed:{}", err);
    }
}
