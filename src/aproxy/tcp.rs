use std::{net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use rustls::{ClientConfig, ClientConnection, ServerName};
use tokio::{
    io::AsyncWriteExt,
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    spawn,
};

use crate::{
    aproxy::tls_stream::{TlsClientReadHalf, TlsClientStream, TlsClientWriteHalf},
    config::OPTIONS,
    proto::{TrojanRequest, CONNECT},
    sys,
    types::Result,
};

pub async fn run_tcp(
    listener: TcpListener,
    server_name: ServerName,
    config: Arc<ClientConfig>,
) -> Result<()> {
    loop {
        let (client, _) = listener.accept().await?;
        let dst_addr = sys::get_oridst_addr(&client)?;
        client.set_nodelay(true)?;
        spawn(start_tcp_proxy(
            client,
            server_name.clone(),
            config.clone(),
            dst_addr,
        ));
    }
}

async fn start_tcp_proxy(
    mut local: TcpStream,
    server_name: ServerName,
    config: Arc<ClientConfig>,
    dst_addr: SocketAddr,
) -> Result<()> {
    let remote = TcpStream::connect(OPTIONS.back_addr.as_ref().unwrap()).await?;
    let session = ClientConnection::new(config, server_name)?;
    let mut remote = TlsClientStream::new(remote, session, 4096);
    let mut request = BytesMut::new();
    TrojanRequest::generate(&mut request, CONNECT, &dst_addr);
    if let Err(err) = remote.write_all(request.as_ref()).await {
        log::error!("send request to remote server failed:{}", err);
        let _ = remote.shutdown().await;
        let _ = local.shutdown().await;
    } else {
        let (remote_read, remote_write) = remote.into_split();
        let (local_read, local_write) = local.into_split();
        spawn(local_to_remote(local_read, remote_write));
        spawn(remote_to_local(remote_read, local_write));
    }
    Ok(())
}

async fn remote_to_local(mut remote: TlsClientReadHalf, mut local: OwnedWriteHalf) {
    if let Err(err) = tokio::io::copy(&mut remote, &mut local).await {
        log::error!("transfer from remote to local failed:{}", err);
    }
    let _ = local.shutdown().await;
}

async fn local_to_remote(mut local: OwnedReadHalf, mut remote: TlsClientWriteHalf) {
    if let Err(err) = tokio::io::copy(&mut local, &mut remote).await {
        log::error!("transfer from local to remote failed:{}", err);
    }
    let _ = remote.shutdown().await;
}
