use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::BytesMut;
use rustls::{ClientConfig, ClientConnection, ServerName};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    spawn,
    sync::mpsc::UnboundedSender,
};

use tokio_rustls::TlsClientStream;

use crate::{
    async_utils::copy,
    config::OPTIONS,
    proto::{TrojanRequest, CONNECT},
    sys,
    types::Result,
};

pub async fn run_tcp(
    listener: TcpListener,
    server_name: ServerName,
    config: Arc<ClientConfig>,
    sender: Option<UnboundedSender<IpAddr>>,
) -> Result<()> {
    loop {
        let (client, _) = listener.accept().await?;
        let dst_addr = sys::get_oridst_addr(&client)?;
        if let Some(ref sender) = sender {
            sender.send(dst_addr.ip())?;
        }
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
    let mut remote = TlsClientStream::new(remote, session);
    let mut request = BytesMut::new();
    TrojanRequest::generate(&mut request, CONNECT, &dst_addr);
    if let Err(err) = remote.write_all(request.as_ref()).await {
        log::error!("send request to remote server failed:{}", err);
        let _ = remote.shutdown().await;
        let _ = local.shutdown().await;
    } else {
        let (remote_read, remote_write) = remote.into_split();
        let (local_read, local_write) = local.into_split();
        spawn(copy(
            local_read,
            remote_write,
            format!("tcp local to remote:{}", dst_addr),
            OPTIONS.tcp_idle_timeout,
        ));
        spawn(copy(
            remote_read,
            local_write,
            format!("tcp remote:{} to local", dst_addr),
            OPTIONS.tcp_idle_timeout,
        ));
    }
    Ok(())
}
