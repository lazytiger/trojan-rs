use bytes::BytesMut;
use rustls_pki_types::ServerName;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{split, AsyncWriteExt, WriteHalf},
    net::{tcp::OwnedReadHalf, TcpListener, TcpStream},
    spawn,
    sync::mpsc::UnboundedSender,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::{
    aproxy::{init_tls_conn, wait_until_stop},
    async_utils::copy,
    config::OPTIONS,
    proto::{TrojanRequest, CONNECT},
    sys,
    types::Result,
};

pub async fn run_tcp(
    listener: TcpListener,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    sender: Option<UnboundedSender<IpAddr>>,
) -> Result<()> {
    loop {
        let (client, _) = listener.accept().await?;
        let dst_addr = sys::get_oridst_addr(&client)?;
        if let Some(ref sender) = sender {
            sender.send(dst_addr.ip())?;
        }
        client.set_nodelay(true)?;
        let server_name_clone = server_name.clone();
        let connector_clone = connector.clone();
        spawn(async move {
            let ret = start_tcp_proxy(client, server_name_clone, connector_clone, dst_addr).await;
            if let Err(err) = ret {
                log::error!("tcp proxy routine exit with:{:?}", err);
            }
        });
    }
}

async fn start_tcp_proxy(
    mut local: TcpStream,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    dst_addr: SocketAddr,
) -> Result<()> {
    let mut remote = tokio::time::timeout(
        Duration::from_secs(3),
        init_tls_conn(connector, server_name),
    )
    .await??;
    let mut request = BytesMut::new();
    TrojanRequest::generate(&mut request, CONNECT, &dst_addr);
    if let Err(err) = remote.write_all(request.as_ref()).await {
        log::error!("send request to remote server failed:{}", err);
        let _ = remote.shutdown().await;
        let _ = local.shutdown().await;
    } else {
        let (remote_read, remote_write) = split(remote);
        let (local_read, local_write) = local.into_split();
        let running = Arc::new(AtomicBool::new(true));
        spawn(local_to_remote(
            running.clone(),
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
        wait_until_stop(running, dst_addr.ip()).await;
    }
    Ok(())
}

async fn local_to_remote(
    running: Arc<AtomicBool>,
    local: OwnedReadHalf,
    remote: WriteHalf<TlsStream<TcpStream>>,
    message: String,
    timeout: u64,
) {
    copy(local, remote, message, timeout).await;
    running.store(false, Ordering::SeqCst);
}
