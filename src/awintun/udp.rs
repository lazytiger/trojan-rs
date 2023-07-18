use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, BytesMut};
use rustls::{ClientConfig, ServerName};
use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    spawn,
    sync::mpsc::{channel, Receiver, Sender},
};

use async_smoltcp::{UdpSocket, UdpWriteHalf};
use tokio_rustls::TlsClientReadHalf;

use crate::{
    awintun::init_tls_conn,
    proto::{UdpAssociate, UdpParseResultEndpoint},
};

enum DispatchReturn {
    Data(Option<(IpEndpoint, IpEndpoint, BytesMut)>),
    Socket(Option<Arc<UdpWriteHalf>>),
    Close(Option<(IpEndpoint, bool)>),
}

pub async fn run_udp_dispatch(
    mut data_receiver: Receiver<(IpEndpoint, IpEndpoint, BytesMut)>,
    mut socket_receiver: Receiver<Arc<UdpWriteHalf>>,
    server_addr: SocketAddr,
    server_name: ServerName,
    config: Arc<ClientConfig>,
    mtu: usize,
    request: Arc<BytesMut>,
    mut close_receiver: Receiver<(IpEndpoint, bool)>,
    close_sender: Sender<(IpEndpoint, bool)>,
) {
    let mut locals: HashMap<IpEndpoint, Arc<UdpWriteHalf>> = HashMap::new();
    let mut req_senders = HashMap::new();
    loop {
        let ret = tokio::select! {
            ret = data_receiver.recv() => {
                DispatchReturn::Data(ret)
            },
            ret = socket_receiver.recv() => {
                DispatchReturn::Socket(ret)
            },
            ret = close_receiver.recv() => {
                DispatchReturn::Close(ret)
            }
        };
        match ret {
            DispatchReturn::Data(ret) => {
                let (src_addr, dst_addr, data) = ret.unwrap();
                log::info!(
                    "found data {} - {} {} bytes",
                    src_addr,
                    dst_addr,
                    data.len()
                );
                if !locals.contains_key(&dst_addr) {
                    log::error!("socket:{} not found in cache", dst_addr);
                    continue;
                }
                let sender = match req_senders.get(&src_addr) {
                    Some(sender) => sender,
                    None => {
                        log::info!("remote for {} not found", src_addr);
                        let local = locals.get(&dst_addr).unwrap().clone();
                        let (req_sender, req_receiver) = channel(mtu);
                        req_senders.insert(src_addr, req_sender);

                        spawn(local_to_remote(
                            req_receiver,
                            config.clone(),
                            server_addr,
                            server_name.clone(),
                            src_addr,
                            local,
                            close_sender.clone(),
                            request.clone(),
                        ));
                        req_senders.get(&src_addr).unwrap()
                    }
                };
                let _ = sender.send((dst_addr, data)).await;
            }
            DispatchReturn::Socket(ret) => {
                let socket = ret.unwrap();
                log::info!("add socket for {}", socket.peer_addr());
                locals.insert(socket.peer_addr(), socket);
            }
            DispatchReturn::Close(ret) => {
                let (addr, is_remote) = ret.unwrap();
                log::info!("close {} {}", addr, is_remote);
                if is_remote {
                    req_senders.remove(&addr);
                    req_senders.shrink_to_fit();
                } else {
                    locals.remove(&addr);
                    locals.shrink_to_fit();
                }
            }
        }
    }
}

pub async fn start_udp(
    mut local: UdpSocket,
    data_sender: Sender<(IpEndpoint, IpEndpoint, BytesMut)>,
    close_sender: Sender<(IpEndpoint, bool)>,
) {
    let target: IpEndpoint = local.peer_addr();
    log::info!("start udp listening for {}", target);
    loop {
        match tokio::time::timeout(Duration::from_secs(120), local.recv_from()).await {
            Ok(Ok((source, data))) => {
                log::info!("receive {} bytes from {} to {}", data.len(), source, target);
                let _ = data_sender.send((source, target, data)).await;
            }
            Err(_) | Ok(Err(_)) => {
                log::info!("udp read from local failed");
                break;
            }
        }
    }
    log::info!("udp socket:{} closed", target);
    local.close().await;
    let _ = close_sender.send((target, false)).await;
}

async fn local_to_remote(
    mut receiver: Receiver<(IpEndpoint, BytesMut)>,
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    server_name: ServerName,
    src_addr: IpEndpoint,
    local: Arc<UdpWriteHalf>,
    sender: Sender<(IpEndpoint, bool)>,
    request: Arc<BytesMut>,
) {
    let dst_addr = local.peer_addr();
    let mut remote =
        if let Ok(client) = init_tls_conn(config, server_addr, server_name.clone()).await {
            let (read_half, mut write_half) = client.into_split();
            if let Err(err) = write_half.write_all(request.as_ref()).await {
                log::error!("udp send handshake failed:{}", err);
                let _ = write_half.shutdown().await;
                let _ = sender.send((src_addr, true)).await;
                return;
            }
            log::info!(
                "remote:{:?} created for source:{}",
                read_half.local_addr().await,
                src_addr
            );

            spawn(remote_to_local(read_half, local, src_addr, sender));
            write_half
        } else {
            log::error!("{} connect to remote server failed", src_addr);
            let _ = sender.send((src_addr, true)).await;
            return;
        };

    log::info!("local to remote started");
    let mut header = BytesMut::new();
    while let Some((target, data)) = receiver.recv().await {
        if data.is_empty() {
            log::warn!("empty data found");
            continue;
        }
        log::info!("send {} bytes data to {}", data.len(), target);
        header.clear();
        UdpAssociate::generate_endpoint(&mut header, &target, data.len() as u16);
        if remote.write_all(header.as_ref()).await.is_err()
            || remote.write_all(data.as_ref()).await.is_err()
        {
            log::warn!("udp write to {} failed", dst_addr);
            break;
        }
    }
    let _ = remote.shutdown().await;
    log::info!(
        "remote:{:?} shutdown now for {}",
        remote.local_addr().await,
        src_addr
    );
}

async fn remote_to_local(
    mut remote: TlsClientReadHalf,
    local: Arc<UdpWriteHalf>,
    source: IpEndpoint,
    sender: Sender<(IpEndpoint, bool)>,
) {
    log::info!("remote to local started");
    let mut buffer = BytesMut::new();
    'main: loop {
        match tokio::time::timeout(Duration::from_secs(120), remote.read_buf(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => {
                log::warn!(
                    "{} read from remote:{:?} failed",
                    source,
                    remote.local_addr().await
                );
                break;
            }
            _ => {}
        }

        loop {
            match UdpAssociate::parse_endpoint(buffer.as_ref()) {
                UdpParseResultEndpoint::Continued => {
                    log::info!("udp continue parsing with {} bytes left", buffer.len());
                    break;
                }
                UdpParseResultEndpoint::Packet(packet) => {
                    let payload = &packet.payload[..packet.length];
                    let _ = local.send_to(payload, source).await;
                    log::info!(
                        "{} - {} get one packet with size:{}",
                        packet.endpoint,
                        source,
                        payload.len()
                    );
                    buffer.advance(packet.offset);
                }
                UdpParseResultEndpoint::InvalidProtocol => {
                    log::error!(
                        "invalid protocol from {:?} to {}",
                        remote.local_addr().await,
                        source
                    );
                    break 'main;
                }
            }
        }
    }

    if let Err(err) = sender.send((source, true)).await {
        log::info!("udp channel send failed:{}", err);
    }
}
