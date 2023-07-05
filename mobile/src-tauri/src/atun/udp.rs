use std::{collections::HashMap, future::Future, net::SocketAddr, sync::Arc, time::Duration};

use bytes::BytesMut;
use rustls::{ClientConfig, ClientConnection, ServerName};
use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    spawn,
    sync::mpsc::Sender,
    task::spawn_blocking,
};

use crate::atun::{
    device::UdpStream,
    init_tls_conn,
    proto::{TrojanRequest, UdpAssociate, UdpParseResultEndpoint, UDP_ASSOCIATE},
    tls_stream::{TlsClientReadHalf, TlsClientStream, TlsClientWriteHalf},
};

pub async fn start_udp(
    mut local: UdpStream,
    server_addr: SocketAddr,
    server_name: ServerName,
    config: Arc<ClientConfig>,
    buffer_size: usize,
    request: Arc<BytesMut>,
) {
    let target = local.target;
    log::info!("start udp listening for {}", target);
    let mut remotes = HashMap::new();
    let mut body = vec![0u8; 1500];
    let mut header = BytesMut::new();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1024);
    loop {
        let timeout = tokio::time::sleep(Duration::from_secs(120));
        let recv = local.recv(body.as_mut_slice());
        tokio::select! {
            ret = recv => {
                match ret {
                    Ok((n, source)) => {
                        log::info!("receive {} bytes from {} to {}", n, source, target);
                        let remote = match remotes.get_mut(&source) {
                            Some(write_half) => write_half,
                            None => {
                                let client = init_tls_conn(
                                    config.clone(),
                                    buffer_size,
                                    server_addr,
                                    server_name.clone())
                                .await;
                                if let Err(err) = client {
                                    log::error!("create tls connection failed:{:?}", err);
                                    continue;
                                }
                                let client = client.unwrap();
                                let (read_half, mut write_half) = client.into_split();
                                if let Err(err) = write_half.write_all(request.as_ref()).await {
                                    log::error!("udp send handshake failed:{}", err);
                                    let _ = write_half.shutdown().await;
                                    continue;
                                }

                                spawn(remote_to_local(
                                    read_half,
                                    local.clone(),
                                    source,
                                    sender.clone(),
                                ));
                                remotes.insert(source, write_half);
                                remotes.get_mut(&source).unwrap()
                            }
                        };
                        header.clear();
                        UdpAssociate::generate_endpoint(
                            &mut header,
                            &target,
                            n as u16,
                        );
                        let _= remote.write_all(header.as_ref()).await;
                        let _= remote.write_all(&body.as_slice()[..n]).await;
                    }
                    Err(err) => {
                        log::info!("udp read from local failed:{}", err);
                        break;
                    }
                }
            },
            _ = timeout => {
                log::info!("timeout for udp {}", target);
                if remotes.is_empty() {
                    break;
                }
            },
            ret = receiver.recv() => {
                if let Some(source) = ret {
                    log::info!("udp source:{} remote closed", source);
                    if let Some(remote) = remotes.get_mut(&source) {
                        let _ = remote.shutdown().await;
                        remotes.remove(&source);
                    }
                } else {
                    log::error!("udp channel is closed");
                }
            }
        }
    }

    let _ = local.shutdown().await;
}

pub async fn remote_to_local(
    mut remote: TlsClientReadHalf,
    mut local: UdpStream,
    target: IpEndpoint,
    sender: Sender<IpEndpoint>,
) {
    let mut buffer = vec![0u8; 2048];
    let mut offset = 0;
    'main: loop {
        let timeout = tokio::time::sleep(Duration::from_secs(120));
        tokio::select! {
            _ = timeout => {
                break;
            }
            ret = remote.read(&mut buffer.as_mut_slice()[offset..]) => {
                match ret {
                    Err(_) | Ok(0) => {
                        log::error!("udp read from remote failed");
                        break;
                    }
                    Ok(n) => {
                        offset += n;
                    }
                }
            }
        }

        let mut data = &buffer.as_slice()[..offset];
        loop {
            match UdpAssociate::parse_endpoint(data) {
                UdpParseResultEndpoint::Continued => {
                    if data.is_empty() {
                        offset = 0;
                    } else {
                        let len = data.len();
                        let remaining = offset - len;
                        buffer.copy_within(remaining..offset, 0);
                        offset = len;
                    }
                    log::info!("udp continue parsing with {} bytes left", offset);
                    break;
                }
                UdpParseResultEndpoint::Packet(packet) => {
                    let payload = &packet.payload[..packet.length];
                    let _ = local.send(payload, target).await;
                    log::info!(
                        "{} - {} get one packet with size:{}",
                        packet.endpoint,
                        target,
                        payload.len()
                    );
                    data = &packet.payload[packet.length..];
                }
                UdpParseResultEndpoint::InvalidProtocol => {
                    log::info!("invalid protocol close now");
                    break 'main;
                }
            }
        }
    }
    if let Err(err) = sender.send(target).await {
        log::error!("udp channel send failed:{}", err);
    }
}
