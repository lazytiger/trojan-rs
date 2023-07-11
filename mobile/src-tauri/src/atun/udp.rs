use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, BytesMut};
use rustls::{ClientConfig, ServerName};
use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    spawn,
    sync::mpsc::Sender,
};

use async_smoltcp::{UdpSocket, UdpWriteHalf};
use tokio_rustls::TlsClientReadHalf;

use crate::atun::{
    init_tls_conn,
    proto::{UdpAssociate, UdpParseResultEndpoint},
};

enum SelectResult {
    Timeout,
    Socket(std::io::Result<(IpEndpoint, Vec<u8>)>),
    Receiver(Option<IpEndpoint>),
}

pub async fn start_udp(
    mut local: UdpSocket,
    server_addr: SocketAddr,
    server_name: ServerName,
    config: Arc<ClientConfig>,
    buffer_size: usize,
    request: Arc<BytesMut>,
) {
    if local.peer_addr().ip() == server_addr.ip() {
        log::error!("ignore udp request to server");
        local.close().await;
        return;
    }
    let target = local.peer_addr().into();
    log::info!("start udp listening for {}", target);
    let mut remotes = HashMap::new();
    let mut header = BytesMut::new();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1024);
    loop {
        let ret = tokio::select! {
            ret = local.recv_from() => {
                SelectResult::Socket(ret)
            },
            _ = tokio::time::sleep(Duration::from_secs(120)) => {
                SelectResult::Timeout
            },
            ret = receiver.recv() => {
                SelectResult::Receiver(ret)
            }
        };
        match ret {
            SelectResult::Timeout => {
                log::info!("timeout for udp {}", target);
                if remotes.is_empty() {
                    break;
                }
            }
            SelectResult::Socket(ret) => match ret {
                Ok((source, data)) => {
                    log::info!("receive {} bytes from {} to {}", data.len(), source, target);
                    let remote = match remotes.get_mut(&source) {
                        Some(write_half) => write_half,
                        None => {
                            if let Ok(client) = init_tls_conn(
                                config.clone(),
                                buffer_size,
                                server_addr,
                                server_name.clone(),
                            )
                            .await
                            {
                                let (read_half, mut write_half) = client.into_split();
                                if let Err(err) = write_half.write_all(request.as_ref()).await {
                                    log::error!("udp send handshake failed:{}", err);
                                    let _ = write_half.shutdown().await;
                                    continue;
                                }

                                spawn(remote_to_local(
                                    read_half,
                                    local.writer(),
                                    source,
                                    sender.clone(),
                                ));
                                remotes.insert(source, write_half);
                                remotes.get_mut(&source).unwrap()
                            } else {
                                continue;
                            }
                        }
                    };
                    header.clear();
                    UdpAssociate::generate_endpoint(&mut header, &target, data.len() as u16);
                    let _ = remote.write_all(header.as_ref()).await;
                    let _ = remote.write_all(data.as_slice()).await;
                }
                Err(err) => {
                    log::info!("udp read from local failed:{}", err);
                    break;
                }
            },
            SelectResult::Receiver(ret) => {
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
    log::info!("udp socket:{} closed", target);
    local.close().await;
}

pub async fn remote_to_local(
    mut remote: TlsClientReadHalf,
    local: UdpWriteHalf,
    target: IpEndpoint,
    sender: Sender<IpEndpoint>,
) {
    let mut buffer = BytesMut::new();
    'main: loop {
        let timeout = tokio::time::sleep(Duration::from_secs(120));
        tokio::select! {
            _ = timeout => {
                break;
            }
            ret = remote.read_buf(&mut buffer) => {
                match ret {
                    Err(_) | Ok(0) => {
                        log::error!("udp read from remote failed");
                        break;
                    }
                    Ok(_) => {
                    }
                }
            }
        }

        loop {
            match UdpAssociate::parse_endpoint(buffer.as_ref()) {
                UdpParseResultEndpoint::Continued => {
                    log::info!("udp continue parsing with {} bytes left", buffer.len());
                    break;
                }
                UdpParseResultEndpoint::Packet(packet) => {
                    let payload = &packet.payload[..packet.length];
                    let _ = local.send_to(payload, target).await;
                    log::info!(
                        "{} - {} get one packet with size:{}",
                        packet.endpoint,
                        target,
                        payload.len()
                    );
                    buffer.advance(packet.offset);
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
