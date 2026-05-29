use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, BytesMut};
use rustls_pki_types::ServerName;
use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf},
    net::TcpStream,
    spawn,
    sync::mpsc::{channel, Receiver, Sender},
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use async_smoltcp::{UdpSocket, UdpWriteHalf};

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
    server_name: ServerName<'static>,
    connector: TlsConnector,
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
            DispatchReturn::Data(Some((src_addr, dst_addr, data))) => {
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
                        let Some(local) = locals.get(&dst_addr).cloned() else {
                            log::warn!("socket:{} removed before remote creation", dst_addr);
                            continue;
                        };
                        let (req_sender, req_receiver) = channel(mtu);
                        req_senders.insert(src_addr, req_sender);

                        spawn(local_to_remote(
                            req_receiver,
                            connector.clone(),
                            server_name.clone(),
                            src_addr,
                            local,
                            close_sender.clone(),
                            request.clone(),
                        ));
                        let Some(sender) = req_senders.get(&src_addr) else {
                            log::warn!("remote sender for {} missing after insert", src_addr);
                            continue;
                        };
                        sender
                    }
                };
                let _ = sender.send((dst_addr, data)).await;
            }
            DispatchReturn::Data(None) => {
                log::info!("udp data channel closed");
                break;
            }
            DispatchReturn::Socket(Some(socket)) => {
                log::info!("add socket for {}", socket.peer_addr());
                locals.insert(socket.peer_addr(), socket);
            }
            DispatchReturn::Socket(None) => {
                log::info!("udp socket channel closed");
                break;
            }
            DispatchReturn::Close(Some((addr, is_remote))) => {
                log::info!("close {} {}", addr, is_remote);
                if is_remote {
                    req_senders.remove(&addr);
                    req_senders.shrink_to_fit();
                } else {
                    locals.remove(&addr);
                    locals.shrink_to_fit();
                }
            }
            DispatchReturn::Close(None) => {
                log::info!("udp close channel closed");
                break;
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
    connector: TlsConnector,
    server_name: ServerName<'static>,
    src_addr: IpEndpoint,
    local: Arc<UdpWriteHalf>,
    sender: Sender<(IpEndpoint, bool)>,
    request: Arc<BytesMut>,
) {
    let dst_addr = local.peer_addr();
    let (mut remote, remote_local_addr) =
        if let Ok(client) = init_tls_conn(connector, server_name.clone()).await {
            let local_addr = match client.get_ref().0.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    log::error!("get remote udp local address failed:{}", err);
                    let _ = sender.send((src_addr, true)).await;
                    return;
                }
            };
            let (read_half, mut write_half) = split(client);
            if let Err(err) = write_half.write_all(request.as_ref()).await {
                log::error!("udp send handshake failed:{}", err);
                let _ = write_half.shutdown().await;
                let _ = sender.send((src_addr, true)).await;
                return;
            }
            log::info!("remote:{:?} created for source:{}", local_addr, src_addr);

            spawn(remote_to_local(
                read_half, local_addr, local, src_addr, sender,
            ));
            (write_half, local_addr)
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
        remote_local_addr,
        src_addr
    );
}

async fn remote_to_local(
    mut remote: ReadHalf<TlsStream<TcpStream>>,
    remote_local_addr: SocketAddr,
    local: Arc<UdpWriteHalf>,
    source: IpEndpoint,
    sender: Sender<(IpEndpoint, bool)>,
) {
    log::info!("remote to local started");
    let mut buffer = BytesMut::new();
    'main: loop {
        match tokio::time::timeout(Duration::from_secs(120), remote.read_buf(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => {
                log::warn!("{} read from remote:{:?} failed", source, remote_local_addr,);
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
                        remote_local_addr,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::BytesMut;
    use rustls::{ClientConfig, RootCertStore};
    use rustls_pki_types::ServerName;
    use tokio::sync::mpsc::channel;
    use tokio_rustls::TlsConnector;

    use super::run_udp_dispatch;

    fn test_connector() -> TlsConnector {
        TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        ))
    }

    #[tokio::test]
    async fn udp_dispatch_exits_when_socket_channel_closes() {
        let (_data_sender, data_receiver) = channel(1);
        let (socket_sender, socket_receiver) = channel(1);
        let (close_sender, close_receiver) = channel(1);
        drop(socket_sender);

        let result = tokio::spawn(run_udp_dispatch(
            data_receiver,
            socket_receiver,
            ServerName::try_from("example.com").unwrap(),
            test_connector(),
            1500,
            Arc::new(BytesMut::new()),
            close_receiver,
            close_sender,
        ))
        .await;

        assert!(result.is_ok(), "udp dispatch should exit without panic");
    }

    #[test]
    fn tls_local_address_error_does_not_panic() {
        let source = include_str!("udp.rs");
        let local_addr_unwrap = concat!("local_addr()", ".unwrap()");

        assert!(
            !source.contains(local_addr_unwrap),
            "tls local address lookup can fail during shutdown and should not panic"
        );
    }
}
