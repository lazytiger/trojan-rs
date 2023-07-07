use std::{collections::HashMap, io, io::ErrorKind, net::SocketAddr, sync::Arc, time::Instant};

use bytes::{Buf, BytesMut};
use rustls::{ClientConfig, ClientConnection, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    spawn,
    sync::mpsc::{channel, Sender},
};

use tokio_rustls::{TlsClientReadHalf, TlsClientStream, TlsClientWriteHalf};

use crate::{
    aproxy::new_socket,
    config::OPTIONS,
    proto::{TrojanRequest, UdpAssociate, UdpParseResult, UDP_ASSOCIATE},
    sys,
    types::Result,
};

enum SelectResult {
    Listener(io::Result<SocketAddr>),
    Receiver(Option<SocketAddr>),
}

pub async fn run_udp(
    listener: UdpSocket,
    server_name: ServerName,
    config: Arc<ClientConfig>,
) -> Result<()> {
    let mut recv_buffer = vec![0u8; 1500];
    let mut remotes: HashMap<SocketAddr, TlsClientWriteHalf> = HashMap::new();
    let mut locals = HashMap::new();
    let empty: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut request = BytesMut::new();
    TrojanRequest::generate(&mut request, UDP_ASSOCIATE, &empty);
    let mut header = BytesMut::new();
    let last_check = Instant::now();
    let (sender, mut receiver) = channel(1024);
    loop {
        let ret = tokio::select! {
            ret = listener.peek_sender() => {
                SelectResult::Listener(ret)
            },
            ret = receiver.recv() => {
                SelectResult::Receiver(ret)
            }
        };
        match ret {
            SelectResult::Listener(ret) => {
                ret?;
                let (size, src_addr, dst_addr) =
                    match sys::recv_from_with_destination(&listener, recv_buffer.as_mut_slice()) {
                        Ok(ret) => ret,
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            log::info!("no udp packet, ignore");
                            continue;
                        }
                        Err(err) => return Err(err.into()),
                    };
                log::info!(
                    "receive {} bytes data from {} to {}",
                    size,
                    src_addr,
                    dst_addr
                );
                let remote = match remotes.get_mut(&src_addr) {
                    Some(ret) => ret,
                    None => {
                        log::info!("remote not found for {}", src_addr);
                        let session = ClientConnection::new(config.clone(), server_name.clone())?;
                        let remote =
                            TcpStream::connect(OPTIONS.back_addr.as_ref().unwrap()).await?;
                        let mut remote = TlsClientStream::new(remote, session, 4096);
                        if let Err(err) = remote.write_all(request.as_ref()).await {
                            log::error!("send handshake to remote failed:{}", err);
                            continue;
                        }
                        let local = locals.entry(dst_addr).or_insert_with(|| {
                            log::info!("local not found for {}", dst_addr);
                            let local = new_socket(dst_addr, true).unwrap();
                            let local = UdpSocket::from_std(local.into()).unwrap();
                            Arc::new(local)
                        });
                        let (read_half, write_half) = remote.into_split();
                        spawn(remote_to_local(
                            read_half,
                            local.clone(),
                            src_addr,
                            sender.clone(),
                        ));
                        remotes.insert(src_addr, write_half);
                        remotes.get_mut(&src_addr).unwrap()
                    }
                };
                header.clear();
                UdpAssociate::generate(&mut header, &dst_addr, size as u16);
                if remote.write_all(header.as_ref()).await.is_err()
                    || remote
                        .write_all(&recv_buffer.as_slice()[..size])
                        .await
                        .is_err()
                {
                    log::error!("send request to remote failed");
                    let _ = remote.shutdown().await;
                    remotes.remove(&src_addr);
                }

                if last_check.elapsed().as_secs() > 3600 {
                    let addrs: Vec<_> = locals
                        .iter()
                        .filter_map(|(k, v)| {
                            if Arc::strong_count(v) == 1 {
                                Some(*k)
                            } else {
                                None
                            }
                        })
                        .collect();
                    for addr in addrs {
                        log::info!("udp socket:{} expired", addr);
                        locals.remove(&addr);
                    }
                }
            }
            SelectResult::Receiver(ret) => {
                let src_addr = ret.unwrap();
                if let Some(remote) = remotes.get_mut(&src_addr) {
                    log::info!("remote closed for {}", src_addr);
                    let _ = remote.shutdown().await;
                    remotes.remove(&src_addr);
                }
            }
        }
    }
}

async fn remote_to_local(
    mut remote: TlsClientReadHalf,
    local: Arc<UdpSocket>,
    src_addr: SocketAddr,
    sender: Sender<SocketAddr>,
) {
    let mut buffer = BytesMut::new();
    'main: loop {
        match remote.read_buf(&mut buffer).await {
            Err(_) | Ok(0) => {
                log::error!("udp remote to local:{} failed, remote closed", src_addr);
                break;
            }
            Ok(_) => loop {
                match UdpAssociate::parse(buffer.as_ref()) {
                    UdpParseResult::Continued => {
                        log::info!("udp continue parsing with {} bytes left", buffer.len());
                        break;
                    }
                    UdpParseResult::Packet(packet) => {
                        let payload = &packet.payload[..packet.length];
                        let _ = local.send_to(payload, src_addr).await;
                        log::info!(
                            "{} - {} get one packet with size:{}",
                            packet.address,
                            src_addr,
                            payload.len()
                        );
                        buffer.advance(packet.offset);
                    }
                    UdpParseResult::InvalidProtocol => {
                        log::info!("invalid protocol close now");
                        break 'main;
                    }
                }
            },
        }
    }
    let _ = sender.send(src_addr).await;
}
