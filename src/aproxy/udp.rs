use std::{
    collections::HashMap,
    io,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Buf, BytesMut};
use rustls::{ClientConfig, ClientConnection, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    spawn,
    sync::mpsc::{channel, Receiver, Sender, UnboundedSender},
};

use tokio_rustls::{TlsClientReadHalf, TlsClientStream};

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
    profiler_sender: Option<UnboundedSender<IpAddr>>,
) -> Result<()> {
    let mut remotes = HashMap::new();
    let mut locals = HashMap::new();
    let empty: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut request = BytesMut::new();
    TrojanRequest::generate(&mut request, UDP_ASSOCIATE, &empty);
    let request = Arc::new(request);
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
                let mut recv_buffer = vec![0u8; 1500];
                let (size, src_addr, dst_addr) =
                    match sys::recv_from_with_destination(&listener, recv_buffer.as_mut_slice()) {
                        Ok(ret) => ret,
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            log::info!("no udp packet, ignore");
                            continue;
                        }
                        Err(err) => return Err(err.into()),
                    };
                unsafe {
                    recv_buffer.set_len(size);
                }
                log::info!(
                    "receive {} bytes data from {} to {}",
                    size,
                    src_addr,
                    dst_addr
                );
                if let Some(ref sender) = profiler_sender {
                    sender.send(dst_addr.ip())?;
                }
                let remote = match remotes.get(&src_addr) {
                    Some(ret) => ret,
                    None => {
                        log::info!("remote not found for {}", src_addr);
                        let session = ClientConnection::new(config.clone(), server_name.clone())?;
                        let local = locals.entry(dst_addr).or_insert_with(|| {
                            log::info!("local not found for {}", dst_addr);
                            let local = new_socket(dst_addr, true).unwrap();
                            let local = UdpSocket::from_std(local.into()).unwrap();
                            Arc::new(local)
                        });
                        let (req_sender, req_receiver) = channel(1024);
                        remotes.insert(src_addr, req_sender);
                        spawn(local_to_remote(
                            req_receiver,
                            local.clone(),
                            session,
                            request.clone(),
                            src_addr,
                            sender.clone(),
                        ));
                        remotes.get(&src_addr).unwrap()
                    }
                };
                let _ = remote.send((dst_addr, recv_buffer)).await;

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
                remotes.remove(&src_addr);
            }
        }
    }
}

async fn local_to_remote(
    mut local: Receiver<(SocketAddr, Vec<u8>)>,
    socket: Arc<UdpSocket>,
    session: ClientConnection,
    request: Arc<BytesMut>,
    src_addr: SocketAddr,
    sender: Sender<SocketAddr>,
) {
    let mut remote =
        if let Ok(remote) = TcpStream::connect(OPTIONS.back_addr.as_ref().unwrap()).await {
            let mut remote = TlsClientStream::new(remote, session);
            if let Err(err) = remote.write_all(request.as_ref()).await {
                let _ = remote.shutdown().await;
                let _ = sender.send(src_addr).await;
                log::error!("send handshake to remote failed:{}", err);
                return;
            }
            let (read_half, write_half) = remote.into_split();
            spawn(remote_to_local(read_half, socket, src_addr, sender));
            write_half
        } else {
            log::error!("connect to remote server failed");
            let _ = sender.send(src_addr).await;
            return;
        };

    let mut header = BytesMut::new();
    while let Some((target, data)) = local.recv().await {
        header.clear();
        UdpAssociate::generate(&mut header, &target, data.len() as u16);
        if remote.write_all(header.as_ref()).await.is_err()
            || remote.write_all(data.as_slice()).await.is_err()
        {
            break;
        }
    }
    local.close();
    let _ = remote.shutdown().await;
}

async fn remote_to_local(
    mut remote: TlsClientReadHalf,
    local: Arc<UdpSocket>,
    src_addr: SocketAddr,
    sender: Sender<SocketAddr>,
) {
    let mut buffer = BytesMut::new();
    'main: loop {
        match tokio::time::timeout(
            Duration::from_secs(OPTIONS.udp_idle_timeout),
            remote.read_buf(&mut buffer),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => loop {
                match UdpAssociate::parse(buffer.as_ref()) {
                    UdpParseResult::Continued => {
                        log::info!("udp continue parsing with {} bytes left", buffer.len());
                        break;
                    }
                    UdpParseResult::Packet(packet) => {
                        let payload = &packet.payload[..packet.length];
                        let _ = local.send_to(payload, src_addr).await;
                        log::info!(
                            "{:?} - {} get one packet with size:{}",
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
            _ => {
                log::error!("udp remote to local:{} failed, remote closed", src_addr);
                break;
            }
        }
    }
    let _ = sender.send(src_addr).await;
}
