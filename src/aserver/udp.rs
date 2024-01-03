use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, BytesMut};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, WriteHalf},
    net::{lookup_host, TcpStream, UdpSocket},
    spawn,
    sync::mpsc::{channel, Receiver},
    time::{timeout, Instant},
};
use tokio_rustls::server::TlsStream;

use crate::{
    config::OPTIONS,
    proto::{Sock5Address, UdpAssociate, UdpParseResult},
    types::Result,
    utils::is_private,
};

pub async fn start_udp(source: TlsStream<TcpStream>, mut buffer: BytesMut) -> Result<()> {
    let src_addr = source.get_ref().0.peer_addr()?;
    let target = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let (mut source, source_write) = split(source);
    let (sender, receiver) = channel(1024);
    let mut dns_cache_store = HashMap::new();
    spawn(target_to_source(target.clone(), source_write, receiver));
    let mut count = 0;
    'main: loop {
        loop {
            match UdpAssociate::parse(buffer.as_ref()) {
                UdpParseResult::Packet(packet) => {
                    let address = match packet.address {
                        Sock5Address::Socket(addr) => addr,
                        Sock5Address::Domain(domain, port) => {
                            if let Some(ip) = dns_cache_store.get(&domain) {
                                SocketAddr::new(*ip, port)
                            } else if let Ok(mut ret) = lookup_host((domain.clone(), port)).await {
                                if let Some(addr) = ret.next() {
                                    dns_cache_store.insert(domain, addr.ip());
                                    addr
                                } else {
                                    log::error!("query {} failed", domain);
                                    continue;
                                }
                            } else {
                                log::error!("query {} failed", domain);
                                continue;
                            }
                        }
                        _ => {
                            unreachable!()
                        }
                    };
                    if !OPTIONS.server_args().allow_private && is_private(&address) {
                        log::error!("address:{} is private which is not allowed", address);
                        break 'main;
                    }

                    if OPTIONS.server_args().disable_udp_hole {
                        let _ = sender.send(address).await;
                    }
                    log::info!("udp request to {}", address);
                    if let Err(err) = target
                        .send_to(&packet.payload[..packet.length], address)
                        .await
                    {
                        log::warn!("send request to target failed:{}", err);
                        break 'main;
                    }
                    buffer.advance(packet.offset);
                    count += 1;
                }
                UdpParseResult::InvalidProtocol => {
                    log::error!("invalid protocol from {:?}", src_addr);
                    break 'main;
                }
                UdpParseResult::Continued => {
                    log::info!("incomplete udp protocol, continue");
                    break;
                }
            }
        }
        match timeout(
            Duration::from_secs(OPTIONS.udp_idle_timeout),
            source.read_buf(&mut buffer),
        )
        .await
        {
            Ok(Ok(0)) => {
                log::warn!("read from source with 0 bytes");
                break;
            }
            Ok(Err(err)) => {
                log::warn!("read from source failed:{}", err);
                break;
            }
            Err(err) => {
                log::warn!("read timeout after {}", err);
                break;
            }
            Ok(Ok(_)) => {}
        }
    }
    log::warn!("udp read from proxy exit after {} packets", count);
    Ok(())
}

enum SelectResult {
    Sleep,
    Receiver(Option<SocketAddr>),
    RemoteRecv(io::Result<(usize, SocketAddr)>),
}

async fn target_to_source(
    target: Arc<UdpSocket>,
    mut source: WriteHalf<TlsStream<TcpStream>>,
    mut receiver: Receiver<SocketAddr>,
) -> Result<()> {
    let mut header = BytesMut::new();
    let mut body = vec![0u8; 1500];
    let mut sources = HashMap::new();
    loop {
        let ret = tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(OPTIONS.udp_idle_timeout)) => {
                SelectResult::Sleep
            },
            ret = receiver.recv() => {
                SelectResult::Receiver(ret)
            },
            ret = target.recv_from(body.as_mut_slice()) => {
                SelectResult::RemoteRecv(ret)
            }
        };
        match ret {
            SelectResult::Sleep => {
                log::info!("udp receive timeout");
                break;
            }
            SelectResult::Receiver(ret) => {
                if ret.is_none() {
                    log::warn!("udp channel is closed");
                    break;
                }
                *sources.entry(ret.unwrap()).or_insert_with(Instant::now) = Instant::now();
            }
            SelectResult::RemoteRecv(ret) => {
                if let Ok((n, target_addr)) = ret {
                    log::info!("get udp {} bytes response from {}", n, target_addr);
                    if OPTIONS.server_args().disable_udp_hole
                        && sources
                            .get(&target_addr)
                            .map(|timeout| {
                                if timeout.elapsed().as_secs() < 60 {
                                    Some(true)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_default()
                            .is_none()
                    {
                        log::error!("skip udp packet from {}", target_addr);
                        continue;
                    }
                    header.clear();
                    UdpAssociate::generate(&mut header, &target_addr, n as u16);
                    if source.write_all(header.as_ref()).await.is_err()
                        || source.write_all(&body.as_slice()[..n]).await.is_err()
                    {
                        log::error!("write to source from:{} failed", target_addr);
                        break;
                    }
                } else {
                    log::warn!("receive from target failed");
                    break;
                }
            }
        }
    }
    let _ = source.shutdown().await;
    log::info!("udp read from target exit");
    Ok(())
}
