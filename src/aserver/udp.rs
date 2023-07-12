use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    spawn,
    sync::mpsc::{channel, Receiver},
    time::{timeout, Instant},
};

use tokio_rustls::{TlsServerStream, TlsServerWriteHalf};

use crate::{
    config::OPTIONS,
    proto::{UdpAssociate, UdpParseResult},
    types::Result,
};

pub async fn start_udp(source: TlsServerStream, mut buffer: BytesMut) -> Result<()> {
    let src_addr = source.peer_addr();
    let target = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let (mut source, source_write) = source.into_split();
    let (sender, receiver) = channel(1024);
    spawn(target_to_source(target.clone(), source_write, receiver));
    'main: loop {
        loop {
            match UdpAssociate::parse(buffer.as_ref()) {
                UdpParseResult::Packet(packet) => {
                    if OPTIONS.server_args().disable_udp_hole {
                        let _ = sender.send(packet.address).await;
                    }
                    log::info!("udp request to {}", packet.address);
                    if let Err(err) = target
                        .send_to(&packet.payload[..packet.length], packet.address)
                        .await
                    {
                        log::warn!("send request to target failed:{}", err);
                        break 'main;
                    }
                    buffer.advance(packet.offset);
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
                log::error!("read from source with 0 bytes");
                break;
            }
            Ok(Err(err)) => {
                log::error!("read from source failed:{}", err);
                break;
            }
            Err(err) => {
                log::error!("read timeout after {}", err);
                break;
            }
            Ok(Ok(_)) => {}
        }
    }
    log::info!("udp read from proxy exit");
    Ok(())
}

enum SelectResult {
    Sleep,
    Receiver(Option<SocketAddr>),
    RemoteRecv(io::Result<(usize, SocketAddr)>),
}

async fn target_to_source(
    target: Arc<UdpSocket>,
    mut source: TlsServerWriteHalf,
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
                *sources
                    .entry(ret.unwrap())
                    .or_insert_with(|| Instant::now()) = Instant::now();
            }
            SelectResult::RemoteRecv(ret) => {
                if let Ok((n, target_addr)) = ret {
                    log::info!("get udp {} bytes response from {}", n, target_addr);
                    if OPTIONS.server_args().disable_udp_hole {
                        if let None = sources
                            .get(&target_addr)
                            .map(|timeout| {
                                if timeout.elapsed().as_secs() < 60 {
                                    Some(true)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_default()
                        {
                            log::error!("skip udp packet from {}", target_addr);
                            continue;
                        }
                    }
                    header.clear();
                    UdpAssociate::generate(&mut header, &target_addr, n as u16);
                    let _ = source.write_all(header.as_ref()).await;
                    let _ = source.write_all(&body.as_slice()[..n]).await;
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
