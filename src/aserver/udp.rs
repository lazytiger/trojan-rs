use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    spawn,
    sync::mpsc::{channel, Receiver},
    time::Instant,
};

use tokio_rustls::{TlsServerStream, TlsServerWriteHalf};

use crate::{
    config::OPTIONS,
    proto::{UdpAssociate, UdpParseResult},
    types::Result,
};

pub async fn start_udp(source: TlsServerStream, mut buffer: Vec<u8>) -> Result<()> {
    let mut offset = buffer.len();
    buffer.reserve(4096 - offset);
    unsafe {
        buffer.set_len(4096);
    }
    let target = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let (mut source, source_write) = source.into_split();
    let (sender, receiver) = channel(1024);
    spawn(target_to_source(target.clone(), source_write, receiver));
    'main: loop {
        let mut data = &buffer.as_slice()[..offset];
        loop {
            match UdpAssociate::parse(data) {
                UdpParseResult::Packet(packet) => {
                    if OPTIONS.server_args().disable_udp_hole {
                        let _ = sender.send(packet.address).await;
                    }
                    if let Err(err) = target
                        .send_to(&packet.payload[..packet.length], packet.address)
                        .await
                    {
                        log::error!("send request to target failed:{}", err);
                        break 'main;
                    }
                    data = &packet.payload[packet.length..];
                }
                UdpParseResult::InvalidProtocol => {
                    break 'main;
                }
                UdpParseResult::Continued => {
                    if data.is_empty() {
                        offset = 0;
                    } else {
                        let len = data.len();
                        let remaining = offset - len;
                        buffer.copy_within(remaining..offset, 0);
                        offset = len;
                    }
                    break;
                }
            }
        }
        match source.read(&mut buffer.as_mut_slice()[offset..]).await {
            Ok(0) | Err(_) => {
                log::error!("read from source failed");
                break;
            }
            Ok(n) => {
                offset += n;
            }
        }
    }
    Ok(())
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
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(OPTIONS.udp_idle_timeout)) => {
                break;
            },
            ret = receiver.recv() => {
                *sources.entry(ret.unwrap()).or_insert_with(||Instant::now()) = Instant::now();
            },
            ret = target.recv_from(body.as_mut_slice()) => {
                if let Ok((n, target_addr)) = ret {
                    if OPTIONS.server_args().disable_udp_hole {
                        if let None = sources.get(&target_addr)
                        .map(|timeout|if timeout.elapsed().as_secs() < 60 {Some(true) }else {None})
                        .unwrap_or_default() {
                            log::error!("skip udp packet from {}", target_addr);
                            continue;
                        }
                    }
                    UdpAssociate::generate(&mut header, &target_addr, n as u16);
                    if source.write_all(header.as_ref()).await.is_err()
                            || source.write_all(&body.as_slice()[..n]).await.is_err()
                    {
                        log::error!("udp write to source failed");
                        break;
                    }
                } else {
                    log::error!("receive from target failed");
                    break;
                }
            }
        }
    }
    let _ = source.shutdown().await;
    Ok(())
}
