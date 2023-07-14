use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Buf, BufMut, BytesMut};
use surge_ping::{Client, ConfigBuilder, PingIdentifier, PingSequence, ICMP};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
};

use tokio_rustls::TlsServerStream;

use crate::{config::OPTIONS, proto, server::ping_backend::PingResult, types::Result};

enum SelectResult {
    Request(Option<(IpAddr, UnboundedSender<PingResult>)>),
    Response(Option<PingResult>),
}

pub async fn start_check_routine(
    mut req_receiver: UnboundedReceiver<(IpAddr, UnboundedSender<PingResult>)>,
) {
    let (resp_sender, mut resp_receiver) = unbounded_channel();
    let config = ConfigBuilder::default().kind(ICMP::V4).build();
    let client4 = Arc::new(Client::new(&config).unwrap());
    let config = ConfigBuilder::default().kind(ICMP::V6).build();
    let client6 = Arc::new(Client::new(&config).unwrap());
    let mut id = 0u16;
    let mut cache_results: HashMap<IpAddr, PingResult> = HashMap::new();
    let mut cache_senders: HashMap<IpAddr, Vec<UnboundedSender<PingResult>>> = HashMap::new();
    loop {
        let ret = tokio::select! {
            ret = req_receiver.recv() => {
                SelectResult::Request(ret)

            },
            ret = resp_receiver.recv() => {
                SelectResult::Response(ret)

            }
        };
        match ret {
            SelectResult::Request(ret) => {
                let (ip, sender) = ret.unwrap();
                if let Some(result) = cache_results.get(&ip) {
                    if result.time.elapsed().as_secs() < OPTIONS.server_args().cached_ping_timeout {
                        let _ = sender.send(result.clone());
                        continue;
                    }
                }
                if cache_senders.get(&ip).is_none() {
                    let client = match ip {
                        IpAddr::V4(_) => client4.clone(),
                        IpAddr::V6(_) => client6.clone(),
                    };
                    tokio::spawn(do_check(ip, id, client, resp_sender.clone()));
                    id = id.wrapping_add(1);
                }
                cache_senders.entry(ip).or_default().push(sender);
            }
            SelectResult::Response(ret) => {
                let result = ret.unwrap();
                if let Some(senders) = cache_senders.remove(&result.ip) {
                    for sender in senders {
                        let _ = sender.send(result.clone());
                    }
                }
                cache_senders.shrink_to_fit();
                cache_results.insert(result.ip, result);
            }
        }
    }
}

async fn do_check(ip: IpAddr, id: u16, client: Arc<Client>, sender: UnboundedSender<PingResult>) {
    let mut pinger = client.pinger(ip, PingIdentifier(id)).await;
    pinger.timeout(Duration::from_millis(999));
    let mut received = 0;
    let mut avg_cost = 0;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    for i in 0..100u128 {
        interval.tick().await;
        if let Ok((_, cost)) = pinger.ping(PingSequence(i as u16), &[]).await {
            avg_cost = ((avg_cost * received) + cost.as_millis()) / (received + 1);
            received += 1;
        }
    }
    if let Err(err) = sender.send(PingResult {
        ip,
        lost: (100 - received) as u8,
        ping: avg_cost as u16,
        time: Instant::now(),
    }) {
        log::error!("send result failed:{}", err);
    }
}

pub async fn start_ping(
    mut source: TlsServerStream,
    mut recv_buffer: BytesMut,
    req_sender: UnboundedSender<(IpAddr, UnboundedSender<PingResult>)>,
) -> Result<()> {
    let mut send_buffer = BytesMut::new();
    let mut request: Option<PingResult> = None;
    let (resp_sender, mut resp_receiver) = unbounded_channel();
    'main: loop {
        if let Some(pr) = request {
            send_buffer.clear();
            match pr.ip {
                IpAddr::V4(ip) => {
                    send_buffer.put_u8(proto::IPV4);
                    send_buffer.extend_from_slice(ip.octets().as_slice());
                }
                IpAddr::V6(ip) => {
                    send_buffer.put_u8(proto::IPV6);
                    send_buffer.extend_from_slice(ip.octets().as_slice())
                }
            };
            send_buffer.put_u16(pr.ping);
            send_buffer.put_u8(pr.lost);
            if let Err(err) = source.write_all(send_buffer.as_ref()).await {
                log::error!("send ping result to source failed:{}", err);
                break;
            }
        } else {
            while !recv_buffer.is_empty() {
                let addr: IpAddr = match *recv_buffer.first().unwrap() {
                    proto::IPV4 => {
                        if recv_buffer.len() < 5 {
                            break;
                        }
                        let mut data = [0u8; 4];
                        data.copy_from_slice(&recv_buffer.as_ref()[1..5]);
                        recv_buffer.advance(5);
                        Ipv4Addr::from(data).into()
                    }
                    proto::IPV6 => {
                        if recv_buffer.len() < 17 {
                            break;
                        }
                        let mut data = [0u8; 16];
                        data.copy_from_slice(&recv_buffer.as_ref()[1..17]);
                        recv_buffer.advance(17);
                        Ipv6Addr::from(data).into()
                    }
                    _ => {
                        log::error!("invalid address type, close connection");
                        break 'main;
                    }
                };
                if addr.is_unspecified() {
                    log::error!("invalid ping protocol, unspecified address is not allowed");
                    break 'main;
                }
                let _ = req_sender.send((addr, resp_sender.clone()));
            }
        }

        request = tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(3600)) => {
                break;
            },
            ret = resp_receiver.recv() => {
                let result = ret.unwrap();
                Some(result)
            },
            ret = source.read_buf(&mut recv_buffer) => {
                match ret {
                   Ok(0) | Err(_) => {
                        log::error!("read from source failed");
                        break;
                    }
                    Ok(_) => {
                        None
                    }
                }
            }
        };
    }
    let _ = source.shutdown().await;
    Ok(())
}
