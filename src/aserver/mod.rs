use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::{Buf, BytesMut};
use rustls::ServerConnection;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    runtime::{Handle, Runtime},
    spawn,
    sync::mpsc::{unbounded_channel, UnboundedSender},
    time::timeout,
};

use tokio_rustls::TlsServerStream;

use crate::{
    aserver::{
        ping::{start_check_routine, start_ping},
        tcp::start_tcp,
        udp::start_udp,
    },
    config::OPTIONS,
    proto::{RequestParseResult, Sock5Address, TrojanRequest, CONNECT, PING, UDP_ASSOCIATE},
    server::{init_config, ping_backend::PingResult},
    types::{Result, TrojanError},
    utils::aresolve,
};

mod ping;
mod tcp;
mod udp;

pub fn run() -> Result<()> {
    let runtime = Runtime::new()?;
    runtime.block_on(async_run())
}

async fn async_run() -> Result<()> {
    let config = init_config()?;
    let listener = TcpListener::bind(OPTIONS.local_addr.as_str()).await?;
    let (req_sender, req_receiver) = unbounded_channel();
    let task_count = Arc::new(AtomicU32::new(0));
    spawn(start_check_routine(req_receiver));
    loop {
        let (client, src_addr) = listener.accept().await?;
        log::info!("accept {}", src_addr);
        let session = ServerConnection::new(config.clone())?;
        let conn = TlsServerStream::new(client, session);
        task_count.fetch_add(1, Ordering::Relaxed);
        spawn(start_proxy(
            conn,
            req_sender.clone(),
            src_addr,
            task_count.clone(),
        ));
        log::error!(
            "connection count:{}, active task count:{}",
            task_count.load(Ordering::Relaxed),
            Handle::current().metrics().active_tasks_count()
        );
    }
}

async fn start_proxy(
    conn: TlsServerStream,
    sender: UnboundedSender<(IpAddr, UnboundedSender<PingResult>)>,
    src_addr: SocketAddr,
    task_count: Arc<AtomicU32>,
) {
    if let Err(err) = start_proxy_internal(conn, sender, src_addr).await {
        log::error!("run proxy failed:{:?}", err);
    }
    task_count.fetch_sub(1, Ordering::Relaxed);
}

async fn start_proxy_internal(
    mut conn: TlsServerStream,
    sender: UnboundedSender<(IpAddr, UnboundedSender<PingResult>)>,
    src_addr: SocketAddr,
) -> Result<()> {
    let mut buffer = BytesMut::new();
    let now = Instant::now();
    let ret = loop {
        match timeout(Duration::from_secs(10), conn.read_buf(&mut buffer)).await {
            Ok(Ok(0)) => {
                log::error!("source:{} shutdown connection", src_addr);
                break None;
            }
            Ok(Ok(n)) => {
                log::info!("read {} bytes from client {}", n, src_addr);
                match TrojanRequest::parse(buffer.as_ref()) {
                    RequestParseResult::PassThrough => {
                        break Some((CONNECT, *OPTIONS.back_addr.as_ref().unwrap()));
                    }
                    RequestParseResult::Request(request) => {
                        let offset = request.offset;
                        let cmd = request.command;
                        let address = request.address;
                        buffer.advance(offset);
                        break Some((
                            cmd,
                            match address {
                                Sock5Address::Socket(addr) => addr,
                                Sock5Address::Domain(domain, port) => {
                                    let ip =
                                        *aresolve(domain.as_str(), OPTIONS.system_dns.as_str())
                                            .await?
                                            .get(0)
                                            .ok_or(TrojanError::Resolve)?;
                                    SocketAddr::new(ip, port)
                                }
                                Sock5Address::None => *OPTIONS.back_addr.as_ref().unwrap(),
                                _ => unreachable!(),
                            },
                        ));
                    }
                    RequestParseResult::InvalidProtocol => {
                        log::error!("invalid protocol from {}", src_addr);
                        break None;
                    }
                    RequestParseResult::Continue => {
                        log::info!("incomplete trojan request, continue");
                    }
                };
            }
            Ok(Err(err)) => {
                log::error!("read from source:{} failed with {}", src_addr, err);
                break None;
            }
            Err(err) => {
                log::error!("read from source:{} timeout {}", src_addr, err);
                break None;
            }
        }
    };
    if let Some((cmd, target_addr)) = ret {
        log::info!("cmd:{} {} - {}", cmd, src_addr, target_addr);
        match cmd {
            CONNECT => start_tcp(conn, target_addr, buffer, src_addr).await,
            UDP_ASSOCIATE => start_udp(conn, buffer).await,
            PING => start_ping(conn, buffer, sender.clone()).await,
            _ => {
                unreachable!()
            }
        }
    } else {
        let time = now.elapsed().as_millis();
        log::error!(
            "read request from {} failed with {} bytes after {} ms",
            src_addr,
            buffer.len(),
            time
        );
        let _ = conn.shutdown().await;
        Ok(())
    }
}
