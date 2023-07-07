use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use bytes::{Buf, BytesMut};
use rustls::ServerConnection;
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    runtime::Runtime,
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
    proto::{Sock5Address, TrojanRequest, CONNECT, PING, UDP_ASSOCIATE},
    server::{init_config, ping_backend::PingResult},
    types::{Result, TrojanError},
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
    spawn(start_check_routine(req_receiver));
    loop {
        let (client, src_addr) = listener.accept().await?;
        let session = ServerConnection::new(config.clone())?;
        let conn = TlsServerStream::new(client, session, 4096);
        spawn(start_proxy(conn, req_sender.clone(), src_addr));
    }
}

async fn start_proxy(
    mut conn: TlsServerStream,
    sender: UnboundedSender<(IpAddr, UnboundedSender<PingResult>)>,
    src_addr: SocketAddr,
) -> Result<()> {
    let mut buffer = BytesMut::new();
    if let Ok(Ok(_)) = timeout(Duration::from_secs(120), conn.read_buf(&mut buffer)).await {
        let (cmd, target_addr) = match TrojanRequest::parse(buffer.as_ref()) {
            None => (CONNECT, *OPTIONS.back_addr.as_ref().unwrap()),
            Some(request) => {
                let offset = request.offset;
                let cmd = request.command;
                let address = request.address;
                buffer.advance(offset);
                (
                    cmd,
                    match address {
                        Sock5Address::Socket(addr) => addr,
                        Sock5Address::Domain(domain, port) => {
                            let ip = *dns_lookup::lookup_host(domain.as_str())?
                                .get(0)
                                .ok_or(TrojanError::Resolve)?;
                            SocketAddr::new(ip, port)
                        }
                        Sock5Address::None => *OPTIONS.back_addr.as_ref().unwrap(),
                        _ => unreachable!(),
                    },
                )
            }
        };
        match cmd {
            CONNECT => start_tcp(conn, target_addr, buffer, src_addr).await,
            UDP_ASSOCIATE => start_udp(conn, buffer).await,
            PING => start_ping(conn, buffer, sender.clone()).await,
            _ => {
                unreachable!()
            }
        }
    } else {
        Ok(())
    }
}
