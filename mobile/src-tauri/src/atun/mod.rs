use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::BytesMut;
use rustls::{ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName};
use sha2::{Digest, Sha224};
use tokio::{net::UdpSocket, runtime::Builder, spawn, sync::mpsc::channel};
use trust_dns_proto::{
    op::{Message, Query},
    rr::{DNSClass, Name, RecordType},
    serialize::binary::BinDecodable,
};

use async_smoltcp::TunDevice;
use tokio_rustls::TlsClientStream;

use crate::{
    atun::{
        dns::start_dns,
        proto::{TrojanRequest, UDP_ASSOCIATE},
        tcp::start_tcp,
        udp::{run_udp_dispatch, start_udp},
    },
    emit_event, platform, types,
    types::{EventType, VpnError},
    Context,
};

mod dns;
mod proto;
mod tcp;
mod udp;

pub async fn init_tls_conn(
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    server_name: ServerName,
) -> types::Result<TlsClientStream> {
    let stream = tokio::net::TcpStream::connect(server_addr).await?;
    let session = ClientConnection::new(config, server_name)?;
    Ok(TlsClientStream::new(stream, session))
}

fn digest_pass(pass: &String) -> String {
    let mut encoder = Sha224::new();
    encoder.update(pass.as_bytes());
    let result = encoder.finalize();
    hex::encode(result.as_slice())
}

/// This function resolves a domain name to a list of IP addresses.
pub async fn resolve(name: &str, dns_server_addr: &str) -> types::Result<Vec<IpAddr>> {
    let dns_server_addr: SocketAddr = dns_server_addr.parse()?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut message = Message::new();
    message.set_recursion_desired(true);
    message.set_id(1);
    let mut query = Query::new();
    let name = Name::from_str(name)?;
    query.set_name(name);
    query.set_query_type(RecordType::A);
    query.set_query_class(DNSClass::IN);
    message.add_query(query);
    let request = message.to_vec()?;
    if request.len() != socket.send_to(request.as_slice(), dns_server_addr).await? {
        log::error!("send dns query to server failed");
        return Err(VpnError::Resolve);
    }
    let mut response = vec![0u8; 1024];
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            log::error!("dns query timeout");
            Err(VpnError::Resolve)
        }
        ret = socket.recv(response.as_mut_slice()) =>  {
            let length = ret?;
            let message = Message::from_bytes(&response.as_slice()[..length])?;
            if message.id() != 1 {
                log::error!("dns response id not match");
                Err(VpnError::Resolve)
            } else {
            Ok(message
                .answers()
                .iter()
                .filter_map(|record| record.data().and_then(|data| data.to_ip_addr()))
                .collect())
            }
        }
    }
}

fn show_info(level: &String) -> bool {
    level == "Debug" || level == "Info" || level == "Trace"
}

pub async fn async_run(
    fd: i32,
    dns: String,
    context: Context,
    running: Arc<AtomicBool>,
) -> types::Result<()> {
    log::error!("vpn process start running");
    let session = Arc::new(platform::Session::new(
        fd,
        context.options.mtu,
        show_info(&context.options.log_level),
    ));

    let mut server_ip = Vec::new();
    for _ in 0..10 {
        if let Ok(ips) = resolve(
            context.options.hostname.as_str(),
            (context.options.untrusted_dns.clone() + ":53").as_str(),
        )
        .await
        {
            server_ip = ips;
            break;
        }
    }
    log::info!("server ip is {:?}", server_ip);

    if server_ip.is_empty() {
        return Err(VpnError::Resolve);
    }

    let server_name: ServerName = context.options.hostname.as_str().try_into()?;

    let server_addr = SocketAddr::new(server_ip[0], context.options.port);
    let dns_addr = dns + ":53";
    let dns_addr: SocketAddr = dns_addr.parse()?;

    let pass = digest_pass(&context.options.password);

    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let mut device = TunDevice::new(context.options.mtu, session);
    device.add_white_ip(dns_addr.ip());

    let trusted_addr = (context.options.trusted_dns.clone() + ":53").parse()?;
    let distrusted_addr = (context.options.untrusted_dns.clone() + ":53").parse()?;

    let empty: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut header = BytesMut::new();
    TrojanRequest::generate(&mut header, UDP_ASSOCIATE, pass.as_bytes(), &empty);
    let udp_header = Arc::new(header);

    let (data_sender, data_receiver) = channel(128);
    let (socket_sender, socket_receiver) = channel(128);
    let (close_sender, close_receiver) = channel(128);
    spawn(run_udp_dispatch(
        data_receiver,
        socket_receiver,
        server_addr,
        server_name.clone(),
        config.clone(),
        udp_header.clone(),
        close_receiver,
        close_sender.clone(),
    ));

    let mut last_speed_time = Instant::now();
    while running.load(Ordering::Relaxed) {
        let (tcp_streams, udp_sockets) = device.poll();

        for stream in tcp_streams {
            log::info!(
                "accept tcp {} - {}",
                stream.local_addr(),
                stream.peer_addr()
            );
            spawn(start_tcp(
                stream,
                config.clone(),
                server_addr,
                server_name.clone(),
                pass.clone(),
            ));
        }
        for socket in udp_sockets {
            log::info!("accept udp to:{}", socket.peer_addr());
            if socket.peer_addr_std() == dns_addr {
                spawn(start_dns(
                    socket,
                    config.clone(),
                    server_addr,
                    server_name.clone(),
                    udp_header.clone(),
                    trusted_addr,
                    distrusted_addr,
                    context.blocked_domains.clone(),
                ));
            } else {
                log::info!("accept udp to:{}", socket.peer_addr());
                let writer = Arc::new(socket.writer());
                let _ = socket_sender.send(writer).await;
                spawn(start_udp(socket, data_sender.clone(), close_sender.clone()));
            }
        }

        if last_speed_time.elapsed().as_millis() >= context.options.speed_update_ms {
            let (rx_speed, tx_speed) = device.calculate_speed();
            let (rx_speed, rx_unit) = get_speed_and_unit(rx_speed);
            let (tx_speed, tx_unit) = get_speed_and_unit(tx_speed);
            emit_event(
                EventType::UpdateSpeed,
                format!(
                    "上行速度:{:.1}{}/s, 下行速度:{:.1}{}/s",
                    rx_speed, rx_unit, tx_speed, tx_unit
                ),
            )?;
            last_speed_time = std::time::Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    Ok(())
}

fn get_speed_and_unit(speed: f64) -> (f64, &'static str) {
    if speed >= 1024.0 {
        (speed / 1024.0, "MB")
    } else {
        (speed, "KB")
    }
}

pub fn run(fd: i32, dns: String, context: Context, running: Arc<AtomicBool>) -> types::Result<()> {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async_run(fd, dns, context, running))
}
