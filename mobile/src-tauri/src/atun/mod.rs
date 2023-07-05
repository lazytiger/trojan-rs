use std::{
    cell::RefCell,
    io::Read,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime},
};

use bytes::BytesMut;
use rustls::{ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName};
use sha2::{Digest, Sha224};
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tauri::utils;
use tokio::{net::UdpSocket, spawn};
use trust_dns_proto::{
    op::{Message, Query},
    rr::{DNSClass, Name, RecordType},
    serialize::binary::BinDecodable,
};

use crate::{
    atun::{
        device::{UdpStream, VpnDevice},
        dns::start_dns,
        proto::{TrojanRequest, UDP_ASSOCIATE},
        tcp::start_tcp,
        tls_stream::TlsClientStream,
        udp::start_udp,
    },
    emit_event, platform, types,
    types::{EventType, VpnError},
    Context,
};

mod device;
mod dns;
mod proto;
mod tcp;
mod tls_stream;
mod udp;

pub async fn init_tls_conn(
    config: Arc<ClientConfig>,
    buffer_size: usize,
    server_addr: SocketAddr,
    server_name: ServerName,
) -> types::Result<TlsClientStream> {
    let stream = tokio::net::TcpStream::connect(server_addr).await?;
    let session = ClientConnection::new(config, server_name)?;
    TlsClientStream::new(stream, session, buffer_size)
}

fn prepare_device(device: &mut VpnDevice) -> Interface {
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut interface = Interface::new(config, device, smoltcp::time::Instant::now());
    interface.set_any_ip(true);
    interface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
        .unwrap();

    interface.update_ip_addrs(|ips| {
        ips.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)).unwrap();
    });
    interface
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
    let mut socket = UdpSocket::bind("0.0.0.0:0").await?;
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

pub async fn run(
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

    let server_ip = resolve(
        context.options.hostname.as_str(),
        (context.options.untrusted_dns.clone() + ":53").as_str(),
    )
    .await?;
    log::info!("server ip is {:?}", server_ip);

    if server_ip.is_empty() {
        return Err(VpnError::Resolve);
    }

    let server_name: ServerName = context.options.hostname.as_str().try_into()?;

    let server_addr = SocketAddr::new(server_ip[0], context.options.port);
    let dns_addr = dns + ":53";
    let dns_addr: IpEndpoint = dns_addr.parse().unwrap();

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
    let sockets = unsafe { std::mem::transmute(SocketSet::new([])) };
    let mut device = VpnDevice::new(
        session.clone(),
        sockets,
        context.options.mtu,
        server_addr.into(),
        dns_addr,
    );

    let mut interface = prepare_device(&mut device);

    let dns_handle = device.create_udp_socket(dns_addr.into());

    let device = Arc::new(Mutex::new(device));

    let trusted_addr = (context.options.trusted_dns.clone() + ":53").parse()?;
    let distrusted_addr = (context.options.untrusted_dns.clone() + ":53").parse()?;

    let dns_socket = VpnDevice::new_udp(&device, dns_handle, dns_addr).await;
    let empty: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut header = BytesMut::new();
    TrojanRequest::generate(&mut header, UDP_ASSOCIATE, pass.as_bytes(), &empty);
    let udp_header = Arc::new(header);

    spawn(start_dns(
        dns_socket,
        config.clone(),
        server_addr,
        server_name.clone(),
        4096,
        udp_header.clone(),
        trusted_addr,
        distrusted_addr,
        context.blocked_domains,
    ));
    let mut last_speed_time = Instant::now();
    while running.load(Ordering::Relaxed) {
        let mut lock = device.lock().unwrap();
        lock.poll(&mut interface);
        drop(lock);

        if last_speed_time.elapsed().as_millis() >= context.options.speed_update_ms {
            let mut lock = device.lock().unwrap();
            let (rx_speed, tx_speed) = lock.calculate_speed();
            drop(lock);
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
        for stream in VpnDevice::accept_tcp(&device).await {
            log::info!("accept tcp {} - {}", stream.src_addr, stream.dst_addr);
            spawn(start_tcp(
                stream,
                config.clone(),
                server_addr,
                server_name.clone(),
                4096,
                pass.clone(),
            ));
        }
        for stream in VpnDevice::accept_udp(&device).await {
            log::info!("accept udp to:{}", stream.target);
            spawn(start_udp(
                stream,
                server_addr,
                server_name.clone(),
                config.clone(),
                4096,
                udp_header.clone(),
            ));
        }
        let mut lock = device.lock().unwrap();
        let delay = lock
            .poll_delay(&mut interface)
            .unwrap_or(smoltcp::time::Duration::from_millis(2));
        drop(lock);
        tokio::time::sleep(delay.into()).await;
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
