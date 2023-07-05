use std::{
    convert::TryInto,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::SystemTime,
};

use mio::{Events, Poll, Token, Waker};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use sha2::{Digest, Sha224};
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    socket::Socket,
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};

use crate::{
    emit_event, platform,
    tun::{
        device::VpnDevice, dns::DnsServer, idle_pool::IdlePool, resolver::DnsResolver,
        tcp::TcpServer, udp::UdpServer,
    },
    types::{EventType, Result, VpnError},
    Context, Options,
};

mod device;
mod dns;
mod idle_pool;
mod proto;
mod resolver;
mod status;
mod tcp;
mod tls_conn;
mod udp;
mod utils;
mod waker;

/// Token used for DNS resolver
const RESOLVER: usize = 1;
/// Minimum index
const MIN_INDEX: usize = 2;
/// Maximum index
const MAX_INDEX: usize = usize::MAX / CHANNEL_CNT;
/// Channel count for index
const CHANNEL_CNT: usize = 3;
/// Channel index  for `IdlePool`
const CHANNEL_IDLE: usize = 0;
/// Channel index for client `UdpConnection`
const CHANNEL_UDP: usize = 1;
/// Channel index for remote tcp connection
const CHANNEL_TCP: usize = 2;

fn prepare_idle_pool(
    poll: &Poll,
    resolver: &DnsResolver,
    options: &Options,
    addr: SocketAddr,
) -> Result<(IdlePool, Arc<ClientConfig>, ServerName)> {
    let hostname: ServerName = options.hostname.as_str().try_into()?;
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let config = Arc::new(config);
    let mut pool = IdlePool::new(
        config.clone(),
        hostname.clone(),
        options.pool_size + 1,
        options.port,
        options.hostname.clone(),
        addr,
    );
    pool.init_index(CHANNEL_CNT, CHANNEL_IDLE, MIN_INDEX, MAX_INDEX);
    pool.init(poll, resolver);
    Ok((pool, config, hostname))
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

fn show_info(level: &String) -> bool {
    level == "Debug" || level == "Info" || level == "Trace"
}

pub fn run(fd: i32, dns: String, context: Context, running: Arc<AtomicBool>) -> Result<()> {
    let session = Arc::new(platform::Session::new(
        fd,
        context.options.mtu,
        show_info(&context.options.log_level),
    ));

    let trusted_addr = (context.options.trusted_dns.clone() + ":53").parse()?;
    let untrusted_addr = (context.options.untrusted_dns.clone() + ":53").parse()?;

    let mut poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), Token(RESOLVER))?);
    let server_ip = utils::resolve(
        context.options.hostname.as_str(),
        (context.options.untrusted_dns.clone() + ":53").as_str(),
    )?;
    if server_ip.is_empty() {
        return Err(VpnError::Resolve);
    }
    log::info!("server ip are {:?}", server_ip);
    let server_addr = SocketAddr::new(server_ip[0], context.options.port);
    let mut resolver = DnsResolver::new(
        waker,
        Token(RESOLVER),
        Some((context.options.untrusted_dns.clone() + ":53").into()),
    );
    let (mut pool, config, hostname) =
        prepare_idle_pool(&poll, &resolver, &context.options, server_addr)?;

    let pass = digest_pass(&context.options.password);
    let mut udp_server = UdpServer::new(pass.clone());
    let mut tcp_server = TcpServer::new(pass.clone());

    let listener_addr = dns + ":53";
    let listener_addr: SocketAddr = listener_addr.parse().unwrap();
    let mut sockets = Arc::new(SocketSet::new([]));
    let mut device = VpnDevice::new(
        session.clone(),
        context.options.mtu,
        IpEndpoint::from(server_addr),
        IpEndpoint::from(listener_addr),
        sockets.clone(),
    );
    let listener = device.create_udp_socket(listener_addr.into());
    let mut interface = prepare_device(&mut device);

    let mut dns_server = DnsServer::new(
        server_addr,
        config,
        hostname,
        listener,
        trusted_addr,
        untrusted_addr,
        context.options.dns_cache_time,
        context.options.mtu,
        pass,
        context.blocked_domains,
    )?;

    let mut events = Events::with_capacity(1024);
    let timeout = Some(Duration::from_millis(1));
    let mut last_check_time = std::time::Instant::now();
    let mut last_speed_time = std::time::Instant::now();
    let check_duration = std::time::Duration::new(60, 0);

    while running.load(Ordering::Relaxed) {
        let now = Instant::now();
        dns_server.ready(&mut device);
        let sockets = unsafe { crate::get_mut_unchecked(&mut sockets) };
        if interface.poll(now, &mut device, sockets) {
            udp_server.do_local(&mut pool, &poll, &resolver, &mut device);
            tcp_server.do_local(&mut pool, &poll, &resolver, &mut device);
            //session.sync();
        }

        let timeout = interface.poll_delay(now, sockets).or(timeout);
        poll.poll(
            &mut events,
            timeout.map(|d| std::time::Duration::from_millis(d.total_millis())),
        )?;
        for event in &events {
            match event.token().0 {
                RESOLVER => {
                    resolver.consume(|_, ip| {
                        pool.resolve(ip);
                    });
                }
                i if i % CHANNEL_CNT == CHANNEL_IDLE => {
                    pool.ready(event, &poll);
                }
                i if i % CHANNEL_CNT == CHANNEL_UDP => {
                    udp_server.do_remote(event, &poll, &mut device);
                }
                _ => {
                    tcp_server.do_remote(event, &poll, &mut device);
                }
            }
        }

        tcp_server.remove_closed(&mut device);
        udp_server.remove_closed();

        if last_speed_time.elapsed().as_millis() >= context.options.speed_update_ms {
            let (rx_speed, tx_speed) = device.calculate_speed();
            log::info!(
                "current speed - rx:{:.3}MB/s, tx:{:.3}/MB/s",
                rx_speed,
                tx_speed
            );
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

        let now = std::time::Instant::now();
        if now - last_check_time > check_duration {
            tcp_server.check_timeout(&poll, now, &mut device);
            udp_server.check_timeout(now, &mut device);

            let (tcp_count, udp_count) = sockets.iter().fold(
                (0, 0),
                |(mut tcp_count, mut udp_count), (handle, socket)| {
                    match socket {
                        Socket::Udp(socket) => {
                            log::info!("udp socket:{} {:?}", handle, socket.endpoint(),);
                            udp_count += 1;
                        }
                        Socket::Tcp(socket) => {
                            log::info!(
                                "tcp socket:{} {} {:?} <-> {:?}",
                                handle,
                                socket.state(),
                                socket.remote_endpoint(),
                                socket.local_endpoint()
                            );
                            tcp_count += 1;
                        }
                        _ => {}
                    }
                    (tcp_count, udp_count)
                },
            );
            log::info!("total tcp sockets count:{}", tcp_count);
            log::info!("total udp sockets count:{}", udp_count);
            pool.check_timeout(&poll);
            last_check_time = now;
        }
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
