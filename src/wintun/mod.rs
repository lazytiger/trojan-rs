use std::{
    convert::TryInto,
    fs::OpenOptions,
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    thread,
    time::SystemTime,
};

use mio::{Events, Poll, Token, Waker};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    socket::Socket,
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address},
};
use wintun::Adapter;

pub use route::route_add_with_if;

use crate::{
    dns::{get_adapter_ip, get_main_adapter_gwif},
    proxy::IdlePool,
    resolver::DnsResolver,
    types::{Result, TrojanError},
    wintun::{ipset::IPSet, tcp::TcpServer, tun::WintunDevice, udp::UdpServer},
    OPTIONS,
};

mod ipset;
mod route;
mod tcp;
mod tun;
mod udp;
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

pub fn apply_ipset(file: &str, index: u32, inverse: bool) -> Result<()> {
    let ipset = IPSet::with_file(file, inverse)?;
    ipset.add_route(index)?;
    log::warn!("route add completed");
    Ok(())
}

fn prepare_idle_pool(poll: &Poll, resolver: &DnsResolver) -> Result<IdlePool> {
    let hostname = OPTIONS.wintun_args().hostname.as_str().try_into()?;
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
        config,
        hostname,
        OPTIONS.wintun_args().pool_size + 1,
        OPTIONS.wintun_args().port,
        OPTIONS.wintun_args().hostname.clone(),
    );
    pool.init_index(CHANNEL_CNT, CHANNEL_IDLE, MIN_INDEX, MAX_INDEX);
    pool.init(poll, resolver);
    Ok(pool)
}

fn prepare_device(device: &mut WintunDevice) -> Interface {
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

pub fn run() -> Result<()> {
    log::info!("dll:{}", OPTIONS.wintun_args().wintun);
    let wintun = unsafe { wintun::load_from_path(&OPTIONS.wintun_args().wintun)? };
    let adapter = Adapter::create(&wintun, "trojan", OPTIONS.wintun_args().name.as_str(), None)?;
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    if let Some((main_gw, main_index)) = get_main_adapter_gwif() {
        log::warn!(
            "main adapter gateway is {}, main adapter index is :{}",
            main_gw,
            main_index
        );
        let gw: Ipv4Addr = main_gw.parse()?;
        if let Some(SocketAddr::V4(v4)) = &OPTIONS.back_addr {
            let index: u32 = (*v4.ip()).into();
            route_add_with_if(index, !0, gw.into(), main_index)?;
        }
    } else {
        log::error!("main adapter gateway not found");
        return Err(TrojanError::MainAdapterNotFound);
    }
    let index = adapter.get_adapter_index()?;
    if let Some(file) = &OPTIONS.wintun_args().route_ipset {
        apply_ipset(file, index, OPTIONS.wintun_args().inverse_route)?;
    }

    let mut poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), Token(RESOLVER))?);
    let mut resolver = DnsResolver::new(
        waker,
        Token(RESOLVER),
        OPTIONS.wintun_args().dns_server_addr.clone(),
    );
    let mut pool = prepare_idle_pool(&poll, &resolver)?;

    let mut udp_server = UdpServer::new();
    let mut tcp_server = TcpServer::new();

    let mut sockets = Arc::new(SocketSet::new([]));
    let mut device = WintunDevice::new(session.clone(), OPTIONS.wintun_args().mtu, sockets.clone());
    let mut interface = prepare_device(&mut device);

    while get_adapter_ip(OPTIONS.wintun_args().name.as_str()).is_none() {
        thread::sleep(std::time::Duration::new(1, 0));
    }
    let gateway = get_adapter_ip(OPTIONS.wintun_args().name.as_str()).unwrap();
    log::warn!("wintun is ready at:{}", gateway);

    let mut events = Events::with_capacity(1024);
    let timeout = Some(Duration::from_millis(1));
    let mut last_check_time = std::time::Instant::now();
    let mut last_speed_time = std::time::Instant::now();
    let check_duration = std::time::Duration::new(60, 0);
    let mut now = Instant::now();

    loop {
        let sockets = unsafe { Arc::get_mut_unchecked(&mut sockets) };
        if interface.poll(now, &mut device, sockets) {
            udp_server.do_local(&mut pool, &poll, &resolver, &mut device);
            tcp_server.do_local(&mut pool, &poll, &resolver, &mut device);
        }

        now = Instant::now();
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

        if last_speed_time.elapsed().as_millis() > 1000 {
            let (rx_speed, tx_speed) = device.calculate_speed();
            log::info!(
                "current speed - rx:{:.4}MB/s, tx:{:.4}/MB/s",
                rx_speed,
                tx_speed
            );
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(OPTIONS.wintun_args().status_file.as_str())?;
            write!(&mut file, "{:.4} {:.4}", rx_speed, tx_speed)?;
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
}
