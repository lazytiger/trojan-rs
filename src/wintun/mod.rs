use std::{
    collections::BTreeMap,
    convert::TryInto,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    thread,
};

use mio::{Events, Poll, Token, Waker};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use smoltcp::{
    iface::{Interface, InterfaceBuilder, Routes},
    socket::Socket,
    time::{Duration, Instant},
    wire::{IpAddress, IpCidr, Ipv4Address},
};
use wintun::{Adapter, Session};

pub use route::route_add_with_if;

use crate::{
    dns::{get_adapter_ip, get_main_adapter_gwif},
    proxy::IdlePool,
    resolver::DnsResolver,
    types::Result,
    wintun::{ipset::IPSet, tcp::TcpServer, tun::WintunInterface, udp::UdpServer, waker::Wakers},
    OPTIONS,
};

mod ipset;
mod route;
mod tcp;
mod tun;
mod udp;
mod waker;

pub(crate) type SocketSet<'a> = Interface<'a, WintunInterface>;

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

fn apply_ipset(file: &str, index: u32, inverse: bool) -> Result<()> {
    let mut ipset = IPSet::with_file(file, inverse)?;
    if OPTIONS.wintun_args().inverse_route {
        ipset = !ipset;
    }
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
    pool.init(poll, resolver);
    pool.init_index(CHANNEL_CNT, CHANNEL_IDLE, MIN_INDEX, MAX_INDEX);
    Ok(pool)
}

fn prepare_device<'a>(session: Arc<Session>) -> Interface<'a, WintunInterface> {
    let ip_addrs = [IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)];

    let mut routes = Routes::new(BTreeMap::new());
    routes
        .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
        .unwrap();
    let interface =
        InterfaceBuilder::new(WintunInterface::new(session, OPTIONS.wintun_args().mtu), [])
            .any_ip(true)
            .ip_addrs(ip_addrs)
            .routes(routes)
            .finalize();
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
    }
    let index = adapter.get_adapter_index()?;
    if let Some(file) = &OPTIONS.wintun_args().route_ipset {
        apply_ipset(file, index, OPTIONS.wintun_args().inverse_route)?;
    }

    let mut poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), Token(RESOLVER))?);
    let mut resolver = DnsResolver::new(waker, Token(RESOLVER));
    let mut pool = prepare_idle_pool(&poll, &resolver)?;

    let mut udp_server = UdpServer::new();
    let mut tcp_server = TcpServer::new();

    let mut interface = prepare_device(session);

    while get_adapter_ip(OPTIONS.wintun_args().name.as_str()).is_none() {
        thread::sleep(std::time::Duration::new(1, 0));
    }
    let gateway = get_adapter_ip(OPTIONS.wintun_args().name.as_str()).unwrap();
    log::warn!("wintun is ready at:{}", gateway);

    let mut events = Events::with_capacity(1024);
    let timeout = Some(Duration::from_millis(1));
    let mut last_check_time = std::time::Instant::now();
    let check_duration = std::time::Duration::new(60, 0);
    let mut now = Instant::now();

    let mut udp_wakers = Wakers::new();
    let mut tcp_wakers = Wakers::new();
    let sockets: *mut Interface<WintunInterface> = unsafe { std::mem::transmute(&mut interface) };
    interface
        .device_mut()
        .init(sockets, &mut tcp_wakers, &mut udp_wakers);
    loop {
        if let Err(err) = interface.poll(now) {
            log::info!("interface error:{}", err);
        }

        udp_server.do_local(&mut pool, &poll, &resolver, &mut udp_wakers, &mut interface);
        tcp_server.do_local(&mut pool, &poll, &resolver, &mut tcp_wakers, &mut interface);

        now = Instant::now();
        let timeout = interface.poll_delay(now).or(timeout);
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
                    udp_server.do_remote(event, &poll, &mut interface);
                }
                _ => {
                    tcp_server.do_remote(event, &poll, &mut interface, &mut tcp_wakers);
                }
            }
        }

        tcp_server.remove_closed(&mut interface);
        udp_server.remove_closed();

        let now = std::time::Instant::now();
        if now - last_check_time > check_duration {
            tcp_server.check_timeout(&poll, now, &mut interface, tcp_wakers.get_dummy_waker());
            let sockets_count = interface.sockets().fold(0, |count, (handle, socket)| {
                if let Socket::Tcp(socket) = socket {
                    log::info!(
                        "tcp socket:{} {} {} <-> {}",
                        handle,
                        socket.state(),
                        socket.remote_endpoint(),
                        socket.local_endpoint()
                    );
                    count + 1
                } else {
                    count
                }
            });
            log::warn!("total tcp sockets count:{}", sockets_count);
            udp_server.check_timeout(now, &mut interface, udp_wakers.get_dummy_waker());
            let sockets_count = interface.sockets().fold(0, |count, (_, socket)| {
                if matches!(socket, Socket::Udp(_)) {
                    count + 1
                } else {
                    count
                }
            });
            log::warn!("total udp sockets count:{}", sockets_count);
            pool.check_timeout(&poll);
            last_check_time = now;
        }
    }
}
