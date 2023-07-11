//! This module provides functions used in proxy mod.
use std::{
    convert::TryInto,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use mio::{
    net::{TcpListener, UdpSocket},
    Events, Interest, Poll, Token, Waker,
};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

pub use crate::idle_pool::IdlePool;
use crate::{
    config::OPTIONS,
    proxy::{
        net_profiler::{start_check_server, NetProfiler},
        tcp_server::TcpServer,
        udp_cache::UdpSvrCache,
        udp_server::UdpServer,
    },
    resolver::DnsResolver,
    sys,
    types::Result,
};

mod net_profiler;
mod tcp_server;
mod udp_cache;
mod udp_server;

/// minimal index used in `IdlePool`, `TcpServer` and `UdpServer`
const MIN_INDEX: usize = 3;
/// maximum index used in `IdlePool`, `TcpServer` and `UdpServer`
const MAX_INDEX: usize = usize::MAX / CHANNEL_CNT;
/// Token used for TcpListener
const TCP_LISTENER: usize = 1;
/// Token used for main Udp Socket
const UDP_LISTENER: usize = 2;
/// Token used for dns resolver
const RESOLVER: usize = 3;
/// Token used for ping
pub(crate) const PINGER: usize = 4;
/// total channel count for Poll
const CHANNEL_CNT: usize = 4;
/// channel index  for `IdlePool`
const CHANNEL_IDLE: usize = 0;
/// channel index for client `UdpConnection`
const CHANNEL_UDP: usize = 1;
/// channel index for client tcp connection
const CHANNEL_CLIENT: usize = 2;
/// channel index for remote tcp connection
const CHANNEL_TCP: usize = 3;

/// Returns next index based on the current one.
/// If the next index overflows (larger than [`MAX_INDEX`]),
/// the [`MIN_INDEX`] returns.
fn next_index(index: &mut usize) -> usize {
    let current = *index;
    *index += 1;
    if *index >= MAX_INDEX {
        *index = MIN_INDEX;
    }
    current
}

pub fn new_socket(addr: SocketAddr, is_udp: bool) -> Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let (typ, protocol) = if is_udp {
        (Type::DGRAM, Protocol::UDP)
    } else {
        (Type::STREAM, Protocol::TCP)
    };
    let socket = Socket::new(domain, typ, Some(protocol))?;
    sys::set_socket_opts(addr.is_ipv4(), is_udp, &socket)?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(addr))?;
    if !is_udp {
        socket.listen(1024)?;
    }
    Ok(socket)
}

pub fn run() -> Result<()> {
    let addr: SocketAddr = OPTIONS.local_addr.parse()?;
    let mut tcp_listener = TcpListener::from_std(new_socket(addr, false)?.into());
    let mut udp_listener = UdpSocket::from_std(new_socket(addr, true)?.into());
    let mut udp_cache = UdpSvrCache::new();
    let mut poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), Token(RESOLVER))?);
    let mut resolver = DnsResolver::new(waker, Token(RESOLVER), None);
    poll.registry()
        .register(&mut tcp_listener, Token(TCP_LISTENER), Interest::READABLE)?;
    poll.registry()
        .register(&mut udp_listener, Token(UDP_LISTENER), Interest::READABLE)?;

    let hostname = OPTIONS.proxy_args().hostname.as_str().try_into()?;

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

    let mut tcp_server = TcpServer::new(tcp_listener);
    let mut udp_server = UdpServer::new(udp_listener);

    start_check_server(
        OPTIONS.proxy_args().hostname.clone(),
        150,
        OPTIONS.proxy_args().bypass_timeout,
    );

    let mut events = Events::with_capacity(1024);

    let mut pool = IdlePool::new(
        config,
        hostname,
        OPTIONS.proxy_args().pool_size + 1,
        OPTIONS.proxy_args().port,
        OPTIONS.proxy_args().hostname.clone(),
    );
    pool.init_index(CHANNEL_CNT, CHANNEL_IDLE, MIN_INDEX, MAX_INDEX);
    pool.init(&poll, &resolver);

    let mut net_profiler = NetProfiler::new(
        OPTIONS.proxy_args().enable_bypass,
        OPTIONS.proxy_args().bypass_timeout,
        OPTIONS.proxy_args().ping_threshold,
        OPTIONS.proxy_args().bypass_ipset.clone(),
        OPTIONS.proxy_args().no_bypass_ipset.clone(),
    );
    if !net_profiler.initialize(&poll, &resolver, &mut pool) {
        panic!("net profiler initialize failed");
    }

    let mut last_check_time = Instant::now();
    let check_duration = Duration::new(1, 0);

    loop {
        poll.poll(&mut events, Some(check_duration))?;
        for event in &events {
            log::trace!("dispatch token:{}", event.token().0);
            match event.token() {
                Token(TCP_LISTENER) => {
                    tcp_server.accept(&poll, &mut pool, &resolver, &mut net_profiler);
                }
                Token(UDP_LISTENER) => {
                    udp_server.accept(
                        &poll,
                        &mut pool,
                        &mut udp_cache,
                        &resolver,
                        &mut net_profiler,
                    );
                }
                Token(RESOLVER) => {
                    resolver.consume(|_, ip| {
                        pool.resolve(ip);
                    });
                }
                Token(PINGER) => {
                    net_profiler.ready(event, &poll, &mut pool, &resolver);
                }
                Token(i) if i % CHANNEL_CNT == CHANNEL_IDLE => {
                    pool.ready(event, &poll);
                }
                Token(i) if i % CHANNEL_CNT == CHANNEL_UDP => {
                    udp_server.ready(event, &poll, &mut udp_cache);
                }
                _ => {
                    tcp_server.ready(event, &poll);
                }
            }
        }
        udp_server.remove_closed();
        tcp_server.remove_closed();
        net_profiler.update();
        let now = Instant::now();
        if now - last_check_time > check_duration {
            tcp_server.check_timeout(&poll, now);
            udp_cache.check_timeout();
            pool.check_timeout(&poll);
            last_check_time = now;
        }
    }
}
