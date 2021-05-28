//! This module provides functions used in proxy mod.
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use mio::{
    net::{TcpListener, UdpSocket},
    Events, Interest, Poll, Token,
};
use rustls::ClientConfig;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use webpki::DNSNameRef;

use crate::{
    config::Opts,
    proxy::{
        idle_pool::IdlePool, tcp_server::TcpServer, udp_cache::UdpSvrCache, udp_server::UdpServer,
    },
    resolver::DnsResolver,
    sys,
};

mod idle_pool;
mod tcp_server;
mod udp_cache;
mod udp_server;

/// minimal index used in `IdlePool`, `TcpServer` and `UdpServer`
const MIN_INDEX: usize = 2;
/// maximum index used in `IdlePool`, `TcpServer` and `UdpServer`
const MAX_INDEX: usize = usize::MAX / CHANNEL_CNT;
/// Token used for TcpListener
const TCP_LISTENER: usize = 1;
/// Token used for main Udp Socket
const UDP_LISTENER: usize = 2;
/// Token used for dns resolver
const RESOLVER: usize = 3;
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

pub fn new_socket(addr: SocketAddr, is_udp: bool) -> Option<Socket> {
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
    let socket = match Socket::new(domain, typ, Some(protocol)) {
        Ok(socket) => socket,
        Err(err) => {
            log::error!("new socket address:{} udp:{} failed:{}", addr, is_udp, err);
            return None;
        }
    };
    if let Err(err) = sys::set_socket_opts(addr.is_ipv4(), is_udp, &socket) {
        log::error!("set_socket_opts failed:{}", err);
        return None;
    }
    if let Err(err) = socket.set_nonblocking(true) {
        log::error!("set_nonblocking failed:{}", err);
        return None;
    }
    if let Err(err) = socket.set_reuse_address(true) {
        log::error!("set_reuse_address failed:{}", err);
        return None;
    }
    if let Err(err) = socket.bind(&SockAddr::from(addr)) {
        log::error!("bind address:{} failed:{}", addr, err);
        return None;
    }
    if !is_udp {
        if let Err(err) = socket.listen(1024) {
            log::error!("socket listen failed:{}", err);
            return None;
        }
    }
    Some(socket)
}

pub fn run(opts: &'static Opts) {
    let addr: SocketAddr = opts.local_addr.parse().unwrap();
    let mut tcp_listener = TcpListener::from_std(new_socket(addr, false).unwrap().into());
    let mut udp_listener = UdpSocket::from_std(new_socket(addr, true).unwrap().into());
    if let Err(err) = sys::set_mark(&udp_listener, opts.marker) {
        log::error!("udp socket set mark failed:{}", err);
        return;
    }
    let mut udp_cache = UdpSvrCache::new();
    let mut poll = Poll::new().unwrap();
    let mut resolver = DnsResolver::new(&poll, Token(RESOLVER));
    poll.registry()
        .register(&mut tcp_listener, Token(TCP_LISTENER), Interest::READABLE)
        .unwrap();
    poll.registry()
        .register(&mut udp_listener, Token(UDP_LISTENER), Interest::READABLE)
        .unwrap();

    let hostname = DNSNameRef::try_from_ascii(opts.proxy_args().hostname.as_bytes())
        .unwrap()
        .to_owned();
    let mut config = ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let config = Arc::new(config);

    let mut tcp_server = TcpServer::new(tcp_listener, opts);
    let mut udp_server = UdpServer::new(udp_listener, opts);

    let mut events = Events::with_capacity(1024);
    let mut last_check_time = Instant::now();
    let check_duration = Duration::new(1, 0);

    let mut pool = IdlePool::new(opts, config, hostname);
    pool.init(&poll, &resolver);

    loop {
        poll.poll(&mut events, Some(check_duration)).unwrap();
        for event in &events {
            log::trace!("dispatch token:{}", event.token().0);
            match event.token() {
                Token(TCP_LISTENER) => {
                    tcp_server.accept(&event, &poll, &mut pool, &resolver);
                }
                Token(UDP_LISTENER) => {
                    udp_server.accept(&event, &poll, &mut pool, &mut udp_cache, &resolver);
                }
                Token(RESOLVER) => {
                    resolver.consume(|_, ip| {
                        pool.resolve(ip);
                    });
                }
                Token(i) if i % CHANNEL_CNT == CHANNEL_IDLE => {
                    pool.ready(&event, &poll);
                }
                Token(i) if i % CHANNEL_CNT == CHANNEL_UDP => {
                    udp_server.ready(&event, &poll, &mut udp_cache);
                }
                _ => {
                    tcp_server.ready(&event, &poll);
                }
            }
        }
        let now = Instant::now();
        if now - last_check_time > opts.udp_idle_duration {
            udp_cache.check_timeout();
            last_check_time = now;
        }
    }
}
