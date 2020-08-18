use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mio::{Events, Poll, PollOpt, Ready, Token};
use mio::net::TcpListener;
use mio::net::UdpSocket;
use rustls::ClientConfig;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use webpki::DNSNameRef;

use crate::config::Opts;
use crate::proxy::idle_pool::IdlePool;
use crate::proxy::tcp_server::TcpServer;
use crate::proxy::udp_cache::UdpSvrCache;
use crate::proxy::udp_server::UdpServer;
use crate::sys;

mod tcp_server;
mod udp_server;
mod udp_cache;
mod idle_pool;

const MIN_INDEX: usize = 2;
const MAX_INDEX: usize = std::usize::MAX / CHANNEL_CNT;
const TCP_LISTENER: usize = 1;
const UDP_LISTENER: usize = 2;
const RESOLVER: usize = 3;
const CHANNEL_CNT: usize = 4;
const CHANNEL_IDLE: usize = 0;
const CHANNEL_UDP: usize = 1;
const CHANNEL_CLIENT: usize = 2;
const CHANNEL_TCP: usize = 3;

fn next_index(index: &mut usize) -> usize {
    let current = *index;
    *index += 1;
    if *index >= MAX_INDEX {
        *index = MIN_INDEX;
    }
    current
}

pub fn new_socket(addr: SocketAddr, is_udp: bool) -> Socket {
    let domain = if addr.is_ipv4() {
        Domain::ipv4()
    } else {
        Domain::ipv6()
    };
    let (typ, protocol) = if is_udp {
        (Type::dgram(), Protocol::udp())
    } else {
        (Type::stream(), Protocol::tcp())
    };
    let socket = Socket::new(domain, typ, Some(protocol)).unwrap();
    sys::set_socket_opts(addr.is_ipv4(), is_udp, &socket).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket.bind(&SockAddr::from(addr)).unwrap();
    if !is_udp {
        socket.listen(1024).unwrap();
    }
    socket
}

pub fn run(opts: &mut Opts) {
    let addr: SocketAddr = opts.local_addr.parse().unwrap();
    let tcp_listener = TcpListener::from_std(new_socket(addr, false).into_tcp_listener()).unwrap();
    let udp_listener = UdpSocket::from_socket(new_socket(addr, true).into_udp_socket()).unwrap();
    if let Err(err) = sys::set_mark(&udp_listener, opts.marker) {
        log::error!("udp socket set mark failed:{}", err);
        return;
    }
    let mut udp_cache = UdpSvrCache::new();
    let poll = Poll::new().unwrap();
    poll.register(&tcp_listener, Token(TCP_LISTENER), Ready::readable(), PollOpt::edge()).unwrap();
    poll.register(&udp_listener, Token(UDP_LISTENER), Ready::readable(), PollOpt::edge()).unwrap();


    let hostname = DNSNameRef::try_from_ascii(opts.proxy_args().hostname.as_bytes()).unwrap().to_owned();
    let mut config = ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let config = Arc::new(config);

    let mut tcp_server = TcpServer::new(tcp_listener);
    let mut udp_server = UdpServer::new(udp_listener);

    let mut events = Events::with_capacity(1024);
    let mut last_check_time = Instant::now();
    let check_duration = Duration::new(1, 0);

    let mut pool = IdlePool::new(opts, config, hostname);

    loop {
        let nevent = poll.poll(&mut events, Some(check_duration)).unwrap();
        log::trace!("poll got {} events", nevent);
        for event in &events {
            log::trace!("dispatch token:{}", event.token().0);
            match event.token() {
                Token(TCP_LISTENER) => {
                    tcp_server.accept(&event, opts, &poll, &mut pool);
                }
                Token(UDP_LISTENER) => {
                    udp_server.accept(&event, opts, &poll, &mut pool);
                }
                Token(RESOLVER) => {
                    pool.resolve(&poll);
                }
                Token(i) if i % CHANNEL_CNT == CHANNEL_IDLE => {
                    pool.ready(&event, &poll);
                }
                Token(i) if i % CHANNEL_CNT == CHANNEL_UDP => {
                    udp_server.ready(&event, opts, &poll, &mut udp_cache);
                }
                _ => {
                    tcp_server.ready(&event, &poll);
                }
            }
        }
        let now = Instant::now();
        if now - last_check_time > check_duration {
            udp_cache.check_timeout(now - opts.udp_idle_duration);
            last_check_time = now;
        }
    }
}
