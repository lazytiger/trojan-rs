use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use mio::{
    net::{TcpStream, UdpSocket},
    Poll, Token,
};

use crate::{
    config::OPTIONS,
    proto,
    proto::{RequestParseResult, Sock5Address, TrojanRequest, CONNECT, PING, UDP_ASSOCIATE},
    resolver::DnsResolver,
    server::{
        ping_backend::PingBackend,
        stat::Statistics,
        tcp_backend::TcpBackend,
        tls_server::{Backend, PollEvent},
        udp_backend::UdpBackend,
        CHANNEL_BACKEND, CHANNEL_CNT, CHANNEL_PROXY,
    },
    status::StatusProvider,
    tls_conn::TlsConn,
};

enum Status {
    HandShake,
    DnsWait,
    TCPForward,
    UDPForward,
    PingServing,
}

pub struct Connection {
    index: usize,
    proxy: TlsConn,
    status: Status,
    sock5_addr: Sock5Address,
    command: u8,
    last_active_time: Instant,
    backend: Option<Box<dyn Backend>>,
    target_addr: Option<SocketAddr>,
    data: Vec<u8>,
    read_backend: bool,
    read_proxy: bool,
}

impl Connection {}

impl Connection {
    pub fn new(index: usize, proxy: TlsConn) -> Connection {
        Connection {
            index,
            proxy,
            status: Status::HandShake,
            command: 0,
            sock5_addr: Sock5Address::None,
            last_active_time: Instant::now(),
            backend: None,
            target_addr: None,
            data: Vec::new(),
            read_proxy: false,
            read_backend: false,
        }
    }

    pub fn destroy(&mut self, poll: &Poll) {
        self.proxy.shutdown();
        self.proxy.check_status(poll);
        if let Some(backend) = &mut self.backend {
            backend.shutdown();
            backend.check_status(poll);
        }
    }

    pub(crate) fn poll_ping(&mut self, stats: &mut Statistics) {
        if self.command == proto::PING {
            if let Some(backend) = &mut self.backend {
                backend.do_read(&mut self.proxy, stats)
            }
        }
    }

    pub fn timeout(&self, recent_active_time: Instant) -> bool {
        if let Some(backend) = &self.backend {
            backend.timeout(self.last_active_time, recent_active_time)
        } else {
            self.last_active_time.elapsed().as_secs() > OPTIONS.tcp_idle_timeout
        }
    }

    fn proxy_token(&self, token: Token) -> bool {
        token.0 % CHANNEL_CNT == CHANNEL_PROXY
    }

    pub fn ready(
        &mut self,
        poll: &Poll,
        event: PollEvent,
        resolver: Option<&mut DnsResolver>,
        stats: &mut Statistics,
    ) {
        self.last_active_time = Instant::now();

        match event {
            PollEvent::Network(event) => {
                if self.proxy_token(event.token()) {
                    if event.is_readable() {
                        let writable = if let Some(backend) = self.backend.as_ref() {
                            backend.writable()
                        } else {
                            true
                        };
                        if writable {
                            self.try_read_proxy(poll, resolver, stats);
                        } else {
                            log::trace!(
                                "backend connection:{} is not writable, stop reading from proxy",
                                self.index
                            );
                            self.read_proxy = true;
                        }
                    }
                    if event.is_writable() {
                        self.proxy.established();
                        self.try_send_proxy();
                        if self.proxy.writable() && self.read_backend {
                            if let Some(backend) = self.backend.as_mut() {
                                backend.do_read(&mut self.proxy, stats);
                            }
                            log::trace!(
                                "proxy connection:{} is writable, restore reading from backend",
                                self.index
                            );
                            self.read_backend = false;
                        }
                    }
                } else {
                    match self.status {
                        Status::UDPForward | Status::TCPForward => {
                            if let Some(backend) = self.backend.as_mut() {
                                if event.is_readable() {
                                    if self.proxy.writable() {
                                        backend.do_read(&mut self.proxy, stats);
                                    } else {
                                        log::trace!("proxy connection:{} is not writable, stop reading from backend", self.index);
                                        self.read_backend = true;
                                    }
                                }
                                if event.is_writable() {
                                    backend.dispatch(&[], stats);
                                    if backend.writable() && self.read_proxy {
                                        log::trace!("backend connection:{} is writable, restore reading from proxy", self.index);
                                        self.try_read_proxy(poll, resolver, stats);
                                        self.read_proxy = false;
                                    }
                                }
                            } else {
                                log::error!("connection:{} has invalid status", self.index);
                            }
                        }
                        _ => {}
                    }
                }
            }
            PollEvent::Dns((_, ip)) => self.try_resolve(poll, ip, stats),
        }

        if let Some(backend) = &mut self.backend {
            if self.proxy.is_shutdown() {
                backend.peer_closed();
            }
            if backend.is_shutdown() {
                self.proxy.peer_closed();
            }
        }
        self.proxy.check_status(poll);
        if let Some(backend) = &mut self.backend {
            backend.check_status(poll);
        }
    }

    pub fn try_resolve(&mut self, poll: &Poll, ip: Option<IpAddr>, stats: &mut Statistics) {
        if let Status::DnsWait = self.status {
            if let Sock5Address::Domain(domain, port) = &self.sock5_addr {
                if let Some(address) = ip {
                    log::debug!(
                        "connection:{} got resolve result {} = {}",
                        self.index,
                        domain,
                        address
                    );
                    let addr = SocketAddr::new(address, *port);
                    self.target_addr.replace(addr);
                    self.dispatch(&[], poll, None, stats);
                } else {
                    log::error!("connection:{} resolve host:{} failed", self.index, domain);
                    self.proxy.shutdown();
                }
            } else {
                log::error!("connection:{} got bug, not a resolver status", self.index);
            }
        } else {
            log::error!(
                "connection:{} status is not DnsWait, but received dns event",
                self.index
            );
        }
    }

    fn try_send_proxy(&mut self) {
        self.proxy.do_send();
    }

    fn try_read_proxy(
        &mut self,
        poll: &Poll,
        resolver: Option<&mut DnsResolver>,
        stats: &mut Statistics,
    ) {
        if let Some(buffer) = self.proxy.do_read() {
            self.dispatch(buffer.as_slice(), poll, resolver, stats);
        }
    }

    fn try_handshake(&mut self, buffer: &mut &[u8], resolver: &mut &mut DnsResolver) -> bool {
        if let RequestParseResult::Request(request) = TrojanRequest::parse(buffer) {
            self.command = request.command;
            self.sock5_addr = request.address;
            *buffer = request.payload;
        } else {
            log::info!(
                "connection:{:?} does not get a trojan request, pass through",
                self.proxy.source()
            );
            self.command = CONNECT;
            self.sock5_addr = Sock5Address::None;
        }
        match &self.sock5_addr {
            Sock5Address::Domain(domain, port) => {
                if self.command != CONNECT {
                    //udp associate bind at 0.0.0.0:0, ignore all domain
                    return true;
                }
                log::debug!("connection:{} has to resolve {}", self.index, domain);
                if let Some(ip) = (*resolver).query_dns(domain.as_str()) {
                    self.target_addr.replace(SocketAddr::new(ip, *port));
                } else {
                    resolver.resolve(domain.clone(), Some(self.target_token()));
                }
            }
            Sock5Address::Socket(address) => {
                log::debug!(
                    "connection:{} got resolved target address:{}",
                    self.index,
                    address
                );
                self.target_addr.replace(*address);
            }
            Sock5Address::None => {
                log::debug!(
                    "connection:{} got default target address:{}",
                    self.index,
                    OPTIONS.back_addr.as_ref().unwrap()
                );
                self.target_addr = OPTIONS.back_addr;
            }
            _ => {
                unreachable!()
            }
        }
        true
    }

    fn dispatch(
        &mut self,
        mut buffer: &[u8],
        poll: &Poll,
        mut resolver: Option<&mut DnsResolver>,
        stats: &mut Statistics,
    ) {
        log::debug!(
            "connection:{} dispatch {} bytes request data",
            self.index,
            buffer.len()
        );
        loop {
            match self.status {
                Status::HandShake => {
                    if self.try_handshake(&mut buffer, resolver.as_mut().unwrap()) {
                        self.status = Status::DnsWait;
                        continue;
                    }
                }
                Status::DnsWait => {
                    match self.command {
                        CONNECT => {
                            //if dns query is not done, cache data now
                            let client_ip = self.proxy.source();
                            if let Err(err) =
                                match (client_ip, self.target_addr == OPTIONS.back_addr) {
                                    (Some(client_ip), true) => {
                                        let mut headers = [httparse::EMPTY_HEADER; 100];
                                        let mut request = httparse::Request::new(&mut headers);
                                        match request.parse(buffer) {
                                            Ok(httparse::Status::Complete(offset)) => {
                                                log::error!("X-Forwarded-For: {}", client_ip);
                                                let mut data = Vec::new();
                                                data.extend_from_slice(&buffer[..offset - 2]);
                                                data.extend_from_slice(b"X-Forwarded-For: ");
                                                data.extend_from_slice(
                                                    client_ip.to_string().as_bytes(),
                                                );
                                                data.extend_from_slice(b"\r\n\r\n");
                                                data.extend_from_slice(&buffer[offset..]);
                                                self.data.write(&data)
                                            }
                                            _ => {
                                                log::error!(
                                                    "http request not completed, ignore now"
                                                );
                                                self.data.write(buffer)
                                            }
                                        }
                                    }
                                    _ => self.data.write(buffer),
                                }
                            {
                                log::warn!("connection:{} cache data failed {}", self.index, err);
                                self.proxy.shutdown();
                            } else if self.target_addr.is_none() {
                                log::warn!("connection:{} dns query not done yet", self.index);
                            } else if self.try_setup_tcp_target(poll, stats) {
                                buffer = &[];
                                self.status = Status::TCPForward;
                                continue;
                            }
                        }
                        PING => {
                            if self.try_setup_ping_target() {
                                self.status = Status::PingServing;
                                continue;
                            }
                        }
                        UDP_ASSOCIATE => {
                            if self.try_setup_udp_target(poll, stats) {
                                self.status = Status::UDPForward;
                                continue;
                            }
                        }
                        _ => unreachable!("invalid command:{}", self.command),
                    }
                }
                _ => {
                    if let Some(backend) = self.backend.as_mut() {
                        backend.dispatch(buffer, stats);
                    } else {
                        log::error!("connection:{} has no backend yet", self.index);
                    }
                }
            }
            break;
        }
    }

    fn try_setup_tcp_target(&mut self, poll: &Poll, stats: &mut Statistics) -> bool {
        log::debug!(
            "connection:{} make a target connection to {}",
            self.index,
            self.target_addr.unwrap()
        );
        match TcpStream::connect(self.target_addr.unwrap()) {
            Ok(tcp_target) => {
                let dst_ip = self.target_addr.map(|addr| addr.ip());
                stats.add_tcp_rx(0, dst_ip, self.proxy.source());
                match TcpBackend::new(tcp_target, dst_ip, self.index, self.target_token(), poll) {
                    Ok(mut backend) => {
                        if !self.data.is_empty() {
                            backend.dispatch(self.data.as_slice(), stats);
                            self.data.clear();
                            self.data.shrink_to_fit();
                        }
                        self.backend.replace(Box::new(backend));
                    }
                    Err(err) => {
                        log::error!("connection:{} setup backend failed:{:?}", self.index, err);
                        self.proxy.shutdown();
                    }
                }
            }
            Err(err) => {
                log::warn!("connection:{} connect to target failed:{}", self.index, err);
                self.proxy.shutdown();
                return false;
            }
        }
        true
    }

    fn try_setup_udp_target(&mut self, poll: &Poll, stats: &mut Statistics) -> bool {
        log::debug!("connection:{} got udp connection", self.index);
        match UdpSocket::bind(OPTIONS.empty_addr.unwrap()) {
            Err(err) => {
                log::error!("connection:{} bind udp socket failed:{}", self.index, err);
                self.proxy.shutdown();
                return false;
            }
            Ok(udp_target) => {
                stats.add_udp_rx(
                    0,
                    udp_target.peer_addr().map(|addr| addr.ip()).ok(),
                    self.proxy.source(),
                );
                match UdpBackend::new(
                    udp_target,
                    self.proxy.source(),
                    self.index,
                    self.target_token(),
                    poll,
                ) {
                    Ok(backend) => {
                        self.backend.replace(Box::new(backend));
                    }
                    Err(err) => {
                        log::error!("connection:{} setup backend failed:{:?}", self.index, err);
                        self.proxy.shutdown();
                    }
                }
            }
        }
        true
    }

    fn try_setup_ping_target(&mut self) -> bool {
        self.backend.replace(Box::new(PingBackend::new()));
        true
    }

    pub fn destroyed(&self) -> bool {
        if let Some(backend) = &self.backend {
            self.proxy.deregistered() && backend.deregistered()
        } else {
            self.proxy.deregistered()
        }
    }

    fn target_token(&self) -> Token {
        Token((self.index * CHANNEL_CNT) + CHANNEL_BACKEND)
    }
}
