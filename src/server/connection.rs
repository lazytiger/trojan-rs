use std::{io::Write, net::SocketAddr, time::Instant};

use mio::{
    event::Event,
    net::{TcpStream, UdpSocket},
    Interest, Poll, Token,
};
use rustls::ServerSession;

use crate::{
    config::Opts,
    proto::{Sock5Address, TrojanRequest, CONNECT},
    resolver::EventedResolver,
    server::{
        tcp_backend::TcpBackend, tls_server::Backend, udp_backend::UdpBackend, CHANNEL_BACKEND,
        CHANNEL_CNT, CHANNEL_PROXY,
    },
    sys,
    tls_conn::TlsConn,
};
use std::net::IpAddr;

enum Status {
    HandShake,
    DnsWait,
    TCPForward,
    UDPForward,
}

pub struct Connection {
    index: usize,
    proxy: TlsConn<ServerSession>,
    status: Status,
    sock5_addr: Sock5Address,
    command: u8,
    last_active_time: Instant,
    backend: Option<Box<dyn Backend>>,
    closing: bool,
    target_addr: Option<SocketAddr>,
    data: Vec<u8>,
}

impl Connection {
    pub fn new(index: usize, proxy: TlsConn<ServerSession>) -> Connection {
        Connection {
            index,
            proxy,
            status: Status::HandShake,
            command: 0,
            sock5_addr: Sock5Address::None,
            last_active_time: Instant::now(),
            backend: None,
            closing: false,
            target_addr: None,
            data: Vec::new(),
        }
    }

    pub fn timeout(&self, recent_active_time: Instant) -> bool {
        if let Some(backend) = &self.backend {
            backend.timeout(self.last_active_time, recent_active_time)
        } else {
            false
        }
    }

    pub fn close_now(&mut self, poll: &Poll) {
        self.proxy.shutdown(poll);
        if let Some(backend) = self.backend.as_mut() {
            backend.shutdown(poll);
        }
    }

    fn proxy_token(&self, token: Token) -> bool {
        token.0 % CHANNEL_CNT == CHANNEL_PROXY
    }

    pub fn ready(
        &mut self,
        poll: &Poll,
        event: &Event,
        opts: &mut Opts,
        resolver: &EventedResolver,
    ) {
        self.last_active_time = Instant::now();

        if self.proxy_token(event.token()) {
            if event.is_readable() {
                self.try_read_proxy(opts, poll, resolver);
            }
            if event.is_writable() {
                self.try_send_proxy();
            }
        } else {
            match self.status {
                Status::UDPForward | Status::TCPForward => {
                    if let Some(backend) = self.backend.as_mut() {
                        backend.ready(event, opts, &mut self.proxy);
                    } else {
                        log::error!("connection:{} has invalid status", self.index);
                    }
                }
                _ => {}
            }
        }

        // handshake failed, no dns query on the way, close now.
        if self.closing {
            self.proxy.shutdown(poll);
            return;
        }

        self.proxy.reregister(poll, self.proxy_readable());
        self.proxy.check_close(poll);
        if let Some(backend) = &mut self.backend {
            backend.reregister(poll, self.proxy.writable());
            backend.check_close(poll);
            if self.proxy.closed() && !backend.closed() {
                //proxy is closing, backend is ok, register backend with write only
                backend.shutdown(poll);
            } else if backend.closed() && !self.proxy.closed() {
                //backend is closing, proxy is ok, register proxy with write only
                self.proxy.shutdown(poll);
            }
        }
    }

    fn proxy_readable(&self) -> bool {
        if let Some(backend) = &self.backend {
            backend.writable()
        } else {
            true
        }
    }

    pub fn try_resolve(
        &mut self,
        poll: &Poll,
        opts: &mut Opts,
        ip: Option<IpAddr>,
        resolver: &EventedResolver,
    ) {
        if let Status::DnsWait = self.status {
            if let Sock5Address::Domain(domain, port) = &self.sock5_addr {
                if let Some(address) = ip {
                    log::debug!(
                        "connection:{} got resolve result {} = {}",
                        self.index,
                        domain,
                        address
                    );
                    opts.update_dns(domain.clone(), address);
                    let addr = SocketAddr::new(address, *port);
                    self.target_addr.replace(addr);
                    self.dispatch(&[], opts, poll, resolver);
                } else {
                    log::error!("connection:{} resolve host:{} failed", self.index, domain);
                    self.closing = true;
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

    fn try_read_proxy(&mut self, opts: &mut Opts, poll: &Poll, resolver: &EventedResolver) {
        if let Some(buffer) = self.proxy.do_read() {
            self.dispatch(buffer.as_slice(), opts, poll, resolver);
        }
    }

    pub fn setup(&mut self, poll: &Poll, _: &Opts) -> bool {
        self.proxy.register(poll)
    }

    fn try_handshake(
        &mut self,
        buffer: &mut &[u8],
        opts: &mut Opts,
        resolver: &EventedResolver,
    ) -> bool {
        if let Some(request) = TrojanRequest::parse(buffer, opts) {
            self.command = request.command;
            self.sock5_addr = request.address;
            *buffer = request.payload;
        } else {
            log::debug!(
                "connection:{} does not get a trojan request, pass through",
                self.index
            );
            self.command = CONNECT;
            self.sock5_addr = Sock5Address::None;
        }
        match &self.sock5_addr {
            Sock5Address::Domain(domain, _) => {
                if self.command != CONNECT {
                    //udp associate bind at 0.0.0.0:0, ignore all domain
                    return true;
                }
                log::debug!("connection:{} has to resolve {}", self.index, domain);
                resolver.resolve(domain.clone(), self.target_token());
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
                    opts.back_addr.as_ref().unwrap()
                );
                self.target_addr = opts.back_addr;
            }
        }
        true
    }

    fn dispatch(
        &mut self,
        mut buffer: &[u8],
        opts: &mut Opts,
        poll: &Poll,
        resolver: &EventedResolver,
    ) {
        log::debug!(
            "connection:{} dispatch {} bytes request data",
            self.index,
            buffer.len()
        );
        loop {
            match self.status {
                Status::HandShake => {
                    if self.try_handshake(&mut buffer, opts, resolver) {
                        self.status = Status::DnsWait;
                    } else {
                        return;
                    }
                }
                Status::DnsWait => {
                    if self.command == CONNECT {
                        //if dns query is not done, cache data now
                        if let Err(err) = self.data.write(buffer) {
                            log::warn!("connection:{} cache data failed {}", self.index, err);
                            self.closing = true;
                            return;
                        }

                        if self.target_addr.is_none() {
                            log::warn!("connection:{} dns query not done yet", self.index);
                            return;
                        }

                        if self.try_setup_tcp_target(opts, poll) {
                            self.status = Status::TCPForward;
                        }
                        return;
                    } else if self.try_setup_udp_target(opts, poll) {
                        self.status = Status::UDPForward;
                    } else {
                        return;
                    }
                }
                _ => {
                    if let Some(backend) = self.backend.as_mut() {
                        backend.dispatch(buffer, opts);
                    } else {
                        log::error!("connection:{} has no backend yet", self.index);
                    }
                    break;
                }
            }
        }
    }

    fn try_setup_tcp_target(&mut self, opts: &mut Opts, poll: &Poll) -> bool {
        log::debug!(
            "connection:{} make a target connection to {}",
            self.index,
            self.target_addr.unwrap()
        );
        match TcpStream::connect(self.target_addr.clone().unwrap()) {
            Ok(mut tcp_target) => {
                if let Err(err) = sys::set_mark(&tcp_target, opts.marker) {
                    log::error!("connection:{} set mark failed:{}", self.index, err);
                    self.closing = true;
                    return false;
                } else if let Err(err) = poll.registry().register(
                    &mut tcp_target,
                    self.target_token(),
                    Interest::READABLE,
                ) {
                    log::error!("connection:{} register target failed:{}", self.index, err);
                    self.closing = true;
                    return false;
                } else if let Err(err) = tcp_target.set_nodelay(true) {
                    log::error!("connection:{} set nodelay failed:{}", self.index, err);
                    self.closing = true;
                    return false;
                }
                let mut backend = TcpBackend::new(
                    tcp_target,
                    self.index,
                    self.target_token(),
                    opts.tcp_idle_duration,
                );
                if !self.data.is_empty() {
                    backend.dispatch(self.data.as_slice(), opts);
                    self.data.clear();
                    self.data.shrink_to_fit();
                }
                self.backend.replace(Box::new(backend));
            }
            Err(err) => {
                log::warn!("connection:{} connect to target failed:{}", self.index, err);
                self.closing = true;
                return false;
            }
        }
        true
    }

    fn try_setup_udp_target(&mut self, opts: &mut Opts, poll: &Poll) -> bool {
        log::debug!("connection:{} got udp connection", self.index);
        match UdpSocket::bind(opts.empty_addr.clone().unwrap()) {
            Err(err) => {
                log::error!("connection:{} bind udp socket failed:{}", self.index, err);
                self.closing = true;
                return false;
            }
            Ok(mut udp_target) => {
                if let Err(err) = sys::set_mark(&udp_target, opts.marker) {
                    log::error!("connection:{} set mark failed:{}", self.index, err);
                    self.closing = true;
                    return false;
                }
                if let Err(err) = poll.registry().register(
                    &mut udp_target,
                    self.target_token(),
                    Interest::READABLE,
                ) {
                    log::error!(
                        "connection:{} register udp target failed:{}",
                        self.index,
                        err
                    );
                    self.closing = true;
                    return false;
                }
                let backend = UdpBackend::new(
                    udp_target,
                    self.index,
                    self.target_token(),
                    opts.udp_idle_duration,
                );
                self.backend.replace(Box::new(backend));
            }
        }
        true
    }

    pub fn destroyed(&self) -> bool {
        if let Some(backend) = &self.backend {
            self.proxy.closed() && backend.closed()
        } else {
            self.proxy.closed()
        }
    }

    fn target_token(&self) -> Token {
        Token((self.index * CHANNEL_CNT) + CHANNEL_BACKEND)
    }
}
