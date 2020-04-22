use std::io::{Read, Write};
use std::net::Shutdown;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::{Buf, BytesMut};
use mio::{Event, Poll, PollOpt, Ready, Token};
use mio::net::{TcpStream, UdpSocket};
use rustls::{ServerSession, Session};

use crate::config::Opts;
use crate::proto::{CONNECT, MAX_UDP_SIZE, Sock5Address, TrojanRequest, UdpAssociate, UdpParseResult};
use crate::server::resolver::EventedResolver;
use crate::session::TcpSession;
use crate::sys;

enum Status {
    HandShake,
    DnsWait,
    TCPForward,
    UDPForward,
}

pub struct Connection {
    index: usize,
    proxy: TcpStream,
    proxy_session: ServerSession,
    target_addr: Option<SocketAddr>,
    tcp_target: Option<TcpStream>,
    udp_target: Option<UdpSocket>,
    udp_send_buffer: BytesMut,
    udp_recv_head: BytesMut,
    udp_recv_body: Vec<u8>,
    resolver: Option<EventedResolver>,
    target_session: TcpSession,
    closing: bool,
    closed: bool,
    proxy_readiness: Ready,
    target_readiness: Ready,
    status: Status,
    sock5_addr: Sock5Address,
    command: u8,
    last_active_time: Instant,
    client_recv: usize,
    client_sent: usize,
    client_time: Instant,
}

impl Connection {
    pub fn new(index: usize, stream: TcpStream, session: ServerSession) -> Connection {
        Connection {
            index,
            proxy: stream,
            proxy_session: session,
            target_addr: None,
            tcp_target: None,
            udp_target: None,
            udp_send_buffer: BytesMut::new(),
            udp_recv_body: vec![0u8; MAX_UDP_SIZE],
            udp_recv_head: BytesMut::new(),
            resolver: None,
            closing: false,
            closed: false,
            proxy_readiness: Ready::readable(),
            target_readiness: Ready::readable(),
            status: Status::HandShake,
            target_session: TcpSession::new(),
            command: 0,
            sock5_addr: Sock5Address::None,
            last_active_time: Instant::now(),
            client_sent: 0,
            client_recv: 0,
            client_time: Instant::now(),
        }
    }

    pub fn timeout(&self, recent_active_time: Instant) -> bool {
        self.last_active_time < recent_active_time
    }

    pub fn close_now(&mut self, poll: &Poll) {
        let secs = self.client_time.elapsed().as_secs();
        if self.target_addr.is_some() {
            log::warn!("connection:{} closed, target address {}, {} seconds,  {} byte read, {} byte sent",
                self.index, self.target_addr.as_ref().unwrap(), secs,  self.client_recv, self.client_sent);
        };
        self.closed = true;

        let _ = poll.deregister(&self.proxy);
        let _ = self.proxy.shutdown(Shutdown::Both);

        if self.tcp_target.is_some() {
            let tcp_target = self.tcp_target.as_ref().unwrap();
            let _ = poll.deregister(tcp_target);
            let _ = tcp_target.shutdown(Shutdown::Both);
        }
        if self.udp_target.is_some() {
            let udp_target = self.udp_target.as_ref().unwrap();
            let _ = poll.deregister(udp_target);
        }
    }

    pub fn ready(&mut self, poll: &Poll, event: &Event, opts: &mut Opts) {
        self.last_active_time = Instant::now();

        if event.readiness().is_readable() {
            if event.token().0 % 2 == 0 {
                self.try_read_proxy(opts, poll);
            } else {
                match self.status {
                    Status::UDPForward => {
                        self.try_read_udp_target();
                    }
                    Status::TCPForward => {
                        self.try_read_tcp_target();
                    }
                    Status::DnsWait => {
                        self.try_resolve(opts, poll);
                    }
                    _ => {
                        log::error!("connection:{} has invalid status when target is readable", self.index);
                    }
                }
            }
        }

        if event.readiness().is_writable() {
            if event.token().0 % 2 == 0 {
                self.try_send_proxy();
            } else {
                match self.status {
                    Status::UDPForward => {
                        self.try_send_udp_target(&[], opts);
                    }
                    Status::TCPForward => {
                        self.try_send_tcp_target();
                    }
                    _ => {
                        log::error!("connection:{} got invalid read status", self.index);
                    }
                }
            }
        }


        self.reregister(poll);
        if self.closing {
            self.close_now(poll);
        }
    }

    fn try_resolve(&mut self, opts: &mut Opts, poll: &Poll) {
        if self.closing {
            return;
        }
        if let Sock5Address::Domain(domain, port) = &self.sock5_addr {
            if let Some(address) = self.resolver.as_ref().unwrap().address() {
                log::info!("connection:{} got resolve result {} = {}", self.index, domain, address);
                opts.update_dns(domain.clone(), address);
                let addr = SocketAddr::new(address, *port);
                self.target_addr.replace(addr);
                self.dispatch(&[], opts, poll);
            } else {
                log::error!("connection:{} resolve host:{} failed", self.index, domain);
                self.closing = true;
            }
        } else {
            log::error!("connection:{} got bug, not a resolver status", self.index);
        }
        let _ = poll.deregister(self.resolver.as_ref().unwrap());
        let _ = self.resolver.take();
    }

    fn try_send_proxy(&mut self) {
        if self.closing {
            return;
        }
        loop {
            if !self.proxy_session.wants_write() {
                log::debug!("connection:{} finished proxy write", self.index);
                break;
            }
            match self.proxy_session.write_tls(&mut self.proxy) {
                Ok(size) => {
                    log::debug!("connection:{} sent {} bytes to proxy", self.index, size);
                    self.client_sent += size;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    log::debug!("connection:{} can't write anymore proxy", self.index);
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} got write proxy error:{}", self.index, err);
                    self.closing = true;
                    return;
                }
            }
        }
    }

    fn try_send_tcp_target(&mut self) {
        if self.closing {
            return;
        }
        match self.target_session.write_backend(self.tcp_target.as_mut().unwrap()) {
            Err(err) => {
                log::warn!("connection:{} write to target failed:{}", self.index, err);
                self.closing = true;
            }
            Ok(size) => {
                log::debug!("connection:{} write {} bytes to target", self.index, size);
            }
        }
    }

    fn try_read_udp_target(&mut self) {
        if self.closing {
            return;
        }
        let udp_socket = self.udp_target.as_ref().unwrap();
        loop {
            match udp_socket.recv_from(self.udp_recv_body.as_mut_slice()) {
                Ok((size, addr)) => {
                    log::debug!("connection:{} got {} bytes udp data from:{}", self.index, size, addr);
                    self.udp_recv_head.clear();
                    UdpAssociate::generate(&mut self.udp_recv_head, &addr, size as u16);
                    if let Err(err) = self.proxy_session.write_all(self.udp_recv_head.as_ref()) {
                        log::error!("connection:{} write to session failed:{}", self.index, err);
                        self.closing = true;
                        return;
                    }
                    if let Err(err) = self.proxy_session.write_all(&self.udp_recv_body.as_slice()[..size]) {
                        log::error!("connection:{} write to session failed:{}", self.index, err);
                        self.closing = true;
                        return;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} got udp read err:{}", self.index, err);
                    self.closing = true;
                    return;
                }
            }
        }
        self.try_send_proxy();
    }

    fn try_read_proxy(&mut self, opts: &mut Opts, poll: &Poll) {
        if self.closing {
            return;
        }
        loop {
            match self.proxy_session.read_tls(&mut self.proxy) {
                Ok(size) => {
                    if size == 0 {
                        log::info!("connection:{} encounter eof from proxy", self.index);
                        self.closing = true;
                        return;
                    }
                    self.client_recv += size;
                    log::debug!("connection:{} got {} bytes proxy data", self.index, size);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    log::debug!("connection:{} has no more data to read from proxy", self.index);
                    break;
                }
                Err(err) => {
                    log::debug!("connection:{} got proxy read error:{}", self.index, err);
                    self.closing = true;
                    return;
                }
            }
        }

        if let Err(err) = self.proxy_session.process_new_packets() {
            log::error!("connection:{} got proxy process error:{}", self.index, err);
            self.closing = true;
            return;
        }

        let mut buffer = Vec::new();
        if let Err(err) = self.proxy_session.read_to_end(&mut buffer) {
            log::warn!("connection:{} got proxy read error:{}", self.index, err);
            self.closing = true;
            return;
        }

        if !buffer.is_empty() {
            self.dispatch(buffer.as_slice(), opts, poll);
        }
    }

    pub fn setup(&mut self, poll: &Poll, opts: &Opts) -> bool {
        if let Err(err) = poll.register(&self.proxy, self.proxy_token(), Ready::readable(), PollOpt::level()) {
            log::error!("connection:{} register proxy failed:{}", self.index, err);
            false
        } else if let Err(err) = sys::set_mark(&self.proxy, opts.marker) {
            log::error!("connection:{} set mark failed:{}", self.index, err);
            false
        } else if let Err(err) = self.proxy.set_nodelay(true) {
            log::error!("connection:{} set nodelay failed:{}", self.index, err);
            false
        } else {
            true
        }
    }

    fn try_read_tcp_target(&mut self) {
        if self.closing {
            return;
        }
        match self.target_session.read_backend(self.tcp_target.as_mut().unwrap()) {
            Err(err) => {
                log::warn!("connection:{} read from target failed:{}", self.index, err);
                self.closing = true;
                return;
            }
            Ok(size) => {
                log::debug!("connection:{} read {} bytes from target", self.index, size);
            }
        }

        let buffer = self.target_session.read_all();
        if !buffer.is_empty() {
            if let Err(err) = self.proxy_session.write_all(buffer.bytes()) {
                log::error!("connection:{} write to proxy failed:{}", self.index, err);
                self.closing = true;
                return;
            } else {
                self.try_send_proxy();
            }
        }
    }

    fn try_handshake(&mut self, buffer: &mut &[u8], opts: &mut Opts, poll: &Poll) -> bool {
        if let Some(request) = TrojanRequest::parse(buffer, opts) {
            self.command = request.command;
            self.sock5_addr = request.address;
            *buffer = request.payload;
        } else {
            log::info!("connection:{} does not get a trojan request, pass through", self.index);
            self.command = CONNECT;
            self.sock5_addr = Sock5Address::None;
        }
        match &self.sock5_addr {
            Sock5Address::Domain(domain, _) => {
                if self.command != CONNECT {
                    //udp associate bind at 0.0.0.0:0, ignore all domain
                    self.target_addr.replace(*opts.empty_addr.as_ref().unwrap());
                    return true;
                }
                log::info!("connection:{} has to resolve {}", self.index, domain);
                let resolver = EventedResolver::new(domain.clone());
                if let Err(err) = poll.register(&resolver, self.target_token(), Ready::readable(), PollOpt::level()) {
                    self.closing = true;
                    log::error!("connection:{} register resolver failed:{}", self.index, err);
                    return false;
                }
                self.resolver.replace(resolver);
            }
            Sock5Address::Socket(address) => {
                log::info!("connection:{} got resolved target address:{}", self.index, address);
                self.target_addr.replace(*address);
            }
            Sock5Address::None => {
                log::info!("connection:{} got default target address:{}", self.index, opts.back_addr.as_ref().unwrap());
                self.target_addr = opts.back_addr.clone();
            }
        }
        true
    }

    fn dispatch(&mut self, mut buffer: &[u8], opts: &mut Opts, poll: &Poll) {
        log::debug!("connection:{} dispatch {} bytes request data", self.index, buffer.len());
        loop {
            match self.status {
                Status::HandShake => {
                    if self.try_handshake(&mut buffer, opts, poll) {
                        self.status = Status::DnsWait;
                    } else {
                        return;
                    }
                }
                Status::DnsWait => {
                    if self.command == CONNECT {
                        if !buffer.is_empty() {
                            log::debug!("connection:{} writing {} bytes payload data to target session", self.index, buffer.len());
                            if let Err(err) = self.target_session.write_all(buffer) {
                                self.closing = true;
                                log::error!("connection:{} write to target session failed:{}", self.index, err);
                                return;
                            } else {
                                buffer = &[];
                            }
                        }

                        if self.target_addr.is_none() {
                            log::warn!("connection:{} dns query not done yet", self.index);
                            return;
                        }

                        if self.try_setup_tcp_target(opts, poll) {
                            self.status = Status::TCPForward;
                        } else {
                            return;
                        }
                    } else {
                        if self.try_setup_udp_target(opts, poll) {
                            self.status = Status::UDPForward;
                        } else {
                            return;
                        }
                    }
                }
                Status::TCPForward => {
                    self.do_send_tcp_target(buffer);
                    break;
                }
                Status::UDPForward => {
                    self.try_send_udp_target(buffer, opts);
                    break;
                }
            }
        }
    }

    fn try_setup_tcp_target(&mut self, opts: &mut Opts, poll: &Poll) -> bool {
        log::info!("connection:{} make a target connection to {}", self.index, self.target_addr.unwrap());
        match TcpStream::connect(self.target_addr.as_ref().unwrap()) {
            Ok(tcp_target) => {
                if let Err(err) = sys::set_mark(&tcp_target, opts.marker) {
                    log::error!("connection:{} set mark failed:{}", self.index, err);
                    self.closing = true;
                    return false;
                } else if let Err(err) = poll.register(&tcp_target, self.target_token(), Ready::readable(), PollOpt::edge()) {
                    log::error!("connection:{} register target failed:{}", self.index, err);
                    self.closing = true;
                    return false;
                } else if let Err(err) = tcp_target.set_nodelay(true) {
                    log::error!("connection:{} set nodelay failed:{}", self.index, err);
                    self.closing = true;
                    return false;
                }
                self.tcp_target.replace(tcp_target);
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
        match UdpSocket::bind(opts.empty_addr.as_ref().unwrap()) {
            Err(err) => {
                log::error!("connection:{} bind udp socket failed:{}", self.index, err);
                self.closing = true;
                return false;
            }
            Ok(udp_target) => {
                if let Err(err) = sys::set_mark(&udp_target, opts.marker) {
                    log::error!("connection:{} set mark failed:{}", self.index, err);
                    self.closing = true;
                    return false;
                }
                if let Err(err) = poll.register(&udp_target, self.target_token(), Ready::readable(), PollOpt::edge()) {
                    log::error!("connection:{} register udp target failed:{}", self.index, err);
                    self.closing = true;
                    return false;
                }
                self.udp_target.replace(udp_target);
            }
        }
        true
    }

    fn do_send_tcp_target(&mut self, mut buffer: &[u8]) {
        // send immediately first
        if self.target_session.wants_write() {
            if let Err(err) = self.target_session.write_all(buffer) {
                self.closing = true;
                log::error!("connection:{} write to back sesion failed:{}", self.index, err);
                return;
            }
            self.try_send_tcp_target();
            return;
        }

        let conn = self.tcp_target.as_mut().unwrap();
        loop {
            if buffer.len() == 0 {
                break;
            }
            match conn.write(buffer) {
                Ok(size) => {
                    buffer = &buffer[size..];
                    log::debug!("connection:{} send {} bytes data to target", self.index, size);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    // if data remains, copy to back session.
                    if let Err(err) = self.target_session.write_all(buffer) {
                        log::error!("connection:{} send to target session failed:{}", self.index, err);
                        self.closing = true;
                    }
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} send to target failed:{}", self.index, err);
                    self.closing = true;
                    break;
                }
            }
        }
    }

    fn try_send_udp_target(&mut self, buffer: &[u8], opts: &mut Opts) {
        if self.closing {
            return;
        }
        if self.udp_send_buffer.is_empty() {
            self.do_send_udp_target(buffer, opts);
        } else {
            self.udp_send_buffer.extend_from_slice(buffer);
            let buffer = self.udp_send_buffer.split();
            self.do_send_udp_target(buffer.as_ref(), opts);
        }
    }

    fn do_send_udp_target(&mut self, mut buffer: &[u8], opts: &mut Opts) {
        loop {
            match UdpAssociate::parse(buffer, opts) {
                UdpParseResult::Packet(packet) => {
                    match self.udp_target.as_ref().unwrap().send_to(&packet.payload[..packet.length], &packet.address) {
                        Ok(size) => {
                            if size != packet.length {
                                log::error!("connection:{} udp packet is truncated, {}：{}", self.index, packet.length, size);
                                self.closing = true;
                                return;
                            }
                            log::debug!("connection:{} write {} bytes to udp target:{}", self.index, size, packet.address);
                            buffer = &packet.payload[packet.length..];
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            self.udp_send_buffer.extend_from_slice(buffer);
                            break;
                        }
                        Err(err) => {
                            log::warn!("connection:{} send_to {} failed:{}", self.index, packet.address, err);
                            self.closing = true;
                            return;
                        }
                    }
                }
                UdpParseResult::InvalidProtocol => {
                    log::error!("connection:{} got invalid udp protocol", self.index);
                    self.closing = true;
                    return;
                }
                UdpParseResult::Continued => {
                    self.udp_send_buffer.extend_from_slice(buffer);
                    break;
                }
            }
        }
    }

    fn reregister(&mut self, poll: &Poll) {
        if self.closing {
            return;
        }
        let mut changed = false;
        if self.proxy_session.wants_write() && !self.proxy_readiness.is_writable() {
            self.proxy_readiness.insert(Ready::writable());
            changed = true;
            log::info!("connection:{} add writable to proxy", self.index)
        }
        if !self.proxy_session.wants_write() && self.proxy_readiness.is_writable() {
            self.proxy_readiness.remove(Ready::writable());
            log::info!("connection:{} remove writable from proxy", self.index);
            changed = true;
        }
        if changed {
            if let Err(err) = poll.reregister(&self.proxy, self.proxy_token(), self.proxy_readiness, PollOpt::level()) {
                log::error!("connection:{} reregister proxy failed:{}", self.index, err);
                self.closing = true;
            }
        }

        if self.tcp_target.is_some() {
            let mut changed = false;
            if self.target_session.wants_write() && !self.target_readiness.is_writable() {
                self.target_readiness.insert(Ready::writable());
                changed = true;
                log::info!("connection:{} add writable to tcp target", self.index);
            }
            if !self.target_session.wants_write() && self.target_readiness.is_writable() {
                self.target_readiness.remove(Ready::writable());
                changed = true;
                log::info!("connection:{} remove writable from tcp target", self.index);
            }

            if changed {
                if let Err(err) = poll.reregister(self.tcp_target.as_ref().unwrap(),
                                                  self.target_token(), self.target_readiness, PollOpt::edge()) {
                    log::error!("connection:{} reregister tcp target failed:{}", self.index, err);
                    self.closing = true;
                }
            }
        }

        if self.udp_target.is_some() {
            let mut changed = false;
            if !self.udp_send_buffer.is_empty() && !self.target_readiness.is_writable() {
                self.target_readiness.insert(Ready::writable());
                changed = true;
                log::info!("connection:{} add writable to udp target", self.index);
            }
            if self.udp_send_buffer.is_empty() && self.target_readiness.is_writable() {
                self.target_readiness.remove(Ready::writable());
                changed = true;
                log::info!("connection:{} remove writable from udp target", self.index);
            }

            if changed {
                if let Err(err) = poll.reregister(self.udp_target.as_ref().unwrap(),
                                                  self.target_token(), self.target_readiness, PollOpt::edge()) {
                    log::error!("connection:{} reregister udp target failed:{}", self.index, err);
                    self.closing = true;
                }
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn proxy_token(&self) -> Token {
        Token(self.index << 1)
    }

    fn target_token(&self) -> Token {
        Token((self.index << 1) + 1)
    }
}
